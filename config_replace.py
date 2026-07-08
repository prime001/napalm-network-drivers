#!/usr/bin/env python3
"""
005_config_replace.py — Atomic full-configuration replacement via NAPALM.

Purpose:
    Replaces a device's entire running configuration with a candidate config file
    using NAPALM's load_replace_candidate(). Displays a unified diff before
    committing so the operator can verify the blast radius, with optional dry-run
    mode and automatic rollback on failure.

    Unlike 003_diff_generator.py (which compares two local files), this script
    actually pushes the candidate to the device and drives a commit/rollback cycle.

Usage:
    python 005_config_replace.py --device 192.168.1.1 --driver ios \\
        --username admin --candidate router.cfg

    python 005_config_replace.py --device 192.168.1.1 --driver eos \\
        --username admin --candidate switch.cfg --dry-run

    python 005_config_replace.py --device 192.168.1.1 --driver junos \\
        --username admin --candidate fw.conf --no-confirm

Prerequisites:
    pip install napalm
    - Candidate config must be a complete, valid device configuration.
    - Credentials must have privilege sufficient to replace configuration.
    - For IOS: 'archive' must be configured for rollback support.
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path

import napalm

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["ios", "eos", "junos", "nxos", "iosxr", "nxos_ssh"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replace device configuration atomically via NAPALM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--device", required=True, help="Device hostname or IP address")
    parser.add_argument(
        "--driver",
        required=True,
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver name",
    )
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--candidate",
        required=True,
        type=Path,
        metavar="FILE",
        help="Path to candidate configuration file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show diff only; discard candidate without committing",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Commit without interactive confirmation prompt",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Device connection timeout",
    )
    parser.add_argument(
        "--optional-args",
        nargs="*",
        metavar="KEY=VALUE",
        help="NAPALM optional_args as space-separated KEY=VALUE pairs (e.g. port=8022)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug-level logging",
    )
    return parser.parse_args()


def parse_optional_args(pairs):
    if not pairs:
        return {}
    result = {}
    for pair in pairs:
        key, _, value = pair.partition("=")
        if not key or not value:
            log.warning("Skipping malformed optional-arg: %r", pair)
            continue
        result[key.strip()] = value.strip()
    return result


def load_candidate(path: Path) -> str:
    if not path.exists():
        log.error("Candidate config not found: %s", path)
        sys.exit(1)
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        log.error("Candidate config file is empty: %s", path)
        sys.exit(1)
    log.info("Loaded candidate config: %s (%d bytes)", path, len(content))
    return content


def prompt_confirm(device: str) -> bool:
    try:
        answer = input(f"\nCommit configuration to {device}? [yes/no]: ").strip().lower()
        return answer in ("yes", "y")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def replace_config(args):
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    candidate = load_candidate(args.candidate)
    optional_args = parse_optional_args(args.optional_args)

    driver_class = napalm.get_network_driver(args.driver)
    conn = driver_class(
        hostname=args.device,
        username=args.username,
        password=password,
        timeout=args.timeout,
        optional_args=optional_args,
    )

    log.info("Connecting to %s via driver '%s'...", args.device, args.driver)
    try:
        conn.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    exit_code = 0
    try:
        log.info("Staging candidate configuration...")
        conn.load_replace_candidate(config=candidate)

        diff = conn.compare_config()
        if not diff.strip():
            log.info("No differences detected. Device is already at desired state.")
            conn.discard_config()
            return

        print("\n--- diff (running vs candidate) ---")
        print(diff)
        print("--- end diff ---\n")

        if args.dry_run:
            log.info("Dry-run: discarding candidate without commit.")
            conn.discard_config()
            return

        commit = args.no_confirm or prompt_confirm(args.device)

        if commit:
            log.info("Committing configuration to %s...", args.device)
            conn.commit_config()
            log.info("Commit successful.")
        else:
            log.info("Commit declined — discarding candidate.")
            conn.discard_config()

    except Exception as exc:
        log.error("Error during config replace: %s", exc)
        log.info("Attempting rollback...")
        try:
            conn.rollback()
            log.info("Rollback completed.")
        except Exception as rb_exc:
            log.error("Rollback failed: %s — manual intervention required.", rb_exc)
        exit_code = 1
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log.info("Connection closed.")

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    replace_config(parse_args())