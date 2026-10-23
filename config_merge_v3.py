The user has provided complete, explicit requirements and said "Output ONLY the script content" — user instruction takes precedence over the brainstorming workflow here.

```python
"""
030_config_merge.py - Safe config merge with pre/post validation and automatic rollback.

Purpose:
    Merge a candidate configuration snippet onto a network device using NAPALM.
    Performs connectivity validation before applying the change. After commit,
    re-validates connectivity and automatically rolls back if the device becomes
    unreachable, preventing runaway misconfigurations in production.

Usage:
    python 030_config_merge.py --device 192.168.1.1 --driver ios \
        --username admin --config snippet.txt

    python 030_config_merge.py --device 192.168.1.1 --driver eos \
        --username admin --config snippet.txt --dry-run --debug

    python 030_config_merge.py --device 192.168.1.1 --driver junos \
        --username admin --password secret --config snippet.txt \
        --yes --validate-delay 10

Prerequisites:
    pip install napalm
    Candidate config file must contain driver-appropriate syntax (IOS, EOS, JunOS, etc.)
    Device must permit SSH and support NAPALM's merge/commit/rollback operations.
"""

import argparse
import getpass
import logging
import sys
import time

import napalm
from napalm.base.exceptions import ConnectionException, MergeConfigException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except Exception:
        logger.error(
            "Unknown or unavailable driver '%s'. Common options: ios, eos, junos, nxos_ssh",
            driver_name,
        )
        sys.exit(1)


def check_connectivity(device) -> bool:
    try:
        device.get_facts()
        return True
    except Exception as exc:
        logger.warning("Connectivity probe failed: %s", exc)
        return False


def read_config_file(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read()
    except OSError as exc:
        logger.error("Cannot read config file '%s': %s", path, exc)
        sys.exit(1)


def run(args: argparse.Namespace) -> None:
    driver_cls = get_driver(args.driver)
    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    optional_args = {}
    if args.port:
        optional_args["port"] = args.port

    logger.info("Connecting to %s via %s driver", args.device, args.driver)
    device = driver_cls(
        hostname=args.device,
        username=args.username,
        password=password,
        optional_args=optional_args,
    )

    try:
        device.open()
    except ConnectionException as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Pre-merge connectivity check ...")
        if not check_connectivity(device):
            logger.error("Pre-merge probe failed — aborting before any change is loaded")
            sys.exit(1)
        logger.info("Pre-merge check passed")

        candidate = read_config_file(args.config)
        logger.info(
            "Loading candidate config from '%s' (%d bytes)", args.config, len(candidate)
        )

        try:
            device.load_merge_candidate(config=candidate)
        except MergeConfigException as exc:
            logger.error("Failed to load candidate config: %s", exc)
            device.discard_config()
            sys.exit(1)

        diff = device.compare_config()
        if not diff.strip():
            logger.info("No diff — device already reflects candidate config, nothing to do")
            device.discard_config()
            return

        print("\n" + "─" * 60)
        print("Config diff:")
        print(diff)
        print("─" * 60 + "\n")

        if args.dry_run:
            logger.info("Dry run — discarding candidate (no changes applied)")
            device.discard_config()
            return

        if not args.yes:
            try:
                answer = input("Apply this configuration merge? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                logger.info("Aborted — discarding candidate config")
                device.discard_config()
                return
            if answer != "y":
                logger.info("User declined — discarding candidate config")
                device.discard_config()
                return

        logger.info("Committing configuration merge ...")
        device.commit_config()
        logger.info("Commit successful")

        if args.validate_delay > 0:
            logger.info(
                "Waiting %ds before post-merge validation ...", args.validate_delay
            )
            time.sleep(args.validate_delay)

        logger.info("Post-merge connectivity check ...")
        if check_connectivity(device):
            logger.info("Post-merge check passed — change is stable")
        else:
            logger.error(
                "Post-merge connectivity check FAILED — device unreachable after commit"
            )
            logger.warning("Initiating automatic rollback ...")
            try:
                device.rollback()
                logger.info("Rollback completed — device restored to pre-change config")
            except Exception as rb_exc:
                logger.critical(
                    "Rollback FAILED: %s — manual intervention required immediately",
                    rb_exc,
                )
            sys.exit(2)

    except KeyboardInterrupt:
        print()
        logger.warning("Interrupted — discarding any pending candidate config")
        try:
            device.discard_config()
        except Exception:
            pass
        sys.exit(1)
    finally:
        device.close()
        logger.debug("Connection closed")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Merge a config snippet onto a device with pre/post connectivity "
            "validation and automatic rollback on failure."
        )
    )
    parser.add_argument("--device", required=True, help="Device hostname or IP address")
    parser.add_argument(
        "--driver",
        required=True,
        help="NAPALM driver name (ios, eos, junos, nxos_ssh, ...)",
    )
    parser.add_argument("--username", required=True, help="Authentication username")
    parser.add_argument(
        "--password", default=None, help="Authentication password (prompted if omitted)"
    )
    parser.add_argument(
        "--port", type=int, default=None, help="SSH port override (uses driver default if omitted)"
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="FILE",
        help="Path to candidate config snippet file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and display diff only — do not commit any changes",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip interactive confirmation prompt",
    )
    parser.add_argument(
        "--validate-delay",
        type=int,
        default=5,
        metavar="SECS",
        help="Seconds to wait before post-merge probe (default: 5)",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable DEBUG-level log output"
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    run(args)
```