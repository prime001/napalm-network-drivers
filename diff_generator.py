The repo doesn't exist yet; the user just wants the script content. Writing it now.

```
"""
003_config_diff.py — NAPALM candidate-config diff generator.

Purpose:
    Load a candidate configuration file and compare it to the running
    configuration on a network device.  Prints a unified diff and exits
    non-zero when a diff exists, making it safe to use in CI pipelines
    or pre-change checklists.  No configuration is committed; the
    candidate is always discarded after comparison.

Usage:
    # Merge diff (default) — show what would be added/changed
    python 003_config_diff.py -d 192.168.1.1 -u admin -p secret candidate.cfg

    # Full-replacement diff — show full delta if entire config were replaced
    python 003_config_diff.py -d 192.168.1.1 -u admin -p secret candidate.cfg \
        --replace --driver eos

    # Pass driver-specific options (e.g. HTTPS transport for EOS)
    python 003_config_diff.py -d 192.168.1.1 -u admin -p secret candidate.cfg \
        --driver eos --optional-args "{'transport': 'https'}"

Prerequisites:
    pip install napalm
    Candidate file must be in the device's native configuration syntax.
    The account used needs read access (merge diff) or config-session
    privileges (replace diff) depending on platform.

Exit codes:
    0  No diff — running config already matches candidate
    1  Diff produced — changes would be applied
    2  Error — connection failure, auth error, or file not found
"""

import argparse
import ast
import logging
import sys

import napalm

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(message)s"
logging.basicConfig(format=_LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["ios", "iosxe", "iosxr", "eos", "nxos", "nxos_ssh", "junos"]


def parse_args():
    p = argparse.ArgumentParser(
        description="Compare a candidate config against the running config (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("candidate", help="Path to candidate configuration file")
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    p.add_argument("-u", "--username", required=True, help="Login username")
    p.add_argument("-p", "--password", required=True, help="Login password")
    p.add_argument(
        "--driver",
        default="ios",
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver (default: ios)",
    )
    p.add_argument("--port", type=int, default=None, help="Override default driver port")
    p.add_argument(
        "--optional-args",
        default="{}",
        metavar="DICT",
        help='Driver optional args as a Python dict literal: \'{"key": "val"}\'',
    )
    p.add_argument(
        "--replace",
        action="store_true",
        help="Diff as full config replacement instead of merge (default: merge)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def read_candidate(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError as exc:
        log.error("Cannot read candidate file '%s': %s", path, exc)
        sys.exit(2)


def parse_optional_args(raw, port):
    try:
        opts = ast.literal_eval(raw)
    except (ValueError, SyntaxError) as exc:
        log.error("--optional-args must be a valid Python dict literal: %s", exc)
        sys.exit(2)
    if not isinstance(opts, dict):
        log.error("--optional-args must evaluate to a dict, got %s", type(opts).__name__)
        sys.exit(2)
    if port is not None:
        opts.setdefault("port", port)
    return opts


def main():
    args = parse_args()
    log.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    optional_args = parse_optional_args(args.optional_args, args.port)
    candidate_text = read_candidate(args.candidate)

    driver_cls = napalm.get_network_driver(args.driver)
    device = driver_cls(
        hostname=args.device,
        username=args.username,
        password=args.password,
        optional_args=optional_args,
    )

    log.info("Connecting to %s (driver: %s)", args.device, args.driver)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(2)

    diff = None
    success = False
    try:
        load_fn = device.load_replace_candidate if args.replace else device.load_merge_candidate
        mode = "replace" if args.replace else "merge"
        log.info("Loading candidate config [%s mode] from '%s'", mode, args.candidate)
        load_fn(config=candidate_text)
        diff = device.compare_config()
        success = True
    except Exception as exc:
        log.error("Failed to load or compare candidate config: %s", exc)
    finally:
        try:
            device.discard_config()
        except Exception as exc:
            log.warning("Could not discard candidate config: %s", exc)
        device.close()
        log.debug("Session closed")

    if not success:
        sys.exit(2)

    if not diff or not diff.strip():
        log.info("No diff — running config already matches candidate")
        sys.exit(0)

    print(diff)
    log.info("Diff: %d line(s). Review changes before committing.", len(diff.splitlines()))
    sys.exit(1)


if __name__ == "__main__":
    main()
```