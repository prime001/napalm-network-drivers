The user's requirements are fully specified — this is a direct code generation request with explicit output format constraints ("Output ONLY the script content"). Proceeding to write the config-merge script.

```python
"""
010_config_merge.py — NAPALM Config Merge

Push a partial (merge) configuration to a network device without replacing
the running config.  Equivalent to pasting config snippets into a CLI
session: stanzas not referenced in the candidate file are preserved as-is.

Use cases:
    - Applying an ACL or prefix-list update
    - Adding SNMP community strings or NTP servers
    - Pushing interface-specific changes across a fleet

Usage:
    python 010_config_merge.py -d 192.0.2.1 -u admin -p secret \\
        --driver ios --config snippet.cfg

    # Dry-run (show diff, do not commit):
    python 010_config_merge.py -d 192.0.2.1 -u admin -p secret \\
        --driver ios --config snippet.cfg --dry-run

    # Suppress diff output (CI/CD pipelines):
    python 010_config_merge.py -d 192.0.2.1 -u admin -p secret \\
        --driver eos --config snippet.cfg --no-diff

Prerequisites:
    pip install napalm
    Supported drivers: eos, junos, iosxr, nxos, ios
"""

import argparse
import logging
import sys

import napalm
from napalm.base.exceptions import ModuleImportError as NapalmImportError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ("eos", "junos", "iosxr", "nxos", "ios")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge a partial config onto a network device via NAPALM",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument(
        "--driver",
        required=True,
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver name",
    )
    parser.add_argument(
        "--config",
        required=True,
        metavar="FILE",
        help="Path to partial config file to merge",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override default device port",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print diff and exit without committing",
    )
    parser.add_argument(
        "--no-diff",
        action="store_true",
        help="Skip diff output (useful in non-interactive pipelines)",
    )
    return parser.parse_args()


def load_config_file(path: str) -> str:
    try:
        with open(path) as fh:
            content = fh.read().strip()
    except OSError as exc:
        log.error("Cannot read config file: %s", exc)
        sys.exit(1)
    if not content:
        log.error("Config file is empty: %s", path)
        sys.exit(1)
    return content


def get_driver(name: str):
    try:
        return napalm.get_network_driver(name)
    except NapalmImportError as exc:
        log.error("NAPALM driver unavailable — is the package installed? %s", exc)
        sys.exit(1)


def main() -> None:
    args = parse_args()
    config_text = load_config_file(args.config)
    driver_cls = get_driver(args.driver)

    optional_args = {}
    if args.port is not None:
        optional_args["port"] = args.port

    log.info("Connecting to %s using driver '%s'", args.device, args.driver)
    device = driver_cls(
        hostname=args.device,
        username=args.username,
        password=args.password,
        optional_args=optional_args,
    )

    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Loading merge candidate from '%s'", args.config)
        device.load_merge_candidate(config=config_text)

        diff = device.compare_config()

        if not args.no_diff:
            if diff.strip():
                print("\n--- pending diff  (- running / + candidate) ---")
                print(diff)
                print("--- end diff ---\n")
            else:
                log.info("No diff — candidate is identical to running config")

        if args.dry_run:
            log.info("Dry-run: discarding candidate without commit")
            device.discard_config()
            return

        if not diff.strip():
            log.info("Nothing to commit — skipping")
            device.discard_config()
            return

        log.info("Committing merge to %s", args.device)
        device.commit_config()
        log.info("Commit successful")

    except Exception as exc:
        log.error("Config merge failed: %s", exc)
        log.warning("Discarding candidate to leave running config unchanged")
        try:
            device.discard_config()
            log.info("Discard successful")
        except Exception as discard_exc:
            log.error("Discard also failed: %s", discard_exc)
        sys.exit(1)

    finally:
        device.close()
        log.info("Connection closed")


if __name__ == "__main__":
    main()
```