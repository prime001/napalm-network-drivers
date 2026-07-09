008_get_config.py — Retrieve and optionally filter the running (or candidate) configuration
from a network device using NAPALM.

Usage:
    python 008_get_config.py -d 192.168.1.1 -u admin -p secret --driver ios
    python 008_get_config.py -d 192.168.1.1 -u admin -p secret --driver eos --section "^interface"
    python 008_get_config.py -d 192.168.1.1 -u admin -p secret --driver iosxr --sanitized --output router.cfg
    python 008_get_config.py -d 192.168.1.1 -u admin -p secret --driver junos --candidate

Prerequisites:
    pip install napalm
    Supported drivers: ios, eos, junos, iosxr, nxos_ssh

Section filtering matches a regex against each line and captures the matched line plus any
indented continuation lines (the block beneath it), making it useful for extracting a single
protocol stanza or interface block from a large config.
"""

import argparse
import logging
import re
import sys
from pathlib import Path

import napalm

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["ios", "eos", "junos", "iosxr", "nxos_ssh"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve running or candidate configuration from a network device via NAPALM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument(
        "--driver",
        required=True,
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--section",
        metavar="REGEX",
        help="Return only lines matching this pattern plus their indented block",
    )
    parser.add_argument(
        "--sanitized",
        action="store_true",
        help="Request sanitized config (secrets replaced with <removed>)",
    )
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="Retrieve candidate config instead of running config",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write config to this file (default: stdout)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational log output",
    )
    return parser.parse_args()


def filter_section(config: str, pattern: str) -> str:
    """Return matched lines and any immediately following indented block lines."""
    regex = re.compile(pattern, re.IGNORECASE)
    result: list[str] = []
    in_block = False

    for line in config.splitlines():
        if regex.search(line):
            result.append(line)
            in_block = True
        elif in_block and line and line[0] == " ":
            result.append(line)
        else:
            in_block = False

    return "\n".join(result)


def retrieve_config(args: argparse.Namespace) -> str:
    driver_class = napalm.get_network_driver(args.driver)
    device = driver_class(
        hostname=args.device,
        username=args.username,
        password=args.password,
        optional_args={"port": args.port},
    )

    log.info("Connecting to %s (%s driver, port %d)", args.device, args.driver, args.port)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    config_type = "candidate" if args.candidate else "running"
    try:
        log.info("Retrieving %s config (sanitized=%s)", config_type, args.sanitized)
        configs = device.get_config(retrieve=config_type, sanitized=args.sanitized)
    except Exception as exc:
        log.error("Failed to retrieve config: %s", exc)
        sys.exit(1)
    finally:
        device.close()
        log.info("Disconnected from %s", args.device)

    config_text: str = configs.get(config_type, "")
    if not config_text:
        log.warning("Device returned an empty '%s' config block", config_type)

    return config_text


def main() -> None:
    args = parse_args()

    if args.quiet:
        logging.disable(logging.CRITICAL)

    config = retrieve_config(args)

    if args.section:
        log.info("Applying section filter: %r", args.section)
        config = filter_section(config, args.section)
        if not config:
            log.warning("Pattern %r matched no lines", args.section)
            sys.exit(0)

    if args.output:
        dest = Path(args.output)
        try:
            dest.write_text(config)
            log.info("Wrote %d bytes to %s", len(config), dest)
        except OSError as exc:
            log.error("Could not write output file: %s", exc)
            sys.exit(1)
    else:
        print(config)


if __name__ == "__main__":
    main()