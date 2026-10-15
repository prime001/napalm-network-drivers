This is the NetAutoCommitter repo, not napalm-network-drivers. The script is going directly to stdout as requested — output only, no fences.

```python
"""
016_arp_table.py — ARP Table Retrieval and Analysis

Retrieves the ARP table from a network device via NAPALM, with optional
filtering by IP prefix or MAC OUI, duplicate detection (same IP or MAC
appearing on multiple interfaces — a common indicator of ARP poisoning or
misconfigured static entries), and CSV export.

Usage:
    python 016_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 016_arp_table.py -d 192.168.1.1 -u admin -p secret --filter-ip 10.0.1
    python 016_arp_table.py -d 192.168.1.1 -u admin -p secret --filter-mac 00:1a:2b
    python 016_arp_table.py -d 192.168.1.1 -u admin -p secret --duplicates-only --csv arp.csv

Prerequisites:
    pip install napalm
    Supported drivers: ios, eos, junos, nxos, nxos_ssh
"""

import argparse
import csv
import logging
import sys
from collections import defaultdict

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown driver '%s': %s", driver_name, exc)
        sys.exit(1)


def open_device(driver, host: str, username: str, password: str, timeout: int):
    device = driver(
        hostname=host,
        username=username,
        password=password,
        timeout=timeout,
        optional_args={},
    )
    try:
        device.open()
    except Exception as exc:
        log.error("Failed to connect to %s: %s", host, exc)
        sys.exit(1)
    return device


def fetch_arp_table(device) -> list[dict]:
    try:
        return device.get_arp_table()
    except Exception as exc:
        log.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)


def apply_filters(
    entries: list[dict],
    filter_ip: str | None,
    filter_mac: str | None,
) -> list[dict]:
    if filter_ip:
        entries = [e for e in entries if e["ip"].startswith(filter_ip)]
    if filter_mac:
        prefix = filter_mac.lower()
        entries = [e for e in entries if e["mac"].lower().startswith(prefix)]
    return entries


def find_duplicates(entries: list[dict]) -> dict[str, list[dict]]:
    """Return entries where the same IP appears on more than one interface."""
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        by_ip[entry["ip"]].append(entry)
    return {ip: recs for ip, recs in by_ip.items() if len(recs) > 1}


def print_table(entries: list[dict], duplicates: dict[str, list[dict]]) -> None:
    header = f"{'IP':<20} {'MAC':<20} {'Interface':<20} {'Age':>6}  Flag"
    print(header)
    print("-" * len(header))
    for e in entries:
        flag = " *** DUPLICATE IP ***" if e["ip"] in duplicates else ""
        print(
            f"{e['ip']:<20} {e['mac']:<20} {e['interface']:<20} "
            f"{e.get('age', -1):>6.0f}{flag}"
        )
    print(f"\nTotal entries: {len(entries)}")
    if duplicates:
        print(f"Duplicate IPs detected: {len(duplicates)}")


def write_csv(entries: list[dict], path: str) -> None:
    fields = ["ip", "mac", "interface", "age"]
    try:
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        log.info("ARP table written to %s (%d entries)", path, len(entries))
    except OSError as exc:
        log.error("Could not write CSV: %s", exc)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Retrieve and analyse the ARP table from a network device."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="Login username")
    p.add_argument("-p", "--password", required=True, help="Login password")
    p.add_argument(
        "--driver",
        default="ios",
        help="NAPALM driver (default: ios)",
    )
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument("--filter-ip", metavar="PREFIX", help="Show only entries whose IP starts with PREFIX")
    p.add_argument("--filter-mac", metavar="OUI", help="Show only entries whose MAC starts with OUI")
    p.add_argument(
        "--duplicates-only",
        action="store_true",
        help="Print only entries with a duplicated IP address",
    )
    p.add_argument("--csv", metavar="FILE", help="Export results to CSV file")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    driver = get_driver(args.driver)
    log.info("Connecting to %s (%s)…", args.device, args.driver)
    device = open_device(driver, args.device, args.username, args.password, args.timeout)

    try:
        raw = fetch_arp_table(device)
    finally:
        device.close()

    log.info("Retrieved %d ARP entries", len(raw))
    entries = apply_filters(raw, args.filter_ip, args.filter_mac)
    duplicates = find_duplicates(entries)

    if args.duplicates_only:
        entries = [e for ip_entries in duplicates.values() for e in ip_entries]

    entries.sort(key=lambda e: [int(x) for x in e["ip"].split(".")])

    print_table(entries, duplicates)

    if args.csv:
        write_csv(entries, args.csv)

    sys.exit(1 if duplicates else 0)
```