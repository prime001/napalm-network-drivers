#!/usr/bin/env python3
"""
ARP Table Retrieval and Analysis

Retrieves the ARP table from a network device using NAPALM and provides
filtering, duplicate-IP detection, and export to JSON or CSV.

Purpose:
    Network engineers use ARP tables to map IP addresses to MAC addresses
    for troubleshooting connectivity, auditing endpoint locations, and
    detecting ARP spoofing (one IP resolving to multiple MACs).

Usage:
    python 028_arp_table.py -d 192.168.1.1 -u admin -p secret --driver ios
    python 028_arp_table.py -d 10.0.0.1 -u admin -p secret --driver eos --filter-ip 10.0.0.100
    python 028_arp_table.py -d 10.0.0.1 -u admin -p secret --driver junos --check-duplicates
    python 028_arp_table.py -d 10.0.0.1 -u admin -p secret --driver nxos --format csv -o arp.csv

Prerequisites:
    pip install napalm
    Supported drivers: ios, eos, junos, nxos, nxos_ssh
"""

import argparse
import csv
import json
import logging
import sys

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["ios", "eos", "junos", "nxos", "nxos_ssh"]


def get_driver(driver_name):
    try:
        return napalm.get_network_driver(driver_name)
    except napalm.base.exceptions.ModuleImportError as exc:
        logger.error("Failed to load driver '%s': %s", driver_name, exc)
        sys.exit(1)


def open_device(driver, hostname, username, password, port):
    device = driver(
        hostname=hostname,
        username=username,
        password=password,
        optional_args={"port": port},
    )
    try:
        device.open()
        logger.info("Connected to %s", hostname)
        return device
    except Exception as exc:
        logger.error("Connection to %s failed: %s", hostname, exc)
        sys.exit(1)


def fetch_arp_table(device):
    try:
        return device.get_arp_table()
    except Exception as exc:
        logger.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)


def apply_filters(entries, filter_ip, filter_mac, filter_iface):
    if filter_ip:
        entries = [e for e in entries if filter_ip in e.get("ip", "")]
    if filter_mac:
        needle = filter_mac.lower()
        entries = [e for e in entries if needle in e.get("mac", "").lower()]
    if filter_iface:
        entries = [e for e in entries if filter_iface in e.get("interface", "")]
    return entries


def find_duplicate_ips(entries):
    mapping = {}
    for entry in entries:
        ip = entry.get("ip", "")
        mac = entry.get("mac", "")
        mapping.setdefault(ip, set()).add(mac)
    return {ip: sorted(macs) for ip, macs in mapping.items() if len(macs) > 1}


def print_table(entries):
    if not entries:
        print("No ARP entries match the given criteria.")
        return
    col = {"ip": 18, "mac": 20, "interface": 22, "age": 10}
    header = (
        f"{'IP Address':<{col['ip']}} {'MAC Address':<{col['mac']}} "
        f"{'Interface':<{col['interface']}} {'Age (min)':<{col['age']}}"
    )
    print(header)
    print("-" * len(header))
    for e in entries:
        age = e.get("age", -1)
        age_str = f"{age:.1f}" if isinstance(age, (int, float)) and age >= 0 else "N/A"
        print(
            f"{e.get('ip', ''):<{col['ip']}} {e.get('mac', ''):<{col['mac']}} "
            f"{e.get('interface', ''):<{col['interface']}} {age_str:<{col['age']}}"
        )
    print(f"\nTotal: {len(entries)} entries")


def write_json(entries, path):
    try:
        with open(path, "w") as fh:
            json.dump(entries, fh, indent=2)
        logger.info("Wrote %d entries to %s", len(entries), path)
    except OSError as exc:
        logger.error("Cannot write JSON to %s: %s", path, exc)
        sys.exit(1)


def write_csv(entries, path):
    if not entries:
        logger.warning("No entries to write.")
        return
    fields = ["ip", "mac", "interface", "age"]
    try:
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        logger.info("Wrote %d entries to %s", len(entries), path)
    except OSError as exc:
        logger.error("Cannot write CSV to %s: %s", path, exc)
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze the ARP table from a network device via NAPALM."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument("--driver", required=True, choices=SUPPORTED_DRIVERS, help="NAPALM driver")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--filter-ip", metavar="SUBSTR", help="Show only entries whose IP contains SUBSTR")
    parser.add_argument("--filter-mac", metavar="SUBSTR", help="Show only entries whose MAC contains SUBSTR")
    parser.add_argument("--filter-iface", metavar="SUBSTR", help="Show only entries on interfaces matching SUBSTR")
    parser.add_argument(
        "--check-duplicates",
        action="store_true",
        help="Report IPs that resolve to more than one MAC address",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("-o", "--output", help="Output file path (required for json/csv formats)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.format in ("json", "csv") and not args.output:
        logger.error("--output is required when --format is json or csv")
        sys.exit(1)

    driver = get_driver(args.driver)
    device = open_device(driver, args.device, args.username, args.password, args.port)

    try:
        entries = fetch_arp_table(device)
    finally:
        device.close()
        logger.debug("Disconnected from %s", args.device)

    entries = apply_filters(entries, args.filter_ip, args.filter_mac, args.filter_iface)

    if args.check_duplicates:
        dupes = find_duplicate_ips(entries)
        if dupes:
            print(f"WARNING: {len(dupes)} IP(s) map to multiple MACs (possible ARP spoofing or misconfiguration):")
            for ip, macs in sorted(dupes.items()):
                print(f"  {ip}  ->  {', '.join(macs)}")
        else:
            print("OK: No duplicate IP-to-MAC mappings detected.")
        print()

    if args.format == "json":
        write_json(entries, args.output)
    elif args.format == "csv":
        write_csv(entries, args.output)
    else:
        print_table(entries)


if __name__ == "__main__":
    main()