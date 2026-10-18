```python
"""
024_arp_table.py — ARP Table Inspector

Purpose:
    Retrieves and analyzes the ARP table from a network device using NAPALM.
    Detects duplicate IP entries (potential IP conflicts), supports filtering
    by interface or subnet, and optionally exports results to CSV for audit
    or IPAM reconciliation workflows.

Usage:
    python 024_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 024_arp_table.py -d 192.168.1.1 -u admin --interface Gi0/0
    python 024_arp_table.py -d 192.168.1.1 -u admin --subnet 10.0.0.0/24
    python 024_arp_table.py -d 192.168.1.1 -u admin --detect-conflicts --csv out.csv
    python 024_arp_table.py -d 192.168.1.1 -u admin --driver eos

Prerequisites:
    pip install napalm
    Device must be reachable and credentials must have read access.
    Supported drivers: ios, eos, junos, nxos, nxos_ssh
"""

import argparse
import csv
import ipaddress
import logging
import sys
from collections import defaultdict
from getpass import getpass

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze ARP table from a network device."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", help="Login password (prompted if omitted)")
    parser.add_argument(
        "--driver",
        default="ios",
        choices=["ios", "eos", "junos", "nxos", "nxos_ssh"],
        help="NAPALM driver (default: ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interface",
        help="Filter entries by interface name (partial match, case-insensitive)",
    )
    parser.add_argument(
        "--subnet",
        help="Filter entries by subnet in CIDR notation (e.g. 10.0.0.0/24)",
    )
    parser.add_argument(
        "--detect-conflicts",
        action="store_true",
        help="Report IP addresses mapped to more than one MAC address",
    )
    parser.add_argument("--csv", dest="csv_file", help="Export filtered results to CSV")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def filter_entries(entries, interface=None, subnet=None):
    result = entries
    if interface:
        result = [
            e for e in result
            if interface.lower() in e.get("interface", "").lower()
        ]
    if subnet:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            logger.error("Invalid subnet %r: %s", subnet, exc)
            sys.exit(1)
        result = [
            e for e in result
            if e.get("ip") and ipaddress.ip_address(e["ip"]) in net
        ]
    return result


def detect_ip_conflicts(entries):
    ip_to_macs = defaultdict(set)
    for entry in entries:
        ip = entry.get("ip")
        mac = entry.get("mac")
        if ip and mac:
            ip_to_macs[ip].add(mac)
    return {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}


def print_table(entries):
    if not entries:
        print("No ARP entries match the given criteria.")
        return
    header = f"{'IP Address':<18} {'MAC Address':<20} {'Interface':<28} {'Age (min)':<10}"
    separator = "-" * len(header)
    print(header)
    print(separator)
    for entry in sorted(entries, key=lambda x: ipaddress.ip_address(x.get("ip", "0.0.0.0"))):
        age = entry.get("age", -1)
        age_str = f"{age:.1f}" if isinstance(age, (int, float)) and age >= 0 else "N/A"
        print(
            f"{entry.get('ip', 'N/A'):<18} "
            f"{entry.get('mac', 'N/A'):<20} "
            f"{entry.get('interface', 'N/A'):<28} "
            f"{age_str:<10}"
        )
    print(f"\nTotal: {len(entries)} entries")


def write_csv(entries, filepath):
    fields = ["ip", "mac", "interface", "age"]
    try:
        with open(filepath, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        logger.info("Exported %d entries to %s", len(entries), filepath)
    except OSError as exc:
        logger.error("Failed to write CSV %r: %s", filepath, exc)
        sys.exit(1)


def main():
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    driver_cls = napalm.get_network_driver(args.driver)
    optional_args = {"port": args.port}

    logger.info("Connecting to %s via %s driver", args.device, args.driver)
    try:
        device = driver_cls(
            hostname=args.device,
            username=args.username,
            password=password,
            optional_args=optional_args,
        )
        device.open()
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        logger.info("Fetching ARP table")
        arp_table = device.get_arp_table()
    except Exception as exc:
        logger.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)
    finally:
        device.close()

    logger.info("Retrieved %d total ARP entries", len(arp_table))

    entries = filter_entries(arp_table, interface=args.interface, subnet=args.subnet)
    if args.interface or args.subnet:
        logger.info("%d entries after filtering", len(entries))

    print_table(entries)

    if args.detect_conflicts:
        conflicts = detect_ip_conflicts(entries)
        if conflicts:
            print(f"\nIP CONFLICTS DETECTED ({len(conflicts)}):")
            for ip, macs in sorted(conflicts.items()):
                print(f"  {ip}  ->  {', '.join(sorted(macs))}")
        else:
            print("\nNo IP conflicts detected.")

    if args.csv_file:
        write_csv(entries, args.csv_file)


if __name__ == "__main__":
    main()
```