The user explicitly says "Output ONLY the script content" — a direct instruction that takes highest priority over the brainstorming workflow. Writing the script now.

```python
"""
035_arp_table.py — ARP Table Retrieval and Anomaly Analysis

Purpose:
    Retrieves the ARP table from a network device via NAPALM and performs
    analysis: duplicate IP detection, duplicate MAC detection (potential
    IP spoofing or NIC replacement), and per-interface filtering. Useful
    for network auditing, troubleshooting, and IP address management.

Usage:
    python 035_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 035_arp_table.py -d 192.168.1.1 -u admin -p secret --driver eos
    python 035_arp_table.py -d 192.168.1.1 -u admin -p secret --filter-iface Vlan10
    python 035_arp_table.py -d 192.168.1.1 -u admin -p secret --csv arp_export.csv

Prerequisites:
    pip install napalm
    Device must be reachable and credentials must have read access.
    Supported NAPALM drivers: eos, junos, iosxr, nxos, ios
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
)
log = logging.getLogger(__name__)


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown driver '%s': %s", driver_name, exc)
        sys.exit(1)


def fetch_arp_table(device) -> list:
    try:
        return device.get_arp_table()
    except Exception as exc:
        log.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)


def analyze_arp(entries: list) -> dict:
    ip_buckets = defaultdict(list)
    mac_buckets = defaultdict(list)

    for entry in entries:
        ip_buckets[entry["ip"]].append(entry)
        mac_buckets[entry["mac"]].append(entry)

    return {
        "total": len(entries),
        "duplicate_ips": {ip: ents for ip, ents in ip_buckets.items() if len(ents) > 1},
        "duplicate_macs": {mac: ents for mac, ents in mac_buckets.items() if len(ents) > 1},
    }


def print_table(entries: list, filter_iface: str = None) -> None:
    if filter_iface:
        entries = [e for e in entries if e.get("interface", "") == filter_iface]

    if not entries:
        print("No ARP entries found.")
        return

    col_w = {"iface": 22, "ip": 18, "mac": 19, "age": 7}
    header = (
        f"{'Interface':<{col_w['iface']}} {'IP':<{col_w['ip']}} "
        f"{'MAC':<{col_w['mac']}} {'Age(s)':>{col_w['age']}}"
    )
    print(header)
    print("-" * len(header))

    for e in sorted(entries, key=lambda x: (x.get("interface", ""), x["ip"])):
        age = e.get("age", -1)
        age_str = f"{age:.0f}" if isinstance(age, (int, float)) and age >= 0 else "n/a"
        iface = e.get("interface", "N/A")
        print(
            f"{iface:<{col_w['iface']}} {e['ip']:<{col_w['ip']}} "
            f"{e['mac']:<{col_w['mac']}} {age_str:>{col_w['age']}}"
        )


def write_csv(entries: list, path: str) -> None:
    fields = ["interface", "ip", "mac", "age"]
    try:
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        log.info("ARP table written to %s (%d entries)", path, len(entries))
    except OSError as exc:
        log.error("Could not write CSV: %s", exc)


def report_anomalies(analysis: dict) -> None:
    anomalies_found = False

    if analysis["duplicate_ips"]:
        anomalies_found = True
        print(f"\n[WARN] Duplicate IPs ({len(analysis['duplicate_ips'])}):")
        for ip, ents in sorted(analysis["duplicate_ips"].items()):
            ifaces = ", ".join(e.get("interface", "?") for e in ents)
            macs = ", ".join(e["mac"] for e in ents)
            print(f"  {ip}  interfaces={ifaces}  macs={macs}")

    if analysis["duplicate_macs"]:
        anomalies_found = True
        print(f"\n[WARN] Duplicate MACs ({len(analysis['duplicate_macs'])}):")
        for mac, ents in sorted(analysis["duplicate_macs"].items()):
            ips = ", ".join(e["ip"] for e in ents)
            print(f"  {mac}  resolves_to={ips}")

    if not anomalies_found:
        print("\n[OK] No anomalies detected.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze the ARP table from a network device via NAPALM."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument(
        "--driver",
        default="ios",
        choices=["eos", "junos", "iosxr", "nxos", "ios"],
        help="NAPALM driver (default: ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--filter-iface",
        metavar="INTERFACE",
        help="Show only entries for this interface",
    )
    parser.add_argument("--csv", metavar="FILE", help="Export ARP table to CSV file")
    parser.add_argument(
        "--no-analysis", action="store_true", help="Skip anomaly analysis"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    driver = get_driver(args.driver)
    device = driver(
        hostname=args.device,
        username=args.username,
        password=args.password,
        optional_args={"port": args.port},
    )

    log.info("Connecting to %s (%s)", args.device, args.driver)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        entries = fetch_arp_table(device)
        print(f"\nARP Table — {args.device}  ({len(entries)} entries)\n")
        print_table(entries, filter_iface=args.filter_iface)

        if args.csv:
            write_csv(entries, args.csv)

        if not args.no_analysis:
            analysis = analyze_arp(entries)
            report_anomalies(analysis)
    finally:
        device.close()
        log.info("Connection closed.")
```