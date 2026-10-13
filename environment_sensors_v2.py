The user's instructions are explicit: "Output ONLY the script content, no markdown fences, no explanation." That overrides the brainstorming workflow. The requirements are fully specified — I'll write the script directly.

The gap in the existing scripts is ARP table analysis — `get_arp_table()` is a NAPALM getter none of the 11 scripts use.

```python
"""
012_arp_inspector.py — ARP Table Collection and Conflict Detection

Purpose:
    Retrieves the ARP table from a network device via NAPALM and analyzes
    entries for duplicate IPs (one IP mapped to multiple MACs) and duplicate
    MACs (one MAC carrying multiple IPs). Either condition may indicate an IP
    address conflict, ARP spoofing, or a misconfigured proxy-ARP setting.

Usage:
    python 012_arp_inspector.py --host 192.168.1.1 --driver ios \
        --username admin --password secret

    python 012_arp_inspector.py --host 192.168.1.1 --driver ios \
        --username admin --password secret \
        --filter-prefix 10.0.0.0/24 --export arp_table.csv

Prerequisites:
    pip install napalm
    Read-level device access. Supported drivers: ios, eos, junos, nxos, nxos_ssh.
"""

import argparse
import csv
import ipaddress
import logging
import sys
from collections import defaultdict

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect ARP table from a device and detect IP/MAC conflicts"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP address")
    parser.add_argument(
        "--driver",
        required=True,
        choices=["ios", "eos", "junos", "nxos", "nxos_ssh"],
        help="NAPALM driver to use",
    )
    parser.add_argument("--username", required=True, help="Device username")
    parser.add_argument("--password", required=True, help="Device password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--filter-prefix",
        metavar="CIDR",
        help="Limit output to entries within this prefix, e.g. 10.0.0.0/24",
    )
    parser.add_argument("--export", metavar="FILE", help="Write ARP table to a CSV file")
    parser.add_argument(
        "--conflicts-only",
        action="store_true",
        help="Suppress the full table; print only conflicting entries",
    )
    return parser.parse_args()


def filter_by_prefix(entries, prefix_str):
    try:
        network = ipaddress.ip_network(prefix_str, strict=False)
    except ValueError as exc:
        log.error("Invalid prefix %r: %s", prefix_str, exc)
        sys.exit(1)
    return [e for e in entries if ipaddress.ip_address(e["ip"]) in network]


def detect_conflicts(entries):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    for entry in entries:
        ip_to_macs[entry["ip"]].add(entry["mac"])
        mac_to_ips[entry["mac"]].add(entry["ip"])
    dup_ips = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    dup_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    return dup_ips, dup_macs


def print_table(entries):
    header = f"{'IP':<18} {'MAC':<20} {'Interface':<22} {'Age':>6}"
    sep = "-" * len(header)
    print(f"\n{header}\n{sep}")
    for e in sorted(entries, key=lambda x: ipaddress.ip_address(x["ip"])):
        age = str(int(e["age"])) if e.get("age") not in (None, -1) else "—"
        print(f"{e['ip']:<18} {e['mac']:<20} {e['interface']:<22} {age:>6}")
    print()


def export_csv(entries, path):
    fieldnames = ["ip", "mac", "interface", "age"]
    try:
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(entries)
        log.info("Exported %d entries to %s", len(entries), path)
    except OSError as exc:
        log.error("Failed to write CSV: %s", exc)


def main():
    args = parse_args()

    driver_cls = napalm.get_network_driver(args.driver)
    device = driver_cls(
        hostname=args.host,
        username=args.username,
        password=args.password,
        optional_args={"port": args.port},
    )

    log.info("Connecting to %s via %s driver", args.host, args.driver)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Fetching ARP table...")
        arp_table = device.get_arp_table()
    except Exception as exc:
        log.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)
    finally:
        device.close()
        log.info("Disconnected from %s", args.host)

    if not arp_table:
        log.warning("ARP table returned empty — check device state or driver support")
        sys.exit(0)

    log.info("Retrieved %d ARP entries", len(arp_table))

    entries = arp_table
    if args.filter_prefix:
        entries = filter_by_prefix(entries, args.filter_prefix)
        log.info("%d entries remain after filtering to %s", len(entries), args.filter_prefix)

    if not args.conflicts_only:
        print(f"ARP Table — {args.host}")
        print_table(entries)

    dup_ips, dup_macs = detect_conflicts(entries)

    if dup_ips:
        print(f"[!] Duplicate IPs ({len(dup_ips)} found — one IP, multiple MACs):")
        for ip, macs in sorted(dup_ips.items(), key=lambda x: ipaddress.ip_address(x[0])):
            print(f"    {ip:>16}  →  {', '.join(sorted(macs))}")
    else:
        print("[OK] No duplicate IP addresses detected")

    if dup_macs:
        print(f"\n[!] Duplicate MACs ({len(dup_macs)} found — one MAC, multiple IPs):")
        for mac, ips in sorted(dup_macs.items()):
            sorted_ips = sorted(ips, key=ipaddress.ip_address)
            print(f"    {mac}  →  {', '.join(sorted_ips)}")
    else:
        print("[OK] No duplicate MAC addresses detected")

    if args.export:
        export_csv(entries, args.export)

    if dup_ips or dup_macs:
        sys.exit(2)


if __name__ == "__main__":
    main()
```