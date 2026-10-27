```python
"""
033_arp_table.py — ARP Table Inspector via NAPALM

Purpose:
    Retrieve and analyze the ARP table from a network device. Supports
    filtering by IP prefix, MAC address pattern, or interface name.
    Flags duplicate MACs (same MAC mapped to multiple IPs) which can
    indicate IP aliasing, HSRP/VRRP virtual addresses, or ARP spoofing.

Usage:
    python 033_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 033_arp_table.py -d 192.168.1.1 -u admin -p secret --filter-ip 10.0.1
    python 033_arp_table.py -d 192.168.1.1 -u admin -p secret --format csv --output arp.csv
    python 033_arp_table.py -d 192.168.1.1 -u admin -p secret --flag-duplicates

Prerequisites:
    pip install napalm
    Supported drivers: eos, ios, iosxr, nxos, junos
"""

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from io import StringIO

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown driver '%s': %s", driver_name, exc)
        sys.exit(1)


def connect(driver, host: str, username: str, password: str, timeout: int):
    device = driver(
        hostname=host,
        username=username,
        password=password,
        optional_args={"timeout": timeout},
    )
    try:
        device.open()
        log.info("Connected to %s", host)
        return device
    except Exception as exc:
        log.error("Failed to connect to %s: %s", host, exc)
        sys.exit(1)


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
    filter_iface: str | None,
) -> list[dict]:
    if filter_ip:
        entries = [e for e in entries if e.get("ip", "").startswith(filter_ip)]
    if filter_mac:
        needle = filter_mac.lower().replace("-", ":").replace(".", ":")
        entries = [e for e in entries if needle in e.get("mac", "").lower()]
    if filter_iface:
        entries = [e for e in entries if filter_iface.lower() in e.get("interface", "").lower()]
    return entries


def find_duplicate_macs(entries: list[dict]) -> dict[str, list[str]]:
    mac_to_ips: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        mac = entry.get("mac", "").lower()
        ip = entry.get("ip", "")
        if mac and ip:
            mac_to_ips[mac].append(ip)
    return {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}


def render_table(entries: list[dict], duplicates: dict[str, list[str]]) -> str:
    col_widths = {"interface": 16, "ip": 16, "mac": 19, "age": 8, "flag": 6}
    header = (
        f"{'Interface':<{col_widths['interface']}}"
        f"{'IP Address':<{col_widths['ip']}}"
        f"{'MAC Address':<{col_widths['mac']}}"
        f"{'Age':>{col_widths['age']}}"
        f"  {'Flag'}"
    )
    separator = "-" * (sum(col_widths.values()) + 4)
    lines = [header, separator]
    for e in sorted(entries, key=lambda x: x.get("interface", "")):
        mac = e.get("mac", "").lower()
        flag = "[DUP]" if mac in duplicates else ""
        age = e.get("age", -1)
        age_str = str(int(age)) if age >= 0 else "?"
        lines.append(
            f"{e.get('interface', ''):<{col_widths['interface']}}"
            f"{e.get('ip', ''):<{col_widths['ip']}}"
            f"{e.get('mac', ''):<{col_widths['mac']}}"
            f"{age_str:>{col_widths['age']}}"
            f"  {flag}"
        )
    lines.append(separator)
    lines.append(f"Total entries: {len(entries)}")
    return "\n".join(lines)


def render_csv(entries: list[dict], duplicates: dict[str, list[str]]) -> str:
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=["interface", "ip", "mac", "age", "duplicate"])
    writer.writeheader()
    for e in entries:
        mac = e.get("mac", "").lower()
        writer.writerow({
            "interface": e.get("interface", ""),
            "ip": e.get("ip", ""),
            "mac": e.get("mac", ""),
            "age": e.get("age", -1),
            "duplicate": "yes" if mac in duplicates else "no",
        })
    return buf.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve and analyze ARP table from a network device via NAPALM"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument("--driver", default="ios", help="NAPALM driver (default: ios)")
    parser.add_argument("--timeout", type=int, default=60, help="Connection timeout in seconds")
    parser.add_argument("--filter-ip", metavar="PREFIX", help="Show only entries matching IP prefix")
    parser.add_argument("--filter-mac", metavar="MAC", help="Show only entries matching MAC substring")
    parser.add_argument("--filter-iface", metavar="IFACE", help="Show only entries on this interface")
    parser.add_argument("--flag-duplicates", action="store_true", help="Highlight MACs mapped to multiple IPs")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--output", metavar="FILE", help="Write output to file instead of stdout")
    args = parser.parse_args()

    driver = get_driver(args.driver)
    device = connect(driver, args.device, args.username, args.password, args.timeout)

    try:
        entries = fetch_arp_table(device)
        log.info("Retrieved %d ARP entries", len(entries))

        entries = apply_filters(entries, args.filter_ip, args.filter_mac, args.filter_iface)
        duplicates = find_duplicate_macs(entries) if args.flag_duplicates else {}

        if duplicates:
            log.warning("Duplicate MACs detected (%d): %s", len(duplicates), list(duplicates.keys()))

        if args.format == "json":
            for e in entries:
                e["duplicate_mac"] = e.get("mac", "").lower() in duplicates
            output = json.dumps(entries, indent=2)
        elif args.format == "csv":
            output = render_csv(entries, duplicates)
        else:
            output = render_table(entries, duplicates)

        if args.output:
            with open(args.output, "w") as fh:
                fh.write(output)
            log.info("Output written to %s", args.output)
        else:
            print(output)
    finally:
        device.close()
        log.info("Disconnected from %s", args.device)


if __name__ == "__main__":
    main()
```