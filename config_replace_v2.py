The user's instructions are explicit and fully specified — "Output ONLY the script content" overrides the brainstorming design gate. Writing the script now.

#!/usr/bin/env python3
"""
015_arp_table.py - ARP Table Retrieval and Conflict Detection

Retrieves the ARP table from a network device via NAPALM and analyzes it for
IP conflicts (multiple MACs mapped to one IP — indicative of ARP spoofing or
duplicate address assignment) and MAC conflicts (one MAC at multiple IPs —
common with NAT devices or misconfigured hosts).

Usage:
    python 015_arp_table.py -d 192.168.1.1 -u admin -p secret
    python 015_arp_table.py -d 10.0.0.1 -u admin -p secret --filter-ip 10.0.0.0/24
    python 015_arp_table.py -d 10.0.0.1 -u admin -p secret --conflicts-only
    python 015_arp_table.py -d 10.0.0.1 -u admin -p secret --output json

Prerequisites:
    pip install napalm
    SSH must be enabled on the target device.
    Supported drivers: ios, eos, junos, iosxr, iosxe, nxos, nxos_ssh

Exit codes:
    0  Success, no conflicts detected
    1  Connection or retrieval error
    2  Success, but ARP conflicts were found (useful for monitoring pipelines)
"""

import argparse
import ipaddress
import json
import logging
import sys
from collections import defaultdict

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def fetch_arp_table(driver_name, hostname, username, password, port, timeout):
    driver = napalm.get_network_driver(driver_name)
    device = driver(
        hostname=hostname,
        username=username,
        password=password,
        optional_args={"port": port, "conn_timeout": timeout},
    )
    logger.info("Connecting to %s (%s driver)", hostname, driver_name)
    device.open()
    try:
        logger.info("Fetching ARP table")
        return device.get_arp_table()
    finally:
        device.close()
        logger.info("Disconnected from %s", hostname)


def filter_entries(entries, prefix=None, iface=None):
    if prefix:
        network = ipaddress.ip_network(prefix, strict=False)
        entries = [e for e in entries if ipaddress.ip_address(e["ip"]) in network]
    if iface:
        entries = [e for e in entries if iface.lower() in e["interface"].lower()]
    return entries


def detect_conflicts(entries):
    ip_to_macs = defaultdict(set)
    mac_to_ips = defaultdict(set)
    for e in entries:
        ip_to_macs[e["ip"]].add(e["mac"])
        mac_to_ips[e["mac"]].add(e["ip"])
    ip_conflicts = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    mac_conflicts = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    return ip_conflicts, mac_conflicts


def _ip_sort_key(ip_str):
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return ipaddress.ip_address("0.0.0.0")


def print_table(entries, ip_conflicts, mac_conflicts):
    w = (18, 20, 26, 8)
    header = (
        f"{'IP':<{w[0]}} {'MAC':<{w[1]}} {'Interface':<{w[2]}} {'Age(s)':>{w[3]}}  Flags"
    )
    sep = "-" * (sum(w) + 12)
    print(sep)
    print(header)
    print(sep)
    for e in sorted(entries, key=lambda x: _ip_sort_key(x["ip"])):
        flags = []
        if e["ip"] in ip_conflicts:
            flags.append("DUP-IP")
        if e["mac"] in mac_conflicts:
            flags.append("DUP-MAC")
        age = (
            f"{e['age']:.0f}"
            if isinstance(e["age"], (int, float)) and e["age"] >= 0
            else "N/A"
        )
        print(
            f"{e['ip']:<{w[0]}} {e['mac']:<{w[1]}} "
            f"{e['interface']:<{w[2]}} {age:>{w[3]}}  {','.join(flags)}"
        )
    print(sep)
    print(f"Total: {len(entries)} entries")


def print_conflicts(ip_conflicts, mac_conflicts):
    if ip_conflicts:
        print(f"\n[!] IP Conflicts ({len(ip_conflicts)} affected IPs):")
        for ip, macs in sorted(ip_conflicts.items(), key=lambda x: _ip_sort_key(x[0])):
            print(f"    {ip}  ->  {', '.join(sorted(macs))}")
    if mac_conflicts:
        print(f"\n[!] MAC Conflicts ({len(mac_conflicts)} affected MACs):")
        for mac, ips in sorted(mac_conflicts.items()):
            print(f"    {mac}  ->  {', '.join(sorted(ips, key=_ip_sort_key))}")
    if not ip_conflicts and not mac_conflicts:
        print("\n[OK] No ARP conflicts detected.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Retrieve ARP table and detect IP/MAC conflicts via NAPALM",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument(
        "--driver",
        default="ios",
        choices=["ios", "eos", "junos", "iosxr", "iosxe", "nxos", "nxos_ssh"],
        help="NAPALM driver",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument(
        "--filter-ip",
        metavar="PREFIX",
        help="Show only entries within this CIDR prefix (e.g. 10.0.0.0/24)",
    )
    parser.add_argument(
        "--filter-iface",
        metavar="IFACE",
        help="Show only entries on interfaces matching this substring",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )
    parser.add_argument(
        "--conflicts-only",
        action="store_true",
        help="Suppress the full ARP table; print only the conflict summary",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        entries = fetch_arp_table(
            args.driver,
            args.device,
            args.username,
            args.password,
            args.port,
            args.timeout,
        )
    except Exception as exc:
        logger.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)

    entries = filter_entries(entries, args.filter_ip, args.filter_iface)
    ip_conflicts, mac_conflicts = detect_conflicts(entries)

    if args.output == "json":
        print(json.dumps(
            {
                "arp_table": entries,
                "ip_conflicts": {ip: sorted(macs) for ip, macs in ip_conflicts.items()},
                "mac_conflicts": {mac: sorted(ips) for mac, ips in mac_conflicts.items()},
            },
            indent=2,
        ))
    else:
        if not args.conflicts_only:
            print_table(entries, ip_conflicts, mac_conflicts)
        print_conflicts(ip_conflicts, mac_conflicts)

    sys.exit(2 if (ip_conflicts or mac_conflicts) else 0)