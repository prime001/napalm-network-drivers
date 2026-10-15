The script goes directly to stdout as requested:

```python
"""014_arp_table.py — NAPALM ARP Table Retrieval and Audit

Fetches the ARP table from a network device and displays IP-to-MAC-to-interface
mappings. Useful for network discovery, connectivity troubleshooting, detecting
rogue or unexpected devices on a segment, and pre-change auditing.

Usage:
    python 014_arp_table.py -d 192.168.1.1 -u admin
    python 014_arp_table.py -d 192.168.1.1 -u admin --driver eos
    python 014_arp_table.py -d 192.168.1.1 -u admin --filter-ip 10.0.1.
    python 014_arp_table.py -d 192.168.1.1 -u admin --filter-mac 00:1a
    python 014_arp_table.py -d 192.168.1.1 -u admin --interface GigabitEthernet0/1
    python 014_arp_table.py -d 192.168.1.1 -u admin --format json > arp_snapshot.json
    python 014_arp_table.py -d 192.168.1.1 -u admin --format csv > arp_export.csv

Prerequisites:
    pip install napalm
    Supported NAPALM drivers: ios, eos, junos, nxos, nxos_ssh
    Device credentials require read-level access (show arp / show ip arp).
"""

import argparse
import getpass
import json
import logging
import sys

import napalm

LOG = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Retrieve and filter the ARP table from a network device via NAPALM",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP address")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", default=None, help="Login password (prompted if omitted)")
    parser.add_argument(
        "--driver",
        default="ios",
        choices=["ios", "eos", "junos", "nxos", "nxos_ssh"],
        help="NAPALM driver",
    )
    parser.add_argument("--timeout", type=int, default=60, help="Connection timeout in seconds")
    parser.add_argument(
        "--filter-ip",
        default=None,
        metavar="SUBSTR",
        help="Show only entries whose IP address contains SUBSTR",
    )
    parser.add_argument(
        "--filter-mac",
        default=None,
        metavar="SUBSTR",
        help="Show only entries whose MAC address contains SUBSTR",
    )
    parser.add_argument(
        "--interface",
        default=None,
        metavar="IFACE",
        help="Show only entries learned on this interface (exact match)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def open_device(driver_cls, host, username, password, timeout):
    device = driver_cls(
        hostname=host,
        username=username,
        password=password,
        optional_args={"timeout": timeout},
    )
    try:
        LOG.debug("Connecting to %s", host)
        device.open()
    except Exception as exc:
        LOG.error("Connection to %s failed: %s", host, exc)
        sys.exit(1)
    return device


def apply_filters(entries, filter_ip, filter_mac, interface):
    if filter_ip:
        entries = [e for e in entries if filter_ip.lower() in e.get("ip", "").lower()]
    if filter_mac:
        entries = [e for e in entries if filter_mac.lower() in e.get("mac", "").lower()]
    if interface:
        entries = [e for e in entries if e.get("interface", "").lower() == interface.lower()]
    return entries


def render_table(entries, host):
    w_ip, w_mac, w_iface, w_age = 18, 20, 24, 10
    header = (
        f"{'IP Address':<{w_ip}} {'MAC Address':<{w_mac}} "
        f"{'Interface':<{w_iface}} {'Age (s)':<{w_age}}"
    )
    rule = "─" * len(header)
    print(f"\nARP Table — {host}  ({len(entries)} entries)")
    print(rule)
    print(header)
    print(rule)
    for entry in sorted(entries, key=lambda e: e.get("ip", "")):
        age = entry.get("age", -1)
        age_str = str(int(age)) if isinstance(age, (int, float)) and age >= 0 else "—"
        print(
            f"{entry.get('ip', ''):<{w_ip}} {entry.get('mac', ''):<{w_mac}} "
            f"{entry.get('interface', ''):<{w_iface}} {age_str:<{w_age}}"
        )
    print(rule)


def render_csv(entries):
    print("ip,mac,interface,age")
    for entry in sorted(entries, key=lambda e: e.get("ip", "")):
        age = entry.get("age", -1)
        print(f"{entry.get('ip','')},{entry.get('mac','')},{entry.get('interface','')},{age}")


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    try:
        driver_cls = napalm.get_network_driver(args.driver)
    except napalm.base.exceptions.ModuleImportError as exc:
        LOG.error("Driver '%s' unavailable: %s", args.driver, exc)
        sys.exit(1)

    device = open_device(driver_cls, args.device, args.username, password, args.timeout)

    try:
        LOG.debug("Retrieving ARP table")
        raw = device.get_arp_table()
    except NotImplementedError:
        LOG.error("Driver '%s' does not implement get_arp_table()", args.driver)
        sys.exit(1)
    except Exception as exc:
        LOG.error("Failed to fetch ARP table: %s", exc)
        sys.exit(1)
    finally:
        device.close()

    entries = apply_filters(raw, args.filter_ip, args.filter_mac, args.interface)

    if not entries:
        print("No ARP entries matched the specified filters.")
        sys.exit(0)

    if args.format == "json":
        print(json.dumps(sorted(entries, key=lambda e: e.get("ip", "")), indent=2))
    elif args.format == "csv":
        render_csv(entries)
    else:
        render_table(entries, args.device)


if __name__ == "__main__":
    main()
```

This covers ARP table retrieval — IP/MAC/interface/age mapping with subnet-prefix filtering, MAC OUI filtering, per-interface scoping, and three output formats (table/JSON/CSV). It's the natural complement to `007_lldp_neighbors.py` (L2 topology) and `006_interface_counters.py` (L2 stats) for switch/router visibility.