The user's request is for a standalone script, not tied to this repo's codebase. I have everything needed — writing the script now.

```python
"""
ARP Table Retrieval — napalm-network-drivers #034

Purpose:
    Fetches the ARP table from a network device via NAPALM and renders it
    as a human-readable table, JSON, or CSV.  Useful for IP-to-MAC audits,
    stale-entry detection, and feeding IPAM tools.

Usage:
    python 034_arp_table.py --host 192.168.1.1 --driver eos \
        --username admin --password secret

    python 034_arp_table.py --host 10.0.0.1 --driver ios \
        --username admin --password secret \
        --output csv --filter-prefix 10.0.0.0/24

    python 034_arp_table.py --host 10.0.0.1 --driver nxos_ssh \
        --username admin --password secret \
        --output json --interface Vlan100

Prerequisites:
    pip install napalm
    Supported drivers: eos, ios, iosxr, nxos_ssh, junos
    Device must support NAPALM's get_arp_table() getter.
"""

import argparse
import csv
import json
import logging
import sys
from ipaddress import ip_address, ip_network

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DRIVERS = ["eos", "ios", "iosxr", "nxos_ssh", "junos"]


def parse_args():
    p = argparse.ArgumentParser(
        description="Retrieve ARP table from a network device via NAPALM"
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--driver", required=True, choices=DRIVERS, help="NAPALM driver")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument(
        "--output",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument(
        "--interface",
        metavar="INTF",
        help="Limit results to a single interface (e.g. GigabitEthernet0/0)",
    )
    p.add_argument(
        "--filter-prefix",
        metavar="CIDR",
        help="Limit results to IPs within a prefix (e.g. 10.0.0.0/24)",
    )
    return p.parse_args()


def apply_filters(entries, interface, filter_prefix):
    if interface:
        entries = [e for e in entries if e.get("interface") == interface]

    if filter_prefix:
        try:
            net = ip_network(filter_prefix, strict=False)
        except ValueError as exc:
            log.error("Invalid prefix %r: %s", filter_prefix, exc)
            sys.exit(1)
        entries = [
            e for e in entries
            if e.get("ip") and ip_address(e["ip"]) in net
        ]

    return sorted(entries, key=lambda e: ip_address(e.get("ip") or "0.0.0.0"))


def render_table(entries):
    if not entries:
        print("No ARP entries match the given filters.")
        return

    w_intf = max(len("Interface"), max(len(e.get("interface", "")) for e in entries))
    w_ip   = max(len("IP Address"), max(len(e.get("ip", "")) for e in entries))
    w_mac  = max(len("MAC Address"), max(len(e.get("mac", "")) for e in entries))

    header = (
        f"{'Interface':<{w_intf}}  {'IP Address':<{w_ip}}  "
        f"{'MAC Address':<{w_mac}}  {'Age (s)'}"
    )
    print(header)
    print("-" * len(header))

    for e in entries:
        age = e.get("age", -1.0)
        age_str = f"{age:.1f}" if isinstance(age, (int, float)) and age >= 0 else "N/A"
        print(
            f"{e.get('interface', ''):<{w_intf}}  "
            f"{e.get('ip', ''):<{w_ip}}  "
            f"{e.get('mac', ''):<{w_mac}}  "
            f"{age_str}"
        )

    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} found.")


def render_csv(entries):
    fields = ["interface", "ip", "mac", "age"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for e in entries:
        writer.writerow({f: e.get(f, "") for f in fields})


def get_arp_table(args):
    driver_class = napalm.get_network_driver(args.driver)
    device = driver_class(
        hostname=args.host,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        optional_args={"port": args.port},
    )

    log.info("Connecting to %s via %s driver", args.host, args.driver)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        log.info("Fetching ARP table")
        return device.get_arp_table()
    except NotImplementedError:
        log.error("Driver %r does not implement get_arp_table()", args.driver)
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to retrieve ARP table: %s", exc)
        sys.exit(1)
    finally:
        device.close()


def main():
    args = parse_args()
    raw = get_arp_table(args)
    entries = apply_filters(raw, args.interface, args.filter_prefix)

    if args.output == "json":
        print(json.dumps(entries, indent=2))
    elif args.output == "csv":
        render_csv(entries)
    else:
        render_table(entries)


if __name__ == "__main__":
    main()
```