```python
"""022_arp_audit.py — ARP Table Auditor

Purpose:
    Retrieve and audit the ARP table from a network device using NAPALM.
    Detects duplicate IP-to-MAC mappings (potential IP conflicts), reports
    per-interface entry counts, and emits structured JSON suitable for
    ingestion by monitoring pipelines or IPAM reconciliation scripts.

Usage:
    python 022_arp_audit.py -d 192.168.1.1 -u admin -p secret --driver ios
    python 022_arp_audit.py -d 10.0.0.1 -u admin -p secret --driver eos --json
    python 022_arp_audit.py -d 10.0.0.1 -u admin -p secret --filter 192.168.10
    python 022_arp_audit.py -d 10.0.0.1 -u admin -p secret --conflicts-only
    python 022_arp_audit.py -d 10.0.0.1 -u admin -p secret --summary

Prerequisites:
    pip install napalm
    Supported NAPALM drivers: ios, eos, junos, nxos_ssh, iosxr
    Device user requires privilege level sufficient to run 'show arp'.
"""

import argparse
import json
import logging
import sys
from collections import defaultdict

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def open_device(driver_name: str, hostname: str, username: str, password: str, port: int):
    driver = napalm.get_network_driver(driver_name)
    device = driver(
        hostname=hostname,
        username=username,
        password=password,
        optional_args={"port": port},
    )
    device.open()
    return device


def fetch_arp_table(device) -> list:
    logger.info("Fetching ARP table")
    return device.get_arp_table()


def find_ip_conflicts(entries: list) -> dict:
    by_ip = defaultdict(list)
    for entry in entries:
        by_ip[entry["ip"]].append(entry)
    return {ip: hits for ip, hits in by_ip.items() if len(hits) > 1}


def find_mac_conflicts(entries: list) -> dict:
    by_mac = defaultdict(list)
    for entry in entries:
        by_mac[entry["mac"]].append(entry)
    return {mac: hits for mac, hits in by_mac.items() if len(hits) > 1}


def summarize_by_interface(entries: list) -> dict:
    counts: dict = defaultdict(int)
    for entry in entries:
        counts[entry.get("interface", "unknown")] += 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def filter_by_prefix(entries: list, prefix: str) -> list:
    return [e for e in entries if e["ip"].startswith(prefix)]


def print_table(entries: list, ip_conflicts: dict, mac_conflicts: dict) -> None:
    conflict_ips = set(ip_conflicts)
    conflict_macs = set(mac_conflicts)
    col = f"{'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'INTERFACE':<22} {'AGE':>7}  FLAG"
    print(col)
    print("-" * len(col))
    for entry in sorted(entries, key=lambda e: tuple(int(o) for o in e["ip"].split(".") if o.isdigit())):
        flags = []
        if entry["ip"] in conflict_ips:
            flags.append("IP-CONFLICT")
        if entry["mac"] in conflict_macs:
            flags.append("MAC-MOVES")
        age = entry.get("age", -1)
        age_str = f"{age:.0f}s" if isinstance(age, (int, float)) and age >= 0 else "N/A"
        print(
            f"{entry['ip']:<18} {entry['mac']:<20} "
            f"{entry.get('interface', ''):<22} {age_str:>7}  {', '.join(flags)}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit ARP table on a network device via NAPALM",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument("--driver", default="ios",
                        help="NAPALM driver (ios, eos, junos, nxos_ssh, iosxr)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--filter", metavar="PREFIX", dest="prefix_filter",
                        help="Show only entries whose IP starts with PREFIX")
    parser.add_argument("--json", action="store_true", dest="output_json",
                        help="Emit full ARP table as JSON and exit")
    parser.add_argument("--conflicts-only", action="store_true",
                        help="Show only entries involved in IP or MAC conflicts")
    parser.add_argument("--summary", action="store_true",
                        help="Print per-interface counts and conflict totals, then exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("Connecting to %s (%s)", args.device, args.driver)
        device = open_device(args.driver, args.device, args.username, args.password, args.port)
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        entries = fetch_arp_table(device)
    except Exception as exc:
        logger.error("ARP table retrieval failed: %s", exc)
        sys.exit(1)
    finally:
        try:
            device.close()
        except Exception:
            pass

    logger.info("Retrieved %d ARP entries", len(entries))

    if args.prefix_filter:
        entries = filter_by_prefix(entries, args.prefix_filter)
        logger.info("%d entries after prefix filter '%s'", len(entries), args.prefix_filter)

    if args.output_json:
        print(json.dumps(entries, indent=2))
        return

    ip_conflicts = find_ip_conflicts(entries)
    mac_conflicts = find_mac_conflicts(entries)

    if args.summary:
        counts = summarize_by_interface(entries)
        print(f"\nARP Audit Summary — {args.device}")
        print(f"  Total entries  : {len(entries)}")
        print(f"  IP conflicts   : {len(ip_conflicts)}")
        print(f"  MAC moves      : {len(mac_conflicts)}")
        print("\n  Entries by interface:")
        for iface, count in counts.items():
            print(f"    {iface:<30} {count:>5}")
        return

    display = entries
    if args.conflicts_only:
        flagged = set(ip_conflicts) | {
            e["ip"] for mac, hits in mac_conflicts.items() for e in hits
        }
        display = [e for e in entries if e["ip"] in flagged]

    total_flags = len(ip_conflicts) + len(mac_conflicts)
    print(f"\nARP Table — {args.device}  "
          f"({len(display)} entries shown, {total_flags} conflict group(s))\n")
    print_table(display, ip_conflicts, mac_conflicts)

    if ip_conflicts:
        print(f"\n[!] {len(ip_conflicts)} IP conflict(s) — same IP, different MACs:")
        for ip, hits in sorted(ip_conflicts.items()):
            macs = "  /  ".join(h["mac"] for h in hits)
            print(f"    {ip}  ->  {macs}")

    if mac_conflicts:
        print(f"\n[!] {len(mac_conflicts)} MAC move(s) — same MAC on multiple IPs:")
        for mac, hits in sorted(mac_conflicts.items()):
            ips = "  /  ".join(h["ip"] for h in hits)
            print(f"    {mac}  ->  {ips}")

    if ip_conflicts or mac_conflicts:
        sys.exit(2)


if __name__ == "__main__":
    main()
```