The repo isn't local — the user wants the script content output directly. Writing it now.

```
"""
004_bgp_neighbor_health.py — BGP Neighbor Health Check via NAPALM

Purpose:
    Connects to one or more network devices and reports the operational state
    of all BGP neighbors: session state, uptime, and per-AFI prefix counts.
    Sessions not in Established state are flagged.  Exit code 1 if any peer
    is down or any device is unreachable; 0 if everything is healthy.

Usage:
    Single device:
        python 004_bgp_neighbor_health.py -d 192.168.1.1 -u admin -p secret --driver eos

    Device list from file (one "host,driver" per line):
        python 004_bgp_neighbor_health.py --device-file devices.txt -u admin -p secret

    Export full results to JSON:
        python 004_bgp_neighbor_health.py -d 192.168.1.1 -u admin -p secret --output bgp.json

Prerequisites:
    pip install napalm
    Supported drivers: ios, eos, junos, nxos, iosxr
    Device file format: one entry per line as "hostname_or_ip,driver".
    Blank lines and lines starting with '#' are ignored.
"""

import argparse
import json
import logging
import sys
from datetime import timedelta
from pathlib import Path

import napalm

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["ios", "eos", "junos", "nxos", "iosxr"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Report BGP neighbor health across one or more devices."
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", metavar="HOST", help="Single device hostname or IP")
    target.add_argument(
        "--device-file", metavar="FILE", help="File with one 'host,driver' per line"
    )
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument(
        "--driver",
        default="ios",
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver (default: ios). Overridden per-host by device-file entries.",
    )
    p.add_argument("--port", type=int, default=22, metavar="N", help="SSH port (default: 22)")
    p.add_argument("--output", metavar="FILE", help="Write full results to this JSON file")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def load_device_list(path: str, default_driver: str) -> list[dict]:
    devices = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",", 1)]
        devices.append(
            {"host": parts[0], "driver": parts[1] if len(parts) > 1 else default_driver}
        )
    return devices


def seconds_to_human(seconds: int) -> str:
    return "never" if seconds < 0 else str(timedelta(seconds=seconds))


def summarize_prefixes(address_family: dict) -> tuple[int, int]:
    received = sent = 0
    for afi_data in address_family.values():
        received += afi_data.get("received_prefixes", 0) or 0
        sent += afi_data.get("sent_prefixes", 0) or 0
    return received, sent


def check_device(host: str, driver: str, username: str, password: str, port: int) -> dict:
    result = {"host": host, "driver": driver, "error": None, "neighbors": []}
    driver_cls = napalm.get_network_driver(driver)
    device = driver_cls(
        hostname=host,
        username=username,
        password=password,
        optional_args={"port": port},
    )
    try:
        log.debug("Connecting to %s via %s driver", host, driver)
        device.open()
        bgp_data = device.get_bgp_neighbors()
    except Exception as exc:
        log.error("%s: connection failed — %s", host, exc)
        result["error"] = str(exc)
        return result
    finally:
        try:
            device.close()
        except Exception:
            pass

    for vrf, vrf_data in bgp_data.items():
        router_id = vrf_data.get("router_id", "unknown")
        for peer_ip, peer in vrf_data.get("peers", {}).items():
            rcvd, sent = summarize_prefixes(peer.get("address_family", {}))
            result["neighbors"].append(
                {
                    "vrf": vrf,
                    "router_id": router_id,
                    "peer_ip": peer_ip,
                    "local_as": peer.get("local_as", "unknown"),
                    "remote_as": peer.get("remote_as", "unknown"),
                    "description": peer.get("description", ""),
                    "state": "Established" if peer.get("is_up") else "Idle",
                    "uptime_sec": peer.get("uptime", -1),
                    "uptime_human": seconds_to_human(peer.get("uptime", -1)),
                    "prefixes_received": rcvd,
                    "prefixes_sent": sent,
                }
            )
    return result


def print_report(results: list[dict]) -> int:
    header = (
        f"  {'VRF':<12} {'Peer IP':<18} {'Remote AS':<12}"
        f" {'State':<14} {'Uptime':<16} {'Rcvd':>6} {'Sent':>6}"
    )
    sep = "  " + "-" * (len(header) - 2)
    total_issues = 0

    for res in results:
        print(f"\n{'='*70}")
        print(f"  Host   : {res['host']}")
        print(f"  Driver : {res['driver']}")
        if res["error"]:
            print(f"  Status : UNREACHABLE — {res['error']}")
            total_issues += 1
            continue
        down_count = sum(1 for n in res["neighbors"] if n["state"] != "Established")
        print(f"  Peers  : {len(res['neighbors'])} total, {down_count} not established")
        if not res["neighbors"]:
            print("  (no BGP neighbors configured)")
            continue
        print()
        print(header)
        print(sep)
        for n in sorted(res["neighbors"], key=lambda x: (x["state"] == "Established", x["peer_ip"])):
            flag = "! " if n["state"] != "Established" else "  "
            print(
                f"{flag} {n['vrf']:<12} {n['peer_ip']:<18} {str(n['remote_as']):<12}"
                f" {n['state']:<14} {n['uptime_human']:<16}"
                f" {n['prefixes_received']:>6} {n['prefixes_sent']:>6}"
            )
        total_issues += down_count

    print(f"\n{'='*70}")
    print(f"  Result : {total_issues} issue(s) across {len(results)} device(s)\n")
    return total_issues


def main() -> None:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.device:
        devices = [{"host": args.device, "driver": args.driver}]
    else:
        try:
            devices = load_device_list(args.device_file, args.driver)
        except FileNotFoundError:
            log.error("Device file not found: %s", args.device_file)
            sys.exit(1)

    if not devices:
        log.error("No devices loaded from %s", args.device_file)
        sys.exit(1)

    results = [
        check_device(d["host"], d["driver"], args.username, args.password, args.port)
        for d in devices
    ]

    issues = print_report(results)

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"JSON results written to {args.output}")

    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
```