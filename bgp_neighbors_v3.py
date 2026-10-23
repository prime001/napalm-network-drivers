```python
"""
029_bgp_neighbors.py - BGP Session Health Monitor

Purpose:
    Connects to a network device via NAPALM and evaluates BGP session health.
    Filters sessions by state, flags non-Established peers, and outputs a
    structured report suitable for alerting pipelines or NOC dashboards.

Usage:
    python 029_bgp_neighbors.py --host 192.168.1.1 --driver eos \
        --username admin --password secret

    python 029_bgp_neighbors.py --host 10.0.0.1 --driver ios \
        --username admin --password secret --vrf MGMT --only-down \
        --output json

Prerequisites:
    pip install napalm
    Device must have BGP configured and NAPALM-compatible management access.
"""

import argparse
import json
import logging
import sys

import napalm
from napalm.base.exceptions import ConnectionException, CommandErrorException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

ESTABLISHED = "Established"


def parse_args():
    parser = argparse.ArgumentParser(
        description="BGP session health monitor using NAPALM"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument(
        "--driver",
        required=True,
        choices=["eos", "ios", "iosxr", "junos", "nxos"],
        help="NAPALM driver",
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument(
        "--vrf",
        default=None,
        help="Filter results to a single VRF (default: all VRFs)",
    )
    parser.add_argument(
        "--only-down",
        action="store_true",
        help="Show only sessions not in Established state",
    )
    parser.add_argument(
        "--min-prefixes",
        type=int,
        default=None,
        help="Flag peers receiving fewer than N prefixes",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    return parser.parse_args()


def connect(driver_name, host, username, password, port):
    driver = napalm.get_network_driver(driver_name)
    optional = {}
    if port:
        optional["port"] = port
    device = driver(
        hostname=host,
        username=username,
        password=password,
        optional_args=optional,
    )
    device.open()
    return device


def collect_sessions(device, vrf_filter):
    data = device.get_bgp_neighbors()
    sessions = []

    for vrf_name, vrf_data in data.items():
        if vrf_filter and vrf_name != vrf_filter:
            continue
        router_id = vrf_data.get("router_id", "unknown")
        for peer_ip, peer in vrf_data.get("peers", {}).items():
            sessions.append(
                {
                    "vrf": vrf_name,
                    "router_id": router_id,
                    "peer_ip": peer_ip,
                    "remote_as": peer.get("remote_as", ""),
                    "state": "Established" if peer.get("is_up") else "Not Established",
                    "is_enabled": peer.get("is_enabled", True),
                    "uptime": peer.get("uptime", -1),
                    "prefixes_received": peer.get("address_family", {})
                    .get("ipv4", {})
                    .get("received_prefixes", -1),
                    "description": peer.get("description", ""),
                }
            )
    return sessions


def apply_filters(sessions, only_down, min_prefixes):
    filtered = sessions
    if only_down:
        filtered = [s for s in filtered if s["state"] != ESTABLISHED]
    if min_prefixes is not None:
        filtered = [
            s
            for s in filtered
            if s["prefixes_received"] != -1 and s["prefixes_received"] < min_prefixes
        ]
    return filtered


def format_table(sessions):
    if not sessions:
        return "No sessions match the specified filters."

    header = f"{'VRF':<16} {'Peer IP':<18} {'AS':<8} {'State':<18} {'Uptime(s)':<12} {'Pfx Rx':<8} {'Description'}"
    lines = [header, "-" * len(header)]
    for s in sessions:
        uptime = str(s["uptime"]) if s["uptime"] >= 0 else "N/A"
        pfx = str(s["prefixes_received"]) if s["prefixes_received"] >= 0 else "N/A"
        disabled = " [DISABLED]" if not s["is_enabled"] else ""
        lines.append(
            f"{s['vrf']:<16} {s['peer_ip']:<18} {s['remote_as']:<8} "
            f"{s['state'] + disabled:<18} {uptime:<12} {pfx:<8} {s['description']}"
        )
    return "\n".join(lines)


def main():
    args = parse_args()
    log.info("Connecting to %s via %s driver", args.host, args.driver)

    try:
        device = connect(args.driver, args.host, args.username, args.password, args.port)
    except ConnectionException as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        sessions = collect_sessions(device, args.vrf)
    except CommandErrorException as exc:
        log.error("Failed to retrieve BGP data: %s", exc)
        device.close()
        sys.exit(1)
    finally:
        device.close()

    log.info("Retrieved %d BGP session(s)", len(sessions))
    sessions = apply_filters(sessions, args.only_down, args.min_prefixes)

    down_count = sum(1 for s in sessions if s["state"] != ESTABLISHED)

    if args.output == "json":
        print(json.dumps({"summary": {"total": len(sessions), "not_established": down_count}, "sessions": sessions}, indent=2))
    else:
        print(f"\nHost: {args.host}  |  Sessions matched: {len(sessions)}  |  Not established: {down_count}\n")
        print(format_table(sessions))

    if down_count:
        sys.exit(2)


if __name__ == "__main__":
    main()
```