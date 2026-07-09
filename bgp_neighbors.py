```python
"""
BGP Neighbor State Monitor — 009_bgp_neighbors.py

Connects to a network device via NAPALM and retrieves BGP neighbor information,
displaying peer state, AS numbers, uptime, and prefix counts in a readable table
or JSON output.

Usage:
    python 009_bgp_neighbors.py -d 192.168.1.1 -u admin -p secret
    python 009_bgp_neighbors.py -d 192.168.1.1 -u admin -p secret --driver eos
    python 009_bgp_neighbors.py -d 192.168.1.1 -u admin -p secret --filter established
    python 009_bgp_neighbors.py -d 192.168.1.1 -u admin -p secret --json

Prerequisites:
    pip install napalm
    Supported drivers: ios, eos, junos, nxos, nxos_ssh
"""

import argparse
import json
import logging
import sys
from datetime import timedelta

import napalm
from napalm.base.exceptions import ConnectionException, NapalmException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

VALID_STATES = {"established", "idle", "active", "connect", "opensent", "openconfirm"}
COLUMN_WIDTHS = (18, 8, 12, 10, 12, 12, 10)
HEADERS = ("Neighbor", "AS", "State", "Uptime", "Pfx Rcvd", "Pfx Sent", "MsgRcvd")


def format_uptime(seconds: int) -> str:
    if seconds < 0:
        return "never"
    td = timedelta(seconds=seconds)
    days = td.days
    hours, rem = divmod(td.seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def print_table(neighbors: list[dict]) -> None:
    fmt = "  ".join(f"{{:<{w}}}" for w in COLUMN_WIDTHS)
    sep = "  ".join("-" * w for w in COLUMN_WIDTHS)
    print(fmt.format(*HEADERS))
    print(sep)
    for n in neighbors:
        stats = n.get("address_family", {})
        ipv4 = stats.get("ipv4", {})
        pfx_rcvd = ipv4.get("received_prefixes", -1)
        pfx_sent = ipv4.get("sent_prefixes", -1)
        print(fmt.format(
            n["neighbor"],
            str(n.get("remote_as", "?")),
            n.get("connection_state", "unknown").lower(),
            format_uptime(n.get("uptime", -1)),
            str(pfx_rcvd) if pfx_rcvd >= 0 else "n/a",
            str(pfx_sent) if pfx_sent >= 0 else "n/a",
            str(n.get("messages_received", 0)),
        ))


def flatten_neighbors(raw: dict) -> list[dict]:
    rows = []
    for vrf, vrf_data in raw.items():
        for peer_ip, peer_data in vrf_data.get("peers", {}).items():
            rows.append({"neighbor": peer_ip, "vrf": vrf, **peer_data})
    return sorted(rows, key=lambda x: x["neighbor"])


def get_bgp_neighbors(device: str, username: str, password: str, driver: str,
                      port: int, optional_args: dict) -> dict:
    driver_cls = napalm.get_network_driver(driver)
    log.info("Connecting to %s (%s) as %s", device, driver, username)
    with driver_cls(hostname=device, username=username, password=password,
                    optional_args={"port": port, **optional_args}) as dev:
        log.info("Fetching BGP neighbors")
        return dev.get_bgp_neighbors()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="BGP neighbor state monitor via NAPALM")
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="Login username")
    p.add_argument("-p", "--password", required=True, help="Login password")
    p.add_argument("--driver", default="ios",
                   choices=["ios", "eos", "junos", "nxos", "nxos_ssh"],
                   help="NAPALM driver (default: ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--filter", dest="state_filter", metavar="STATE",
                   help=f"Show only peers in this state: {', '.join(sorted(VALID_STATES))}")
    p.add_argument("--vrf", default=None, help="Limit output to a specific VRF")
    p.add_argument("--json", dest="output_json", action="store_true",
                   help="Output raw JSON instead of table")
    p.add_argument("--enable-password", dest="enable_password", default=None,
                   help="Enable password (IOS only)")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.state_filter and args.state_filter.lower() not in VALID_STATES:
        log.error("Invalid state filter '%s'. Choose from: %s",
                  args.state_filter, ", ".join(sorted(VALID_STATES)))
        return 1

    optional = {}
    if args.enable_password:
        optional["enable_password"] = args.enable_password

    try:
        raw = get_bgp_neighbors(args.device, args.username, args.password,
                                args.driver, args.port, optional)
    except ConnectionException as exc:
        log.error("Connection failed: %s", exc)
        return 1
    except NapalmException as exc:
        log.error("NAPALM error: %s", exc)
        return 1

    if args.vrf:
        if args.vrf not in raw:
            log.error("VRF '%s' not found. Available: %s",
                      args.vrf, ", ".join(raw.keys()) or "none")
            return 1
        raw = {args.vrf: raw[args.vrf]}

    if args.output_json:
        print(json.dumps(raw, indent=2, default=str))
        return 0

    neighbors = flatten_neighbors(raw)

    if args.state_filter:
        target = args.state_filter.lower()
        neighbors = [n for n in neighbors
                     if n.get("connection_state", "").lower() == target]

    if not neighbors:
        log.info("No BGP neighbors found matching the given criteria.")
        return 0

    established = sum(1 for n in neighbors
                      if n.get("connection_state", "").lower() == "established")
    print(f"\nDevice : {args.device}")
    print(f"Peers  : {len(neighbors)} total, {established} established\n")
    print_table(neighbors)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```