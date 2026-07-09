The user wants the script content as output only. Here it is:

```
"""
007_lldp_neighbors.py — LLDP Neighbor Discovery via NAPALM

Purpose:
    Query LLDP neighbor tables from network devices and present physical
    topology adjacencies in human-readable or machine-parseable formats.
    Useful for topology audits, cable documentation, and change verification.

Usage:
    python 007_lldp_neighbors.py --host 192.168.1.1 --driver ios \
        --username admin --password secret

    python 007_lldp_neighbors.py --host 192.168.1.1 --driver eos \
        --username admin --password secret --detail --format json

    python 007_lldp_neighbors.py --host 192.168.1.1 --driver nxos_ssh \
        --username admin --password secret --interface Eth1/1 --format csv

Prerequisites:
    pip install napalm
    Python 3.10+
    LLDP must be globally enabled on the target device and on neighbor-facing
    interfaces. Confirm with: show lldp neighbors (IOS/NX-OS) or
    show lldp neighbors (EOS).

Supported drivers: ios, eos, junos, nxos_ssh, iosxr
"""

import argparse
import csv
import json
import logging
import sys
from typing import Optional

import napalm
from napalm.base.exceptions import ConnectionException, NapalmException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

DRIVERS = ["ios", "eos", "junos", "nxos_ssh", "iosxr"]


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except Exception as exc:
        log.error("Cannot load driver '%s': %s", driver_name, exc)
        sys.exit(1)


def connect(driver, host: str, username: str, password: str, port: int, timeout: int):
    device = driver(
        hostname=host,
        username=username,
        password=password,
        optional_args={"port": port, "conn_timeout": timeout},
    )
    try:
        log.info("Connecting to %s ...", host)
        device.open()
    except ConnectionException as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)
    return device


def fetch_neighbors(device, detail: bool, iface_filter: Optional[str]) -> dict:
    try:
        raw = device.get_lldp_neighbors_detail() if detail else device.get_lldp_neighbors()
    except NapalmException as exc:
        log.error("Failed to retrieve LLDP data: %s", exc)
        device.close()
        sys.exit(1)

    if iface_filter:
        raw = {k: v for k, v in raw.items() if iface_filter.lower() in k.lower()}
        if not raw:
            log.warning("No neighbors matched interface filter '%s'", iface_filter)

    return raw


def flatten_detail(raw: dict) -> list:
    rows = []
    for local_iface, neighbors in raw.items():
        for n in neighbors:
            desc = (n.get("remote_system_description") or "").replace("\n", " ").strip()
            rows.append({
                "local_interface": local_iface,
                "remote_system": n.get("remote_system_name", ""),
                "remote_port": n.get("remote_port", ""),
                "remote_port_desc": n.get("remote_port_description", ""),
                "remote_chassis_id": n.get("remote_chassis_id", ""),
                "remote_system_desc": desc[:72],
                "capabilities": ", ".join(n.get("remote_system_enable_capab", []) or []),
            })
    return rows


def flatten_basic(raw: dict) -> list:
    rows = []
    for local_iface, neighbors in raw.items():
        for n in neighbors:
            rows.append({
                "local_interface": local_iface,
                "remote_system": n.get("hostname", ""),
                "remote_port": n.get("port", ""),
            })
    return rows


def output_table(rows: list, detail: bool) -> None:
    if not rows:
        print("No LLDP neighbors found.")
        return

    cols = (
        ["local_interface", "remote_system", "remote_port",
         "remote_chassis_id", "remote_system_desc"]
        if detail
        else ["local_interface", "remote_system", "remote_port"]
    )
    widths = {
        c: max(len(c), max((len(str(r.get(c, ""))) for r in rows), default=0))
        for c in cols
    }
    fmt = "  ".join("{:<" + str(widths[c]) + "}" for c in cols)

    print(fmt.format(*[c.upper() for c in cols]))
    print(fmt.format(*["-" * widths[c] for c in cols]))
    for row in rows:
        print(fmt.format(*[str(row.get(c, "")) for c in cols]))
    print(f"\n{len(rows)} neighbor(s) found.")


def output_json(rows: list) -> None:
    print(json.dumps(rows, indent=2))


def output_csv(rows: list) -> None:
    if not rows:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Query LLDP neighbor tables from network devices via NAPALM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device hostname or IP address")
    p.add_argument("--driver", required=True, choices=DRIVERS, help="NAPALM driver name")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout (seconds)")
    p.add_argument("--detail", action="store_true",
                   help="Fetch extended attributes: chassis ID, capabilities, system description")
    p.add_argument("--interface", metavar="IFACE",
                   help="Filter to a local interface (substring match, e.g. 'Gi0/1')")
    p.add_argument("--format", dest="fmt", choices=["table", "json", "csv"],
                   default="table", help="Output format")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    driver = get_driver(args.driver)
    device = connect(driver, args.host, args.username, args.password, args.port, args.timeout)

    try:
        raw = fetch_neighbors(device, args.detail, args.interface)
        rows = flatten_detail(raw) if args.detail else flatten_basic(raw)
    finally:
        device.close()
        log.info("Disconnected from %s", args.host)

    if args.fmt == "table":
        output_table(rows, args.detail)
    elif args.fmt == "json":
        output_json(rows)
    elif args.fmt == "csv":
        output_csv(rows)
```