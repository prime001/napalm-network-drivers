```python
"""
017_lldp_topology.py — Multi-Device LLDP Topology Builder

Purpose:
    Collects LLDP neighbor data from multiple network devices and builds
    a deduplicated network topology. Useful for auditing discovered adjacencies
    across a fleet and generating topology diagrams.

    Unlike 007_lldp_neighbors.py (single-device neighbor listing), this script
    queries an inventory of devices concurrently, resolves bidirectional
    duplicate links, and emits structured output for downstream tooling.

Usage:
    python 017_lldp_topology.py -d 10.0.0.1 10.0.0.2 --driver eos -p secret
    python 017_lldp_topology.py --inventory hosts.txt --driver ios -u admin -p secret
    python 017_lldp_topology.py -d 10.0.0.1 --driver eos -p s3cr3t --format dot > topo.dot
    dot -Tpng topo.dot -o topology.png

Prerequisites:
    pip install napalm
    LLDP must be enabled on all target devices.
    Credentials must have at least read-only privilege.

Supported drivers: eos, ios, junos, nxos, nxos_ssh
"""

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_driver(name: str):
    try:
        return napalm.get_network_driver(name)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown NAPALM driver '%s': %s", name, exc)
        sys.exit(1)


def collect_device(host: str, driver, username: str, password: str, port: int) -> dict | None:
    device = driver(
        hostname=host,
        username=username,
        password=password,
        optional_args={"port": port},
    )
    try:
        log.info("Connecting to %s", host)
        device.open()
        neighbors = device.get_lldp_neighbors()
        facts = device.get_facts()
        return {"host": host, "hostname": facts.get("hostname", host), "neighbors": neighbors}
    except Exception as exc:
        log.error("%s — collection failed: %s", host, exc)
        return None
    finally:
        try:
            device.close()
        except Exception:
            pass


def build_edges(results: list) -> list:
    seen = set()
    edges = []
    for result in results:
        src = result["hostname"]
        for local_iface, neighbors in result["neighbors"].items():
            for nbr in neighbors:
                dst = nbr.get("hostname", "unknown")
                dst_iface = nbr.get("port", "unknown")
                key = tuple(sorted([(src, local_iface), (dst, dst_iface)]))
                if key in seen:
                    continue
                seen.add(key)
                edges.append(
                    {
                        "local_device": src,
                        "local_interface": local_iface,
                        "remote_device": dst,
                        "remote_interface": dst_iface,
                    }
                )
    return sorted(edges, key=lambda e: (e["local_device"], e["local_interface"]))


def fmt_table(edges: list) -> None:
    if not edges:
        print("No LLDP adjacencies found.")
        return
    col = [28, 22, 28, 22]
    header = (
        f"{'LOCAL DEVICE':<{col[0]}} {'LOCAL INTF':<{col[1]}} "
        f"{'REMOTE DEVICE':<{col[2]}} {'REMOTE INTF':<{col[3]}}"
    )
    print(header)
    print("-" * len(header))
    for e in edges:
        print(
            f"{e['local_device']:<{col[0]}} {e['local_interface']:<{col[1]}} "
            f"{e['remote_device']:<{col[2]}} {e['remote_interface']:<{col[3]}}"
        )


def fmt_dot(edges: list) -> None:
    devices = set()
    for e in edges:
        devices.update([e["local_device"], e["remote_device"]])
    print("graph network_topology {")
    print('    graph [layout=neato overlap=false splines=true];')
    for d in sorted(devices):
        print(f'    "{d}";')
    for e in edges:
        label = f'{e["local_interface"]} — {e["remote_interface"]}'
        print(f'    "{e["local_device"]}" -- "{e["remote_device"]}" [label="{label}"];')
    print("}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build a deduplicated LLDP topology from multiple devices."
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--devices", nargs="+", metavar="HOST")
    src.add_argument("--inventory", metavar="FILE", help="One host per line, # comments ignored")
    p.add_argument("--driver", required=True,
                   choices=["eos", "ios", "junos", "nxos", "nxos_ssh"])
    p.add_argument("-u", "--username", default="admin")
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--format", choices=["table", "json", "dot"], default="table")
    p.add_argument("--workers", type=int, default=5,
                   help="Concurrent device connections (default: 5)")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.inventory:
        try:
            with open(args.inventory) as fh:
                devices = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as exc:
            log.error("Cannot read inventory: %s", exc)
            sys.exit(1)
    else:
        devices = args.devices

    driver = get_driver(args.driver)
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(collect_device, h, driver, args.username, args.password, args.port): h
            for h in devices
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                results.append(result)

    if not results:
        log.error("No data collected. Check credentials and connectivity.")
        sys.exit(1)

    edges = build_edges(results)
    log.info("Found %d unique adjacencies across %d device(s).", len(edges), len(results))

    if args.format == "json":
        print(json.dumps(edges, indent=2))
    elif args.format == "dot":
        fmt_dot(edges)
    else:
        fmt_table(edges)


if __name__ == "__main__":
    main()
```