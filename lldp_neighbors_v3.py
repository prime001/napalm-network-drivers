The user's explicit instruction is "Output ONLY the script content, no markdown fences, no explanation" — this takes precedence over the brainstorming workflow per the skill's own priority rule. Writing the script directly.

"""
027_lldp_neighbors.py — LLDP Topology Mapper

Retrieves LLDP neighbor detail from a network device and exports the
adjacency data in one of three formats:

  table  — aligned ASCII table printed to stdout (default)
  json   — JSON array, optionally written to a file with --output
  dot    — Graphviz DOT language for topology visualization

DOT output can be piped directly to graphviz:
    python 027_lldp_neighbors.py --host 10.0.0.1 --driver eos \
        --username admin --password secret --format dot \
        | dot -Tpng -o topology.png

Prerequisites:
    pip install napalm
    graphviz package (OS-level) required only for DOT rendering

Tested drivers: ios, eos, junos, nxos_ssh
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

import napalm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def connect(host, driver, username, password, optional_args):
    driver_cls = napalm.get_network_driver(driver)
    device = driver_cls(
        hostname=host,
        username=username,
        password=password,
        optional_args=optional_args,
    )
    device.open()
    return device


def collect(device):
    facts = device.get_facts()
    neighbors = device.get_lldp_neighbors_detail()
    return facts, neighbors


def flatten(facts, neighbors):
    local_host = facts.get("hostname", "unknown")
    records = []
    for local_iface, nbr_list in neighbors.items():
        for nbr in nbr_list:
            records.append(
                {
                    "local_host": local_host,
                    "local_interface": local_iface,
                    "remote_host": nbr.get("remote_system_name", ""),
                    "remote_interface": nbr.get("remote_port", ""),
                    "remote_port_description": nbr.get("remote_port_description", ""),
                    "remote_chassis_id": nbr.get("remote_chassis_id", ""),
                    "remote_system_description": nbr.get("remote_system_description", ""),
                    "remote_capabilities": nbr.get("remote_system_capab", []),
                }
            )
    return records


def render_table(records):
    if not records:
        print("No LLDP neighbors found.")
        return

    w_li = max(len("Local Interface"), max(len(r["local_interface"]) for r in records))
    w_rh = max(len("Remote Host"), max(len(r["remote_host"]) for r in records))
    w_ri = max(len("Remote Interface"), max(len(r["remote_interface"]) for r in records))
    w_rd = min(48, max(len("Description"), max(len(r["remote_port_description"]) for r in records)))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (
        f"{'Local Interface':<{w_li}}  "
        f"{'Remote Host':<{w_rh}}  "
        f"{'Remote Interface':<{w_ri}}  "
        f"{'Description':<{w_rd}}"
    )
    sep = "─" * len(header)

    print(f"\nLLDP Neighbors — {records[0]['local_host']}  ({ts})")
    print(sep)
    print(header)
    print(sep)
    for r in records:
        desc = r["remote_port_description"][:w_rd]
        print(
            f"{r['local_interface']:<{w_li}}  "
            f"{r['remote_host']:<{w_rh}}  "
            f"{r['remote_interface']:<{w_ri}}  "
            f"{desc:<{w_rd}}"
        )
    print(sep)
    print(f"{len(records)} neighbor(s)\n")


def render_json(records, output_path=None):
    payload = json.dumps(records, indent=2)
    if output_path:
        with open(output_path, "w") as fh:
            fh.write(payload)
        log.info("JSON written to %s", output_path)
    else:
        print(payload)


def render_dot(records):
    seen_edges = set()
    lines = [
        "graph lldp_topology {",
        '    graph [layout=neato overlap=false splines=true];',
        '    node [shape=box fontname="Helvetica"];',
    ]
    for r in records:
        src = r["local_host"]
        dst = r["remote_host"] or r["remote_chassis_id"] or "unknown"
        edge_key = tuple(sorted([f"{src}:{r['local_interface']}", f"{dst}:{r['remote_interface']}"]))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        label = f"{r['local_interface']} — {r['remote_interface']}"
        lines.append(f'    "{src}" -- "{dst}" [label="{label}"];')
    lines.append("}")
    print("\n".join(lines))


def parse_optional_args(raw):
    if not raw:
        return {}
    result = {}
    for pair in raw:
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def build_parser():
    p = argparse.ArgumentParser(
        description="Retrieve LLDP neighbor detail and export as table, JSON, or Graphviz DOT."
    )
    p.add_argument("--host", required=True, help="Device hostname or IP address")
    p.add_argument("--driver", default="ios", help="NAPALM driver name (default: ios)")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument(
        "--format",
        choices=["table", "json", "dot"],
        default="table",
        help="Output format (default: table)",
    )
    p.add_argument("--output", metavar="FILE", help="Write output to FILE (json format only)")
    p.add_argument(
        "--optional-args",
        nargs="*",
        metavar="KEY=VALUE",
        help="NAPALM optional_args as key=value pairs (e.g. port=22 secret=enable)",
    )
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    optional_args = parse_optional_args(args.optional_args)

    log.info("Connecting to %s via %s driver", args.host, args.driver)
    try:
        device = connect(args.host, args.driver, args.username, args.password, optional_args)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        facts, neighbors = collect(device)
        records = flatten(facts, neighbors)
    except Exception as exc:
        log.error("Data retrieval failed: %s", exc)
        sys.exit(1)
    finally:
        device.close()
        log.debug("Disconnected from %s", args.host)

    if args.format == "table":
        render_table(records)
    elif args.format == "json":
        render_json(records, args.output)
    elif args.format == "dot":
        render_dot(records)