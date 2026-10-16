The brainstorming skill doesn't apply here — the user provided a complete, precise specification and explicitly requested only raw script output. Proceeding directly.

"""BGP Neighbor Health Monitor

Connects to a network device via NAPALM and evaluates the health of all BGP
neighbor sessions. Reports non-established sessions, prefix count anomalies,
and session age as stability indicators. Suitable for integration with
monitoring pipelines: returns Nagios-compatible exit codes and optional JSON.

Usage:
    python 019_bgp_neighbor_health.py --host 192.0.2.1 --driver ios \
        --username admin [--password SECRET] \
        [--prefix-warn 400] [--prefix-crit 500] \
        [--min-uptime 300] [--json]

Prerequisites:
    pip install napalm
"""

import argparse
import getpass
import json
import logging
import sys
from typing import Any

import napalm

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_WARN = 1
EXIT_CRIT = 2


def get_driver(driver_name: str):
    try:
        return napalm.get_network_driver(driver_name)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown NAPALM driver %r: %s", driver_name, exc)
        sys.exit(EXIT_CRIT)


def connect(driver, host: str, username: str, password: str, port: int, timeout: int):
    device = driver(
        hostname=host,
        username=username,
        password=password,
        optional_args={"port": port, "timeout": timeout},
    )
    try:
        device.open()
        return device
    except Exception as exc:
        log.error("Cannot connect to %s: %s", host, exc)
        sys.exit(EXIT_CRIT)


def assess_neighbors(
    bgp_data: dict[str, Any],
    prefix_warn: int,
    prefix_crit: int,
    min_uptime: int,
) -> tuple[list[dict], int]:
    issues = []
    worst = EXIT_OK

    for vrf, vrf_data in bgp_data.items():
        peers = vrf_data.get("peers", {})
        for peer_ip, peer in peers.items():
            is_up = peer.get("is_up", False)
            is_enabled = peer.get("is_enabled", True)
            uptime = peer.get("uptime", -1)

            total_prefixes = sum(
                af.get("received_prefixes", 0)
                for af in peer.get("address_family", {}).values()
            )

            entry = {
                "vrf": vrf,
                "peer": peer_ip,
                "state": "ESTABLISHED" if is_up else "DOWN",
                "enabled": is_enabled,
                "uptime_seconds": uptime,
                "received_prefixes": total_prefixes,
                "severity": "OK",
                "flags": [],
            }

            if not is_enabled:
                entry["flags"].append("administratively_shutdown")
                continue

            if not is_up:
                entry["severity"] = "CRITICAL"
                entry["flags"].append("session_down")
                worst = max(worst, EXIT_CRIT)
            elif 0 <= uptime < min_uptime:
                entry["severity"] = "WARNING"
                entry["flags"].append(f"recently_reset_uptime={uptime}s")
                worst = max(worst, EXIT_WARN)

            if total_prefixes >= prefix_crit:
                entry["severity"] = "CRITICAL"
                entry["flags"].append(f"prefix_critical={total_prefixes}>={prefix_crit}")
                worst = max(worst, EXIT_CRIT)
            elif total_prefixes >= prefix_warn:
                if entry["severity"] == "OK":
                    entry["severity"] = "WARNING"
                entry["flags"].append(f"prefix_warning={total_prefixes}>={prefix_warn}")
                worst = max(worst, EXIT_WARN)

            if entry["flags"]:
                issues.append(entry)

    return issues, worst


def print_report(issues: list[dict], host: str, as_json: bool, exit_code: int) -> None:
    status_label = {EXIT_OK: "OK", EXIT_WARN: "WARNING", EXIT_CRIT: "CRITICAL"}[exit_code]

    if as_json:
        print(json.dumps({"host": host, "status": status_label, "issues": issues}, indent=2))
        return

    if not issues:
        print(f"BGP {status_label}: all neighbors ESTABLISHED on {host}")
        return

    print(f"BGP {status_label}: {len(issues)} neighbor(s) with issues on {host}")
    for item in issues:
        flags = ", ".join(item["flags"])
        print(
            f"  [{item['severity']:8s}] {item['peer']:20s}  vrf={item['vrf']}"
            f"  state={item['state']}  prefixes={item['received_prefixes']}"
            f"  uptime={item['uptime_seconds']}s  flags={flags}"
        )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Assess BGP neighbor health via NAPALM")
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--driver", default="ios", help="NAPALM driver (default: ios)")
    p.add_argument("--username", required=True, help="Login username")
    p.add_argument("--password", default=None, help="Password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument("--prefix-warn", type=int, default=400,
                   help="Received-prefix WARNING threshold per neighbor")
    p.add_argument("--prefix-crit", type=int, default=500,
                   help="Received-prefix CRITICAL threshold per neighbor")
    p.add_argument("--min-uptime", type=int, default=300,
                   help="Flag sessions up fewer than N seconds as WARNING (default: 300)")
    p.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    driver = get_driver(args.driver)
    device = connect(driver, args.host, args.username, password, args.port, args.timeout)

    try:
        log.info("Fetching BGP neighbor data from %s", args.host)
        bgp_data = device.get_bgp_neighbors()
    except Exception as exc:
        log.error("Failed to retrieve BGP data: %s", exc)
        sys.exit(EXIT_CRIT)
    finally:
        device.close()

    issues, exit_code = assess_neighbors(
        bgp_data, args.prefix_warn, args.prefix_crit, args.min_uptime
    )
    print_report(issues, args.host, args.as_json, exit_code)
    sys.exit(exit_code)