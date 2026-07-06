#!/usr/bin/env python3
"""
compliance_validate.py — NAPALM-based network device compliance checker.

Purpose:
    Validates a network device's live state against a compliance policy defined
    in a YAML file. Checks NTP server configuration, interface operational state,
    BGP session health, and SNMP community configuration.

Usage:
    python compliance_validate.py \
        --host 192.168.1.1 \
        --driver eos \
        --username admin \
        --password secret \
        --policy policy.yaml

    python compliance_validate.py \
        --host 192.168.1.1 \
        --driver ios \
        --username admin \
        --key ~/.ssh/id_rsa \
        --policy policy.yaml \
        --timeout 30 \
        --debug

Supported drivers:  eos, ios, iosxr, junos, nxos_ssh

Policy file format (YAML):
    ntp_servers:
      - 10.0.0.1
      - 10.0.0.2
    interfaces_up:
      - GigabitEthernet0/0
      - GigabitEthernet0/1
    bgp_neighbors:
      - peer: 10.1.1.1
        expected_state: Established
    snmp_communities:
      - public

Prerequisites:
    pip install napalm pyyaml

Exit codes:
    0 — all checks passed (device is compliant)
    1 — one or more compliance checks failed
    2 — connection or configuration error
"""

import argparse
import logging
import sys
from pathlib import Path

import napalm
import yaml

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["eos", "ios", "iosxr", "junos", "nxos_ssh"]


def load_policy(path: str) -> dict:
    policy_file = Path(path)
    if not policy_file.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    with policy_file.open() as fh:
        policy = yaml.safe_load(fh)
    return policy or {}


def check_ntp(device_ntp: dict, required: list) -> list:
    configured = set(device_ntp.keys())
    return [s for s in required if s not in configured]


def check_interfaces_up(device_interfaces: dict, required_up: list) -> list:
    failed = []
    for iface in required_up:
        info = device_interfaces.get(iface)
        if info is None:
            failed.append(f"{iface}: not found on device")
        elif not info.get("is_up", False):
            admin = info.get("is_enabled", "unknown")
            failed.append(f"{iface}: oper_up=False (admin_enabled={admin})")
    return failed


def check_bgp(device_bgp: dict, required_neighbors: list) -> list:
    all_peers = {}
    for vrf_data in device_bgp.values():
        all_peers.update(vrf_data.get("peers", {}))

    failed = []
    for entry in required_neighbors:
        peer = entry.get("peer", "")
        peer_data = all_peers.get(peer)
        if peer_data is None:
            failed.append(f"{peer}: peer not found in BGP table")
        elif not peer_data.get("is_up", False):
            uptime = peer_data.get("uptime", -1)
            failed.append(f"{peer}: session down (uptime={uptime}s)")
    return failed


def check_snmp(device_snmp: dict, required_communities: list) -> list:
    configured = set(device_snmp.get("community", {}).keys())
    return [c for c in required_communities if c not in configured]


def run_compliance(device, policy: dict) -> dict:
    results = {}

    if "ntp_servers" in policy:
        log.info("Fetching NTP configuration...")
        results["ntp_servers"] = check_ntp(
            device.get_ntp_servers(), policy["ntp_servers"]
        )

    if "interfaces_up" in policy:
        log.info("Fetching interface states...")
        results["interfaces_up"] = check_interfaces_up(
            device.get_interfaces(), policy["interfaces_up"]
        )

    if "bgp_neighbors" in policy:
        log.info("Fetching BGP neighbor table...")
        try:
            results["bgp_neighbors"] = check_bgp(
                device.get_bgp_neighbors(), policy["bgp_neighbors"]
            )
        except NotImplementedError:
            log.warning("BGP check skipped: driver does not support get_bgp_neighbors()")

    if "snmp_communities" in policy:
        log.info("Fetching SNMP configuration...")
        try:
            results["snmp_communities"] = check_snmp(
                device.get_snmp_information(), policy["snmp_communities"]
            )
        except NotImplementedError:
            log.warning("SNMP check skipped: driver does not support get_snmp_information()")

    return results


def print_report(host: str, results: dict) -> bool:
    all_passed = True
    width = 60
    print(f"\n{'=' * width}")
    print(f"  Compliance Report — {host}")
    print(f"{'=' * width}")
    for check, failures in results.items():
        if failures:
            all_passed = False
            print(f"  [FAIL]  {check}")
            for item in failures:
                print(f"            - {item}")
        else:
            print(f"  [PASS]  {check}")
    print(f"{'=' * width}")
    verdict = "COMPLIANT" if all_passed else "NON-COMPLIANT"
    print(f"  Verdict: {verdict}")
    print(f"{'=' * width}\n")
    return all_passed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate network device state against a YAML compliance policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for policy file format and examples.",
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument(
        "--driver",
        required=True,
        choices=SUPPORTED_DRIVERS,
        help="NAPALM driver name",
    )
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument(
        "--password", default="", help="SSH password (omit when using --key)"
    )
    parser.add_argument("--key", default=None, help="Path to SSH private key")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=60, help="Connection timeout in seconds (default: 60)"
    )
    parser.add_argument(
        "--policy", required=True, help="Path to YAML compliance policy file"
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug-level logging"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        policy = load_policy(args.policy)
    except (FileNotFoundError, yaml.YAMLError) as exc:
        log.error("Policy load failed: %s", exc)
        return 2

    if not policy:
        log.error("Policy file is empty — nothing to check")
        return 2

    optional_args = {"port": args.port}
    if args.key:
        optional_args["key_file"] = args.key

    log.info("Connecting to %s via %s driver...", args.host, args.driver)
    driver_class = napalm.get_network_driver(args.driver)
    device = driver_class(
        hostname=args.host,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        optional_args=optional_args,
    )

    try:
        device.open()
        log.info("Connected — running compliance checks")
        results = run_compliance(device, policy)
    except Exception as exc:
        log.error("Device error: %s", exc)
        return 2
    finally:
        device.close()
        log.debug("Connection closed")

    passed = print_report(args.host, results)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())