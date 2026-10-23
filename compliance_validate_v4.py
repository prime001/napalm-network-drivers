The user's instructions are explicit: "Output ONLY the script content." That overrides the brainstorming flow. Writing the script now.

"""
031_compliance_validate.py - Network Device Hardening Compliance Validator

Purpose:
    Validates network device configuration against a YAML-defined hardening
    policy. Checks NTP peer configuration, syslog server presence, DNS
    resolver settings, login banner existence, and forbidden SNMP community
    strings. Exits non-zero when any check fails, making it suitable for
    CI/CD pipelines or scheduled compliance sweeps.

Usage:
    python 031_compliance_validate.py \
        --host 192.168.1.1 \
        --username admin \
        --password secret \
        --driver ios \
        --policy hardening_policy.yaml

    Example policy file (YAML):
        ntp_servers:
          - 192.168.0.10
          - 192.168.0.11
        syslog_servers:
          - 10.0.0.50
        dns_servers:
          - 8.8.8.8
        require_login_banner: true
        forbidden_snmp_communities:
          - public
          - private

Prerequisites:
    pip install napalm pyyaml
"""

import argparse
import logging
import sys
from pathlib import Path

import napalm
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def load_policy(path: str) -> dict:
    policy_path = Path(path)
    if not policy_path.exists():
        log.error("Policy file not found: %s", path)
        sys.exit(1)
    with policy_path.open() as fh:
        return yaml.safe_load(fh) or {}


def check_ntp(ntp_peers: dict, policy: dict) -> list:
    results = []
    required = policy.get("ntp_servers", [])
    if not required:
        return results
    configured = set(ntp_peers.keys())
    for server in required:
        passed = server in configured
        results.append({
            "check": f"ntp_server:{server}",
            "passed": passed,
            "detail": "configured" if passed else "missing from NTP peers",
        })
    return results


def check_syslog(running: str, policy: dict) -> list:
    results = []
    for server in policy.get("syslog_servers", []):
        passed = server in running
        results.append({
            "check": f"syslog_server:{server}",
            "passed": passed,
            "detail": "found in config" if passed else "not found in config",
        })
    return results


def check_dns(running: str, policy: dict) -> list:
    results = []
    for server in policy.get("dns_servers", []):
        passed = server in running
        results.append({
            "check": f"dns_server:{server}",
            "passed": passed,
            "detail": "found in config" if passed else "not found in config",
        })
    return results


def check_banner(running: str, policy: dict) -> list:
    if not policy.get("require_login_banner", False):
        return []
    passed = "banner login" in running or "banner motd" in running
    return [{
        "check": "login_banner_present",
        "passed": passed,
        "detail": "banner found" if passed else "no login or motd banner configured",
    }]


def check_snmp(running: str, policy: dict) -> list:
    results = []
    for community in policy.get("forbidden_snmp_communities", []):
        present = f"snmp-server community {community}" in running
        results.append({
            "check": f"forbidden_snmp_community:{community}",
            "passed": not present,
            "detail": "not present" if not present else f"forbidden community '{community}' is configured",
        })
    return results


def render_results(results: list) -> int:
    if not results:
        log.warning("No compliance checks produced — verify policy file has content")
        return 0

    col = max(len(r["check"]) for r in results)
    print(f"\n{'CHECK':<{col}}  {'STATUS':<6}  DETAIL")
    print("-" * (col + 32))

    failures = 0
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        prefix = "  " if r["passed"] else "! "
        print(f"{prefix}{r['check']:<{col}}  {status:<6}  {r['detail']}")
        if not r["passed"]:
            failures += 1

    print("-" * (col + 32))
    total = len(results)
    print(f"\n{total - failures}/{total} checks passed\n")
    return failures


def main():
    parser = argparse.ArgumentParser(
        description="Validate device hardening against a YAML policy"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--driver",
        default="ios",
        choices=["ios", "eos", "junos", "nxos", "iosxr"],
        help="NAPALM driver (default: ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--policy", required=True, help="Path to YAML policy file")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    policy = load_policy(args.policy)
    log.info("Loaded policy: %s", args.policy)

    driver_class = napalm.get_network_driver(args.driver)
    device = driver_class(
        hostname=args.host,
        username=args.username,
        password=args.password,
        optional_args={"port": args.port},
    )

    try:
        log.info("Connecting to %s via %s driver", args.host, args.driver)
        device.open()
        ntp_peers = device.get_ntp_peers()
        config = device.get_config(retrieve="running")
        running = config.get("running", "")
    except Exception as exc:
        log.error("Device communication error: %s", exc)
        sys.exit(2)
    finally:
        device.close()

    results = []
    results.extend(check_ntp(ntp_peers, policy))
    results.extend(check_syslog(running, policy))
    results.extend(check_dns(running, policy))
    results.extend(check_banner(running, policy))
    results.extend(check_snmp(running, policy))

    failures = render_results(results)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()