```python
"""
032_environment_sensors.py - Environment Sensor Threshold Monitor

Purpose:
    Poll NAPALM-supported devices for environment sensor data (temperature,
    fans, power supplies, CPU, memory) and evaluate readings against
    configurable thresholds.  Exits non-zero when any threshold is breached,
    making it suitable for use in Nagios/Icinga checks or CI health gates.

Usage:
    python 032_environment_sensors.py -H 192.0.2.1 -u admin -p secret
    python 032_environment_sensors.py -H 192.0.2.1 -u admin -p secret \
        --driver eos --temp-warn 60 --temp-crit 75 --output json

Prerequisites:
    pip install napalm
    Device must support NAPALM's get_environment() getter.
    Supported drivers: eos, ios, iosxr, junos, nxos_ssh, etc.
"""

import argparse
import json
import logging
import sys
from getpass import getpass

import napalm

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
EXIT_UNKNOWN = 3


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate device environment sensors against thresholds."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument(
        "-p", "--password", default=None,
        help="Login password (prompted if omitted)",
    )
    parser.add_argument(
        "--driver", default="ios",
        help="NAPALM driver name (default: ios)",
    )
    parser.add_argument(
        "--port", type=int, default=22,
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--temp-warn", type=float, default=55.0, metavar="CELSIUS",
        help="Temperature warning threshold °C (default: 55)",
    )
    parser.add_argument(
        "--temp-crit", type=float, default=70.0, metavar="CELSIUS",
        help="Temperature critical threshold °C (default: 70)",
    )
    parser.add_argument(
        "--cpu-warn", type=float, default=75.0, metavar="PCT",
        help="CPU usage warning threshold %% (default: 75)",
    )
    parser.add_argument(
        "--cpu-crit", type=float, default=90.0, metavar="PCT",
        help="CPU usage critical threshold %% (default: 90)",
    )
    parser.add_argument(
        "--mem-warn", type=float, default=75.0, metavar="PCT",
        help="Memory usage warning threshold %% (default: 75)",
    )
    parser.add_argument(
        "--mem-crit", type=float, default=90.0, metavar="PCT",
        help="Memory usage critical threshold %% (default: 90)",
    )
    parser.add_argument(
        "--output", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show all sensors including OK results",
    )
    return parser.parse_args()


def threshold_status(value, warn, crit):
    if value >= crit:
        return "CRITICAL", EXIT_CRITICAL
    if value >= warn:
        return "WARNING", EXIT_WARNING
    return "OK", EXIT_OK


def evaluate_environment(env, args):
    findings = []
    worst = EXIT_OK

    for name, data in env.get("temperature", {}).items():
        temp = data.get("temperature", 0.0)
        is_alert = data.get("is_alert")
        if is_alert is None:
            status, code = "UNKNOWN", EXIT_UNKNOWN
        elif is_alert or temp >= args.temp_crit:
            status, code = "CRITICAL", EXIT_CRITICAL
        elif temp >= args.temp_warn:
            status, code = "WARNING", EXIT_WARNING
        else:
            status, code = "OK", EXIT_OK
        worst = max(worst, code)
        findings.append({
            "sensor": name, "type": "temperature",
            "value": f"{temp:.1f} C", "status": status,
        })

    for name, data in env.get("fans", {}).items():
        ok = data.get("status", True)
        status, code = ("OK", EXIT_OK) if ok else ("CRITICAL", EXIT_CRITICAL)
        worst = max(worst, code)
        findings.append({
            "sensor": name, "type": "fan",
            "value": "spinning" if ok else "failed", "status": status,
        })

    for name, data in env.get("power", {}).items():
        ok = data.get("status", True)
        capacity = data.get("capacity")
        output = data.get("output")
        if capacity and output:
            val = f"{output:.0f}/{capacity:.0f} W"
        else:
            val = "ok" if ok else "failed"
        status, code = ("OK", EXIT_OK) if ok else ("CRITICAL", EXIT_CRITICAL)
        worst = max(worst, code)
        findings.append({
            "sensor": name, "type": "power",
            "value": val, "status": status,
        })

    for slot, data in env.get("cpu", {}).items():
        usage = data.get("%usage", 0.0)
        status, code = threshold_status(usage, args.cpu_warn, args.cpu_crit)
        worst = max(worst, code)
        findings.append({
            "sensor": f"cpu_{slot}", "type": "cpu",
            "value": f"{usage:.1f}%", "status": status,
        })

    mem = env.get("memory", {})
    if mem:
        avail = mem.get("available_ram", 0)
        used = mem.get("used_ram", 0)
        total = avail + used
        pct_used = (used / total * 100) if total else 0.0
        status, code = threshold_status(pct_used, args.mem_warn, args.mem_crit)
        worst = max(worst, code)
        findings.append({
            "sensor": "memory", "type": "memory",
            "value": f"{pct_used:.1f}% used", "status": status,
        })

    return worst, findings


def render_text(findings, verbose, host):
    shown = 0
    for f in findings:
        if not verbose and f["status"] == "OK":
            continue
        print(f"[{f['status']:8s}] {host}  {f['type']:12s}  {f['sensor']:30s}  {f['value']}")
        shown += 1
    if shown == 0:
        print(f"[OK      ] {host}  all sensors within thresholds")


def main():
    args = parse_args()

    if args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.host}: ")

    try:
        driver_cls = napalm.get_network_driver(args.driver)
    except napalm.base.exceptions.ModuleImportError as exc:
        log.error("Unknown driver '%s': %s", args.driver, exc)
        sys.exit(EXIT_UNKNOWN)

    device = driver_cls(
        hostname=args.host,
        username=args.username,
        password=args.password,
        optional_args={"port": args.port},
    )

    log.info("Connecting to %s via %s driver", args.host, args.driver)
    try:
        device.open()
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(EXIT_UNKNOWN)

    try:
        env = device.get_environment()
    except Exception as exc:
        log.error("get_environment() failed: %s", exc)
        sys.exit(EXIT_UNKNOWN)
    finally:
        device.close()

    exit_code, findings = evaluate_environment(env, args)

    if args.output == "json":
        label = {EXIT_OK: "OK", EXIT_WARNING: "WARNING",
                 EXIT_CRITICAL: "CRITICAL", EXIT_UNKNOWN: "UNKNOWN"}
        print(json.dumps({
            "host": args.host,
            "overall": label[exit_code],
            "findings": findings,
        }, indent=2))
    else:
        render_text(findings, args.verbose, args.host)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
```