```python
#!/usr/bin/env python3
"""
environment_sensors.py — NAPALM-based network device environmental monitoring.

Purpose:
    Monitors physical device sensors (temperature, power supply, fan, CPU, memory)
    and alerts when thresholds are exceeded. Useful for NOC health dashboards
    and capacity planning.

Usage:
    python environment_sensors.py \
        --host 192.168.1.1 \
        --driver eos \
        --username admin \
        --password secret

    python environment_sensors.py \
        --host 192.168.1.1 \
        --driver nxos_ssh \
        --username admin \
        --key ~/.ssh/id_rsa \
        --temp-warn 70 \
        --temp-crit 85 \
        --output json

Supported drivers:  eos, ios, iosxr, junos, nxos_ssh

Thresholds (Celsius for temperature):
    --temp-warn    Temperature warning threshold (default: 65)
    --temp-crit    Temperature critical threshold (default: 80)

Output formats:
    text — human-readable report (default)
    json — JSON output for parsing/alerting

Prerequisites:
    pip install napalm

Exit codes:
    0 — all sensors normal
    1 — one or more thresholds exceeded
    2 — connection or collection error
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import napalm

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["eos", "ios", "iosxr", "junos", "nxos_ssh"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor network device environmental sensors and thresholds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for threshold defaults and output formats.",
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
        "--timeout", type=int, default=60, help="Connection timeout in seconds"
    )
    parser.add_argument(
        "--temp-warn",
        type=float,
        default=65.0,
        help="Temperature warning threshold in Celsius (default: 65)",
    )
    parser.add_argument(
        "--temp-crit",
        type=float,
        default=80.0,
        help="Temperature critical threshold in Celsius (default: 80)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug-level logging"
    )
    return parser.parse_args()


def collect_sensors(device) -> dict:
    """Retrieve environment data from device."""
    log.info("Collecting environmental sensors...")
    return device.get_environment()


def check_thresholds(environment: dict, temp_warn: float, temp_crit: float) -> dict:
    """Evaluate sensor data against thresholds and flag anomalies."""
    alerts = {
        "critical": [],
        "warning": [],
        "normal": [],
    }

    # Check temperatures
    for temp_entry in environment.get("temperature", []):
        sensor = temp_entry.get("name", "unknown")
        current = temp_entry.get("current", 0)
        
        if current >= temp_crit:
            alerts["critical"].append({
                "type": "temperature",
                "sensor": sensor,
                "value": current,
                "threshold": temp_crit,
                "severity": "CRITICAL",
            })
        elif current >= temp_warn:
            alerts["warning"].append({
                "type": "temperature",
                "sensor": sensor,
                "value": current,
                "threshold": temp_warn,
                "severity": "WARNING",
            })
        else:
            alerts["normal"].append({
                "type": "temperature",
                "sensor": sensor,
                "value": current,
            })

    # Check power supplies
    for psu_entry in environment.get("power", []):
        name = psu_entry.get("name", "unknown")
        status = psu_entry.get("status", "unknown")
        if status not in ["ok", "up", "normal"]:
            alerts["critical"].append({
                "type": "power_supply",
                "name": name,
                "status": status,
                "severity": "CRITICAL",
            })

    # Check fans
    for fan_entry in environment.get("fans", []):
        name = fan_entry.get("name", "unknown")
        status = fan_entry.get("status", "unknown")
        if status not in ["ok", "up", "normal"]:
            alerts["warning"].append({
                "type": "fan",
                "name": name,
                "status": status,
                "severity": "WARNING",
            })

    # Check memory and CPU
    for iface_entry in environment.get("cpu", {}).items():
        cpu_data = iface_entry[1] if isinstance(iface_entry, tuple) else iface_entry
        if isinstance(cpu_data, dict):
            usage = cpu_data.get("%usage", 0)
            if usage > 90:
                alerts["critical"].append({
                    "type": "cpu",
                    "usage": usage,
                    "threshold": 90,
                    "severity": "CRITICAL",
                })

    return alerts


def print_text_report(host: str, alerts: dict) -> bool:
    """Print human-readable alert report."""
    critical_count = len(alerts.get("critical", []))
    warning_count = len(alerts.get("warning", []))
    normal_count = len(alerts.get("normal", []))
    
    width = 70
    print(f"\n{'=' * width}")
    print(f"  Environmental Sensors — {host}")
    print(f"  Collected: {datetime.now().isoformat()}")
    print(f"{'=' * width}")
    
    if critical_count > 0:
        print(f"  [CRITICAL] {critical_count} threshold(s) exceeded")
        for alert in alerts["critical"]:
            _type = alert.get("type", "unknown")
            if _type == "temperature":
                print(f"    - {alert['sensor']}: {alert['value']:.1f}°C (limit: {alert['threshold']}°C)")
            else:
                print(f"    - {alert.get('name', alert.get('sensor', 'unknown'))}: {alert.get('status', 'unknown')}")
    
    if warning_count > 0:
        print(f"  [WARNING] {warning_count} warning(s)")
        for alert in alerts["warning"]:
            _type = alert.get("type", "unknown")
            if _type == "temperature":
                print(f"    - {alert['sensor']}: {alert['value']:.1f}°C (limit: {alert['threshold']}°C)")
            else:
                print(f"    - {alert.get('name', 'unknown')}: {alert.get('status', 'unknown')}")
    
    print(f"  [NORMAL] {normal_count} sensor(s)")
    print(f"{'=' * width}\n")
    
    return critical_count == 0 and warning_count == 0


def print_json_report(host: str, alerts: dict) -> bool:
    """Print JSON output for parsing."""
    output = {
        "host": host,
        "timestamp": datetime.now().isoformat(),
        "critical": len(alerts.get("critical", [])),
        "warning": len(alerts.get("warning", [])),
        "normal": len(alerts.get("normal", [])),
        "alerts": alerts,
    }
    print(json.dumps(output, indent=2))
    return output["critical"] == 0 and output["warning"] == 0


def main() -> int:
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

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
        log.info("Connected — collecting sensor data")
        environment = collect_sensors(device)
        alerts = check_thresholds(environment, args.temp_warn, args.temp_crit)
    except Exception as exc:
        log.error("Device error: %s", exc)
        return 2
    finally:
        device.close()
        log.debug("Connection closed")

    if args.output == "json":
        passed = print_json_report(args.host, alerts)
    else:
        passed = print_text_report(args.host, alerts)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
```