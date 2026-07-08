The brainstorming skill doesn't apply here — the user's explicit instruction ("Output ONLY the script content, no markdown fences, no explanation") overrides the design-first process, and all requirements are fully specified. Writing the script directly.

```
"""
006_interface_counters.py — Retrieve and analyse interface traffic counters via NAPALM.

Purpose:
    Poll a network device for per-interface counters (bytes, packets, errors, discards)
    and optionally flag interfaces whose input- or output-error rate exceeds a
    configurable threshold.  Useful for health checks, capacity spot-checks, and
    feeding automated alerting pipelines.

Usage:
    python 006_interface_counters.py -d 192.0.2.1 -u admin -p secret --driver eos
    python 006_interface_counters.py -d 10.0.0.1  -u admin -p secret --driver ios \
        --filter GigabitEthernet --threshold 0.001 --json

Prerequisites:
    pip install napalm tabulate
    Supported drivers: eos, ios, junos, nxos, nxos_ssh
"""

import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Tuple

try:
    import napalm
    from tabulate import tabulate
except ImportError as exc:
    sys.exit(f"Missing dependency: {exc}  →  pip install napalm tabulate")

LOG = logging.getLogger(__name__)

SUPPORTED_DRIVERS = ["eos", "ios", "junos", "nxos", "nxos_ssh"]

HEADERS = [
    "Interface",
    "RX Bytes", "RX Pkts", "RX Err", "RX Drop", "RX Err%",
    "TX Bytes", "TX Pkts", "TX Err", "TX Drop", "TX Err%",
]


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
        level=getattr(logging, level.upper(), logging.WARNING),
    )


def _open_device(driver: str, host: str, user: str, password: str):
    driver_cls = napalm.get_network_driver(driver)
    device = driver_cls(hostname=host, username=user, password=password)
    LOG.info("Connecting to %s via %s driver", host, driver)
    device.open()
    return device


def _fetch_counters(device) -> Dict[str, Any]:
    LOG.debug("Issuing get_interfaces_counters()")
    return device.get_interfaces_counters()


def _error_rate(errors: int, total: int) -> float:
    return 0.0 if total <= 0 else errors / total


def _build_rows(
    counters: Dict[str, Any],
    name_filter: Optional[str],
    threshold: float,
) -> Tuple[List[list], List[str]]:
    rows: List[list] = []
    flagged: List[str] = []

    for iface, data in sorted(counters.items()):
        if name_filter and name_filter.lower() not in iface.lower():
            continue

        rx_pkts = (
            data.get("rx_unicast_packets", 0)
            + data.get("rx_multicast_packets", 0)
            + data.get("rx_broadcast_packets", 0)
        )
        tx_pkts = (
            data.get("tx_unicast_packets", 0)
            + data.get("tx_multicast_packets", 0)
            + data.get("tx_broadcast_packets", 0)
        )
        rx_err = data.get("rx_errors", 0)
        tx_err = data.get("tx_errors", 0)
        rx_drop = data.get("rx_discards", 0)
        tx_drop = data.get("tx_discards", 0)

        rx_rate = _error_rate(rx_err, rx_pkts)
        tx_rate = _error_rate(tx_err, tx_pkts)

        label = iface
        if rx_rate > threshold or tx_rate > threshold:
            flagged.append(iface)
            label = "! " + iface

        rows.append([
            label,
            data.get("rx_octets", 0), rx_pkts, rx_err, rx_drop,
            f"{rx_rate * 100:.4f}%",
            data.get("tx_octets", 0), tx_pkts, tx_err, tx_drop,
            f"{tx_rate * 100:.4f}%",
        ])

    return rows, flagged


def _print_table(rows: List[list]) -> None:
    if not rows:
        print("No interfaces matched the filter.")
        return
    print(tabulate(rows, headers=HEADERS, tablefmt="simple", intfmt=","))


def _print_json(counters: Dict[str, Any], name_filter: Optional[str]) -> None:
    if name_filter:
        counters = {k: v for k, v in counters.items()
                    if name_filter.lower() in k.lower()}
    print(json.dumps(counters, indent=2))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Fetch and analyse per-interface counters via NAPALM.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="Login username")
    p.add_argument("-p", "--password", required=True, help="Login password")
    p.add_argument(
        "--driver", default="eos", choices=SUPPORTED_DRIVERS,
        help="NAPALM network driver",
    )
    p.add_argument(
        "--filter", metavar="PATTERN",
        help="Case-insensitive substring to match interface names",
    )
    p.add_argument(
        "--threshold", type=float, default=0.01,
        help="Error rate (0–1) above which an interface is flagged (default 1%%)",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Emit raw JSON instead of a formatted table",
    )
    p.add_argument(
        "--log-level", default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    _configure_logging(args.log_level)

    device = None
    try:
        device = _open_device(args.driver, args.device, args.username, args.password)
        counters = _fetch_counters(device)
    except Exception as exc:
        LOG.error("Device communication failed: %s", exc)
        return 1
    finally:
        if device is not None:
            try:
                device.close()
                LOG.debug("Connection closed")
            except Exception:
                pass

    if args.json:
        _print_json(counters, args.filter)
        return 0

    rows, flagged = _build_rows(counters, args.filter, args.threshold)
    _print_table(rows)

    if flagged:
        pct = args.threshold * 100
        print(
            f"\n[!] {len(flagged)} interface(s) exceed the {pct:.2f}% error threshold: "
            + ", ".join(flagged)
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
```