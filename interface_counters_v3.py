#!/usr/bin/env python3
"""
Interface Counter Analyzer - Monitor network interfaces for anomalies.

Retrieves interface counters from network devices via NAPALM and analyzes
them for error conditions, high discard rates, and operational issues.

Usage:
    python3 interface_counter_analyzer.py -d 192.168.1.1 -u admin -p secret -t ios
    python3 interface_counter_analyzer.py -d 192.168.1.1 -u admin -p secret -t ios --error-threshold 5

Prerequisites:
    - napalm library installed (pip install napalm)
    - Network device SSH/API access enabled
    - Device credentials with read permissions
"""

import argparse
import logging
import sys
from typing import Dict, Any, List, Tuple

from napalm import get_network_driver


def setup_logging(verbose: bool = False) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def analyze_interface_counters(
    device: Any,
    error_threshold: int = 10,
    discard_threshold: int = 5,
) -> Tuple[Dict[str, Any], List[Tuple[str, List[str]]]]:
    """
    Analyze interface counters for anomalies.
    
    Args:
        device: NAPALM device connection object
        error_threshold: Alert if error rate exceeds this percentage
        discard_threshold: Alert if discard rate exceeds this percentage
    
    Returns:
        Tuple of (summary dict, list of anomalies)
    """
    logger = logging.getLogger(__name__)
    
    try:
        counters = device.get_interfaces_counters()
        logger.info(f"Retrieved counters from {device.hostname}")
    except Exception as e:
        logger.error(f"Failed to retrieve counters: {e}")
        raise
    
    anomalies = []
    summary = {
        'total_interfaces': len(counters),
        'interfaces_with_anomalies': 0,
        'details': []
    }
    
    for interface, stats in counters.items():
        rx_unicast = stats.get('rx_unicast_packets', 0)
        rx_errors = stats.get('rx_errors', 0)
        rx_discards = stats.get('rx_discarded_packets', 0)
        tx_errors = stats.get('tx_errors', 0)
        tx_discards = stats.get('tx_discarded_packets', 0)
        
        total_rx = rx_unicast + rx_errors + rx_discards
        issues = []
        
        if total_rx > 0:
            rx_error_rate = (rx_errors / total_rx) * 100
            if rx_error_rate > error_threshold:
                issues.append(
                    f"RX error rate: {rx_error_rate:.2f}% ({rx_errors} errors)"
                )
            
            rx_discard_rate = (rx_discards / total_rx) * 100
            if rx_discard_rate > discard_threshold:
                issues.append(
                    f"RX discard rate: {rx_discard_rate:.2f}% ({rx_discards} discards)"
                )
        
        if tx_errors > 0:
            issues.append(f"TX errors: {tx_errors}")
        
        if tx_discards > 0:
            issues.append(f"TX discards: {tx_discards}")
        
        if issues:
            summary['interfaces_with_anomalies'] += 1
            summary['details'].append({
                'interface': interface,
                'issues': issues,
                'rx_packets': rx_unicast,
                'rx_errors': rx_errors,
                'rx_discards': rx_discards,
                'tx_errors': tx_errors,
                'tx_discards': tx_discards
            })
            anomalies.append((interface, issues))
    
    return summary, anomalies


def print_results(summary: Dict[str, Any], anomalies: List[Tuple]) -> None:
    """Format and print analysis results."""
    print("\n" + "="*70)
    print("INTERFACE COUNTER ANALYSIS REPORT")
    print("="*70)
    print(f"Total Interfaces: {summary['total_interfaces']}")
    print(f"Interfaces with Anomalies: {summary['interfaces_with_anomalies']}")
    print("="*70)
    
    if anomalies:
        print("\nANOMALIES DETECTED:\n")
        for interface, issues in anomalies:
            print(f"  {interface}:")
            for issue in issues:
                print(f"    - {issue}")
        print()
    else:
        print("\nNo anomalies detected.\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Analyze network interface counters for anomalies'
    )
    
    parser.add_argument('-d', '--device', required=True,
                       help='Device IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                       help='Device username')
    parser.add_argument('-p', '--password', required=True,
                       help='Device password')
    parser.add_argument('-t', '--driver', required=True,
                       choices=['ios', 'iosxe', 'iosxr', 'nxos', 'eos', 'junos'],
                       help='NAPALM driver type')
    parser.add_argument('--error-threshold', type=int, default=10,
                       help='Error rate threshold percent (default: 10)')
    parser.add_argument('--discard-threshold', type=int, default=5,
                       help='Discard rate threshold percent (default: 5)')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Connection timeout in seconds (default: 60)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        driver_class = get_network_driver(args.driver)
        device = driver_class(
            hostname=args.device,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            optional_args={'port': 22}
        )
        
        logger.info(f"Connecting to {args.device}...")
        device.open()
        logger.info(f"Successfully connected to {device.hostname}")
        
        summary, anomalies = analyze_interface_counters(
            device,
            error_threshold=args.error_threshold,
            discard_threshold=args.discard_threshold
        )
        
        print_results(summary, anomalies)
        sys.exit(1 if anomalies else 0)
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
        sys.exit(2)
    finally:
        try:
            device.close()
            logger.info("Connection closed")
        except Exception:
            pass


if __name__ == "__main__":
    main()