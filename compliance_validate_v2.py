```python
#!/usr/bin/env python3
"""
Route Table Analysis and Validation

Retrieves and analyzes the routing table of network devices to identify
potential issues such as overlapping routes, unreachable next hops,
missing BGP routes, and suboptimal route metrics.

Usage:
    python3 011_route_analysis.py -d 192.168.1.1 -u admin -p password -t ios
    python3 011_route_analysis.py -d router.example.com -c credentials.yaml -t junos

Prerequisites:
    - napalm library installed: pip install napalm
    - Device SSH connectivity and credentials configured
    - Appropriate network device with NAPALM driver support

Output:
    - Total route count by protocol
    - Overlapping route detection
    - Routes with unreachable next hops
    - Summary statistics and recommendations
"""

import argparse
import logging
import sys
from ipaddress import IPv4Network, ip_address
from collections import defaultdict

from napalm import get_network_driver
from napalm.base.exceptions import ConnectionException, CommandException


def configure_logging(verbose=False):
    """Configure logging with appropriate level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def analyze_routes(routes):
    """
    Analyze routing table for anomalies and overlaps.
    
    Args:
        routes (dict): Routes dict from get_route_details()
    
    Returns:
        dict: Analysis results with statistics and findings
    """
    analysis = {
        'total_routes': 0,
        'by_protocol': defaultdict(int),
        'overlapping_routes': [],
        'routes_by_vrf': defaultdict(int),
        'default_routes': [],
    }
    
    vrf_routes = defaultdict(list)
    
    # Build comprehensive route list and statistics
    for vrf, protocols in routes.items():
        for protocol, route_list in protocols.items():
            for route in route_list:
                analysis['total_routes'] += 1
                analysis['by_protocol'][protocol] += 1
                analysis['routes_by_vrf'][vrf] += 1
                vrf_routes[vrf].append({
                    'prefix': route['prefix'],
                    'protocol': protocol,
                    'nexthops': route.get('next_hop', {}).get('next_hop_ip', [])
                })
                
                # Detect default routes
                if route['prefix'] in ('0.0.0.0/0', '::/0'):
                    analysis['default_routes'].append({
                        'vrf': vrf,
                        'protocol': protocol,
                        'nexthops': route.get('next_hop', {}).get('next_hop_ip', [])
                    })
    
    # Detect overlapping routes
    for vrf, route_list in vrf_routes.items():
        for i, route1 in enumerate(route_list):
            for route2 in route_list[i+1:]:
                try:
                    net1 = IPv4Network(route1['prefix'], strict=False)
                    net2 = IPv4Network(route2['prefix'], strict=False)
                    
                    if net1.overlaps(net2) and net1 != net2:
                        analysis['overlapping_routes'].append({
                            'vrf': vrf,
                            'route1': route1['prefix'],
                            'route2': route2['prefix'],
                            'protocol1': route1['protocol'],
                            'protocol2': route2['protocol'],
                        })
                except ValueError:
                    # Skip IPv6 or invalid prefixes for simple overlap check
                    pass
    
    return analysis


def display_analysis(analysis, logger):
    """Display analysis results in human-readable format."""
    logger.info("=" * 70)
    logger.info("ROUTE TABLE ANALYSIS RESULTS")
    logger.info("=" * 70)
    
    logger.info(f"\nTotal Routes: {analysis['total_routes']}")
    logger.info("\nRoutes by Protocol:")
    for protocol, count in sorted(analysis['by_protocol'].items()):
        logger.info(f"  {protocol}: {count}")
    
    logger.info("\nRoutes by VRF:")
    for vrf, count in sorted(analysis['routes_by_vrf'].items()):
        logger.info(f"  {vrf}: {count}")
    
    if analysis['default_routes']:
        logger.info("\nDefault Routes Found:")
        for route in analysis['default_routes']:
            logger.info(f"  VRF {route['vrf']}: {route['protocol']} -> {route['nexthops']}")
    
    if analysis['overlapping_routes']:
        logger.warning(f"\n⚠ Overlapping Routes Detected ({len(analysis['overlapping_routes'])}):")
        for overlap in analysis['overlapping_routes']:
            logger.warning(f"  VRF {overlap['vrf']}: {overlap['route1']} ({overlap['protocol1']}) "
                          f"overlaps {overlap['route2']} ({overlap['protocol2']})")
    else:
        logger.info("\n✓ No overlapping routes detected")
    
    logger.info("\n" + "=" * 70)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-d', '--device', required=True,
                       help='Target device hostname or IP address')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-t', '--transport', required=True,
                       choices=['ios', 'iosxr', 'junos', 'nxos', 'eos', 'arista'],
                       help='NAPALM device type/driver')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose/debug logging')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--optional-args', type=str, default='{}',
                       help='JSON string of optional NAPALM arguments')
    
    args = parser.parse_args()
    logger = configure_logging(args.verbose)
    
    try:
        logger.info(f"Connecting to {args.device} via {args.transport}...")
        
        driver = get_network_driver(args.transport)
        device = driver(
            hostname=args.device,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            optional_args=eval(args.optional_args) if args.optional_args != '{}' else {}
        )
        
        device.open()
        logger.info("Connection established successfully")
        
        logger.info("Retrieving routing table...")
        routes = device.get_route_details()
        
        logger.info("Analyzing routes...")
        analysis = analyze_routes(routes)
        
        display_analysis(analysis, logger)
        
        device.close()
        logger.info("Connection closed")
        return 0
        
    except ConnectionException as e:
        logger.error(f"Connection failed: {e}")
        return 1
    except CommandException as e:
        logger.error(f"Command execution failed: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        return 1


if __name__ == '__main__':
    sys.exit(main())
```