```python
#!/usr/bin/env python3
"""
Route retrieval and analysis tool for network devices.

Purpose:
    Retrieve and analyze the device's routing table using NAPALM.
    Supports filtering by destination prefix or protocol and outputs
    in text or JSON format for analysis and reporting.

Usage:
    python3 018_route_analysis.py --host 192.0.2.1 \
        --username admin --password secret --driver arista
    
    python3 018_route_analysis.py --host 10.0.0.1 \
        --username admin --password secret --driver cisco_ios \
        --filter-prefix 10.0.0.0/8 --filter-protocol bgp --json

Prerequisites:
    - NAPALM library: pip install napalm
    - Network device must be reachable via SSH/API
    - Credentials must have read permission on routing tables
    - Supported drivers: arista, cisco_ios, cisco_iosxr, juniper, etc.

"""

import argparse
import json
import logging
import sys
from napalm import get_network_driver
from napalm.base.exceptions import NapalmException


def configure_logging(verbose: bool = False) -> None:
    """Configure logging output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
    )


def get_routes(host, username, password, driver_name, optional_args=None):
    """Connect to device and retrieve routing table."""
    try:
        logging.info(f"Connecting to {host} using {driver_name} driver")
        driver_class = get_network_driver(driver_name)
        device = driver_class(
            host,
            username,
            password,
            optional_args=optional_args or {},
        )
        device.open()
        routes = device.get_route_to()
        device.close()
        logging.info(f"Retrieved {len(routes)} route destinations")
        return routes
    except NapalmException as e:
        logging.error(f"NAPALM error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Connection error: {e}")
        sys.exit(1)


def filter_routes(routes, prefix_filter=None, protocol_filter=None):
    """Filter routes based on destination prefix and/or protocol."""
    filtered = {}
    
    for destination, route_list in routes.items():
        if prefix_filter and not destination.startswith(prefix_filter):
            continue
        
        matching = []
        for route in route_list:
            if protocol_filter and route.get('protocol') != protocol_filter:
                continue
            matching.append(route)
        
        if matching:
            filtered[destination] = matching
    
    return filtered


def format_text_output(routes):
    """Format routes as human-readable text table."""
    lines = [
        f"{'Destination':<25} {'Protocol':<12} {'Metric':<8} Next-Hops",
        "-" * 70,
    ]
    
    for destination in sorted(routes.keys()):
        for route in routes[destination]:
            protocol = route.get('protocol', 'unknown')
            metric = route.get('metric', '-')
            nexthops = route.get('next_hop', {})
            nh_str = ', '.join(str(nh) for nh in nexthops.keys()) \
                if nexthops else 'unknown'
            lines.append(
                f"{destination:<25} {protocol:<12} {metric!s:<8} {nh_str}"
            )
    
    return '\n'.join(lines)


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Retrieve and analyze device routing tables'
    )
    parser.add_argument(
        '--host',
        required=True,
        help='Device IP address or hostname',
    )
    parser.add_argument(
        '--username',
        required=True,
        help='SSH/API username for device authentication',
    )
    parser.add_argument(
        '--password',
        required=True,
        help='SSH/API password for device authentication',
    )
    parser.add_argument(
        '--driver',
        required=True,
        help='NAPALM driver name (arista, cisco_ios, cisco_iosxr, juniper, etc.)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=22,
        help='SSH port (default: 22)',
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=60,
        help='Connection timeout in seconds (default: 60)',
    )
    parser.add_argument(
        '--filter-prefix',
        help='Filter routes by destination prefix (e.g., 10.0.0.0/8)',
    )
    parser.add_argument(
        '--filter-protocol',
        help='Filter routes by protocol (bgp, static, connected, etc.)',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON instead of text',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable debug-level logging',
    )
    
    args = parser.parse_args()
    configure_logging(args.verbose)
    
    # Retrieve routing table
    optional_args = {
        'port': args.port,
        'timeout': args.timeout,
    }
    routes = get_routes(
        args.host,
        args.username,
        args.password,
        args.driver,
        optional_args,
    )
    
    # Apply filters
    filtered_routes = filter_routes(
        routes,
        args.filter_prefix,
        args.filter_protocol,
    )
    logging.info(f"Displaying {len(filtered_routes)} routes after filtering")
    
    # Output results
    if args.json:
        output = json.dumps(filtered_routes, indent=2, default=str)
    else:
        output = format_text_output(filtered_routes)
    
    print(output)


if __name__ == '__main__':
    main()
```