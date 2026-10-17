```python
"""
Configuration Backup and Drift Detection Script

Purpose:
    Backs up network device configurations with timestamped snapshots,
    detects configuration drift between consecutive backups, and generates
    detailed change reports for audit and compliance tracking.

Usage:
    python 021_config_backup_drift.py --host 10.0.1.1 \
        --username admin --password secret --backup-dir ./backups

Prerequisites:
    - napalm library installed (pip install napalm)
    - Device reachable with valid SSH credentials
    - Backup directory writable by user
    - Supported device OS (ios, eos, junos, nxos, etc.)

Output:
    - Timestamped configuration files in backup directory
    - Drift detection report with line-by-line differences
    - Backup metadata (device facts, timestamp, file location)
    - Console and file logging for audit trails
"""

import os
import sys
import logging
import argparse
import json
from datetime import datetime
from pathlib import Path
from difflib import unified_diff

try:
    from napalm import get_network_driver
except ImportError:
    print("Error: napalm not found. Install with: pip install napalm")
    sys.exit(1)


def setup_logging(verbose=False):
    """Configure logging to console and file."""
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    file_handler = logging.FileHandler('config_backup_drift.log')
    file_handler.setFormatter(formatter)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger


def connect_to_device(driver_name, hostname, username, password, timeout=60):
    """Establish connection to network device using napalm."""
    try:
        driver_class = get_network_driver(driver_name)
        device = driver_class(
            hostname=hostname,
            username=username,
            password=password,
            optional_args={'timeout': timeout}
        )
        device.open()
        logging.info(f"Connected to {hostname} ({driver_name})")
        return device
    except Exception as e:
        logging.error(f"Connection to {hostname} failed: {str(e)}")
        raise


def retrieve_config_and_facts(device):
    """Get running configuration and device facts."""
    try:
        config = device.get_config(retrieve='running')
        running_config = config.get('running', '')
        
        facts = device.get_facts()
        facts_dict = {
            'hostname': facts.get('hostname'),
            'model': facts.get('model'),
            'os_version': facts.get('os_version'),
            'serial_number': facts.get('serial_number'),
            'uptime_seconds': facts.get('uptime_seconds')
        }
        
        return running_config, facts_dict
    except Exception as e:
        logging.error(f"Failed to retrieve config/facts: {str(e)}")
        raise


def save_backup(config, backup_dir, hostname, facts):
    """Save configuration backup with metadata."""
    backup_path = Path(backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    config_file = backup_path / f"{hostname}_{timestamp}.cfg"
    metadata_file = backup_path / f"{hostname}_{timestamp}.json"
    
    try:
        with open(config_file, 'w') as f:
            f.write(config)
        
        metadata = {
            'timestamp': datetime.now().isoformat(),
            'hostname': hostname,
            'config_file': str(config_file),
            'config_size_bytes': len(config),
            'facts': facts
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logging.info(f"Backup saved: {config_file} ({len(config)} bytes)")
        return str(config_file)
    except IOError as e:
        logging.error(f"Failed to save backup: {str(e)}")
        raise


def find_previous_backup(backup_dir, hostname):
    """Find the most recent previous backup for drift comparison."""
    backup_path = Path(backup_dir)
    if not backup_path.exists():
        return None
    
    backups = sorted(
        backup_path.glob(f"{hostname}_*.cfg"),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    return str(backups[1]) if len(backups) > 1 else None


def detect_drift(current_config, previous_backup_file):
    """Detect configuration changes between backups."""
    try:
        with open(previous_backup_file, 'r') as f:
            previous_config = f.read()
    except IOError as e:
        logging.warning(f"Could not read previous backup: {str(e)}")
        return None
    
    if current_config == previous_config:
        logging.info("No configuration drift detected")
        return None
    
    current_lines = current_config.splitlines(keepends=True)
    previous_lines = previous_config.splitlines(keepends=True)
    
    diff = list(unified_diff(
        previous_lines,
        current_lines,
        fromfile='Previous Backup',
        tofile='Current Backup',
        lineterm=''
    ))
    
    return diff if diff else None


def print_drift_report(diff, hostname):
    """Display formatted drift report with colored output."""
    print(f"\n{'=' * 70}")
    print(f"Configuration Drift Report: {hostname}")
    print(f"{'=' * 70}\n")
    
    additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    
    print(f"Changes Detected:")
    print(f"  Lines Added:   {additions}")
    print(f"  Lines Deleted: {deletions}")
    print(f"  Total Changes: {additions + deletions}\n")
    print(f"{'-' * 70}\n")
    
    for line in diff:
        if line.startswith('+') and not line.startswith('+++'):
            print(f"\033[92m{line}\033[0m", end='')
        elif line.startswith('-') and not line.startswith('---'):
            print(f"\033[91m{line}\033[0m", end='')
        else:
            print(line, end='')
    
    print(f"\n{'=' * 70}\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Backup network device configs and detect drift'
    )
    parser.add_argument('--host', required=True, help='Device hostname or IP address')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--driver', default='ios', help='NAPALM driver (ios, eos, junos, nxos)')
    parser.add_argument('--backup-dir', default='./backups', help='Backup directory path')
    parser.add_argument('--timeout', type=int, default=60, help='Connection timeout in seconds')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    
    try:
        logger.info(f"Starting backup process for {args.host}")
        
        device = connect_to_device(args.driver, args.host, args.username, args.password, args.timeout)
        
        logger.info("Retrieving configuration and device facts")
        config, facts = retrieve_config_and_facts(device)
        
        backup_file = save_backup(config, args.backup_dir, args.host, facts)
        
        previous_backup = find_previous_backup(args.backup_dir, args.host)
        if previous_backup:
            logger.info(f"Comparing with previous backup")
            drift = detect_drift(config, previous_backup)
            if drift:
                print_drift_report(drift, args.host)
            else:
                print(f"\nNo configuration drift detected for {args.host}\n")
        else:
            logger.info("First backup - no previous version to compare")
        
        device.close()
        logger.info("Backup completed successfully")
        
    except Exception as e:
        logger.error(f"Backup process failed: {str(e)}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == '__main__':
    main()
```