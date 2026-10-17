The user wants me to output only the script content. Let me write a Jinja2 template-driven config merge script (distinct from the existing basic `010_config_merge.py`).

```
"""
020_template_config_push.py - Jinja2-template-driven configuration merge via NAPALM.

Purpose:
    Renders a Jinja2 template against a YAML variables file to produce a device-specific
    config snippet, then merges it onto a target device using NAPALM's load_merge_candidate.
    Displays a candidate diff before committing and supports dry-run mode.

    This pattern is common in production workflows where a shared template (e.g., NTP policy,
    AAA baseline, SNMP community strings) must be applied consistently across many devices,
    each with slightly different variable values (hostnames, loopback IPs, site codes).

Usage:
    python 020_template_config_push.py \
        --host 192.168.1.1 --driver ios \
        --template templates/ntp_policy.j2 \
        --vars vars/core-sw1.yaml \
        [--dry-run] [--no-confirm] [--username admin] [--port 22]

Prerequisites:
    pip install napalm jinja2 pyyaml

    Template files must be valid Jinja2. Variable files must be valid YAML mappings.
    The rendered output must be non-empty or the script exits before connecting.
"""

import argparse
import getpass
import logging
import os
import sys

import napalm
import yaml
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def render_template(template_path: str, vars_path: str) -> str:
    template_dir = os.path.dirname(os.path.abspath(template_path))
    template_name = os.path.basename(template_path)

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=False,
        keep_trailing_newline=True,
    )
    try:
        template = env.get_template(template_name)
    except TemplateNotFound:
        log.error("Template not found: %s", template_path)
        sys.exit(1)

    try:
        with open(vars_path) as f:
            variables = yaml.safe_load(f) or {}
    except FileNotFoundError:
        log.error("Variables file not found: %s", vars_path)
        sys.exit(1)
    except yaml.YAMLError as exc:
        log.error("Failed to parse variables file: %s", exc)
        sys.exit(1)

    if not isinstance(variables, dict):
        log.error("Variables file must be a YAML mapping, got: %s", type(variables).__name__)
        sys.exit(1)

    return template.render(**variables)


def open_device(host: str, driver: str, username: str, password: str, port: int):
    driver_cls = napalm.get_network_driver(driver)
    device = driver_cls(
        hostname=host,
        username=username,
        password=password,
        optional_args={"port": port},
    )
    device.open()
    return device


def push_config(device, config: str, dry_run: bool, no_confirm: bool) -> bool:
    log.info("Loading merge candidate (%d chars)", len(config))
    device.load_merge_candidate(config=config)

    diff = device.compare_config()
    if not diff.strip():
        log.info("No configuration changes detected — device already up to date.")
        device.discard_config()
        return True

    print("\n--- Candidate diff ---")
    print(diff)
    print("--- End diff ---\n")

    if dry_run:
        log.info("Dry-run: discarding candidate without committing.")
        device.discard_config()
        return True

    if not no_confirm:
        try:
            answer = input("Apply this configuration? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            log.info("Commit cancelled.")
            device.discard_config()
            return False
        if answer != "y":
            log.info("Commit cancelled by user.")
            device.discard_config()
            return False

    device.commit_config()
    log.info("Configuration committed successfully.")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render a Jinja2 config template with per-device YAML variables "
            "and merge the result onto a device via NAPALM."
        )
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP address")
    parser.add_argument(
        "--driver",
        required=True,
        choices=["ios", "eos", "junos", "nxos", "nxos_ssh"],
        help="NAPALM driver name",
    )
    parser.add_argument("--username", default="admin", help="Login username (default: admin)")
    parser.add_argument("--password", help="Login password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--template", required=True, metavar="FILE",
        help="Path to Jinja2 template file (e.g. templates/ntp_policy.j2)",
    )
    parser.add_argument(
        "--vars", required=True, metavar="FILE",
        help="Path to YAML variables file for the template",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Render and diff only; discard candidate without committing",
    )
    parser.add_argument(
        "--no-confirm", action="store_true",
        help="Commit without interactive confirmation prompt",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    log.info("Rendering %s with vars from %s", args.template, args.vars)
    config = render_template(args.template, args.vars)

    if not config.strip():
        log.error("Rendered configuration is empty — check template logic and variables.")
        sys.exit(1)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    log.info("Connecting to %s via %s driver", args.host, args.driver)
    try:
        device = open_device(args.host, args.driver, args.username, password, args.port)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        success = push_config(device, config, args.dry_run, args.no_confirm)
    except Exception as exc:
        log.error("Configuration push failed: %s", exc)
        try:
            device.discard_config()
        except Exception:
            pass
        sys.exit(1)
    finally:
        device.close()
        log.info("Connection closed.")

    sys.exit(0 if success else 1)
```