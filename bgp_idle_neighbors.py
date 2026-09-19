#!/usr/bin/env python3

import csv
import getpass
import ipaddress
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)


CSV_FILE = "bgp_idle_neighbors.csv"
MAX_WORKERS = 10
DEVICE_TYPE = "cisco_ios"


def is_ip_address(value):
    """Return True when value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse_idle_neighbors(output):
    """Find Idle BGP neighbors, excluding administratively shut-down peers."""
    idle_neighbors = []

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("Neighbor", "BGP router identifier")):
            continue

        fields = line.split()
        if not fields or not is_ip_address(fields[0]):
            continue

        # Cisco may display a shut-down peer as "Idle (Admin)".
        idle_match = re.search(
            r"\bIdle\b(?:\s*\([^)]*\))?",
            line,
            re.IGNORECASE,
        )

        if not idle_match:
            continue

        state = idle_match.group(0)
        state_lower = state.lower()

        if "admin" in state_lower or "shutdown" in state_lower:
            continue

        idle_neighbors.append(
            {
                "neighbor": fields[0],
                "state": state,
                "raw_line": line,
            }
        )

    return idle_neighbors


def find_neighbor_config(bgp_config, neighbor):
    """Return BGP configuration lines that directly reference a neighbor."""
    pattern = re.compile(
        rf"^\s*neighbor\s+{re.escape(neighbor)}\b.*$",
        re.IGNORECASE,
    )

    return [
        line.strip()
        for line in bgp_config.splitlines()
        if pattern.match(line)
    ]


def collect_switch(hostname, username, password):
    device = {
        "device_type": DEVICE_TYPE,
        "host": hostname,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    connection = None

    try:
        print(f"\nConnecting to {hostname}...")
        connection = ConnectHandler(**device)

        output = connection.send_command(
            "show ip bgp summary",
            read_timeout=60,
        )
        bgp_config = connection.send_command(
            "show running-config | section ^router bgp",
            read_timeout=60,
        )

        idle_neighbors = parse_idle_neighbors(output)

        return {
            "hostname": hostname,
            "output": output,
            "bgp_config": bgp_config,
            "idle_neighbors": idle_neighbors,
            "error": "",
        }

    except NetmikoAuthenticationException:
        return {
            "hostname": hostname,
            "output": "",
            "bgp_config": "",
            "idle_neighbors": [],
            "error": "Authentication failed",
        }

    except NetmikoTimeoutException:
        return {
            "hostname": hostname,
            "output": "",
            "bgp_config": "",
            "idle_neighbors": [],
            "error": "Connection timed out",
        }

    except Exception as exc:
        return {
            "hostname": hostname,
            "output": "",
            "bgp_config": "",
            "idle_neighbors": [],
            "error": str(exc),
        }

    finally:
        if connection:
            connection.disconnect()


def main():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    host_input = input("Switch name(s), comma-delimited: ")

    hostnames = [
        hostname.strip()
        for hostname in host_input.split(",")
        if hostname.strip()
    ]

    if not hostnames:
        print("No switch names provided.", file=sys.stderr)
        sys.exit(1)

    results = [None] * len(hostnames)
    worker_count = min(MAX_WORKERS, len(hostnames))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                collect_switch,
                hostname,
                username,
                password,
            ): index
            for index, hostname in enumerate(hostnames)
        }

        for future in as_completed(futures):
            index = futures[future]
            results[index] = future.result()

    csv_rows = []
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    for result in results:
        hostname = result["hostname"]

        print(f"\n{'=' * 80}")
        print(f"BGP SUMMARY: {hostname}")
        print(f"{'=' * 80}")

        if result["error"]:
            print(f"ERROR: {result['error']}", file=sys.stderr)
            continue

        print(result["output"])

        if not result["idle_neighbors"]:
            print("No non-shutdown idle BGP neighbors found.")
            continue

        print("\nNon-shutdown idle neighbors requiring review:")

        for neighbor in result["idle_neighbors"]:
            neighbor_config = find_neighbor_config(
                result["bgp_config"],
                neighbor["neighbor"],
            )
            config_evidence = " | ".join(neighbor_config)
            config_match = "Yes" if neighbor_config else "No direct match"

            print(
                f"  {neighbor['neighbor']} - {neighbor['state']} - "
                "Review Required"
            )
            print(f"    Configuration match: {config_match}")
            if neighbor_config:
                for config_line in neighbor_config:
                    print(f"    {config_line}")

            csv_rows.append(
                {
                    "Timestamp": timestamp,
                    "Switch": hostname,
                    "BGP Neighbor": neighbor["neighbor"],
                    "BGP State": neighbor["state"],
                    "Shutdown Assessment": "Review Required",
                    "Configuration Match": config_match,
                    "BGP Configuration Evidence": config_evidence,
                    "Raw Neighbor Entry": neighbor["raw_line"],
                }
            )

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "Timestamp",
            "Switch",
            "BGP Neighbor",
            "BGP State",
            "Shutdown Assessment",
            "Configuration Match",
            "BGP Configuration Evidence",
            "Raw Neighbor Entry",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Idle BGP neighbors found: {len(csv_rows)}")


if __name__ == "__main__":
    main()
