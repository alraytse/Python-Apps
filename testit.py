#!/usr/bin/env python3

import csv
import getpass
import re
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

OUTPUT_FILE = (
    f"precheck_report_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
)

def load_csv(filename):
    """
    CSV format:

    Switch Name,Port
    DDC1-ISP-DSW1,Eth1/4
    DDC1-ISP-DSW1,Eth1/8
    """

    inventory = {}

    with open(filename, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing headers.")

        required_headers = {"Switch Name", "Port"}
        missing_headers = required_headers - set(reader.fieldnames)

        if missing_headers:
            raise ValueError(
                "CSV is missing required header(s): "
                + ", ".join(sorted(missing_headers))
            )

        for line_number, row in enumerate(reader, start=2):
            switch = (row.get("Switch Name") or "").strip()
            interface = (row.get("Port") or "").strip()

            if not switch or not interface:
                print(
                    f"Skipping incomplete CSV row {line_number}."
                )
                continue

            inventory.setdefault(switch, []).append(interface)

    return inventory

def connect_device(host, username, password):
    device = {
        "device_type": "cisco_nxos",
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    return ConnectHandler(**device)

def count_macs(output):
    mac_regex = r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}"

    count = 0

    for line in output.splitlines():
        if re.search(mac_regex, line, re.IGNORECASE):
            count += 1

    return count

def evaluate_interface(conn, interface):
    result = {
        "status": "",
        "description": "",
        "admin_state": "",
        "mode": "",
        "port_channel": "NO",
        "mac_count": 0,
        "cdp": "NO",
        "lldp": "NO",
        "recommendation": "",
    }

    try:
        status_output = conn.send_command(
            f"show interface status | include {interface}",
            read_timeout=60,
        )

        result["status"] = status_output.strip()

        description_output = conn.send_command(
            f"show interface description | include {interface}",
            read_timeout=60,
        )

        result["description"] = description_output.strip()

        run_output = conn.send_command(
            f"show running-config interface {interface}",
            read_timeout=60,
        )

        if re.search(r"^\s*shutdown\s*$", run_output, re.MULTILINE):
            result["admin_state"] = "SHUTDOWN"
            result["recommendation"] = "ALREADY_SHUTDOWN"
            return result

        result["admin_state"] = "NO SHUTDOWN"

        run_output_lower = run_output.lower()

        if "switchport mode trunk" in run_output_lower:
            result["mode"] = "TRUNK"

        elif "switchport mode access" in run_output_lower:
            result["mode"] = "ACCESS"

        else:
            result["mode"] = "UNKNOWN"

        port_channel_output = conn.send_command(
            f"show port-channel summary | include {interface}",
            read_timeout=60,
        )

        if port_channel_output.strip():
            result["port_channel"] = "YES"

        mac_output = conn.send_command(
            f"show mac address-table interface {interface}",
            read_timeout=60,
        )

        result["mac_count"] = count_macs(mac_output)

        cdp_output = conn.send_command(
            f"show cdp neighbors interface {interface}",
            read_timeout=60,
        )

        if "device id" in cdp_output.lower():
            result["cdp"] = "YES"

        lldp_output = conn.send_command(
            f"show lldp neighbors interface {interface}",
            read_timeout=60,
        )

        lldp_markers = (
            "device id",
            "local intf",
            "port id",
        )

        if any(marker in lldp_output.lower() for marker in lldp_markers):
            result["lldp"] = "YES"

        safe_to_shutdown = True

        if "connected" in status_output.lower():
            safe_to_shutdown = False

        if result["port_channel"] == "YES":
            safe_to_shutdown = False

        if result["mode"] == "TRUNK":
            safe_to_shutdown = False

        if result["mac_count"] > 0:
            safe_to_shutdown = False

        if result["cdp"] == "YES":
            safe_to_shutdown = False

        if result["lldp"] == "YES":
            safe_to_shutdown = False

        if safe_to_shutdown:
            result["recommendation"] = "SAFE_TO_SHUTDOWN"
        else:
            result["recommendation"] = "REVIEW_REQUIRED"

    except Exception as exc:
        result["recommendation"] = f"ERROR: {exc}"

    return result

def main():
    print("\n=== Down Interface Precheck Utility ===\n")

    csv_file = input("CSV File: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    switch_filter = input(
        "\nComma Delimited Switch List "
        "(blank = all switches): "
    ).strip()

    try:
        inventory = load_csv(csv_file)

    except FileNotFoundError:
        print(f"CSV file not found: {csv_file}")
        return

    except ValueError as exc:
        print(f"CSV error: {exc}")
        return

    if not inventory:
        print("No valid switch/interface entries were found.")
        return

    if switch_filter:
        allowed_switches = {
            switch.strip().upper()
            for switch in switch_filter.split(",")
            if switch.strip()
        }

        inventory = {
            switch: interfaces
            for switch, interfaces in inventory.items()
            if switch.upper() in allowed_switches
        }

    if not inventory:
        print("No switches matched the supplied filter.")
        return

    try:
        with open(
            OUTPUT_FILE,
            "w",
            newline="",
            encoding="utf-8",
        ) as outfile:

            writer = csv.writer(outfile)

            writer.writerow(
                [
                    "Switch",
                    "Interface",
                    "Admin_State",
                    "Status",
                    "Description",
                    "Mode",
                    "PortChannel",
                    "MAC_Count",
                    "CDP",
                    "LLDP",
                    "Recommendation",
                ]
            )

            for switch, interfaces in inventory.items():
                print(f"\nConnecting to {switch}")

                conn = None

                try:
                    conn = connect_device(
                        switch,
                        username,
                        password,
                    )

                    for interface in interfaces:
                        print(f"  Checking {interface}")

                        result = evaluate_interface(
                            conn,
                            interface,
                        )

                        writer.writerow(
                            [
                                switch,
                                interface,
                                result["admin_state"],
                                result["status"],
                                result["description"],
                                result["mode"],
                                result["port_channel"],
                                result["mac_count"],
                                result["cdp"],
                                result["lldp"],
                                result["recommendation"],
                            ]
                        )

                except NetmikoAuthenticationException:
                    print(f"Authentication Failure: {switch}")

                except NetmikoTimeoutException:
                    print(f"Timeout: {switch}")

                except Exception as exc:
                    print(f"Error connecting to {switch}: {exc}")

                finally:
                    if conn is not None:
                        conn.disconnect()

    except OSError as exc:
        print(f"Unable to write report: {exc}")
        return

    print("\nCompleted.")
    print(f"Report: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
