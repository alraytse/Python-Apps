#!/usr/bin/env python3
"""Collect IP address information from multiple Cisco IOS switches."""

from datetime import datetime
from getpass import getpass
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


DEVICE_TYPE = "cisco_ios"
COMMANDS = (
    "show interface description",
    "show ip interface brief",
)


def prompt_for_switches():
    while True:
        switch_input = input(
            "Enter comma-delimited switch names or IP addresses: "
        ).strip()
        switches = [switch.strip() for switch in switch_input.split(",") if switch.strip()]

        if switches:
            return switches

        print("Please enter at least one switch name or IP address.")


def collect_switch_output(host, username, password):
    device = {
        "device_type": DEVICE_TYPE,
        "host": host,
        "username": username,
        "password": password,
        "conn_timeout": 10,
        "auth_timeout": 10,
        "banner_timeout": 15,
        "fast_cli": False,
    }

    output = [f"\n{'=' * 80}", f"Switch: {host}", f"{'=' * 80}"]

    try:
        with ConnectHandler(**device) as connection:
            for command in COMMANDS:
                output.append(f"\n----- {command} -----\n")
                output.append(connection.send_command(command))

    except NetmikoAuthenticationException:
        output.append("ERROR: Authentication failed.")
    except NetmikoTimeoutException:
        output.append("ERROR: Connection timed out.")
    except Exception as exc:
        output.append(f"ERROR: {type(exc).__name__}: {exc}")

    return "\n".join(output)


def main():
    print("Cisco Switch IP Address Collector")
    print("=" * 40)

    username = input("User ID: ").strip()
    password = getpass("Password: ")
    switches = prompt_for_switches()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = Path(f"switch_ip_dump_{timestamp}.txt")
    report_sections = []

    for switch in switches:
        print(f"\nCollecting data from {switch}...")
        switch_output = collect_switch_output(switch, username, password)
        report_sections.append(switch_output)
        print(switch_output)

    report_path.write_text("\n".join(report_sections) + "\n", encoding="utf-8")
    print(f"\nReport saved to: {report_path.resolve()}")


if __name__ == "__main__":
    main()
