#!/usr/bin/env python3

import argparse
import csv
import getpass
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None


DEFAULT_OUTPUT_FILE = "stp_vlan_report.csv"
COMMAND_TIMEOUT = 30


_MAC_LOOKUP = None

if MacLookup is not None:
    try:
        _MAC_LOOKUP = MacLookup()
    except Exception:
        _MAC_LOOKUP = None


OUTPUT_FIELDS = [
    "Device",
    "VLAN",
    "VLAN_Name",
    "SVI_IP",
    "SVI_Description",
    "MAC_Count",
    "MAC_Addresses",
    "MAC_Interfaces",
    "MAC_Device_Decode",
    "Root_Bridge",
    "Root_Check",
]


MAC_RE = r"\b[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}\b"

INTERFACE_RE = (
    r"(?:(?:Eth|Gi|Te|Po|Tu)\d+(?:/\d+)*|"
    r"(?:Ethernet|GigabitEthernet|TenGigabitEthernet|"
    r"Port-channel|Tunnel)\d+(?:/\d+)*)"
)


PORT_RE = (
    rf"(?P<interface>{INTERFACE_RE})"
)


def normalize_interface_name(interface):
    replacements = {
        "Ethernet": "Eth",
        "GigabitEthernet": "Gi",
        "TenGigabitEthernet": "Te",
        "Port-channel": "Po",
        "Tunnel": "Tu",
    }

    for long_name, short_name in replacements.items():
        if interface.startswith(long_name):
            return interface.replace(long_name, short_name, 1)

    return interface


def normalize_mac(mac_address):
    """Normalize a MAC address to colon-separated notation."""
    hex_only = re.sub(r"[^0-9a-f]", "", mac_address.lower())

    if len(hex_only) != 12:
        return mac_address.lower()

    return ":".join(
        hex_only[index:index + 2]
        for index in range(0, 12, 2)
    )


def format_mac(mac_address):
    """Format a MAC address as xxxx.xxxx.xxxx."""
    hex_only = re.sub(r"[^0-9a-f]", "", mac_address.lower())

    if len(hex_only) != 12:
        return mac_address.lower()

    return (
        f"{hex_only[0:4]}."
        f"{hex_only[4:8]}."
        f"{hex_only[8:12]}"
    )


def lookup_mac_vendor(mac_address):
    """Return the manufacturer associated with the MAC OUI."""
    if _MAC_LOOKUP is None:
        return "Unknown"

    try:
        return _MAC_LOOKUP.lookup(normalize_mac(mac_address))
    except Exception:
        return "Unknown"


def parse_vlans(output):
    """Parse VLAN ID and name entries from show vlan brief."""
    vlans = []
    seen_vlans = set()

    for line in output.splitlines():
        line = line.strip()

        if not line or line.startswith("-"):
            continue

        match = re.match(
            r"^(?P<vlan>\d{1,4})\s+"
            r"(?P<name>\S+)\s+"
            r"(?P<status>\S+)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        vlan_id = match.group("vlan")

        if vlan_id in seen_vlans:
            continue

        seen_vlans.add(vlan_id)

        vlans.append(
            {
                "vlan": vlan_id,
                "name": match.group("name"),
                "status": match.group("status"),
            }
        )

    return vlans


def parse_mac_table(output):
    """Parse MAC addresses and learned interfaces from NX-OS output."""
    entries = []
    seen_entries = set()

    for line in output.splitlines():
        mac_match = re.search(MAC_RE, line, re.IGNORECASE)

        if not mac_match:
            continue

        interface_matches = list(
            re.finditer(PORT_RE, line, re.IGNORECASE)
        )

        interface = ""

        if interface_matches:
            interface = normalize_interface_name(
                interface_matches[-1].group("interface")
            )

        mac_address = format_mac(mac_match.group(0))
        entry_key = (mac_address, interface)

        if entry_key in seen_entries:
            continue

        seen_entries.add(entry_key)

        entries.append(
            {
                "mac": mac_address,
                "interface": interface,
                "vendor": lookup_mac_vendor(mac_address),
            }
        )

    return entries


def get_mac_info(connection, vlan):
    """Collect MAC addresses and vendor decoding for a VLAN."""
    try:
        output = connection.send_command(
            f"show mac address-table vlan {vlan}",
            read_timeout=COMMAND_TIMEOUT,
        )

        entries = parse_mac_table(output)
        addresses = []
        interfaces = []
        decodes = []

        for entry in entries:
            if entry["mac"] not in addresses:
                addresses.append(entry["mac"])

            if entry["interface"] and entry["interface"] not in interfaces:
                interfaces.append(entry["interface"])

            decode = f"{entry['mac']}={entry['vendor']}"

            if decode not in decodes:
                decodes.append(decode)

        return {
            "count": len(addresses),
            "addresses": ", ".join(addresses),
            "interfaces": ", ".join(interfaces),
            "decode": "; ".join(decodes) if decodes else "Unknown",
            "check": "OK",
        }

    except Exception as exc:
        return {
            "count": 0,
            "addresses": "",
            "interfaces": "",
            "decode": "Unknown",
            "check": f"MAC check failed: {exc}",
        }


def check_root(connection, vlan):
    """Return YES, NO, or UNKNOWN for the local root state."""
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=COMMAND_TIMEOUT,
        )

        if re.search(
            r"This bridge is the root",
            output,
            re.IGNORECASE,
        ):
            return "YES", "Local switch is the root bridge"

        if re.search(
            r"Root ID|Bridge ID|Spanning tree enabled",
            output,
            re.IGNORECASE,
        ):
            return (
                "NO",
                "Another bridge is the root or root information exists",
            )

        if re.search(
            r"does not exist|invalid|not found|no spanning tree",
            output,
            re.IGNORECASE,
        ):
            return (
                "UNKNOWN",
                "VLAN has no usable spanning-tree information",
            )

        return (
            "UNKNOWN",
            "Unable to determine spanning-tree root state",
        )

    except Exception as exc:
        return "UNKNOWN", f"Root check failed: {exc}"


def get_svi_info(connection, vlan):
    """Return SVI description and configured IP addresses."""
    try:
        output = connection.send_command(
            f"show run interface vlan {vlan}",
            read_timeout=COMMAND_TIMEOUT,
        )

        descriptions = []
        ip_addresses = []

        for raw_line in output.splitlines():
            line = raw_line.strip()

            description_match = re.match(
                r"^description\s+(.+)$",
                line,
                re.IGNORECASE,
            )

            if description_match:
                descriptions.append(
                    description_match.group(1).strip()
                )
                continue

            ip_match = re.match(
                r"^ip address\s+(.+)$",
                line,
                re.IGNORECASE,
            )

            if ip_match:
                ip_addresses.append(
                    ip_match.group(1).strip()
                )

        return (
            "; ".join(descriptions),
            "; ".join(ip_addresses),
            "OK",
        )

    except Exception as exc:
        return "", "", f"SVI check failed: {exc}"


def get_hostname(connection):
    prompt = connection.find_prompt().strip()
    return prompt.rstrip("#>").strip()


def process_switch(device):
    results = []
    connection = None

    try:
        print(f"\nConnecting to {device['host']}...")

        connection = ConnectHandler(**device)
        hostname = get_hostname(connection)

        vlan_output = connection.send_command(
            "show vlan brief",
            read_timeout=COMMAND_TIMEOUT,
        )

        vlans = parse_vlans(vlan_output)

        print(f"{hostname}: Found {len(vlans)} VLANs")

        for vlan_info in vlans:
            vlan_id = vlan_info["vlan"]
            vlan_name = vlan_info["name"]

            root_status, root_check = check_root(
                connection,
                vlan_id,
            )

            svi_description, svi_ip, svi_check = get_svi_info(
                connection,
                vlan_id,
            )

            mac_info = get_mac_info(
                connection,
                vlan_id,
            )

            check_messages = []

            if root_status == "UNKNOWN":
                check_messages.append(root_check)

            if svi_check != "OK":
                check_messages.append(svi_check)

            if mac_info["check"] != "OK":
                check_messages.append(mac_info["check"])

            results.append(
                {
                    "Device": hostname,
                    "VLAN": vlan_id,
                    "VLAN_Name": vlan_name,
                    "SVI_IP": svi_ip,
                    "SVI_Description": svi_description,
                    "MAC_Count": mac_info["count"],
                    "MAC_Addresses": mac_info["addresses"],
                    "MAC_Interfaces": mac_info["interfaces"],
                    "MAC_Device_Decode": mac_info["decode"],
                    "Root_Bridge": root_status,
                    "Root_Check": (
                        "OK"
                        if not check_messages
                        else "; ".join(check_messages)
                    ),
                }
            )

    except NetmikoAuthenticationException:
        print(
            f"Authentication failure: {device['host']}",
            file=sys.stderr,
        )

    except NetmikoTimeoutException:
        print(
            f"Connection timeout: {device['host']}",
            file=sys.stderr,
        )

    except Exception as exc:
        print(
            f"Failed to process {device['host']}: {exc}",
            file=sys.stderr,
        )

    finally:
        if connection is not None:
            connection.disconnect()

    return results


def write_csv(results, filename):
    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=OUTPUT_FIELDS,
        )

        writer.writeheader()
        writer.writerows(results)


def shorten(value, width):
    value = str(value or "")

    if len(value) <= width:
        return value

    return value[: width - 3] + "..."


def display_results(results):
    print("\n" + "=" * 230)
    print("VLAN / SVI / MAC / SPANNING TREE ROOT REPORT")
    print("=" * 230)

    current_device = ""

    for row in results:
        if row["Device"] != current_device:
            current_device = row["Device"]

            print(f"\nSwitch: {current_device}")
            print("-" * 230)

            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<25}"
                f"{'SVI IP':<22}"
                f"{'MACs':<7}"
                f"{'MAC Device Decode':<55}"
                f"{'Root':<10}"
                f"{'Description':<55}"
            )

            print("-" * 230)

        print(
            f"{row['VLAN']:<8}"
            f"{shorten(row['VLAN_Name'], 24):<25}"
            f"{shorten(row['SVI_IP'], 21):<22}"
            f"{row['MAC_Count']:<7}"
            f"{shorten(row['MAC_Device_Decode'], 54):<55}"
            f"{row['Root_Bridge']:<10}"
            f"{shorten(row['SVI_Description'], 54):<55}"
        )

    root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "YES"
    )

    non_root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "NO"
    )

    unknown_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "UNKNOWN"
    )

    total_macs = sum(
        int(row["MAC_Count"])
        for row in results
    )

    print("\n" + "=" * 230)
    print(f"Total VLANs Processed : {len(results)}")
    print(f"Total MAC Addresses   : {total_macs}")
    print(f"Total Root VLANs      : {root_count}")
    print(f"Total Non-Root VLANs  : {non_root_count}")
    print(f"Total Unknown Checks  : {unknown_count}")
    print("=" * 230)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Collect VLAN, SVI, MAC address, vendor decode, "
            "and spanning-tree root information from Cisco NX-OS switches."
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_FILE,
        help=(
            "CSV output filename; default: "
            f"{DEFAULT_OUTPUT_FILE}"
        ),
    )

    args = parser.parse_args()

    hosts = input(
        "Enter switch hostnames/IPs (comma delimited): "
    ).strip()

    host_list = [
        host.strip()
        for host in hosts.split(",")
        if host.strip()
    ]

    if not host_list:
        print("No switch hostnames or IP addresses were provided.")
        sys.exit(1)

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if _MAC_LOOKUP is None:
        print(
            "Warning: mac-vendor-lookup is unavailable. "
            "MAC device decoding will show Unknown."
        )

    all_results = []

    for host in host_list:
        device = {
            "device_type": "cisco_nxos",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False,
        }

        all_results.extend(process_switch(device))

    all_results.sort(
        key=lambda row: (
            row["Device"],
            int(row["VLAN"]),
        )
    )

    display_results(all_results)
    write_csv(all_results, args.output)

    print(f"\nCSV report saved to: {args.output}")


if __name__ == "__main__":
    main()
