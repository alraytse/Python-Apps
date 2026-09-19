#!/usr/bin/env python3

import argparse
import csv
import getpass
import io
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

from netmiko import ConnectHandler

CSV_FILE = "stp_vlan_report.csv"
MAC_OID_BASE = "1.3.6.1.2.1.17.4.3.1.1"
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def parse_vlans(output):
    vlans = []

    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)", line.strip())
        if match:
            vlans.append({
                "vlan": match.group(1),
                "name": match.group(2),
            })

    return vlans


def normalize_mac(mac):
    hex_digits = re.sub(r"[^0-9a-fA-F]", "", mac)

    if len(hex_digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")

    return [
        int(hex_digits[index:index + 2], 16)
        for index in range(0, 12, 2)
    ]


def format_mac(mac, output_format="cisco"):
    octets = normalize_mac(mac)
    value = "".join(f"{octet:02x}" for octet in octets)

    if output_format == "colon":
        return ":".join(
            value[index:index + 2]
            for index in range(0, 12, 2)
        )

    if output_format == "hyphen":
        return "-".join(
            value[index:index + 2]
            for index in range(0, 12, 2)
        )

    return ".".join(
        value[index:index + 4]
        for index in range(0, 12, 4)
    )


def mac_to_oid(mac, base_oid=MAC_OID_BASE):
    mac_octets = normalize_mac(mac)
    base_parts = [int(part) for part in base_oid.strip(".").split(".")]

    return ".".join(
        str(value)
        for value in base_parts + mac_octets
    )


def parse_mac_table(output):
    """Return a list of {'vlan': ..., 'mac': ...} entries from NX-OS output."""
    entries = []
    mac_pattern = (
        r"^\s*\*?\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12})\b"
    )

    for line in output.splitlines():
        match = re.match(mac_pattern, line)
        if match:
            entries.append({
                "vlan": match.group(1),
                "mac": format_mac(match.group(2)),
            })

    return entries


def parse_arp_table(output):
    """Return ARP entries grouped by VLAN from NX-OS output."""
    mac_pattern = (
        r"[0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12}"
    )
    vlan_pattern = r"\b[Vv]lan(\d+)\b"
    arp_entries = {}

    for line in output.splitlines():
        mac_match = re.search(mac_pattern, line)
        vlan_match = re.search(vlan_pattern, line)

        if mac_match and vlan_match:
            vlan = vlan_match.group(1)
            mac = format_mac(mac_match.group(0))
            arp_entries.setdefault(vlan, set()).add(mac)

    return arp_entries


def get_arp_table(connection):
    try:
        output = connection.send_command(
            "show ip arp",
            read_timeout=30,
        )
        return parse_arp_table(output), True
    except Exception as error:
        print(f"ARP lookup failed: {error}")
        return {}, False


def check_mac_arp(mac_info, vlan, arp_entries, arp_available):
    macs = [
        mac.strip()
        for mac in mac_info["MAC_Address"].split(";")
        if mac.strip()
    ]

    if not arp_available:
        return "ARP_UNAVAILABLE", ""

    if not macs:
        return "NO_MACS", ""

    vlan_arp_macs = arp_entries.get(str(vlan), set())
    missing_macs = [
        mac
        for mac in macs
        if mac not in vlan_arp_macs
    ]

    if missing_macs:
        return "MISSING_ARP", "; ".join(missing_macs)

    return "PASS", ""


def get_mac_info(connection, vlan, base_oid, oui_registry):
    try:
        output = connection.send_command(
            "show mac address-table",
            read_timeout=30,
        )

        entries = [
            entry
            for entry in parse_mac_table(output)
            if entry["vlan"] == str(vlan)
        ]

        mac_addresses = []
        mac_ouis = []
        mac_oids = []
        mac_companies = []

        for entry in entries:
            mac = entry["mac"]
            octets = normalize_mac(mac)
            oui = "".join(f"{octet:02X}" for octet in octets[:3])
            first_octet = octets[0]

            mac_addresses.append(mac)
            mac_ouis.append(
                f"{oui[:2]}-{oui[2:4]}-{oui[4:6]}"
            )
            mac_oids.append(mac_to_oid(mac, base_oid))

            if first_octet & 0x01:
                company = "Multicast address"
            elif first_octet & 0x02:
                company = "Locally administered/randomized MAC"
            else:
                company = oui_registry.get(
                    oui,
                    "Not found in IEEE OUI registry",
                )

            mac_companies.append(company)

        return {
            "MAC_Count": str(len(mac_addresses)),
            "MAC_Address": "; ".join(mac_addresses),
            "MAC_OUI": "; ".join(mac_ouis),
            "MAC_OID": "; ".join(mac_oids),
            "MAC_Company": "; ".join(mac_companies),
        }

    except Exception as error:
        print(f"MAC lookup failed for VLAN {vlan}: {error}")
        return {
            "MAC_Count": "0",
            "MAC_Address": "",
            "MAC_OUI": "",
            "MAC_OID": "",
            "MAC_Company": "",
        }


def check_root(connection, vlan):
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30,
        )
        return "This bridge is the root" in output
    except Exception:
        return False


def get_svi_info(connection, vlan):
    try:
        output = connection.send_command(
            f"show run interface vlan {vlan}",
            read_timeout=30,
        )

        description = ""
        ip_address = ""

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("description "):
                description = line.replace("description ", "", 1)
            elif line.startswith("ip address "):
                ip_address = line.replace("ip address ", "", 1)

        return description, ip_address

    except Exception:
        return "", ""


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


def process_switch(device, base_oid, oui_registry):
    results = []
    connection = None

    try:
        print(f"\nConnecting to {device['host']}...")
        connection = ConnectHandler(**device)
        hostname = get_hostname(connection)

        vlan_output = connection.send_command(
            "show vlan brief",
            read_timeout=30,
        )
        vlans = parse_vlans(vlan_output)
        arp_entries, arp_available = get_arp_table(connection)
        print(f"{hostname}: Found {len(vlans)} VLANs")

        for vlan_info in vlans:
            vlan_id = vlan_info["vlan"]
            mac_info = get_mac_info(
                connection,
                vlan_id,
                base_oid,
                oui_registry,
            )
            arp_check, arp_missing_macs = check_mac_arp(
                mac_info,
                vlan_id,
                arp_entries,
                arp_available,
            )
            svi_description, svi_ip = get_svi_info(connection, vlan_id)
            is_root = check_root(connection, vlan_id)

            results.append({
                "Device": hostname,
                "VLAN": vlan_id,
                "VLAN_Name": vlan_info["name"],
                "SVI_IP": svi_ip,
                "SVI_Description": svi_description,
                "MAC_Count": mac_info["MAC_Count"],
                "MAC_Address": mac_info["MAC_Address"],
                "MAC_OUI": mac_info["MAC_OUI"],
                "MAC_OID": mac_info["MAC_OID"],
                "MAC_Company": mac_info["MAC_Company"],
                "ARP_Check": arp_check,
                "ARP_Missing_MACs": arp_missing_macs,
                "Root_Bridge": "YES" if is_root else "NO",
            })

    except Exception as error:
        print(f"Failed to connect to {device['host']} : {error}")

    finally:
        if connection:
            connection.disconnect()

    return results


def normalize_assignment(value):
    value = re.sub(r"[^0-9a-fA-F]", "", value)
    return value[:6].upper() if len(value) >= 6 else ""


def read_oui_csv(csv_text):
    reader = csv.DictReader(io.StringIO(csv_text))
    if not reader.fieldnames:
        raise ValueError("The OUI file does not contain a CSV header.")

    assignment_field = next(
        (
            field
            for field in reader.fieldnames
            if field.strip().lower() == "assignment"
        ),
        None,
    )
    organization_field = next(
        (
            field
            for field in reader.fieldnames
            if field.strip().lower()
            in {"organization name", "organization"}
        ),
        None,
    )

    if not assignment_field or not organization_field:
        raise ValueError(
            "The OUI CSV must contain Assignment and Organization Name columns."
        )

    organizations = {}
    for row in reader:
        assignment = normalize_assignment(row.get(assignment_field, ""))
        organization = row.get(organization_field, "").strip()

        if assignment and organization:
            organizations[assignment] = organization

    return organizations


def load_oui_registry(oui_file=None, offline=False):
    if oui_file:
        path = Path(oui_file)
        return read_oui_csv(path.read_text(encoding="utf-8"))

    if offline:
        return {}

    request = Request(
        IEEE_OUI_URL,
        headers={"User-Agent": "stp-vlan-report/1.0"},
    )

    with urlopen(request, timeout=20) as response:
        csv_text = response.read().decode("utf-8-sig")

    return read_oui_csv(csv_text)


def write_csv(results, csv_file):
    fields = [
        "Device",
        "VLAN",
        "VLAN_Name",
        "SVI_IP",
        "SVI_Description",
        "MAC_Count",
        "MAC_Address",
        "MAC_OUI",
        "MAC_OID",
        "MAC_Company",
        "ARP_Check",
        "ARP_Missing_MACs",
        "Root_Bridge",
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def display_results(results):
    print("\n" + "=" * 240)
    print("VLAN / SVI / MAC / OID / COMPANY / SPANNING TREE ROOT REPORT")
    print("=" * 240)

    current_device = ""

    for row in results:
        if row["Device"] != current_device:
            current_device = row["Device"]
            print(f"\nSwitch: {current_device}")
            print("-" * 240)
            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<20}"
                f"{'SVI IP':<20}"
                f"{'MACs':<6}"
                f"{'MAC Address':<24}"
                f"{'OUI':<12}"
                f"{'Company':<32}"
                f"{'ARP Check':<16}"
                f"{'Root':<8}"
            )
            print("-" * 240)

        print(
            f"{row['VLAN']:<8}"
            f"{row['VLAN_Name']:<20}"
            f"{row['SVI_IP']:<20}"
            f"{row['MAC_Count']:<6}"
            f"{row['MAC_Address']:<24}"
            f"{row['MAC_OUI']:<12}"
            f"{row['MAC_Company']:<32}"
            f"{row['ARP_Check']:<16}"
            f"{row['Root_Bridge']:<8}"
        )
        if row["MAC_OID"]:
            print(f"{'':<8}{'MAC OID: ' + row['MAC_OID']}")
        if row["ARP_Missing_MACs"]:
            print(f"{'':<8}{'MACs missing ARP: ' + row['ARP_Missing_MACs']}")
        if row["SVI_Description"]:
            print(f"{'':<8}{'SVI Description: ' + row['SVI_Description']}")

    root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "YES"
    )

    print("\n" + "=" * 240)
    print(f"Total VLANs Processed : {len(results)}")
    print(f"Total Root VLANs      : {root_count}")
    print("=" * 240)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect VLAN, SVI, MAC OID, OUI, company, and STP root data."
    )
    parser.add_argument(
        "--csv-file",
        default=CSV_FILE,
        help=f"Output CSV file. Default: {CSV_FILE}",
    )
    parser.add_argument(
        "--mac-oid-base",
        default=MAC_OID_BASE,
        help=f"MAC OID base. Default: {MAC_OID_BASE}",
    )
    parser.add_argument(
        "--oui-file",
        help="Local IEEE OUI CSV file. If omitted, the current IEEE registry is fetched.",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip IEEE registry download and report company as unavailable.",
    )
    return parser


def main():
    args = build_parser().parse_args()

    hosts = input(
        "Enter switch hostnames/IPs (comma delimited): "
    ).strip()
    host_list = [host.strip() for host in hosts.split(",") if host.strip()]

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    try:
        oui_registry = load_oui_registry(args.oui_file, args.offline)
        print(f"Loaded {len(oui_registry)} IEEE OUI assignments")
    except Exception as error:
        print(f"Warning: IEEE OUI registry unavailable: {error}")
        print("Company lookup will report unavailable assignments.")
        oui_registry = {}

    all_results = []

    for host in host_list:
        device = {
            "device_type": "cisco_nxos",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False,
        }
        all_results.extend(
            process_switch(device, args.mac_oid_base, oui_registry)
        )

    all_results.sort(
        key=lambda row: (
            row["Device"],
            int(row["VLAN"]),
        )
    )

    display_results(all_results)
    write_csv(all_results, args.csv_file)
    print(f"\nCSV report saved to: {args.csv_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
