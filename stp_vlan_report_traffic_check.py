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
DEFAULT_MAX_MAC_COUNT = 2
DEFAULT_MAX_ARP_COUNT = 2


def parse_vlans(output):
    vlan_map = {}

    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)", line.strip())
        if match:
            vlan_id = match.group(1)
            vlan_map[vlan_id] = {
                "vlan": vlan_id,
                "name": match.group(2),
            }

    return list(vlan_map.values())


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
    """Return dynamic VLAN/MAC/port entries from NX-OS output."""
    entries = []
    mac_pattern = (
        r"^\s*\*?\s*(\d+)\s+"
        r"([0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
        r"[0-9a-fA-F]{12})\b"
    )

    for line in output.splitlines():
        match = re.match(mac_pattern, line)
        is_dynamic = re.search(r"\bdynamic\b", line, re.IGNORECASE)
        port_match = re.search(
            r"\b((?:Eth(?:ernet)?|Po(?:rt-channel)?|"
            r"port-channel|sup-eth|mgmt)\S*)\s*$",
            line,
            re.IGNORECASE,
        )
        if match and is_dynamic:
            entries.append({
                "vlan": match.group(1),
                "mac": format_mac(match.group(2)),
                "port": port_match.group(1) if port_match else "",
            })

    return entries


def is_port_channel(port):
    """Return True when an interface name identifies a port-channel."""
    return bool(
        re.match(
            r"^(?:po|port-channel)\S*$",
            port.strip(),
            re.IGNORECASE,
        )
    )


def parse_arp_table(output):
    """Return distinct ARP MAC addresses grouped by VLAN."""
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


def get_arp_count(arp_entries, vlan):
    return len(arp_entries.get(str(vlan), set()))


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


def decode_mac(mac, base_oid, oui_registry):
    """Return formatted OUI, OID, and organization details for a MAC."""
    octets = normalize_mac(mac)
    oui = "".join(f"{octet:02X}" for octet in octets[:3])
    formatted_oui = f"{oui[:2]}-{oui[2:4]}-{oui[4:6]}"
    oid = mac_to_oid(mac, base_oid)
    first_octet = octets[0]

    if first_octet & 0x01:
        company = "Multicast address"
    elif first_octet & 0x02:
        company = "Locally administered/randomized MAC"
    else:
        company = oui_registry.get(
            oui,
            "Not found in IEEE OUI registry",
        )

    return formatted_oui, oid, company


def get_mac_info(connection, vlan, base_oid, oui_registry):
    """Return dynamic MAC data while excluding port-channel entries."""
    try:
        output = connection.send_command(
            "show mac address-table",
            read_timeout=30,
        )

        entries = [
            entry
            for entry in parse_mac_table(output)
            if (
                entry["vlan"] == str(vlan)
                and not is_port_channel(entry["port"])
            )
        ]

        mac_addresses = []
        mac_companies = []
        mac_ports = []

        for entry in entries:
            mac = entry["mac"]
            _, _, mac_company = decode_mac(
                mac,
                base_oid,
                oui_registry,
            )
            mac_addresses.append(mac)
            mac_companies.append(mac_company)
            if entry["port"]:
                mac_ports.append(entry["port"])

        return {
            "MAC_Count": str(len(mac_addresses)),
            "MAC_Address": "; ".join(mac_addresses),
            "MAC_Company": "; ".join(mac_companies),
            "MAC_Port": "; ".join(dict.fromkeys(mac_ports)),
        }

    except Exception as error:
        print(f"MAC lookup failed for VLAN {vlan}: {error}")
        return {
            "MAC_Count": "0",
            "MAC_Address": "",
            "MAC_Company": "",
            "MAC_Port": "",
        }


def parse_interface_rate(output, direction):
    """Return the highest parsed recent input/output rate in bits per second."""
    pattern = re.compile(
        rf"(?:5 minute|30 seconds)\s+{direction}put rate\s+"
        r"([0-9,]+)\s+bits/sec",
        re.IGNORECASE,
    )
    rates = []

    for match in pattern.finditer(output):
        rates.append(int(match.group(1).replace(",", "")))

    return max(rates, default=None)


def check_port_traffic(connection, port_list):
    """Check recent traffic rates on access ports associated with dynamic MACs."""
    ports = [
        port.strip()
        for port in port_list.split(";")
        if port.strip()
    ]

    if not ports:
        return "NO_ACCESS_PORTS", "", ""

    checked_ports = []
    traffic_statistics = []
    traffic_detected = False
    successful_checks = 0

    for port in dict.fromkeys(ports):
        try:
            output = connection.send_command(
                f"show interface {port}",
                read_timeout=30,
            )
            input_rate = parse_interface_rate(output, "in")
            output_rate = parse_interface_rate(output, "out")

            if input_rate is None and output_rate is None:
                continue

            successful_checks += 1
            checked_ports.append(port)
            traffic_statistics.append(
                f"{port}: IN {input_rate if input_rate is not None else 'N/A'} "
                f"bps / OUT {output_rate if output_rate is not None else 'N/A'} bps"
            )
            if (input_rate or 0) > 0 or (output_rate or 0) > 0:
                traffic_detected = True

        except Exception:
            continue

    if traffic_detected:
        status = "TRAFFIC_DETECTED"
    elif successful_checks:
        status = "NO_TRAFFIC"
    else:
        status = "TRAFFIC_UNAVAILABLE"

    return (
        status,
        "; ".join(checked_ports),
        "; ".join(traffic_statistics),
    )


def check_root(connection, vlan):
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30,
        )
        return "This bridge is the root" in output
    except Exception:
        return False


def get_svi_info(connection, vlan, base_oid, oui_registry):
    description = ""
    ip_address = ""
    svi_mac = ""
    svi_company = ""

    try:
        output = connection.send_command(
            f"show run interface vlan {vlan}",
            read_timeout=30,
        )

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("description "):
                description = line.replace("description ", "", 1)
            elif line.startswith("ip address "):
                ip_address = line.replace("ip address ", "", 1)

    except Exception:
        pass

    try:
        output = connection.send_command(
            f"show interface vlan {vlan}",
            read_timeout=30,
        )
        mac_pattern = (
            r"\baddress is\s+"
            r"([0-9a-fA-F]{4}(?:[.:-][0-9a-fA-F]{4}){2}|"
            r"[0-9a-fA-F]{12})\b"
        )

        for line in output.splitlines():
            match = re.search(mac_pattern, line, re.IGNORECASE)
            if match:
                svi_mac = format_mac(match.group(1))
                _, _, svi_company = decode_mac(
                    svi_mac,
                    base_oid,
                    oui_registry,
                )
                break

    except Exception:
        pass

    return (
        description,
        ip_address,
        svi_mac,
        svi_company,
    )


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


def process_switch(
    device,
    base_oid,
    oui_registry,
    max_mac_count,
    max_arp_count,
):
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
            mac_count = int(mac_info["MAC_Count"])
            arp_count = get_arp_count(arp_entries, vlan_id)

            if arp_available:
                if (
                    mac_count > max_mac_count
                    or arp_count > max_arp_count
                ):
                    continue
            elif mac_count > max_mac_count:
                continue

            traffic_check = "NOT_CHECKED"
            traffic_ports = ""
            traffic_statistics = ""
            if mac_count >= 2:
                (
                    traffic_check,
                    traffic_ports,
                    traffic_statistics,
                ) = check_port_traffic(
                    connection,
                    mac_info["MAC_Port"],
                )

            arp_check, arp_missing_macs = check_mac_arp(
                mac_info,
                vlan_id,
                arp_entries,
                arp_available,
            )
            svi_description, svi_ip, svi_mac, svi_company = get_svi_info(
                connection,
                vlan_id,
                base_oid,
                oui_registry,
            )
            is_root = check_root(connection, vlan_id)
            shutdown_recommendation = (
                "YES"
                if mac_count == 0 and arp_count == 0
                else "NO"
            )

            results.append({
                "Device": hostname,
                "VLAN": vlan_id,
                "VLAN_Name": vlan_info["name"],
                "SVI_IP": svi_ip,
                "SVI_MAC": svi_mac,
                "SVI_MAC_Company": svi_company,
                "SVI_Description": svi_description,
                "MAC_Count": mac_info["MAC_Count"],
                "ARP_Count": str(arp_count),
                "Traffic_Check": traffic_check,
                "Traffic_Ports": traffic_ports,
                "Traffic_Statistics": traffic_statistics,
                "MAC_Address": mac_info["MAC_Address"],
                "MAC_Company": mac_info["MAC_Company"],
                "ARP_Check": arp_check,
                "ARP_Missing_MACs": arp_missing_macs,
                "Root_Bridge": "YES" if is_root else "NO",
                "Shutdown_Recommendation": shutdown_recommendation,
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
        "SVI_MAC",
        "SVI_MAC_Company",
        "SVI_Description",
        "MAC_Count",
        "ARP_Count",
        "Traffic_Check",
        "Traffic_Ports",
        "Traffic_Statistics",
        "MAC_Address",
        "MAC_Company",
        "ARP_Check",
        "ARP_Missing_MACs",
        "Root_Bridge",
        "Shutdown_Recommendation",
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def deduplicate_results(results):
    """Keep only one report row per switch and numeric VLAN ID."""
    unique_results = {}

    for row in results:
        vlan_id = str(int(row["VLAN"]))
        row["VLAN"] = vlan_id
        result_key = (row["Device"], vlan_id)
        if result_key not in unique_results:
            unique_results[result_key] = row

    return list(unique_results.values())


def display_results(results, max_mac_count, max_arp_count):
    print("\n" + "=" * 240)
    print(
        "VLAN / SVI / MAC / ARP / OID / COMPANY / "
        "SPANNING TREE ROOT REPORT "
        f"(MAC MAX {max_mac_count}, ARP MAX {max_arp_count})"
    )
    print("=" * 240)

    current_device = ""
    displayed_vlans = set()

    for row in results:
        vlan_id = str(int(row["VLAN"]))
        display_key = (row["Device"], vlan_id)
        if display_key in displayed_vlans:
            continue
        displayed_vlans.add(display_key)
        if row["Device"] != current_device:
            current_device = row["Device"]
            print(f"\nSwitch: {current_device}")
            print("-" * 240)
            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<20}"
                f"{'SVI IP':<20}"
                f"{'SVI MAC':<20}"
                f"{'MACs':<6}"
                f"{'ARPs':<6}"
                f"{'Traffic':<18}"
                f"{'Traffic Stats':<42}"
                f"{'MAC Address':<24}"
                f"{'Company':<32}"
                f"{'ARP Check':<16}"
                f"{'Root':<8}"
                f"{'Shutdown':<10}"
            )
            print("-" * 240)

        print(
            f"{row['VLAN']:<8}"
            f"{row['VLAN_Name']:<20}"
            f"{row['SVI_IP']:<20}"
            f"{row['SVI_MAC']:<20}"
            f"{row['MAC_Count']:<6}"
            f"{row['ARP_Count']:<6}"
            f"{row['Traffic_Check']:<18}"
            f"{row['Traffic_Statistics']:<42}"
            f"{row['MAC_Address']:<24}"
            f"{row['MAC_Company']:<32}"
            f"{row['ARP_Check']:<16}"
            f"{row['Root_Bridge']:<8}"
            f"{row['Shutdown_Recommendation']:<10}"
        )
        if row["SVI_MAC"]:
            print(f"{'':<8}{'SVI MAC: ' + row['SVI_MAC']}")
        if row["SVI_MAC_Company"]:
            print(f"{'':<8}{'SVI MAC Company: ' + row['SVI_MAC_Company']}")
        if row["Traffic_Ports"]:
            print(f"{'':<8}{'Traffic ports checked: ' + row['Traffic_Ports']}")
        if row["Traffic_Statistics"]:
            print(f"{'':<8}{'Traffic statistics: ' + row['Traffic_Statistics']}")
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
        description=(
            "Collect VLAN, SVI, MAC OID, OUI, company, and STP root data "
            "for VLANs meeting maximum MAC and ARP count filters."
        )
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
        "--max-mac-count",
        type=int,
        default=DEFAULT_MAX_MAC_COUNT,
        help=(
            "Only include VLANs with at most this many MAC addresses. "
            f"Default: {DEFAULT_MAX_MAC_COUNT}"
        ),
    )
    parser.add_argument(
        "--max-arp-count",
        type=int,
        default=DEFAULT_MAX_ARP_COUNT,
        help=(
            "Only include VLANs with at most this many distinct ARP entries. "
            f"Default: {DEFAULT_MAX_ARP_COUNT}"
        ),
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

    if args.max_mac_count < 0:
        print("Error: --max-mac-count cannot be negative.")
        return 2

    if args.max_arp_count < 0:
        print("Error: --max-arp-count cannot be negative.")
        return 2

    if args.max_mac_count > 2:
        print("Error: --max-mac-count cannot exceed 2.")
        return 2

    if args.max_arp_count > 2:
        print("Error: --max-arp-count cannot exceed 2.")
        return 2

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
            process_switch(
                device,
                args.mac_oid_base,
                oui_registry,
                args.max_mac_count,
                args.max_arp_count,
            )
        )

    all_results = deduplicate_results(all_results)

    all_results.sort(
        key=lambda row: (
            row["Device"],
            int(row["VLAN"]),
        )
    )

    display_results(
        all_results,
        args.max_mac_count,
        args.max_arp_count,
    )
    write_csv(all_results, args.csv_file)
    print(f"\nCSV report saved to: {args.csv_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
