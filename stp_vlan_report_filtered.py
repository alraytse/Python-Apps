#!/usr/bin/env python3

import csv
import getpass
import re

from netmiko import ConnectHandler

CSV_FILE = "stp_vlan_report.csv"
MAX_MAC_ADDRESSES = 3
IFNAME_OID_BASE = "1.3.6.1.2.1.31.1.1.1.1"
MAC_PATTERN = re.compile(
    r"(?i)(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|"
    r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"
)


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


def get_svi_snmp_oid(connection, vlan):
    """Return the IF-MIB ifName OID for the SVI, or an empty string."""
    try:
        output = connection.send_command(
            "show interface snmp-ifindex",
            read_timeout=30,
        )

        svi_name = f"vlan{vlan}".lower()

        for line in output.splitlines():
            fields = line.split()

            if len(fields) < 2:
                continue

            if fields[0].lower() == svi_name and fields[-1].isdigit():
                if_index = fields[-1]
                return f"{IFNAME_OID_BASE}.{if_index}"

    except Exception as e:
        print(f"Unable to get SNMP OID for VLAN {vlan}: {e}")

    return ""


def get_mac_count(connection, vlan):
    try:
        output = connection.send_command(
            f"show mac address-table vlan {vlan}",
            read_timeout=30,
        )

        mac_addresses = {
            mac.lower()
            for mac in MAC_PATTERN.findall(output)
        }

        return len(mac_addresses)

    except Exception as e:
        print(f"Unable to count MAC addresses for VLAN {vlan}: {e}")
        return None


def get_hostname(connection):
    prompt = connection.find_prompt()
    return prompt.replace("#", "").replace(">", "").strip()


def process_switch(device):
    results = []
    conn = None

    try:
        print(f"\nConnecting to {device['host']}...")

        conn = ConnectHandler(**device)
        hostname = get_hostname(conn)

        vlan_output = conn.send_command(
            "show vlan brief",
            read_timeout=30,
        )

        vlans = parse_vlans(vlan_output)
        print(f"{hostname}: Found {len(vlans)} VLANs")

        for vlan_info in vlans:
            vlan_id = vlan_info["vlan"]
            vlan_name = vlan_info["name"]
            mac_count = get_mac_count(conn, vlan_id)

            if mac_count is None or mac_count > MAX_MAC_ADDRESSES:
                continue

            is_root = check_root(conn, vlan_id)
            svi_description, svi_ip = get_svi_info(conn, vlan_id)
            svi_oid = get_svi_snmp_oid(conn, vlan_id)

            results.append({
                "Device": hostname,
                "VLAN": vlan_id,
                "VLAN_Name": vlan_name,
                "MAC_Count": mac_count,
                "SVI_IP": svi_ip,
                "SVI_Description": svi_description,
                "OID": svi_oid,
                "Root_Bridge": "YES" if is_root else "NO",
            })

    except Exception as e:
        print(f"Failed to connect to {device['host']} : {e}")

    finally:
        if conn:
            conn.disconnect()

    return results


def write_csv(results):
    fields = [
        "Device",
        "VLAN",
        "VLAN_Name",
        "MAC_Count",
        "SVI_IP",
        "SVI_Description",
        "OID",
        "Root_Bridge",
    ]

    with open(CSV_FILE, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def display_results(results):
    print("\n" + "=" * 220)
    print("VLAN / SVI REPORT - VLANS WITH 3 OR FEWER LEARNED MAC ADDRESSES")
    print("=" * 220)

    current_device = ""

    for row in results:
        if row["Device"] != current_device:
            current_device = row["Device"]

            print(f"\nSwitch: {current_device}")
            print("-" * 220)
            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<30}"
                f"{'MACs':<8}"
                f"{'SVI IP':<25}"
                f"{'SVI Description':<75}"
                f"{'OID':<35}"
                f"{'Root':<10}"
            )
            print("-" * 220)

        print(
            f"{row['VLAN']:<8}"
            f"{row['VLAN_Name']:<30}"
            f"{row['MAC_Count']:<8}"
            f"{row['SVI_IP']:<25}"
            f"{row['SVI_Description']:<75}"
            f"{row['OID']:<35}"
            f"{row['Root_Bridge']:<10}"
        )

    root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "YES"
    )

    print("\n" + "=" * 220)
    print(f"Total VLANs/SVIs Displayed : {len(results)}")
    print(f"MAC address threshold      : {MAX_MAC_ADDRESSES} or fewer")
    print(f"SNMP OID                   : IF-MIB::ifName.<ifIndex>")
    print(f"Total Root VLANs            : {root_count}")
    print("=" * 220)


def main():
    hosts = input(
        "Enter switch hostnames/IPs (comma delimited): "
    ).strip()

    host_list = [
        host.strip()
        for host in hosts.split(",")
        if host.strip()
    ]

    username = input("Username: ")
    password = getpass.getpass("Password: ")

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
    write_csv(all_results)

    print(f"\nCSV report saved to: {CSV_FILE}")


if __name__ == "__main__":
    main()
