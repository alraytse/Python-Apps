#!/usr/bin/env python3

import getpass
import csv
import re
from netmiko import ConnectHandler

CSV_FILE = "stp_vlan_report.csv"


def parse_vlans(output):

    vlans = []

    for line in output.splitlines():

        match = re.match(r"^(\d+)\s+(\S+)", line.strip())

        if match:

            vlans.append({
                "vlan": match.group(1),
                "name": match.group(2)
            })

    return vlans


def check_root(connection, vlan):

    try:

        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30
        )

        return "This bridge is the root" in output

    except Exception:

        return False


def get_svi_info(connection, vlan):

    try:

        output = connection.send_command(
            f"show run interface vlan {vlan}",
            read_timeout=30
        )

        description = ""
        ip_address = ""

        for line in output.splitlines():

            line = line.strip()

            if line.startswith("description "):
                description = line.replace(
                    "description ",
                    ""
                )

            elif line.startswith("ip address "):
                ip_address = line.replace(
                    "ip address ",
                    ""
                )

        return description, ip_address

    except Exception:

        return "", ""


def get_hostname(connection):

    prompt = connection.find_prompt()

    return prompt.replace("#", "").replace(">", "")


def process_switch(device):

    results = []

    try:

        print(f"\nConnecting to {device['host']}...")

        conn = ConnectHandler(**device)

        hostname = get_hostname(conn)

        vlan_output = conn.send_command(
            "show vlan brief",
            read_timeout=30
        )

        vlans = parse_vlans(vlan_output)

        print(
            f"{hostname}: Found {len(vlans)} VLANs"
        )

        for vlan_info in vlans:

            vlan_id = vlan_info["vlan"]
            vlan_name = vlan_info["name"]

            is_root = check_root(
                conn,
                vlan_id
            )

            svi_description, svi_ip = get_svi_info(
                conn,
                vlan_id
            )

            results.append({
                "Device": hostname,
                "VLAN": vlan_id,
                "VLAN_Name": vlan_name,
                "SVI_IP": svi_ip,
                "SVI_Description": svi_description,
                "Root_Bridge": (
                    "YES"
                    if is_root
                    else "NO"
                )
            })

        conn.disconnect()

    except Exception as e:

        print(
            f"Failed to connect to "
            f"{device['host']} : {e}"
        )

    return results


def write_csv(results):

    with open(
        CSV_FILE,
        "w",
        newline=""
    ) as csvfile:

        fields = [
            "Device",
            "VLAN",
            "VLAN_Name",
            "SVI_IP",
            "SVI_Description",
            "Root_Bridge"
        ]

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fields
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)


def display_results(results):

    print("\n" + "=" * 180)
    print("VLAN / SVI / SPANNING TREE ROOT REPORT")
    print("=" * 180)

    current_device = ""

    for row in results:

        if row["Device"] != current_device:

            current_device = row["Device"]

            print(
                f"\nSwitch: "
                f"{current_device}"
            )

            print("-" * 180)

            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<30}"
                f"{'SVI IP':<25}"
                f"{'SVI Description':<90}"
                f"{'Root':<10}"
            )

            print("-" * 180)

        print(
            f"{row['VLAN']:<8}"
            f"{row['VLAN_Name']:<30}"
            f"{row['SVI_IP']:<25}"
            f"{row['SVI_Description']:<90}"
            f"{row['Root_Bridge']:<10}"
        )

    root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "YES"
    )

    print("\n" + "=" * 180)
    print(
        f"Total VLANs Processed : "
        f"{len(results)}"
    )

    print(
        f"Total Root VLANs      : "
        f"{root_count}"
    )

    print("=" * 180)


def main():

    hosts = input(
        "Enter switch hostnames/IPs "
        "(comma delimited): "
    ).strip()

    host_list = [
        h.strip()
        for h in hosts.split(",")
        if h.strip()
    ]

    username = input(
        "Username: "
    )

    password = getpass.getpass(
        "Password: "
    )

    all_results = []

    for host in host_list:

        device = {
            "device_type": "cisco_nxos",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False
        }

        results = process_switch(
            device
        )

        all_results.extend(
            results
        )

    all_results = sorted(
        all_results,
        key=lambda x: (
            x["Device"],
            int(x["VLAN"])
        )
    )

    display_results(
        all_results
    )

    write_csv(
        all_results
    )

    print(
        f"\nCSV report saved to: "
        f"{CSV_FILE}"
    )


if __name__ == "__main__":
    main()