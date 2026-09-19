#!/usr/bin/env python3

from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime

import ipaddress
import getpass
import csv
import re

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

REPORT_FILE = f"subnet_report_{TIMESTAMP}.csv"
AUDIT_FILE = f"command_audit_{TIMESTAMP}.csv"
FAILED_FILE = f"failed_devices_{TIMESTAMP}.csv"

COMMAND_LOG = []
FAILED_DEVICES = []
COMMAND_LOCK = Lock()
FAILED_LOCK = Lock()

DEVICE_TYPES = [
    "cisco_nxos",
    "cisco_xe",
    "cisco_ios",
    "arista_eos",
]


def detect_device_type(host, username, password):
    print(f"[{host}] Detecting platform...")

    for device_type in DEVICE_TYPES:
        conn = None
        try:
            conn = ConnectHandler(
                device_type=device_type,
                host=host,
                username=username,
                password=password,
                fast_cli=False,
                banner_timeout=60,
                auth_timeout=60,
                conn_timeout=30,
            )
            print(f"[{host}] Platform detected: {device_type}")
            return device_type
        except Exception:
            pass
        finally:
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass

    raise Exception("Unable to determine device type")


def send_command(conn, host, command):
    with COMMAND_LOCK:
        COMMAND_LOG.append([host, command])

    print(f"[{host}] Executing: {command}")
    return conn.send_command(command, read_timeout=120)


def build_vlan_db(output):
    vlan_db = {}
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)", line)
        if match:
            vlan_db[f"Vlan{match.group(1)}"] = match.group(2)
    return vlan_db


def get_vlan_info(interface_name, vlan_db):
    interface_name = interface_name or ""
    match = re.search(r"Vlan(\d+)", interface_name, re.IGNORECASE)
    if not match:
        match = re.search(r"\.(\d+)$", interface_name)
    if not match:
        return "", ""

    vlan_id = match.group(1)
    return vlan_id, vlan_db.get(f"Vlan{vlan_id}", "")


def get_arp_count(arp_output, subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    unique_ips = set()

    for line in arp_output.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not match:
            continue
        try:
            ip = ipaddress.ip_address(match.group(1))
            if ip in network:
                unique_ips.add(str(ip))
        except Exception:
            pass

    return len(unique_ips)


def get_utilization(subnet, arp_count):
    network = ipaddress.ip_network(subnet, strict=False)
    usable_hosts = max(network.num_addresses - 2, 1)
    return round((arp_count / usable_hosts) * 100, 2)


def classify_decom_candidate(route_present, arp_count):
    if not route_present and arp_count == 0:
        return "YES", "No route and no ARP entries"
    if not route_present and arp_count > 0:
        return "REVIEW", "ARP entries found but route not detected"
    return "NO", "Route present"


def get_route_info(conn, host, subnet, device_type):
    network = ipaddress.ip_network(subnet, strict=False)

    if device_type == "cisco_nxos":
        command = f"show ip route vrf all {network.network_address}"
    else:
        command = f"show ip route {network.network_address}"

    output = send_command(conn, host, command)
    lower = output.lower()

    null_route = bool(re.search(
        r"\bnull0\b|\bdiscard\b|\bblackhole\b|\breject\b",
        lower,
    ))

    not_found_markers = [
        "network not in table",
        "subnet not in table",
        "route not found",
        "no route",
        "% invalid",
        "not found in routing table",
    ]

    route_not_found = any(marker in lower for marker in not_found_markers)
    route_present = not route_not_found and bool(re.search(
        r"routing entry for|is directly connected|directly connected|"
        r"via\s+\d+\.\d+\.\d+\.\d+|known via",
        output,
        re.IGNORECASE,
    ))

    if null_route:
        route_type = "Null Route"
    elif not route_present:
        route_type = "No Route"
    else:
        route_type = "Unknown"
        protocol_map = [
            (r"is directly connected|directly connected|\bconnected\b", "Connected"),
            (r"\bbgp\b", "BGP"),
            (r"\bospf\b", "OSPF"),
            (r"\beigrp\b", "EIGRP"),
            (r"\bisis\b", "ISIS"),
            (r"\bstatic\b", "Static"),
        ]
        for pattern, protocol in protocol_map:
            if re.search(pattern, output, re.IGNORECASE):
                route_type = protocol
                break

    next_hop = ""
    match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output, re.IGNORECASE)
    if match:
        next_hop = match.group(1)

    interface = ""
    interface_patterns = [
        r"(Vlan\d+)",
        r"(Loopback\d+)",
        r"(Port-channel\d+)",
        r"(Port-Channel\d+)",
        r"(Po\d+)",
        r"(GigabitEthernet\S+)",
        r"(TenGigabitEthernet\S+)",
        r"(TwentyFiveGigE\S+)",
        r"(FortyGigE\S+)",
        r"(HundredGigE\S+)",
        r"(TenGigE\S+)",
        r"(Ethernet\S+)",
        r"(Eth\S+)",
    ]

    for pattern in interface_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            interface = match.group(1)
            break

    return {
        "route_present": route_present,
        "null_route": null_route,
        "route_type": route_type,
        "interface": interface,
        "next_hop": next_hop,
    }


def process_device(host, username, password, subnets):
    results = []
    conn = None

    try:
        print(f"[{host}] Connecting...")
        device_type = detect_device_type(host, username, password)

        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            fast_cli=False,
            banner_timeout=60,
            auth_timeout=60,
            conn_timeout=30,
        )

        print(f"[{host}] Connected ({device_type})")

        try:
            send_command(conn, host, "terminal length 0")
        except Exception:
            pass

        arp_command = (
            "show ip arp vrf all"
            if device_type == "cisco_nxos"
            else "show ip arp"
        )
        arp_output = send_command(conn, host, arp_command)
        vlan_output = send_command(conn, host, "show vlan brief")
        vlan_db = build_vlan_db(vlan_output)

        for index, subnet in enumerate(subnets, start=1):
            print(f"[{host}] Subnet {index}/{len(subnets)} {subnet}")

            route = get_route_info(conn, host, subnet, device_type)
            vlan_id, vlan_name = get_vlan_info(route["interface"], vlan_db)
            arp_count = get_arp_count(arp_output, subnet)
            utilization = get_utilization(subnet, arp_count)

            if route["null_route"]:
                decom_candidate = "NO"
                decom_reason = "Intentional null/discard route"
            else:
                decom_candidate, decom_reason = classify_decom_candidate(
                    route["route_present"],
                    arp_count,
                )

            results.append([
                subnet,
                host,
                device_type,
                "YES" if route["route_present"] else "NO",
                route["route_type"],
                route["interface"],
                vlan_id,
                vlan_name,
                route["next_hop"],
                arp_count,
                utilization,
                "YES" if route["null_route"] else "NO",
                decom_candidate,
                decom_reason,
            ])

        print(f"[{host}] Finished {len(subnets)} subnets")

    except Exception as exc:
        print(f"[{host}] FAILED: {exc}")
        with FAILED_LOCK:
            FAILED_DEVICES.append([host, str(exc)])

    finally:
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass

    return results


def main():
    start_time = datetime.now()

    hosts = [
        host.strip()
        for host in input("Hosts (comma delimited): ").split(",")
        if host.strip()
    ]
    if not hosts:
        print("No hosts provided. Exiting.")
        return

    start = input("Starting subnet: ").strip()
    end = input("Ending subnet: ").strip()
    mask = input("Mask Length: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    start_net = ipaddress.ip_network(f"{start}/{mask}", strict=False)
    end_net = ipaddress.ip_network(f"{end}/{mask}", strict=False)

    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError("Starting and ending subnets must use the same mask")
    if end_net.network_address < start_net.network_address:
        raise ValueError("Ending subnet must be greater than or equal to starting subnet")

    subnets = []
    current = start_net.network_address
    while current <= end_net.network_address:
        network = ipaddress.ip_network(f"{current}/{mask}", strict=False)
        subnets.append(str(network))
        current += network.num_addresses

    print("\n" + "=" * 60)
    print("Subnet Audit Tool")
    print("=" * 60)
    print(f"Devices: {len(hosts)}")
    print(f"Subnet Range: {start_net} -> {end_net}")
    print(f"Total Subnets: {len(subnets)}")

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as pool:
        futures = [
            pool.submit(process_device, host, username, password, subnets)
            for host in hosts
        ]
        for future in futures:
            results.extend(future.result())

    results.sort(key=lambda row: (row[1], row[0]))

    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP Subnet",
            "Device",
            "Device Type",
            "Route Present",
            "Route Type",
            "Interface",
            "VLAN ID",
            "VLAN Name",
            "Next Hop",
            "# ARPs",
            "ARP Utilization %",
            "Null Route",
            "Decom Candidate",
            "Decom Reason",
        ])
        writer.writerows(results)

    with open(AUDIT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["Device", "Command"])
        writer.writerows(COMMAND_LOG)

    with open(FAILED_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["Device", "Error"])
        writer.writerows(FAILED_DEVICES)

    runtime = datetime.now() - start_time
    print("\n" + "=" * 60)
    print("Processing Complete")
    print("=" * 60)
    print(f"Records Generated : {len(results)}")
    print(f"Failed Devices    : {len(FAILED_DEVICES)}")
    print(f"Runtime           : {runtime}")
    print("\nGenerated Files:")
    print(f"  {REPORT_FILE}")
    print(f"  {AUDIT_FILE}")
    print(f"  {FAILED_FILE}")


if __name__ == "__main__":
    main()
