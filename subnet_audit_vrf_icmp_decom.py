#!/usr/bin/env python3

from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime

import ipaddress
import getpass
import csv
import re
import time

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

PING_COUNT = 5
PING_TIMEOUT = 1


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


def normalize_vrf(value):
    value = (value or "").strip()
    if not value or value.lower() in {"global", "default", "none"}:
        return None
    return value


def build_arp_command(device_type, vrf):
    if vrf:
        if device_type == "cisco_nxos":
            return f"show ip arp vrf {vrf}"
        return f"show ip arp vrf {vrf}"
    if device_type == "cisco_nxos":
        return "show ip arp vrf all"
    return "show ip arp"


def build_route_command(subnet, device_type, vrf):
    network = ipaddress.ip_network(subnet, strict=False)
    target = network.network_address
    if vrf:
        return f"show ip route vrf {vrf} {target}"
    if device_type == "cisco_nxos":
        return f"show ip route vrf all {target}"
    return f"show ip route {target}"


def build_ping_command(target, device_type, vrf):
    if device_type == "cisco_nxos":
        command = f"ping {target} count {PING_COUNT} timeout {PING_TIMEOUT}"
        if vrf:
            command += f" vrf {vrf}"
        return command

    prefix = f"ping vrf {vrf} " if vrf else "ping "
    return f"{prefix}{target} repeat {PING_COUNT} timeout {PING_TIMEOUT}"


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


def get_arp_ips(arp_output, subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    unique_ips = []
    for line in arp_output.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not match:
            continue
        try:
            ip = ipaddress.ip_address(match.group(1))
            if ip in network and str(ip) not in unique_ips:
                unique_ips.append(str(ip))
        except Exception:
            pass
    return unique_ips


def subnet_fields(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    return (
        str(network.network_address),
        str(network.prefixlen),
        str(network.netmask),
    )


def get_utilization(subnet, arp_count):
    network = ipaddress.ip_network(subnet, strict=False)
    usable_hosts = max(network.num_addresses - 2, 1)
    return round((arp_count / usable_hosts) * 100, 2)


def choose_ping_target(subnet, arp_ips, next_hop):
    network = ipaddress.ip_network(subnet, strict=False)
    for ip in arp_ips:
        address = ipaddress.ip_address(ip)
        if address not in {network.network_address, network.broadcast_address}:
            return ip
    if next_hop:
        try:
            if ipaddress.ip_address(next_hop) in network:
                return next_hop
        except ValueError:
            pass
    hosts = list(network.hosts())
    return str(hosts[0]) if hosts else str(network.network_address)


def parse_ping_output(output):
    text = output.lower()

    match = re.search(r"success rate is\s+(\d+)\s*percent", text)
    if match:
        rate = int(match.group(1))
        return rate, ping_status(rate)

    match = re.search(
        r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets )?received",
        text,
    )
    if match:
        sent = int(match.group(1))
        received = int(match.group(2))
        rate = round((received / sent) * 100) if sent else 0
        return rate, ping_status(rate)

    match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss", text)
    if match:
        loss = float(match.group(1))
        rate = int(round(100 - loss))
        return rate, ping_status(rate)

    if "bytes from" in text or "reply from" in text:
        return 100, "REACHABLE"

    return 0, "PING_PARSE_ERROR"


def ping_status(rate):
    if rate == 100:
        return "REACHABLE"
    if rate > 0:
        return "PARTIAL"
    return "UNREACHABLE"


def get_route_info(conn, host, subnet, device_type, vrf):
    command = build_route_command(subnet, device_type, vrf)
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


def classify_decom_candidate(route_present, null_route, arp_count, reachability):
    if null_route:
        return "NO", "Intentional null/discard route"
    if route_present and reachability == "REACHABLE":
        return "NO", "Route present and endpoint reachable"
    if route_present and reachability in {"PARTIAL"}:
        return "REVIEW", "Route present with partial reachability"
    if route_present and arp_count > 0:
        return "REVIEW", "Route and ARP present but no ICMP reply"
    if route_present and arp_count == 0:
        return "REVIEW", "Route present but no ARP or ICMP activity"
    if not route_present and arp_count > 0:
        return "REVIEW", "ARP entries found but route not detected"
    return "YES", "No route, no ARP, and no reachability"


def process_device(host, username, password, subnets, vrf):
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

        print(f"[{host}] Connected ({device_type}) VRF={vrf or 'GLOBAL'}")

        try:
            send_command(conn, host, "terminal length 0")
        except Exception:
            pass

        arp_output = send_command(conn, host, build_arp_command(device_type, vrf))
        vlan_output = send_command(conn, host, "show vlan brief")
        vlan_db = build_vlan_db(vlan_output)

        for index, subnet in enumerate(subnets, start=1):
            print(f"[{host}] Subnet {index}/{len(subnets)} {subnet}")

            route = get_route_info(conn, host, subnet, device_type, vrf)
            vlan_id, vlan_name = get_vlan_info(route["interface"], vlan_db)
            arp_ips = get_arp_ips(arp_output, subnet)
            arp_count = len(arp_ips)
            utilization = get_utilization(subnet, arp_count)
            network_address, prefix_length, subnet_mask = subnet_fields(subnet)

            ping_target = ""
            success_rate = 0
            reachability = "NOT_TESTED"

            if route["null_route"]:
                reachability = "NULL_ROUTE"
            elif route["route_present"]:
                ping_target = choose_ping_target(subnet, arp_ips, route["next_hop"])
                try:
                    ping_output = send_command(
                        conn,
                        host,
                        build_ping_command(ping_target, device_type, vrf),
                    )
                    success_rate, reachability = parse_ping_output(ping_output)
                except Exception as ping_exc:
                    reachability = "PING_ERROR"
                    print(f"[{host}] Ping error {ping_target}: {ping_exc}")
            elif arp_count > 0:
                reachability = "ARP_ONLY"
            else:
                reachability = "NO_ROUTE"

            decom_candidate, decom_reason = classify_decom_candidate(
                route["route_present"],
                route["null_route"],
                arp_count,
                reachability,
            )

            results.append([
                subnet,
                network_address,
                prefix_length,
                subnet_mask,
                host,
                device_type,
                vrf or "GLOBAL",
                "YES" if route["route_present"] else "NO",
                route["route_type"],
                route["interface"],
                vlan_id,
                vlan_name,
                route["next_hop"],
                arp_count,
                utilization,
                ping_target,
                success_rate,
                reachability,
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
    vrf = normalize_vrf(input("VRF (blank for global): "))
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
    print("Subnet Audit Tool (VRF-aware + ICMP reachability)")
    print("=" * 60)
    print(f"Devices: {len(hosts)}")
    print(f"VRF: {vrf or 'GLOBAL'}")
    print(f"Subnet Range: {start_net} -> {end_net}")
    print(f"Total Subnets: {len(subnets)}")

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(hosts))) as pool:
        futures = [
            pool.submit(process_device, host, username, password, subnets, vrf)
            for host in hosts
        ]
        for future in futures:
            results.extend(future.result())

    results.sort(key=lambda row: (row[4], row[0]))

    with open(REPORT_FILE, "w", newline="", encoding="utf-8") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow([
            "IP Subnet",
            "Network Address",
            "Prefix Length",
            "Subnet Mask",
            "Device",
            "Device Type",
            "VRF",
            "Route Present",
            "Route Type",
            "Interface",
            "VLAN ID",
            "VLAN Name",
            "Next Hop",
            "# ARPs",
            "ARP Utilization %",
            "Ping Target",
            "ICMP Success %",
            "Reachability",
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
