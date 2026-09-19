#!/usr/bin/env python3

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
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
DEFAULT_WORKERS = 5
TRAFFIC_NOT_CONFIRMED = {
    "TRAFFIC_UNAVAILABLE",
    "NOT_CHECKED",
    "NO_ACCESS_PORTS",
}

P2P_DEPENDENCY_KEYWORDS = (
    "p2p",
    "point-to-point",
    "point to point",
    "transit",
    "router",
    "rtr",
    "firewall",
    "fw",
    "wan",
    "edge",
    "upstream",
    "downstream",
    "peer",
    "mpls",
    "outside",
    "inside",
)

SVI_DEPENDENCY_PATTERNS = (
    (r"\bhsrp\b", "HSRP configured"),
    (r"\bvrrp\b", "VRRP configured"),
    (r"\bglbp\b", "GLBP configured"),
    (r"^ip helper-address\b", "DHCP helper configured"),
    (r"^ip dhcp relay\b", "DHCP relay configured"),
    (r"^ip pim\b", "Multicast PIM configured"),
    (r"^ip igmp\b", "IGMP configured"),
    (r"^ip route\b", "Route configured under SVI"),
    (r"^ipv6 address\b", "IPv6 address configured"),
    (r"^vrf member\b", "VRF membership configured"),
    (r"^fabric forwarding\b", "Fabric forwarding configured"),
    (r"^service-policy\b", "Service policy configured"),
)


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
        return "NO_ACCESS_PORTS", ""

    checked_ports = []
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

    return status, "; ".join(checked_ports)


def check_svi_traffic(connection, vlan):
    """Check recent traffic rates on the VLAN SVI itself."""
    try:
        output = connection.send_command(
            f"show interface vlan {vlan}",
            read_timeout=30,
        )
        input_rate = parse_interface_rate(output, "in")
        output_rate = parse_interface_rate(output, "out")

        if input_rate is None and output_rate is None:
            return "TRAFFIC_UNAVAILABLE", f"Vlan{vlan}"

        if (input_rate or 0) > 0 or (output_rate or 0) > 0:
            return "TRAFFIC_DETECTED", f"Vlan{vlan}"

        return "NO_TRAFFIC", f"Vlan{vlan}"

    except Exception:
        return "TRAFFIC_UNAVAILABLE", f"Vlan{vlan}"


def check_root(connection, vlan):
    try:
        output = connection.send_command(
            f"show spanning-tree vlan {vlan}",
            read_timeout=30,
        )
        return "This bridge is the root" in output, ""
    except Exception as error:
        return False, f"STP root check failed: {error}"


def parse_svi_inventory(output):
    """Parse configured VLAN SVIs and configuration dependencies."""
    inventory = {}
    current_vlan = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = re.match(r"^interface\s+Vlan(\d+)\s*$", line, re.IGNORECASE)

        if match:
            current_vlan = match.group(1)
            inventory[current_vlan] = {
                "description": "",
                "ip_addresses": [],
                "shutdown": False,
                "dependency_lines": [],
            }
            continue

        if current_vlan is None or not line:
            continue

        if line.lower() == "shutdown":
            inventory[current_vlan]["shutdown"] = True
        elif line.lower().startswith("description "):
            inventory[current_vlan]["description"] = line.split(
                " ",
                1,
            )[1].strip()
        elif line.lower().startswith("ip address "):
            inventory[current_vlan]["ip_addresses"].append(line)

        for pattern, label in SVI_DEPENDENCY_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                inventory[current_vlan]["dependency_lines"].append(
                    f"{label}: {line}"
                )

    return inventory


def get_svi_inventory(connection):
    try:
        output = connection.send_command(
            "show running-config | section ^interface Vlan",
            read_timeout=30,
        )
        return parse_svi_inventory(output), ""
    except Exception as error:
        return {}, f"SVI configuration check failed: {error}"


def parse_interface_descriptions(output):
    """Return raw interface-description lines keyed by interface."""
    descriptions = {}
    pattern = re.compile(
        r"^\s*((?:Eth(?:ernet)?|Po(?:rt-channel)?|"
        r"port-channel|sup-eth|mgmt)\S*)\s+(.+)$",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            descriptions[match.group(1)] = line.strip()

    return descriptions


def get_interface_descriptions(connection):
    try:
        output = connection.send_command(
            "show interface description",
            read_timeout=30,
        )
        return parse_interface_descriptions(output), ""
    except Exception as error:
        return {}, f"Interface description check failed: {error}"


def vlan_in_list(vlan, value):
    """Return whether a VLAN appears in a comma/range VLAN list."""
    target = int(vlan)

    for token in re.findall(r"\d+(?:\s*-\s*\d+)?", value):
        if "-" in token:
            start, end = [int(part.strip()) for part in token.split("-")]
            if start <= target <= end:
                return True
        elif int(token) == target:
            return True

    return False


def parse_trunk_dependencies(output, vlan):
    """Find trunk interfaces whose displayed VLAN list contains vlan."""
    dependencies = []
    in_allowed_section = False
    port_pattern = re.compile(
        r"^\s*((?:Eth(?:ernet)?|Po(?:rt-channel)?|"
        r"port-channel)\S*)\s+(.+)$",
        re.IGNORECASE,
    )

    for raw_line in output.splitlines():
        line = raw_line.strip()
        lower_line = line.lower()

        if "vlans allowed on trunk" in lower_line:
            in_allowed_section = True
            continue

        if in_allowed_section and (
            "vlans allowed and active" in lower_line
            or "vlans in spanning tree forwarding state" in lower_line
        ):
            in_allowed_section = False

        if not in_allowed_section:
            continue

        match = port_pattern.match(line)
        if match and vlan_in_list(vlan, match.group(2)):
            dependencies.append(match.group(1))

    return list(dict.fromkeys(dependencies))


def get_trunk_output(connection):
    try:
        return connection.send_command(
            "show interface trunk",
            read_timeout=30,
        ), ""
    except Exception as error:
        return "", f"Trunk dependency check failed: {error}"


def get_dependency_context(connection):
    svi_inventory, svi_error = get_svi_inventory(connection)
    interface_descriptions, description_error = (
        get_interface_descriptions(connection)
    )
    trunk_output, trunk_error = get_trunk_output(connection)

    return {
        "svi_inventory": svi_inventory,
        "interface_descriptions": interface_descriptions,
        "trunk_output": trunk_output,
        "errors": [
            error
            for error in (svi_error, description_error, trunk_error)
            if error
        ],
    }


def get_svi_oper_state(connection, vlan):
    """Return SVI operational state from show interface vlan output."""
    try:
        output = connection.send_command(
            f"show interface vlan {vlan}",
            read_timeout=30,
        )
        first_line = next(
            (line.strip() for line in output.splitlines() if line.strip()),
            "",
        )
        lower_output = output.lower()
        admin_down = "administratively down" in lower_output
        interface_up = bool(
            re.search(r"\bvlan\d+\s+is\s+up\b", first_line, re.IGNORECASE)
        )
        protocol_up = "line protocol is up" in first_line.lower()

        if admin_down:
            state = "ADMINISTRATIVELY_DOWN"
        elif interface_up and protocol_up:
            state = "UP/UP"
        elif interface_up:
            state = "UP/PROTOCOL_DOWN"
        else:
            state = "DOWN"

        return {
            "state": state,
            "admin_down": admin_down,
            "interface_up": interface_up,
            "protocol_up": protocol_up,
        }, ""
    except Exception as error:
        return {
            "state": "UNAVAILABLE",
            "admin_down": False,
            "interface_up": False,
            "protocol_up": False,
        }, f"SVI operational-state check failed: {error}"


def get_vlan_member_ports(connection, vlan):
    """Return access/trunk interface names listed for a VLAN."""
    try:
        output = connection.send_command(
            f"show vlan id {vlan}",
            read_timeout=30,
        )
        pattern = re.compile(
            r"\b((?:Eth(?:ernet)?|Po(?:rt-channel)?|"
            r"port-channel|sup-eth|mgmt)\S*)\b",
            re.IGNORECASE,
        )
        ports = [match.group(1) for match in pattern.finditer(output)]
        return list(dict.fromkeys(ports)), ""
    except Exception as error:
        return [], f"VLAN member-port check failed: {error}"


def get_vlan_dependency_reasons(
    vlan,
    vlan_ids,
    svi_inventory,
    interface_descriptions,
    trunk_output,
    vlan_member_ports,
):
    """Return safety dependencies detected for a VLAN."""
    vlan = str(vlan)
    reasons = []
    svi = svi_inventory.get(vlan)

    if svi is not None:
        reasons.extend(svi["dependency_lines"])
        svi_text = " ".join(
            [svi["description"]] + svi["ip_addresses"]
        ).lower()

        if any(keyword in svi_text for keyword in P2P_DEPENDENCY_KEYWORDS):
            if "firewall" in svi_text or " fw" in f" {svi_text}":
                reasons.append("Router-to-firewall/P2P indicator in SVI configuration")
            else:
                reasons.append("Router-to-router/P2P indicator in SVI configuration")

        if re.search(r"/(30|31)\b", svi_text):
            reasons.append("Routed point-to-point subnet (/30 or /31)")

    trunk_ports = parse_trunk_dependencies(trunk_output, vlan)
    if trunk_ports:
        reasons.append(
            "VLAN allowed on trunk(s): " + ", ".join(trunk_ports)
        )

    for interface in vlan_member_ports:
        description = interface_descriptions.get(interface, "")
        lower_description = description.lower()
        if any(keyword in lower_description for keyword in P2P_DEPENDENCY_KEYWORDS):
            reasons.append(
                f"P2P/router/firewall indicator on {interface}: {description}"
            )

    return list(dict.fromkeys(reasons))


def get_shutdown_recommendation(
    mac_count,
    arp_count,
    traffic_check,
    svi_present,
    is_root,
    dependency_reasons=None,
    dependency_checks_complete=True,
):
    """Return recommendation strength and supporting reason.

    HIGHLY_RECOMMENDED requires every safety condition to be true:
      - zero dynamic MAC addresses
      - zero ARP entries
      - no SVI configured for the VLAN
      - no traffic
      - no trunk or P2P dependency
      - confirmed non-root status
    """
    dependency_reasons = dependency_reasons or []

    if is_root:
        return (
            "NONE",
            "STP root bridge; do not recommend shutdown without topology review",
        )

    if dependency_reasons:
        return (
            "MODERATE",
            "Dependency requires review before shutdown: "
            + " | ".join(dependency_reasons),
        )

    if not dependency_checks_complete:
        return (
            "MODERATE",
            "Dependency checks incomplete; safe shutdown cannot be confirmed",
        )

    if mac_count == 0 and arp_count == 0:
        if not svi_present and traffic_check == "NO_SVI":
            return (
                "HIGHLY_RECOMMENDED",
                "No MACs, no ARPs, no SVI, no traffic, no trunk/P2P dependency, and not STP root",
            )

        if traffic_check == "TRAFFIC_DETECTED":
            return (
                "NONE",
                "Traffic detected despite empty MAC and ARP tables",
            )

        if svi_present:
            return (
                "MODERATE",
                "No MACs or ARPs and no traffic, but an SVI is configured",
            )

        if traffic_check in TRAFFIC_NOT_CONFIRMED:
            return (
                "MODERATE",
                "No MACs or ARPs; traffic could not be confirmed",
            )

        return (
            "MODERATE",
            "No MACs or ARPs; required shutdown conditions were not fully confirmed",
        )

    if mac_count == 0 or arp_count == 0:
        missing_source = "MACs" if mac_count == 0 else "ARP entries"
        return (
            "WEAK",
            f"No {missing_source}; the other endpoint data source still has entries",
        )

    return "NONE", "Active MAC and ARP entries detected"

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
        vlan_ids = {vlan["vlan"] for vlan in vlans}
        dependency_context = get_dependency_context(connection)
        arp_entries, arp_available = get_arp_table(connection)
        print(f"{hostname}: Found {len(vlans)} VLANs")

        orphan_svis = sorted(
            set(dependency_context["svi_inventory"]) - vlan_ids,
            key=int,
        )
        if orphan_svis:
            print(
                f"{hostname}: VLAN/SVI mismatch detected; "
                f"SVIs without VLANs: {', '.join(orphan_svis)}"
            )

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

            if not arp_available:
                print(
                    f"Skipping VLAN {vlan_id} on {hostname}: "
                    "ARP count unavailable; maximum MAC/ARP filter cannot be verified"
                )
                continue

            if (
                mac_count > max_mac_count
                or arp_count > max_arp_count
            ):
                continue

            traffic_check = "NOT_CHECKED"
            traffic_ports = ""

            svi_present = vlan_id in dependency_context["svi_inventory"]
            if mac_count == 0 and arp_count == 0 and not svi_present:
                traffic_check = "NO_SVI"
                traffic_ports = ""
            elif mac_count == 0 and arp_count == 0:
                traffic_check, traffic_ports = check_svi_traffic(
                    connection,
                    vlan_id,
                )
            elif (
                1 <= mac_count <= max_mac_count
                or 1 <= arp_count <= max_arp_count
            ):
                traffic_check, traffic_ports = check_port_traffic(
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
            is_root, root_state_error = check_root(connection, vlan_id)
            if svi_present:
                svi_state, svi_state_error = get_svi_oper_state(
                    connection,
                    vlan_id,
                )
            else:
                svi_state = {
                    "state": "NOT_PRESENT",
                    "admin_down": False,
                    "interface_up": False,
                    "protocol_up": False,
                }
                svi_state_error = ""

            vlan_member_ports, vlan_member_error = get_vlan_member_ports(
                connection,
                vlan_id,
            )
            dependency_reasons = get_vlan_dependency_reasons(
                vlan_id,
                vlan_ids,
                dependency_context["svi_inventory"],
                dependency_context["interface_descriptions"],
                dependency_context["trunk_output"],
                vlan_member_ports,
            )

            if svi_state["interface_up"] or svi_state["protocol_up"]:
                dependency_reasons.append(
                    f"Active SVI associated with VLAN ({svi_state['state']})"
                )

            if root_state_error:
                dependency_reasons.append(root_state_error)

            if svi_state_error:
                dependency_reasons.append(svi_state_error)

            if vlan_member_error:
                dependency_reasons.append(vlan_member_error)

            dependency_check_errors = dependency_context["errors"]
            recommendation_strength, recommendation_reason = (
                get_shutdown_recommendation(
                    mac_count,
                    arp_count,
                    traffic_check,
                    svi_present,
                    is_root,
                    dependency_reasons,
                    not dependency_check_errors
                    and not root_state_error
                    and not svi_state_error
                    and not vlan_member_error,
                )
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
                "MAC_Address": mac_info["MAC_Address"],
                "MAC_Company": mac_info["MAC_Company"],
                "ARP_Check": arp_check,
                "ARP_Missing_MACs": arp_missing_macs,
                "Root_Bridge": "YES" if is_root else "NO",
                "VLAN_SVI_Status": (
                    "SVI_PRESENT"
                    if svi_present
                    else "NO_SVI"
                ),
                "SVI_State": svi_state["state"],
                "Dependency_Check": (
                    "BLOCKED"
                    if dependency_reasons
                    else "CLEAR"
                    if not dependency_check_errors and not svi_state_error
                    else "INCOMPLETE"
                ),
                "Dependency_Details": "; ".join(
                    dependency_reasons + dependency_check_errors
                ),
                "VLAN_Member_Ports": "; ".join(vlan_member_ports),
                "Shutdown_Recommendation": recommendation_strength,
                "Shutdown_Recommendation_Reason": recommendation_reason,
            })

        for orphan_vlan in orphan_svis:
            orphan_svi = dependency_context["svi_inventory"][orphan_vlan]
            results.append({
                "Device": hostname,
                "VLAN": orphan_vlan,
                "VLAN_Name": "<SVI WITHOUT VLAN>",
                "SVI_IP": "; ".join(orphan_svi["ip_addresses"]),
                "SVI_MAC": "",
                "SVI_MAC_Company": "",
                "SVI_Description": orphan_svi["description"],
                "MAC_Count": "",
                "ARP_Count": "",
                "Traffic_Check": "NOT_CHECKED",
                "Traffic_Ports": "",
                "MAC_Address": "",
                "MAC_Company": "",
                "ARP_Check": "NOT_CHECKED",
                "ARP_Missing_MACs": "",
                "Root_Bridge": "UNKNOWN",
                "VLAN_SVI_Status": "MISMATCH",
                "SVI_State": "NOT_CHECKED",
                "Dependency_Check": "BLOCKED",
                "Dependency_Details": "SVI configured but VLAN is absent",
                "VLAN_Member_Ports": "",
                "Shutdown_Recommendation": "NONE",
                "Shutdown_Recommendation_Reason": (
                    "VLAN/SVI mismatch; SVI exists without corresponding VLAN"
                ),
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
        "MAC_Address",
        "MAC_Company",
        "ARP_Check",
        "ARP_Missing_MACs",
        "Root_Bridge",
        "VLAN_SVI_Status",
        "SVI_State",
        "Dependency_Check",
        "Dependency_Details",
        "VLAN_Member_Ports",
        "Shutdown_Recommendation",
        "Shutdown_Recommendation_Reason",
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
    print("\n" + "=" * 270)
    print(
        "VLAN / SVI / MAC / ARP / OID / COMPANY / "
        "SPANNING TREE ROOT REPORT "
        f"(MAC MAX {max_mac_count}, ARP MAX {max_arp_count})"
    )
    print("=" * 270)

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
            print("-" * 270)
            print(
                f"{'VLAN':<8}"
                f"{'VLAN Name':<20}"
                f"{'SVI IP':<20}"
                f"{'SVI MAC':<20}"
                f"{'MACs':<6}"
                f"{'ARPs':<6}"
                f"{'Traffic':<18}"
                f"{'MAC Address':<24}"
                f"{'Company':<32}"
                f"{'ARP Check':<16}"
                f"{'Root':<8}"
                f"{'Shutdown':<12}"
            )
            print("-" * 270)

        print(
            f"{row['VLAN']:<8}"
            f"{row['VLAN_Name']:<20}"
            f"{row['SVI_IP']:<20}"
            f"{row['SVI_MAC']:<20}"
            f"{row['MAC_Count']:<6}"
            f"{row['ARP_Count']:<6}"
            f"{row['Traffic_Check']:<18}"
            f"{row['MAC_Address']:<24}"
            f"{row['MAC_Company']:<32}"
            f"{row['ARP_Check']:<16}"
            f"{row['Root_Bridge']:<8}"
            f"{row['Shutdown_Recommendation']:<12}"
        )
        if row["SVI_MAC"]:
            print(f"{'':<8}{'SVI MAC: ' + row['SVI_MAC']}")
        if row["SVI_MAC_Company"]:
            print(f"{'':<8}{'SVI MAC Company: ' + row['SVI_MAC_Company']}")
        if row["Traffic_Ports"]:
            print(f"{'':<8}{'Traffic ports checked: ' + row['Traffic_Ports']}")
        if row["ARP_Missing_MACs"]:
            print(f"{'':<8}{'MACs missing ARP: ' + row['ARP_Missing_MACs']}")
        if row["SVI_Description"]:
            print(f"{'':<8}{'SVI Description: ' + row['SVI_Description']}")
        if row["VLAN_SVI_Status"]:
            print(
                f"{'':<8}"
                f"VLAN/SVI status: {row['VLAN_SVI_Status']}"
            )
        if row["SVI_State"]:
            print(
                f"{'':<8}"
                f"SVI state: {row['SVI_State']}"
            )
        if row["Dependency_Check"]:
            print(
                f"{'':<8}"
                f"Dependency check: {row['Dependency_Check']}"
            )
        if row["Dependency_Details"]:
            print(
                f"{'':<8}"
                f"Dependencies: {row['Dependency_Details']}"
            )
        if row["VLAN_Member_Ports"]:
            print(
                f"{'':<8}"
                f"VLAN member ports: {row['VLAN_Member_Ports']}"
            )
        if row["Shutdown_Recommendation_Reason"]:
            print(
                f"{'':<8}"
                f"Shutdown recommendation reason: "
                f"{row['Shutdown_Recommendation_Reason']}"
            )

    root_count = sum(
        1
        for row in results
        if row["Root_Bridge"] == "YES"
    )

    recommendation_counts = {
        level: sum(
            1
            for row in results
            if row["Shutdown_Recommendation"] == level
        )
        for level in (
            "HIGHLY_RECOMMENDED",
            "MODERATE",
            "WEAK",
        )
    }

    print("\n" + "=" * 270)
    print(f"Total VLANs Processed : {len(results)}")
    print(f"Total Root VLANs      : {root_count}")
    print(
        "Highly Recommended    : "
        f"{recommendation_counts['HIGHLY_RECOMMENDED']}"
    )
    print(f"Moderate Recommendations: {recommendation_counts['MODERATE']}")
    print(f"Weak Recommendations  : {recommendation_counts['WEAK']}")
    print("=" * 270)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Collect VLAN, SVI, MAC OID, OUI, company, and STP root data "
            "for VLANs at or below both the maximum MAC and ARP counts."
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
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=(
            "Number of switches to process concurrently. "
            f"Default: {DEFAULT_WORKERS}"
        ),
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

    if args.workers < 1:
        print("Error: --workers must be at least 1.")
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

    devices = [
        {
            "device_type": "cisco_nxos",
            "host": host,
            "username": username,
            "password": password,
            "fast_cli": False,
        }
        for host in host_list
    ]

    all_results = []
    if devices:
        worker_count = min(args.workers, len(devices))
        print(
            f"Processing {len(devices)} switch(es) with "
            f"{worker_count} concurrent worker(s)..."
        )

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    process_switch,
                    device,
                    args.mac_oid_base,
                    oui_registry,
                    args.max_mac_count,
                    args.max_arp_count,
                ): device["host"]
                for device in devices
            }

            for future in as_completed(futures):
                host = futures[future]
                try:
                    all_results.extend(future.result())
                except Exception as error:
                    print(f"Worker failed for {host}: {error}")

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
