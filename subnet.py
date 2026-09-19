#!/usr/bin/env python3

import re
import csv
import socket
from getpass import getpass
from netmiko import ConnectHandler

OUTPUT_CSV = "inventory_report.csv"
OUI_FILE = "oui.csv"

VENDOR_KEYWORDS = {
    "VERIZON": "Verizon",
    "ATT": "AT&T",
    "AT&T": "AT&T",
    "LUMEN": "Lumen",
    "CENTURYLINK": "CenturyLink",
    "COGENT": "Cogent",
    "COMCAST": "Comcast",
    "CHARTER": "Charter",
    "ZAYO": "Zayo",
    "WINDSTREAM": "Windstream"
}

KEYWORD_DEFINITIONS = {
    "FW": "Firewall Connection",
    "FIREWALL": "Firewall Connection",
    "ISP": "Internet Service Provider Connection",
    "INTERNET": "Internet Circuit",
    "MPLS": "MPLS WAN Circuit",
    "VPN": "VPN Connection",
    "WAN": "Wide Area Network Connection",
    "VERIZON": "Verizon Carrier Circuit",
    "ATT": "AT&T Carrier Circuit",
    "LUMEN": "Lumen Carrier Circuit",
    "CENTURYLINK": "CenturyLink Carrier Circuit",
    "COGENT": "Cogent Carrier Circuit",
    "COMCAST": "Comcast Carrier Circuit",
    "CHARTER": "Charter Carrier Circuit",
    "ZAYO": "Zayo Carrier Circuit",
    "WINDSTREAM": "Windstream Carrier Circuit",
    "DMZ": "Demilitarized Zone",
    "PCI": "PCI Network",
    "B2B": "Business-to-Business Network",
    "USON": "US Oncology Network"
}

TYPE_KEYWORDS = {
    "FW": "Firewall",
    "FIREWALL": "Firewall",
    "ISP": "Internet",
    "INTERNET": "Internet",
    "MPLS": "MPLS",
    "VPN": "VPN",
    "WAN": "WAN"
}

MAC_PATTERN = re.compile(
    r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b"
    r"|\b(?:[0-9A-F]{4}\.){2}[0-9A-F]{4}\b",
    re.IGNORECASE
)

def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return hostname

def normalize_mac(value):
    return re.sub(r"[^0-9A-F]", "", value.upper())

def load_oui_database(filename):
    oui_database = {}

    try:
        with open(filename, newline="", encoding="utf-8") as file:
            reader = csv.reader(file)

            for row in reader:
                if len(row) < 2:
                    continue

                oui = normalize_mac(row[0])[:6]
                manufacturer = row[1].strip()

                if len(oui) == 6 and manufacturer:
                    oui_database[oui] = manufacturer

    except FileNotFoundError:
        print(
            f"Warning: {filename} not found. "
            "MAC manufacturer lookup will return Unknown."
        )

    return oui_database

def extract_mac_addresses(mac_output):
    matches = MAC_PATTERN.findall(mac_output)

    return sorted(
        set(normalize_mac(mac) for mac in matches)
    )

def determine_manufacturer(mac_addresses, oui_database):
    if len(mac_addresses) == 0:
        return "No MAC Address"

    if len(mac_addresses) >= 2:
        return "Multiple MAC Addresses"

    oui = mac_addresses[0][:6]

    return oui_database.get(oui, "Unknown")

def detect_vendor(description):
    description_upper = description.upper()

    for keyword, vendor in VENDOR_KEYWORDS.items():
        if keyword in description_upper:
            return vendor

    return "Unknown"

def detect_circuit_type(description):
    description_upper = description.upper()

    found_types = [
        value
        for keyword, value in TYPE_KEYWORDS.items()
        if keyword in description_upper
    ]

    return ",".join(sorted(set(found_types))) \
        if found_types else "Unknown"

def matched_keywords(description):
    description_upper = description.upper()

    matches = [
        keyword
        for keyword in KEYWORD_DEFINITIONS
        if keyword in description_upper
    ]

    return ",".join(sorted(set(matches)))

def matched_keyword_definitions(description):
    description_upper = description.upper()

    definitions = [
        value
        for keyword, value in KEYWORD_DEFINITIONS.items()
        if keyword in description_upper
    ]

    return "; ".join(sorted(set(definitions)))

def find_attached_device(description):
    matches = re.findall(
        r"(DDC1-[A-Za-z0-9\-]+|BUMSH\d+)",
        description,
        re.IGNORECASE
    )

    return matches[0] if matches else ""

def extract_circuit_id(text):
    patterns = [
        r"CID[:=\s]+([A-Za-z0-9\-_/\.]+)",
        r"CKT[:=\s]+([A-Za-z0-9\-_/\.]+)",
        r"CIRCUIT[:=\s]+([A-Za-z0-9\-_/\.]+)",
        r"VCID[:=\s]+([A-Za-z0-9\-_/\.]+)",
        r"\bVZ[0-9]{6,}\b",
        r"\bATT[0-9]{6,}\b",
        r"\bCTL[0-9]{6,}\b",
        r"\bZAYO[0-9]{6,}\b",
        r"\b[A-Z]{2,5}[0-9]{6,}\b"
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)

        if match:
            return match.group(1) if match.groups() else match.group(0)

    return ""

def build_notes(status, vendor, circuit_id):
    notes = []

    if status.lower() not in ["connected", "up"]:
        notes.append("Interface Down")

    if vendor == "Unknown":
        notes.append("Vendor Unknown")

    if circuit_id:
        notes.append(f"Circuit ID Found: {circuit_id}")
    else:
        notes.append("Circuit ID Missing")

    return "; ".join(notes)

def parse_interface_config(cfg):
    mode = ""
    native = ""
    allowed = ""

    match = re.search(
        r"switchport mode\s+(\S+)",
        cfg,
        re.IGNORECASE
    )
    if match:
        mode = match.group(1)

    match = re.search(
        r"switchport trunk native vlan\s+(\d+)",
        cfg,
        re.IGNORECASE
    )
    if match:
        native = match.group(1)

    match = re.search(
        r"switchport trunk allowed vlan\s+([0-9,\-]+)",
        cfg,
        re.IGNORECASE
    )
    if match:
        allowed = match.group(1)

    return mode, native, allowed

def get_mac_output(conn, interface):
    try:
        output = conn.send_command(
            f"show mac address-table interface {interface}",
            read_timeout=60
        )

        return output.strip() or "No MAC entries found"

    except Exception as error:
        return f"ERROR: {error}"

def connect_device(host, username, password):
    return ConnectHandler(
        device_type="cisco_nxos",
        host=host,
        username=username,
        password=password,
        fast_cli=False
    )

def main():
    devices = input(
        "Enter device names (comma separated): "
    ).strip()

    username = input("Username: ").strip()
    password = getpass("Password: ")

    oui_database = load_oui_database(OUI_FILE)
    report = []

    hosts = [
        host.strip()
        for host in devices.split(",")
        if host.strip()
    ]

    for host in hosts:
        conn = None

        try:
            print(f"Connecting to {host} ...")

            conn = connect_device(
                host,
                username,
                password
            )

            conn.disable_paging()

            interface_output = conn.send_command(
                "show interface status",
                read_timeout=120
            )

            mgmt_ip = resolve_ip(host)

            for line in interface_output.splitlines():
                if not re.match(
                    r"^(Eth|Po|mgmt)",
                    line.strip(),
                    re.IGNORECASE
                ):
                    continue

                parts = re.split(r"\s{2,}", line.strip())

                if len(parts) < 3:
                    continue

                interface = parts[0]

                description = (
                    parts[1]
                    if len(parts) > 4
                    else ""
                )

                status = (
                    parts[2]
                    if len(parts) > 4
                    else parts[1]
                )

                vlan = (
                    parts[3]
                    if len(parts) > 4
                    else ""
                )

                try:
                    cfg = conn.send_command(
                        f"show running-config interface {interface}",
                        read_timeout=60
                    )
                except Exception:
                    cfg = ""

                mode, native, allowed = parse_interface_config(cfg)

                mac_output = get_mac_output(
                    conn,
                    interface
                )

                mac_addresses = extract_mac_addresses(
                    mac_output
                )

                manufacturer = determine_manufacturer(
                    mac_addresses,
                    oui_database
                )

                circuit_id = extract_circuit_id(description)

                if not circuit_id:
                    circuit_id = extract_circuit_id(cfg)

                vendor = detect_vendor(description)

                report.append({
                    "Device": host,
                    "Management IP": mgmt_ip,
                    "Interface": interface,
                    "Interface Status": status,
                    "Admin Status": status,
                    "Operational Status": status,
                    "VLAN": vlan,
                    "Mode": mode,
                    "Native VLAN": native,
                    "Allowed VLANs": allowed,
                    "Circuit Vendor": vendor,
                    "Circuit IDs": circuit_id,
                    "Circuit Type": detect_circuit_type(description),
                    "Circuit Directly Attached": find_attached_device(
                        description
                    ),
                    "Matched Keywords": matched_keywords(
                        description
                    ),
                    "Matched Keyword Definitions": (
                        matched_keyword_definitions(description)
                    ),
                    "Description": description,
                    "MAC Address Output": mac_output,
                    "MAC Count": len(mac_addresses),
                    "MAC Addresses": ", ".join(mac_addresses),
                    "Device Manufacturer": manufacturer,
                    "Notes": build_notes(
                        status,
                        vendor,
                        circuit_id
                    )
                })

        except Exception as error:
            print(f"{host}: {error}")

        finally:
            if conn:
                conn.disconnect()

    fields = [
        "Device",
        "Management IP",
        "Interface",
        "Interface Status",
        "Admin Status",
        "Operational Status",
        "VLAN",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
        "Circuit Vendor",
        "Circuit IDs",
        "Circuit Type",
        "Circuit Directly Attached",
        "Matched Keywords",
        "Matched Keyword Definitions",
        "Description",
        "MAC Address Output",
        "MAC Count",
        "MAC Addresses",
        "Device Manufacturer",
        "Notes"
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(report)

    print(f"CSV written to {OUTPUT_CSV}")
    print(f"Interfaces processed: {len(report)}")

if __name__ == "__main__":
    main()
