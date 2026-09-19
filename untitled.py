
#!/usr/bin/env python3

import argparse
import csv
import getpass
import logging
import re
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None

_MAC_LOOKUP = None

if MacLookup is not None:
    try:
        _MAC_LOOKUP = MacLookup()
    except Exception:
        _MAC_LOOKUP = None

CSV_FILE = "inventory_report.csv"

logger = logging.getLogger(__name__)

INTERFACE_RE = (
    r"(?:(?:Eth|Gi|Te|Po|Tu)\d+(?:/\d+)*|"
    r"(?:Ethernet|GigabitEthernet|TenGigabitEthernet|"
    r"Port-channel|Tunnel)\d+(?:/\d+)*)"
)

def find_vendor(desc):
    vendors = [
        ("AT&T", r"\bAT\s*&\s*T\b"),
        ("ATT", r"\bATT\b"),
        ("VERIZON", r"\bVERIZON\b"),
        ("CLINK", r"\bCLINK\b"),
        ("CENTURYLINK", r"\bCENTURYLINK\b"),
        ("LUMEN", r"\bLUMEN\b"),
        ("COMCAST", r"\bCOMCAST\b"),
        ("COGENT", r"\bCOGENT\b"),
        ("CHARTER", r"\bCHARTER\b"),
        ("SPECTRUM", r"\bSPECTRUM\b"),
    ]

    for vendor, pattern in vendors:
        if re.search(pattern, desc, re.IGNORECASE):
            return vendor

    return "Unknown"

def find_circuit_id(desc):
    patterns = [
        r"\bCID\s*[:=]?\s*([A-Za-z0-9-]+)",
        r"\bCIRCUIT\s*[:=]?\s*([A-Za-z0-9-]+)",
        r"\b(\d{8,})\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, desc, re.IGNORECASE)

        if match:
            return match.group(1)

    return ""

def find_keywords(desc):
    keywords = [
        "FW",
        "ISP",
        "INTERNET",
        "VERIZON",
        "CLINK",
        "LUMEN",
        "WAN",
        "PRISMA",
        "VPN",
        "B2B",
        "DMZ",
        "PA",
    ]

    found = []
    desc_u = desc.upper()

    for keyword in keywords:
        if re.search(rf"\b{re.escape(keyword)}\b", desc_u):
            found.append(keyword)

    return ",".join(found)

def circuit_type(desc):
    desc_u = desc.upper()

    if "INTERNET" in desc_u:
        return "Internet"

    if re.search(r"\bFW\b", desc_u):
        return "Firewall"

    if re.search(r"\bWAN\b", desc_u):
        return "WAN"

    return ""

def directly_attached(desc):
    match = re.match(r"^\s*(\S+)", desc)
    return match.group(1) if match else ""

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

VALID_OPER_STATES = {
    "up",
    "down",
    "admin-down",
    "unknown",
    "testing",
}

def normalize_operational_status(status, fallback_status=""):
    """Convert show-interface-status values into operational states."""
    status_map = {
        "connected": "up",
        "up": "up",
        "notconnect": "down",
        "notconnec": "down",
        "down": "down",
        "disabled": "shutdown",
        "shutdown": "shutdown",
        "suspended": "down",
        "err-disabled": "down",
        "xcvrd": "down",
        "xcvr": "down",
        "xcvrabsn": "down",
        "xcvrabsent": "down",
        "sfpabsent": "down",
        "inactive": "down",
        "link-down": "down",
        "channel-down": "down",
        "channeldown": "down",
        "channeldo": "down",
        "admin-down": "shutdown",
        "testing": "testing",
        "unknown": "unknown",
    }

    normalized = (status or "").lower().strip()

    if normalized in status_map:
        return status_map[normalized]

    fallback = (fallback_status or "").lower().strip()

    if fallback in VALID_OPER_STATES:
        return fallback

    if normalized or fallback:
        logger.warning(
            "Ignoring invalid operational status value %r; fallback=%r",
            status,
            fallback_status,
        )

    return "unknown"

def normalize_admin_status(status, fallback_status=""):
    """Derive administrative state from show interface status."""
    normalized = (status or "").lower().strip()

    if normalized in {"disabled", "shutdown", "admin-down"}:
        return "admin down"

    if normalized in {
        "connected",
        "up",
        "down",
        "notconnect",
        "notconnec",
        "suspended",
        "err-disabled",
        "xcvrd",
        "xcvr",
        "xcvrabsn",
        "xcvrabsent",
        "sfpabsent",
        "inactive",
        "link-down",
        "channeldown",
        "channeldo",
        "channel-down",
        "noopermem",
        "out-of-service",
        "testing",
        "unknown",
    }:
        return "up"

    fallback = (fallback_status or "").lower().strip()

    if fallback in {"admin down", "admin-down", "shutdown"}:
        return "admin down"

    if fallback in {"up", "down"}:
        return fallback

    return "unknown"

def display_interface_status(interface, status, fallback_status=""):
    """Format port-channel state and prevent blank status values."""
    status = (status or fallback_status or "unknown").lower().strip()

    if interface.startswith("Po"):
        if status in {"connected", "up"}:
            return f"{interface}/up"

        if status in {"disabled", "shutdown"}:
            return f"{interface}/shutdown"

        if status in {
            "down",
            "notconnect",
            "notconnec",
            "suspended",
            "err-disabled",
            "channel-down",
            "channeldown",
            "channeldo",
            "unknown",
        }:
            return f"{interface}/down"

    if status in {"channeldo", "channeldown"}:
        return "ChannelDown"

    return status or "unknown"

def parse_interface_status(output):
    """Parse NX-OS show interface status output."""
    results = {}

    status_pattern = (
        r"connected|notconnect|notconnec|disabled|suspended|"
        r"err-disabled|xcvrd|xcvr|xcvrAbsn|xcvrAbsent|sfpAbsent|"
        r"inactive|link-down|linkDown|channel-down|channelDown|channelDo|"
        r"noOperMem|out-of-service|shutdown|unknown|up|down"
    )

    for line_number, line in enumerate(output.splitlines(), start=1):
        interface_match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})(?=\s|$)",
            line,
            re.IGNORECASE,
        )

        if not interface_match:
            if line.strip():
                logger.debug(
                    "Ignoring non-interface status line %d: %s",
                    line_number,
                    line.strip(),
                )
            continue

        interface = normalize_interface_name(
            interface_match.group("interface")
        )

        remainder = line[interface_match.end():]

        status_match = re.search(
            rf"\b(?P<status>{status_pattern})\b",
            remainder,
            re.IGNORECASE,
        )

        if not status_match:
            logger.warning(
                "Unable to parse status token on line %d: %s",
                line_number,
                line.strip(),
            )
            continue

        status = status_match.group("status")
        after_status = remainder[status_match.end():]

        vlan_match = re.match(r"\s+(?P<vlan>\S+)", after_status)
        vlan = vlan_match.group("vlan") if vlan_match else ""

        results[interface] = {
            "status": status,
            "vlan": vlan,
        }

        logger.debug(
            "Parsed interface status: %s status=%s vlan=%s",
            interface,
            status,
            vlan,
        )

    return results

def parse_port_channel_summary(output):
    """Parse NX-OS port-channel flags such as Po1(SU) and Po1(D)."""
    results = {}

    for line_number, line in enumerate(output.splitlines(), start=1):
        match = re.search(
            r"\b(?P<interface>Po\d+)\((?P<flags>[^)]+)\)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        interface = normalize_interface_name(match.group("interface"))
        flags = match.group("flags").upper()

        status = (
            "down"
            if "D" in flags
            else "up"
            if "U" in flags
            else "unknown"
        )

        results[interface] = {
            "status": status,
            "flags": flags,
        }

        logger.debug(
            "Parsed port-channel summary: %s flags=%s status=%s",
            interface,
            flags,
            status,
        )

    return results

def parse_interface_description(output):
    interfaces = {}

    for line in output.splitlines():
        if not re.match(rf"^\s*{INTERFACE_RE}\b", line):
            continue

        parts = re.split(r"\s{2,}", line.strip())

        if len(parts) < 3:
            continue

        iface = normalize_interface_name(parts[0])
        admin = parts[1]
        oper = parts[2]
        desc = parts[3] if len(parts) >= 4 else ""

        interfaces[iface] = {
            "admin": admin,
            "oper": oper,
            "desc": desc,
        }

    return interfaces

def parse_interface_switchport(output):
    results = {}
    current_interface = None

    for raw_line in output.splitlines():
        line = raw_line.strip()

        interface_match = re.match(
            rf"^Name:\s*(?P<interface>{INTERFACE_RE})",
            line,
            re.IGNORECASE,
        )

        if interface_match:
            current_interface = normalize_interface_name(
                interface_match.group("interface")
            )

            results[current_interface] = {
                "mode": "",
                "native_vlan": "",
                "allowed_vlans": "",
            }

            continue

        if not current_interface:
            continue

        mode_match = re.match(
            r"^Operational Mode:\s*(.+)$",
            line,
            re.IGNORECASE,
        )

        if mode_match:
            results[current_interface]["mode"] = mode_match.group(1).strip()
            continue

        access_vlan_match = re.match(
            r"^Access Mode VLAN:\s*(\S+)",
            line,
            re.IGNORECASE,
        )

        if access_vlan_match:
            results[current_interface]["native_vlan"] = (
                access_vlan_match.group(1)
            )
            continue

        native_vlan_match = re.match(
            r"^Trunking Native Mode VLAN:\s*(\S+)",
            line,
            re.IGNORECASE,
        )

        if native_vlan_match:
            results[current_interface]["native_vlan"] = (
                native_vlan_match.group(1)
            )
            continue

        allowed_vlan_match = re.match(
            r"^Trunking VLANs Enabled:\s*(.+)$",
            line,
            re.IGNORECASE,
        )

        if allowed_vlan_match:
            results[current_interface]["allowed_vlans"] = (
                allowed_vlan_match.group(1).strip()
            )

    return results

def parse_mac_table(output):
    mac_data = {}

    for line in output.splitlines():
        mac_match = re.search(
            r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b",
            line,
            re.IGNORECASE,
        )

        if not mac_match:
            continue

        interface_match = re.search(
            rf"\b(?P<interface>{INTERFACE_RE})\b",
            line,
            re.IGNORECASE,
        )

        if not interface_match:
            continue

        interface = normalize_interface_name(
            interface_match.group("interface")
        )

        mac_address = mac_match.group(0).lower()

        if interface not in mac_data:
            mac_data[interface] = {
                "count": 0,
                "addresses": [],
            }

        mac_data[interface]["count"] += 1
        mac_data[interface]["addresses"].append(mac_address)

    return mac_data

def lookup_mac_vendor(mac_address):
    """Return the manufacturer associated with a MAC OUI."""
    if _MAC_LOOKUP is None:
        return "Unknown"

    try:
        return _MAC_LOOKUP.lookup(mac_address)
    except Exception:
        return "Unknown"

def classify_device(description, vendors):
    """Best-effort device classification."""
    text = f"{description} {' '.join(vendors)}".upper()

    description_types = [
        ("Firewall", r"\b(FW|FIREWALL)\b"),
        (
            "Wireless Access Point",
            r"\b(AP|ACCESS POINT|WAP|WIRELESS)\b",
        ),
        ("IP Phone", r"\b(IP PHONE|VOIP|PHONE)\b"),
        ("Printer", r"\b(PRINTER|MFP|COPIER)\b"),
        ("Camera", r"\b(CAMERA|CAM|CCTV)\b"),
        ("Server", r"\b(SERVER|ESXI|HYPERV|HYPER-V)\b"),
    ]

    for device_type, pattern in description_types:
        if re.search(pattern, description, re.IGNORECASE):
            return device_type

    if re.search(
        r"CISCO|ARISTA|JUNIPER|FORTINET|PALO ALTO|PALOALTO|"
        r"MERAKI|UBIQUITI|RUCKUS|BROCADE|EXTREME NETWORKS|HUAWEI",
        text,
    ):
        return "Network Device"

    if re.search(
        r"VMWARE|MICROSOFT|HYPER-V|QEMU|KVM|VIRTUALBOX|PARALLELS",
        text,
    ):
        return "Virtual Machine/Hypervisor"

    if re.search(
        r"HEWLETT[- ]PACKARD|HP INC|BROTHER|CANON|EPSON|LEXMARK|"
        r"RICOH|KONICA MINOLTA",
        text,
    ):
        return "Printer"

    return "Unknown"

def build_notes(row):
    notes = []

    if row["Operational Status"].lower() in {"down", "shutdown"}:
        notes.append("Interface Down")

    if row["Circuit Vendor"] == "Unknown":
        notes.append("Vendor Unknown")

    if not row["Circuit IDs"]:
        notes.append("Circuit ID Missing")

    if row["MAC Count"] == 0:
        notes.append("No MAC Addresses Learned")

    return "; ".join(notes)

def shutdown_reason(row):
    """Explain why an interface was selected for the shutdown report."""
    operational_status = row["Operational Status"].strip().lower()

    if operational_status == "shutdown":
        return "Interface is already shutdown"

    if operational_status == "down":
        return "Interface is operationally down"

    if operational_status == "up":
        return "Interface is operationally up but marked as a candidate"

    return "Decom/Scream Test candidate"

def collect_host(hostname, username, password):
    device = {
        "device_type": "cisco_nxos",
        "host": hostname,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    conn = None

    try:
        print(f"\nConnecting to {hostname}...\n")

        conn = ConnectHandler(**device)

        show_desc = conn.send_command(
            "show interface description",
            read_timeout=60,
        )

        show_status = conn.send_command(
            "show interface status",
            read_timeout=60,
        )

        show_port_channel = conn.send_command(
            "show port-channel summary",
            read_timeout=60,
        )

        show_switchport = conn.send_command(
            "show interface switchport",
            read_timeout=60,
        )

        show_mac = conn.send_command(
            "show mac address-table",
            read_timeout=60,
        )

        mgmt_ip = conn.host

    except NetmikoAuthenticationException:
        print(
            f"{hostname}: authentication failed.",
            file=sys.stderr,
        )
        return []

    except NetmikoTimeoutException:
        print(
            f"{hostname}: connection timed out.",
            file=sys.stderr,
        )
        return []

    except Exception as exc:
        print(
            f"{hostname}: connection or command failure: {exc}",
            file=sys.stderr,
        )
        return []

    finally:
        if conn:
            conn.disconnect()

    interfaces = parse_interface_description(show_desc)
    status_data = parse_interface_status(show_status)
    port_channel_data = parse_port_channel_summary(show_port_channel)
    switchport_data = parse_interface_switchport(show_switchport)
    mac_data = parse_mac_table(show_mac)

    for iface, interface_data in interfaces.items():
        if iface not in status_data:
            logger.warning(
                "%s: no parsed status for %s; description operational "
                "status=%r",
                hostname,
                iface,
                interface_data.get("oper", ""),
            )

    rows = []

    for iface, data in interfaces.items():
        desc = data["desc"]

        switchport = switchport_data.get(
            iface,
            {
                "mode": "",
                "native_vlan": "",
                "allowed_vlans": "",
            },
        )

        mac_info = mac_data.get(
            iface,
            {
                "count": 0,
                "addresses": [],
            },
        )

        mac_count = mac_info["count"]
        mac_list = mac_info["addresses"]

        mac_addresses = (
            ", ".join(mac_list)
            if 0 < mac_count <= 2
            else ""
        )

        mac_vendors = []

        for mac_address in mac_list:
            vendor = lookup_mac_vendor(mac_address)

            if vendor != "Unknown" and vendor not in mac_vendors:
                mac_vendors.append(vendor)

        mac_vendor = (
            "; ".join(sorted(mac_vendors))
            if mac_vendors
            else "Unknown"
        )

        device_type = classify_device(desc, mac_vendors)

        raw_interface_status = status_data.get(
            iface,
            {},
        ).get("status", "")

        if iface.startswith("Po") and iface in port_channel_data:
            raw_interface_status = port_channel_data[iface]["status"]

        admin_status = normalize_admin_status(
            raw_interface_status,
            data.get("admin", ""),
        )

        operational_status = normalize_operational_status(
            raw_interface_status,
            data.get("oper", ""),
        )

        interface_status = display_interface_status(
            iface,
            raw_interface_status,
            operational_status,
        )

        decom_scream_candidate = (
            operational_status in {"down", "shutdown"}
            or (
                operational_status == "up"
                and mac_count in {1, 2}
            )
        )

        row = {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "Interface Status": interface_status,
            "Admin Status": admin_status,
            "Operational Status": operational_status,
            "Decom/Scream Test Candidate": (
                "Yes"
                if decom_scream_candidate
                else "No"
            ),
            "Score Rate": (
                1
                if operational_status == "down"
                else 0
            ),
            "VLAN": status_data.get(iface, {}).get("vlan", ""),
            "Mode": switchport["mode"],
            "Native VLAN": switchport["native_vlan"],
            "Allowed VLANs": switchport["allowed_vlans"],
            "Circuit Vendor": find_vendor(desc),
            "Circuit IDs": find_circuit_id(desc),
            "Circuit Type": circuit_type(desc),
            "Circuit Directly Attached": directly_attached(desc),
            "Matched Keywords": find_keywords(desc),
            "Description": desc,
            "MAC Count": mac_count,
            "MAC Addresses": mac_addresses,
            "MAC Vendor": mac_vendor,
            "Device Type": device_type,
        }

        row["Notes"] = build_notes(row)
        rows.append(row)

    return rows

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Collect Cisco NX-OS interface inventory into a CSV file."
        )
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable detailed parser and collection logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    username = input("Username: ")
    password = getpass.getpass("Password: ")
    host_input = input("Switch Hostname/IP(s), comma-delimited: ")

    hostnames = [
        hostname.strip()
        for hostname in host_input.split(",")
        if hostname.strip()
    ]

    if not hostnames:
        print(
            "No hostnames provided.",
            file=sys.stderr,
        )
        sys.exit(1)

    fields = [
        "Device",
        "Management IP",
        "Interface",
        "Interface Status",
        "Admin Status",
        "Operational Status",
        "Decom/Scream Test Candidate",
        "Score Rate",
        "VLAN",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
        "Circuit Vendor",
        "Circuit IDs",
        "Circuit Type",
        "Circuit Directly Attached",
        "Matched Keywords",
        "Description",
        "MAC Count",
        "MAC Addresses",
        "MAC Vendor",
        "Device Type",
        "Notes",
    ]

    max_workers = min(10, len(hostnames))
    rows_by_host = [None] * len(hostnames)

    print(
        f"Starting parallel collection for {len(hostnames)} device(s) "
        f"using {max_workers} worker(s)..."
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                collect_host,
                hostname,
                username,
                password,
            ): index
            for index, hostname in enumerate(hostnames)
        }

        for future in as_completed(futures):
            index = futures[future]
            hostname = hostnames[index]

            try:
                rows_by_host[index] = future.result()

            except Exception as exc:
                print(
                    f"{hostname}: unexpected collection failure: {exc}",
                    file=sys.stderr,
                )
                rows_by_host[index] = []

    all_rows = []

    for host_rows in rows_by_host:
        all_rows.extend(host_rows or [])

    shutdown_report_rows = [
        row
        for row in all_rows
        if row["Decom/Scream Test Candidate"] == "Yes"
        and not (
            row["Operational Status"].strip().lower() == "up"
            and row["Admin Status"].strip().lower() == "up"
        )
    ]

    all_rows = [
        row
        for row in all_rows
        if row["Operational Status"].strip().lower() != "shutdown"
    ]

    down_not_shutdown = [
        (row["Device"], row["Interface"])
        for row in all_rows
        if row["Operational Status"].lower() == "down"
        and row["Admin Status"].lower()
        not in {"admin down", "shutdown"}
    ]

    with open(
        CSV_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(all_rows)

        summary_writer = csv.writer(file)

        summary_writer.writerow([])
        summary_writer.writerow(["Down Ports Not Shutdown"])
        summary_writer.writerow(["Switch Name", "Port"])
        summary_writer.writerows(down_not_shutdown)

        summary_writer.writerow([])
        summary_writer.writerow(
            ["Interfaces Scheduled for Shutdown"]
        )

        summary_writer.writerow(
            [
                "Switch Name",
                "Management IP",
                "Interface",
                "Interface Status",
                "Admin Status",
                "Operational Status",
                "MAC Count",
                "MAC Addresses",
                "Description",
                "Shutdown Reason",
            ]
        )

        for row in sorted(
            shutdown_report_rows,
            key=lambda item: (
                item["Device"],
                item["Interface"],
            ),
        ):
            summary_writer.writerow(
                [
                    row["Device"],
                    row["Management IP"],
                    row["Interface"],
                    row["Interface Status"],
                    row["Admin Status"],
                    row["Operational Status"],
                    row["MAC Count"],
                    row["MAC Addresses"],
                    row["Description"],
                    shutdown_reason(row),
                ]
            )

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Devices processed: {len(hostnames)}")
    print(f"Interfaces processed: {len(all_rows)}")
    print(f"Down ports not shutdown: {len(down_not_shutdown)}")
    print(
        "Interfaces scheduled for shutdown: "
        f"{len(shutdown_report_rows)}"
    )

if __name__ == "__main__":
    main()
