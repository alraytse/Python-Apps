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

DEFAULT_INVENTORY_CSV = "inventory_report.csv"
DEFAULT_STRETCH_CSV = "vlan_stretch_analysis.csv"

logger = logging.getLogger(__name__)

INTERFACE_RE = (
    r"(?:(?:Eth|Gi|Te|Po)\d+(?:/\d+)*|"
    r"(?:Ethernet|GigabitEthernet|TenGigabitEthernet|Port-channel)"
    r"\d+(?:/\d+)*)"
)

# Explicit project candidates from the DA11 design.
EXPLICIT_STRETCH_VLANS = {
    "110": "vMotion",
    "111": "HMC1",
    "112": "HMC2",
}

# These are conditional candidates, not automatic stretch decisions.
CONDITIONAL_KEYWORDS = (
    "USON",
    "SPECIALTY",
    "MVP_USON",
    "DOMAIN",
    "ACTIVE_DIRECTORY",
    "ACTIVE DIRECTORY",
    "DNS",
    "ISE",
)

VALID_OPER_STATES = {
    "up",
    "down",
    "admin-down",
    "unknown",
    "testing",
}


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
    }

    for long_name, short_name in replacements.items():
        if interface.startswith(long_name):
            return interface.replace(long_name, short_name, 1)

    return interface


def normalize_operational_status(status, fallback_status=""):
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
        "linkflaperrdisabled": "down",
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
        "linkflaperrdisabled",
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
            "linkflaperrdisabled",
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
    results = {}
    status_pattern = (
        r"connected|notconnect|notconnec|disabled|suspended|"
        r"err-disabled|linkFlapErrDisabled|xcvrd|xcvr|xcvrAbsn|xcvrAbsent|sfpAbsent|"
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
            continue

        interface = normalize_interface_name(interface_match.group("interface"))
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

    return results


def parse_port_channel_summary(output):
    results = {}

    for line in output.splitlines():
        match = re.search(
            r"\b(?P<interface>Po\d+)\((?P<flags>[^)]+)\)",
            line,
            re.IGNORECASE,
        )

        if not match:
            continue

        interface = normalize_interface_name(match.group("interface"))
        flags = match.group("flags").upper()
        status = "down" if "D" in flags else "up" if "U" in flags else "unknown"

        results[interface] = {
            "status": status,
            "flags": flags,
        }

    return results


def parse_interface_description(output):
    interfaces = {}

    for line in output.splitlines():
        if not re.match(rf"^\s*{INTERFACE_RE}\b", line, re.IGNORECASE):
            continue

        parts = re.split(r"\s{2,}", line.strip())

        if len(parts) < 3:
            continue

        iface = normalize_interface_name(parts[0])
        interfaces[iface] = {
            "admin": parts[1],
            "oper": parts[2],
            "desc": parts[3] if len(parts) >= 4 else "",
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
            results[current_interface]["native_vlan"] = access_vlan_match.group(1)
            continue

        native_vlan_match = re.match(
            r"^Trunking Native Mode VLAN:\s*(\S+)",
            line,
            re.IGNORECASE,
        )
        if native_vlan_match:
            results[current_interface]["native_vlan"] = native_vlan_match.group(1)
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

        interface = normalize_interface_name(interface_match.group("interface"))
        mac_address = mac_match.group(0).lower()

        if interface not in mac_data:
            mac_data[interface] = {"count": 0, "addresses": []}

        mac_data[interface]["count"] += 1
        mac_data[interface]["addresses"].append(mac_address)

    return mac_data


def parse_vlan_brief(output):
    """Parse show vlan brief output into VLAN ID/name/status records."""
    results = {}
    pattern = re.compile(
        r"^\s*(?P<vlan>\d+)\s+"
        r"(?P<name>\S+)\s+"
        r"(?P<status>active|suspend|shutdown|act/unsup)"
        r"(?:\s+(?P<ports>.*))?$",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue

        vlan_id = match.group("vlan")
        results[vlan_id] = {
            "name": match.group("name"),
            "status": match.group("status"),
            "ports": (match.group("ports") or "").strip(),
        }

    return results


def parse_svi_data(output):
    """Parse show ip interface brief lines for VLAN SVIs."""
    results = {}

    for line in output.splitlines():
        match = re.match(
            r"^\s*Vlan(?P<vlan>\d+)\s+"
            r"(?P<ip>\S+)\s+\S+\s+\S+\s+"
            r"(?P<status>\S+)\s+(?P<protocol>\S+)",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue

        results[match.group("vlan")] = {
            "ip": match.group("ip"),
            "status": match.group("status"),
            "protocol": match.group("protocol"),
        }

    return results


def expand_vlan_expression(expression):
    """Expand common NX-OS VLAN lists into comparable VLAN IDs."""
    if not expression:
        return set()

    expression = expression.strip()
    if expression.lower() in {"all", "none", "-"}:
        return set()

    values = set()
    expression = expression.replace(" ", "")

    for item in expression.split(","):
        if not item:
            continue

        if "-" in item:
            start, end = item.split("-", 1)
            if start.isdigit() and end.isdigit():
                values.update(str(v) for v in range(int(start), int(end) + 1))
        elif item.isdigit():
            values.add(item)

    return values


def parse_interface_error_counters(output):
    """Parse per-interface error-counter lines from NX-OS output."""
    results = {}

    for line in output.splitlines():
        match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})\s+(?P<counters>.+)$",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue

        interface = normalize_interface_name(match.group("interface"))
        results[interface] = match.group("counters").strip()

    return results


def interface_log_evidence(output, interface):
    """Return log lines containing the short or long interface name."""
    aliases = {interface.lower()}
    long_names = {
        "eth": "ethernet",
        "gi": "gigabitethernet",
        "te": "tengigabitethernet",
        "po": "port-channel",
    }

    match = re.match(r"^(eth|gi|te|po)(.+)$", interface, re.IGNORECASE)
    if match:
        aliases.add((long_names[match.group(1).lower()] + match.group(2)).lower())

    evidence = []
    for line in output.splitlines():
        line_lower = line.lower()
        if any(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", line_lower)
               for alias in aliases):
            evidence.append(line.strip())

    return "; ".join(evidence)


def lookup_mac_vendor(mac_address):
    if _MAC_LOOKUP is None:
        return "Unknown"

    try:
        return _MAC_LOOKUP.lookup(mac_address)
    except Exception:
        return "Unknown"


def classify_device(description, vendors):
    text = f"{description} {' '.join(vendors)}".upper()

    description_types = [
        ("Firewall", r"\b(FW|FIREWALL)\b"),
        ("Wireless Access Point", r"\b(AP|ACCESS POINT|WAP|WIRELESS)\b"),
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


def normalize_vlan_name(name):
    return re.sub(r"[^A-Z0-9]+", "_", (name or "").upper()).strip("_")


def stretch_assessment(vlan_id, vlan_name, sites_seen):
    vlan_id = str(vlan_id)
    name_key = normalize_vlan_name(vlan_name)

    if vlan_id in EXPLICIT_STRETCH_VLANS:
        return (
            "Candidate",
            "High",
            f"Explicit DA11 Layer 2 candidate: {EXPLICIT_STRETCH_VLANS[vlan_id]}",
        )

    if any(keyword in name_key for keyword in CONDITIONAL_KEYWORDS):
        return (
            "Conditional",
            "Medium",
            "USON/AD/DNS/ISE-related name; validate endpoint and IP-retention dependency",
        )

    if len(sites_seen) > 1:
        return (
            "Review",
            "Low",
            "Observed on multiple labeled sites; confirm whether the same subnet must remain Layer 2 adjacent",
        )

    return "Do not stretch by default", "Low", "No explicit Layer 2 or conditional service indicator"


def collect_host(hostname, site, username, password):
    device = {
        "device_type": "cisco_nxos",
        "host": hostname,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    conn = None

    try:
        print(f"\nConnecting to {hostname} ({site})...\n")
        conn = ConnectHandler(**device)

        show_desc = conn.send_command("show interface description", read_timeout=60)
        show_status = conn.send_command("show interface status", read_timeout=60)
        show_port_channel = conn.send_command(
            "show port-channel summary", read_timeout=60
        )
        show_switchport = conn.send_command(
            "show interface switchport", read_timeout=60
        )
        show_mac = conn.send_command("show mac address-table", read_timeout=60)
        show_error_counters = conn.send_command(
            "show interface counters errors", read_timeout=60
        )
        show_logging = conn.send_command(
            "show logging logfile | include linkFlapErrDisabled|err-disable|ERR_DISABLE|LINK-3-UPDOWN",
            read_timeout=60,
        )
        show_vlan = conn.send_command("show vlan brief", read_timeout=60)
        show_trunk = conn.send_command("show interface trunk", read_timeout=60)
        show_svi = conn.send_command(
            "show ip interface brief | include ^Vlan", read_timeout=60
        )
        mgmt_ip = conn.host

    except NetmikoAuthenticationException:
        print(f"{hostname}: authentication failed.", file=sys.stderr)
        return {"rows": [], "vlan_observations": []}

    except NetmikoTimeoutException:
        print(f"{hostname}: connection timed out.", file=sys.stderr)
        return {"rows": [], "vlan_observations": []}

    except Exception as exc:
        print(
            f"{hostname}: connection or command failure: {exc}",
            file=sys.stderr,
        )
        return {"rows": [], "vlan_observations": []}

    finally:
        if conn:
            conn.disconnect()

    interfaces = parse_interface_description(show_desc)
    status_data = parse_interface_status(show_status)
    port_channel_data = parse_port_channel_summary(show_port_channel)
    switchport_data = parse_interface_switchport(show_switchport)
    mac_data = parse_mac_table(show_mac)
    error_counter_data = parse_interface_error_counters(show_error_counters)
    vlan_data = parse_vlan_brief(show_vlan)
    svi_data = parse_svi_data(show_svi)

    # Parsing the trunk command separately provides a fallback when the detailed
    # switchport output omits a trunk's allowed VLAN list.
    trunk_allowed_by_interface = {}
    for line in show_trunk.splitlines():
        match = re.match(
            rf"^\s*(?P<interface>{INTERFACE_RE})\s+"
            r".*?(?P<allowed>\d[\d,\-]*)\s*$",
            line,
            re.IGNORECASE,
        )
        if match:
            interface = normalize_interface_name(match.group("interface"))
            trunk_allowed_by_interface[interface] = match.group("allowed")

    rows = []
    vlan_observations = []

    for iface, data in interfaces.items():
        desc = data["desc"]
        switchport = switchport_data.get(
            iface,
            {"mode": "", "native_vlan": "", "allowed_vlans": ""},
        )

        if not switchport["allowed_vlans"]:
            switchport["allowed_vlans"] = trunk_allowed_by_interface.get(iface, "")

        mac_info = mac_data.get(iface, {"count": 0, "addresses": []})
        mac_count = mac_info["count"]
        mac_list = mac_info["addresses"]
        mac_addresses = ", ".join(mac_list) if 0 < mac_count <= 2 else ""
        mac_vendors = []

        for mac_address in mac_list:
            vendor = lookup_mac_vendor(mac_address)
            if vendor != "Unknown" and vendor not in mac_vendors:
                mac_vendors.append(vendor)

        mac_vendor = "; ".join(sorted(mac_vendors)) if mac_vendors else "Unknown"
        device_type = classify_device(desc, mac_vendors)
        raw_interface_status = status_data.get(iface, {}).get("status", "")

        if iface.startswith("Po") and iface in port_channel_data:
            raw_interface_status = port_channel_data[iface]["status"]

        admin_status = normalize_admin_status(raw_interface_status, data.get("admin", ""))
        operational_status = normalize_operational_status(
            raw_interface_status, data.get("oper", "")
        )
        interface_status = display_interface_status(
            iface, raw_interface_status, operational_status
        )

        access_vlan = status_data.get(iface, {}).get("vlan", "")
        if not access_vlan.isdigit():
            access_vlan = switchport.get("native_vlan", "")

        vlan_info = vlan_data.get(str(access_vlan), {})
        vlan_name = vlan_info.get("name", "")
        svi_info = svi_data.get(str(access_vlan), {})
        allowed_vlans = switchport.get("allowed_vlans", "")
        observed_vlans = set()
        if access_vlan.isdigit():
            observed_vlans.add(access_vlan)
        observed_vlans.update(expand_vlan_expression(allowed_vlans))

        decom_scream_candidate = (
            operational_status in {"down", "shutdown"}
            or operational_status == "up" and mac_count in {1, 2}
        )

        errdisable_reason = (
            raw_interface_status
            if re.search(r"err-disabled|linkflaperrdisabled", raw_interface_status, re.IGNORECASE)
            else ""
        )
        row = {
            "Site": site,
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Interface": iface,
            "Interface Status": interface_status,
            "Admin Status": admin_status,
            "Operational Status": operational_status,
            "Decom/Scream Test Candidate": (
                "Yes" if decom_scream_candidate else "No"
            ),
            "Score Rate": 1 if operational_status == "down" else 0,
            "VLAN": access_vlan,
            "VLAN Name": vlan_name,
            "VLAN Status": vlan_info.get("status", ""),
            "SVI IP": svi_info.get("ip", ""),
            "Error Counters": error_counter_data.get(iface, ""),
            "Errdisable Reason": errdisable_reason,
            "Errdisable Log Evidence": interface_log_evidence(show_logging, iface),
            "Mode": switchport["mode"],
            "Native VLAN": switchport["native_vlan"],
            "Allowed VLANs": allowed_vlans,
            "Observed VLANs": ",".join(sorted(observed_vlans, key=int)),
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

        candidate, confidence, basis = stretch_assessment(
            access_vlan, vlan_name, {site}
        )
        row["Stretch Candidate"] = candidate
        row["Stretch Confidence"] = confidence
        row["Stretch Basis"] = basis
        row["Notes"] = build_notes(row)
        rows.append(row)

        for vlan_id in observed_vlans:
            info = vlan_data.get(vlan_id, {})
            vlan_observations.append(
                {
                    "Site": site,
                    "Device": hostname,
                    "VLAN": vlan_id,
                    "VLAN Name": info.get("name", "") or (
                        vlan_name if vlan_id == access_vlan else ""
                    ),
                    "VLAN Status": info.get("status", ""),
                    "Access Interface": iface if vlan_id == access_vlan else "",
                    "Mode": switchport.get("mode", ""),
                    "SVI IP": svi_data.get(vlan_id, {}).get("ip", ""),
                    "MAC Count": mac_count if vlan_id == access_vlan else 0,
                }
            )

    return {"rows": rows, "vlan_observations": vlan_observations}


def parse_host_input(raw_input, default_site):
    """Parse HOST or SITE=HOST entries while preserving old input behavior."""
    hosts = []

    for token in raw_input.split(","):
        token = token.strip()
        if not token:
            continue

        if "=" in token:
            site, hostname = token.split("=", 1)
            site = site.strip() or default_site
            hostname = hostname.strip()
        else:
            site = default_site
            hostname = token

        if hostname:
            hosts.append((site, hostname))

    return hosts


def write_inventory_csv(path, rows):
    fields = [
        "Site",
        "Device",
        "Management IP",
        "Interface",
        "Interface Status",
        "Admin Status",
        "Operational Status",
        "Decom/Scream Test Candidate",
        "Score Rate",
        "VLAN",
        "VLAN Name",
        "VLAN Status",
        "SVI IP",
        "Error Counters",
        "Errdisable Reason",
        "Errdisable Log Evidence",
        "Mode",
        "Native VLAN",
        "Allowed VLANs",
        "Observed VLANs",
        "Stretch Candidate",
        "Stretch Confidence",
        "Stretch Basis",
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

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_stretch_csv(path, observations):
    grouped = {}

    for observation in observations:
        vlan_id = str(observation["VLAN"])
        entry = grouped.setdefault(
            vlan_id,
            {
                "VLAN": vlan_id,
                "VLAN Names": set(),
                "Sites": set(),
                "Devices": set(),
                "Access Interfaces": set(),
                "Modes": set(),
                "SVI IPs": set(),
                "VLAN Statuses": set(),
                "MAC Count": 0,
            },
        )

        for key, source_key in (
            ("VLAN Names", "VLAN Name"),
            ("Sites", "Site"),
            ("Devices", "Device"),
            ("Access Interfaces", "Access Interface"),
            ("Modes", "Mode"),
            ("SVI IPs", "SVI IP"),
            ("VLAN Statuses", "VLAN Status"),
        ):
            value = observation[source_key]
            if value:
                entry[key].add(value)

        entry["MAC Count"] += int(observation.get("MAC Count", 0) or 0)

    fields = [
        "VLAN",
        "VLAN Names",
        "Sites",
        "Devices",
        "Access Interfaces",
        "Modes",
        "SVI IPs",
        "VLAN Statuses",
        "MAC Count",
        "Stretch Candidate",
        "Stretch Confidence",
        "Stretch Basis",
    ]

    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for vlan_id in sorted(grouped, key=lambda value: int(value)):
            entry = grouped[vlan_id]
            names = sorted(entry["VLAN Names"])
            sites = sorted(entry["Sites"])
            candidate, confidence, basis = stretch_assessment(
                vlan_id,
                " ".join(names),
                set(sites),
            )

            writer.writerow(
                {
                    "VLAN": vlan_id,
                    "VLAN Names": "; ".join(names),
                    "Sites": "; ".join(sites),
                    "Devices": "; ".join(sorted(entry["Devices"])),
                    "Access Interfaces": "; ".join(
                        sorted(entry["Access Interfaces"])
                    ),
                    "Modes": "; ".join(sorted(entry["Modes"])),
                    "SVI IPs": "; ".join(sorted(entry["SVI IPs"])),
                    "VLAN Statuses": "; ".join(sorted(entry["VLAN Statuses"])),
                    "MAC Count": entry["MAC Count"],
                    "Stretch Candidate": candidate,
                    "Stretch Confidence": confidence,
                    "Stretch Basis": basis,
                }
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Collect Cisco NX-OS inventory and identify DDC1-to-DA11 VLAN stretch candidates."
        )
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable detailed parser and collection logging",
    )
    parser.add_argument(
        "--default-site",
        default="Unknown",
        help="site applied to hosts without SITE=HOST notation",
    )
    parser.add_argument(
        "--inventory-csv",
        default=DEFAULT_INVENTORY_CSV,
        help=f"detailed inventory output path (default: {DEFAULT_INVENTORY_CSV})",
    )
    parser.add_argument(
        "--stretch-csv",
        default=DEFAULT_STRETCH_CSV,
        help=f"VLAN summary output path (default: {DEFAULT_STRETCH_CSV})",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    username = input("Username: ")
    password = getpass.getpass("Password: ")
    host_input = input(
        "Switch Hostname/IP(s), comma-delimited "
        "(optional SITE=HOST format): "
    )
    hosts = parse_host_input(host_input, args.default_site)

    if not hosts:
        print("No hostnames provided.", file=sys.stderr)
        sys.exit(1)

    max_workers = min(10, len(hosts))
    results_by_host = [None] * len(hosts)

    print(
        f"Starting parallel collection for {len(hosts)} device(s) "
        f"using {max_workers} worker(s)..."
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                collect_host,
                hostname,
                site,
                username,
                password,
            ): index
            for index, (site, hostname) in enumerate(hosts)
        }

        for future in as_completed(futures):
            index = futures[future]
            site, hostname = hosts[index]

            try:
                results_by_host[index] = future.result()
            except Exception as exc:
                print(
                    f"{hostname} ({site}): unexpected collection failure: {exc}",
                    file=sys.stderr,
                )
                results_by_host[index] = {
                    "rows": [],
                    "vlan_observations": [],
                }

    all_rows = []
    all_observations = []
    for result in results_by_host:
        if not result:
            continue
        all_rows.extend(result.get("rows", []))
        all_observations.extend(result.get("vlan_observations", []))

    # Recalculate each row's assessment using all labeled sites, so a VLAN seen
    # at both DDC1 and DA11 is visibly marked for review in the detailed report.
    sites_by_vlan = {}
    for observation in all_observations:
        sites_by_vlan.setdefault(str(observation["VLAN"]), set()).add(
            observation["Site"]
        )

    for row in all_rows:
        vlan_id = str(row.get("VLAN", ""))
        if not vlan_id.isdigit():
            continue
        candidate, confidence, basis = stretch_assessment(
            vlan_id,
            row.get("VLAN Name", ""),
            sites_by_vlan.get(vlan_id, set()),
        )
        row["Stretch Candidate"] = candidate
        row["Stretch Confidence"] = confidence
        row["Stretch Basis"] = basis

    down_not_shutdown = [
        (row["Device"], row["Interface"])
        for row in all_rows
        if row["Operational Status"].lower() == "down"
        and row["Admin Status"].lower() not in {"admin down", "shutdown"}
    ]

    write_inventory_csv(args.inventory_csv, all_rows)
    write_stretch_csv(args.stretch_csv, all_observations)

    print(f"\nDetailed inventory written to {args.inventory_csv}")
    print(f"VLAN stretch analysis written to {args.stretch_csv}")
    print(f"Devices processed: {len(hosts)}")
    print(f"Interfaces processed: {len(all_rows)}")
    print(f"VLANs observed: {len({o['VLAN'] for o in all_observations})}")
    print(f"Down ports not shutdown: {len(down_not_shutdown)}")


if __name__ == "__main__":
    main()
