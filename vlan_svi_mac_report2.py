#!/usr/bin/env python3

import csv
import getpass
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


CSV_FILE = "vlan_svi_mac_report.csv"
MAX_MAC_COUNT = 2

PHYSICAL_INTERFACE_RE = (
    r"(?:Eth(?:ernet)?\d+(?:/\d+){1,3}|"
    r"Gi(?:gabitEthernet)?\d+(?:/\d+){1,3}|"
    r"Te(?:nGigabitEthernet)?\d+(?:/\d+){1,3}|"
    r"Po(?:rt-channel)?\d+)"
)
SVI_INTERFACE_RE = r"Vlan\d+"

VLAN_STATUS_RE = (
    r"active|act/unsup|act/lshut|suspended|suspend|shutdown|"
    r"sus/lshut|act/unchecked"
)


FIELDS = [
    "Device",
    "Management IP",
    "Record Type",
    "Interface",
    "VLAN",
    "VLAN Name",
    "VLAN Status",
    "SVI IP Address",
    "SVI Physical Status",
    "SVI Protocol Status",
    "MAC Count",
    "MAC Addresses",
    "MAC Vendor",
    "Connected Ports",
    "Configured Port Membership",
    "Description",
    "Notes",
]


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


def interface_sort_key(interface):
    numbers = tuple(int(value) for value in re.findall(r"\d+", interface))
    return (interface.lower().startswith("po"), numbers, interface)


def find_vlan_id(value):
    match = re.search(r"\b(\d+)\b", value or "")
    return match.group(1) if match else ""


def expand_vlan_expression(value):
    """Expand a VLAN list such as '20,30-32' into VLAN ID strings."""
    vlan_ids = set()

    for token in re.split(r"[,\s]+", value or ""):
        token = token.strip().strip("()")
        if not token or token.lower() in {"none", "all"}:
            continue

        range_match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", token)
        if range_match:
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            if start <= end and end - start <= 4094:
                vlan_ids.update(str(number) for number in range(start, end + 1))
            continue

        if token.isdigit():
            vlan_ids.add(token)

    return vlan_ids


def find_vendor_from_values(values):
    vendors = [
        ("Apple", r"APPLE"),
        ("Arista", r"ARISTA"),
        ("Cisco", r"CISCO"),
        ("Dell", r"DELL"),
        ("Fortinet", r"FORTINET"),
        ("Hewlett-Packard", r"HEWLETT[- ]PACKARD|HP INC"),
        ("Juniper", r"JUNIPER"),
        ("Microsoft", r"MICROSOFT"),
        ("Palo Alto Networks", r"PALO ALTO|PALOALTO"),
        ("Ubiquiti", r"UBIQUITI"),
        ("VMware", r"VMWARE"),
    ]

    text = " ".join(values).upper()
    for vendor, pattern in vendors:
        if re.search(pattern, text):
            return vendor

    return "Unknown"


def parse_show_vlan_brief(output):
    """Return VLAN records and access-port membership from show vlan brief."""
    vlans = {}
    current_vlan = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        match = re.match(
            rf"^\s*(?P<vlan_id>\d+)\s+"
            rf"(?P<name>.*?)\s+"
            rf"(?P<status>{VLAN_STATUS_RE})"
            rf"(?:\s+(?P<ports>.*?))?\s*$",
            line,
            re.IGNORECASE,
        )

        if match:
            vlan_id = match.group("vlan_id")
            ports = {
                normalize_interface_name(port)
                for port in re.findall(
                    rf"\b(?P<interface>{PHYSICAL_INTERFACE_RE})\b",
                    match.group("ports") or "",
                    re.IGNORECASE,
                )
            }
            vlans[vlan_id] = {
                "name": match.group("name").strip(),
                "status": match.group("status"),
                "ports": ports,
            }
            current_vlan = vlan_id
            continue

        if current_vlan and line.strip():
            continuation_ports = {
                normalize_interface_name(port)
                for port in re.findall(
                    rf"\b(?P<interface>{PHYSICAL_INTERFACE_RE})\b",
                    line,
                    re.IGNORECASE,
                )
            }
            vlans[current_vlan]["ports"].update(continuation_ports)

    return vlans


def parse_svi_status(output):
    """Return SVI IP and operational status from show ip interface brief."""
    svis = {}

    for raw_line in output.splitlines():
        parts = raw_line.strip().split()
        if len(parts) < 4 or not re.fullmatch(SVI_INTERFACE_RE, parts[0], re.IGNORECASE):
            continue

        interface = parts[0]
        svis[interface] = {
            "ip_address": parts[1],
            "physical_status": parts[-2],
            "protocol_status": parts[-1],
        }

    return svis


def parse_svi_descriptions(output):
    """Return descriptions and admin/oper state for Vlan<number> interfaces."""
    descriptions = {}

    for raw_line in output.splitlines():
        parts = raw_line.strip().split(maxsplit=3)
        if len(parts) < 3 or not re.fullmatch(SVI_INTERFACE_RE, parts[0], re.IGNORECASE):
            continue

        descriptions[parts[0]] = {
            "admin": parts[1],
            "oper": parts[2],
            "description": parts[3] if len(parts) == 4 else "",
        }

    return descriptions


def parse_interface_switchport(output):
    """Return configured access/trunk VLAN membership by physical interface."""
    results = {}
    blocks = re.split(r"(?=^\s*Name:\s*)", output, flags=re.MULTILINE)

    for block in blocks:
        name_match = re.search(
            rf"^\s*Name:\s*(?P<interface>{PHYSICAL_INTERFACE_RE})\b",
            block,
            re.IGNORECASE | re.MULTILINE,
        )
        if not name_match:
            continue

        interface = normalize_interface_name(name_match.group("interface"))
        mode = ""
        access_vlan = ""
        native_vlan = ""
        allowed_vlan_text = []
        collecting_allowed = False

        for raw_line in block.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            mode_match = re.match(r"Operational Mode:\s*(.+)$", line, re.IGNORECASE)
            if mode_match:
                mode = mode_match.group(1).strip()
                collecting_allowed = False
                continue

            access_match = re.match(r"Access Mode VLAN:\s*(.+)$", line, re.IGNORECASE)
            if access_match:
                access_vlan = find_vlan_id(access_match.group(1))
                collecting_allowed = False
                continue

            native_match = re.match(
                r"Trunking Native Mode VLAN:\s*(.+)$",
                line,
                re.IGNORECASE,
            )
            if native_match:
                native_vlan = find_vlan_id(native_match.group(1))
                collecting_allowed = False
                continue

            allowed_match = re.match(
                r"Trunking VLANs Enabled:\s*(.*)$",
                line,
                re.IGNORECASE,
            )
            if allowed_match:
                allowed_vlan_text.append(allowed_match.group(1).strip())
                collecting_allowed = True
                continue

            if collecting_allowed:
                if re.match(r"^[A-Za-z][A-Za-z ]*:\s*", line):
                    collecting_allowed = False
                else:
                    allowed_vlan_text.append(line)

        mode_lower = mode.lower()
        configured_vlans = set()
        if "access" in mode_lower and "trunk" not in mode_lower:
            configured_vlans.update(expand_vlan_expression(access_vlan))
        elif "trunk" in mode_lower:
            configured_vlans.update(expand_vlan_expression(native_vlan))
            configured_vlans.update(expand_vlan_expression(" ".join(allowed_vlan_text)))

        results[interface] = {
            "mode": mode,
            "configured_vlans": configured_vlans,
        }

    return results


def parse_mac_table(output):
    """Return learned MAC details grouped by VLAN ID."""
    mac_data = {}

    for line in output.splitlines():
        mac_match = re.search(
            r"\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b",
            line,
            re.IGNORECASE,
        )
        if not mac_match:
            continue

        prefix_numbers = re.findall(r"(?<![\w/])\d+(?![\w/])", line[:mac_match.start()])
        if not prefix_numbers:
            continue
        vlan_id = prefix_numbers[-1]

        interface_match = re.search(
            rf"\b(?P<interface>{PHYSICAL_INTERFACE_RE})\b",
            line,
            re.IGNORECASE,
        )
        if not interface_match:
            continue

        interface = normalize_interface_name(interface_match.group("interface"))
        mac_address = mac_match.group(0).lower()
        mac_data.setdefault(vlan_id, []).append(
            {
                "address": mac_address,
                "interface": interface,
                "vendor": lookup_mac_vendor(mac_address),
            }
        )

    return mac_data


def lookup_mac_vendor(mac_address):
    """Return the manufacturer associated with a MAC OUI when available."""
    if _MAC_LOOKUP is None:
        return "Unknown"

    try:
        return _MAC_LOOKUP.lookup(mac_address)
    except Exception:
        return "Unknown"


def build_mac_fields(mac_entries):
    mac_count = len(mac_entries)
    addresses = ", ".join(entry["address"] for entry in mac_entries)
    vendors = sorted(
        {
            entry["vendor"]
            for entry in mac_entries
            if entry["vendor"] != "Unknown"
        }
    )
    ports = sorted(
        {entry["interface"] for entry in mac_entries},
        key=interface_sort_key,
    )

    return {
        "count": mac_count,
        "addresses": addresses if mac_count <= MAX_MAC_COUNT else "",
        "vendor": "; ".join(vendors) if vendors else "Unknown",
        "ports": ", ".join(ports),
    }


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

        show_vlan = conn.send_command("show vlan brief", read_timeout=60)
        show_svi = conn.send_command("show ip interface brief", read_timeout=60)
        show_desc = conn.send_command("show interface description", read_timeout=60)
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
        print(f"{hostname}: authentication failed.", file=sys.stderr)
        return []
    except NetmikoTimeoutException:
        print(f"{hostname}: connection timed out.", file=sys.stderr)
        return []
    except Exception as exc:
        print(f"{hostname}: connection or command failure: {exc}", file=sys.stderr)
        return []
    finally:
        if conn:
            conn.disconnect()

    vlan_data = parse_show_vlan_brief(show_vlan)
    svi_data = parse_svi_status(show_svi)
    svi_descriptions = parse_svi_descriptions(show_desc)
    switchport_data = parse_interface_switchport(show_switchport)
    mac_data = parse_mac_table(show_mac)

    configured_membership = {vlan_id: set() for vlan_id in vlan_data}
    for vlan_id, vlan in vlan_data.items():
        configured_membership[vlan_id].update(vlan["ports"])

    for interface, switchport in switchport_data.items():
        for vlan_id in switchport["configured_vlans"]:
            configured_membership.setdefault(vlan_id, set()).add(interface)

    svi_by_vlan = {}
    for interface in svi_data:
        vlan_id = find_vlan_id(interface)
        if vlan_id:
            svi_by_vlan[vlan_id] = interface

    rows = []

    def base_row(record_type, interface, vlan_id, vlan):
        mac_fields = build_mac_fields(mac_data.get(vlan_id, []))
        membership = sorted(
            configured_membership.get(vlan_id, set()),
            key=interface_sort_key,
        )
        return {
            "Device": hostname,
            "Management IP": mgmt_ip,
            "Record Type": record_type,
            "Interface": interface,
            "VLAN": vlan_id,
            "VLAN Name": vlan.get("name", ""),
            "VLAN Status": vlan.get("status", ""),
            "SVI IP Address": "",
            "SVI Physical Status": "",
            "SVI Protocol Status": "",
            "MAC Count": mac_fields["count"],
            "MAC Addresses": mac_fields["addresses"],
            "MAC Vendor": mac_fields["vendor"],
            "Connected Ports": mac_fields["ports"],
            "Configured Port Membership": ", ".join(membership),
            "Description": "",
            "Notes": "",
        }

    # Report VLANs only when there is no SVI, no configured access/trunk
    # membership, and no more than two learned MAC addresses.
    for vlan_id, vlan in vlan_data.items():
        if vlan_id in svi_by_vlan:
            continue

        row = base_row("VLAN", "", vlan_id, vlan)
        if row["MAC Count"] > MAX_MAC_COUNT:
            continue
        if row["Configured Port Membership"]:
            continue

        row["Notes"] = "Unused VLAN; no SVI or configured access/trunk membership"
        rows.append(row)

    # Report SVIs only when their VLAN has no configured access/trunk
    # membership and no more than two learned MAC addresses.
    for vlan_id, interface in svi_by_vlan.items():
        vlan = vlan_data.get(
            vlan_id,
            {"name": "", "status": ""},
        )
        row = base_row("SVI", interface, vlan_id, vlan)
        svi_status = svi_data.get(interface, {})
        description = svi_descriptions.get(interface, {})
        row["SVI IP Address"] = svi_status.get("ip_address", "")
        row["SVI Physical Status"] = svi_status.get("physical_status", "")
        row["SVI Protocol Status"] = svi_status.get("protocol_status", "")
        row["Description"] = description.get("description", "")

        if row["MAC Count"] > MAX_MAC_COUNT:
            continue
        if row["Configured Port Membership"]:
            continue

        row["Notes"] = "Unused SVI; no configured access/trunk membership"
        rows.append(row)

    return sorted(
        rows,
        key=lambda row: (
            row["Device"].lower(),
            row["VLAN"] if row["VLAN"].isdigit() else "999999",
            row["Record Type"],
        ),
    )


def main():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    host_input = input("Switch Hostname/IP(s), comma-delimited: ")

    hostnames = [
        hostname.strip()
        for hostname in host_input.split(",")
        if hostname.strip()
    ]

    if not hostnames:
        print("No hostnames provided.", file=sys.stderr)
        sys.exit(1)

    max_workers = min(10, len(hostnames))
    rows_by_host = [None] * len(hostnames)

    print(
        f"Starting VLAN/SVI collection for {len(hostnames)} device(s) "
        f"using {max_workers} worker(s)..."
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(collect_host, hostname, username, password): index
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

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nCSV written to {CSV_FILE}")
    print(f"Devices processed: {len(hostnames)}")
    print(f"VLAN/SVI records written: {len(all_rows)}")


if __name__ == "__main__":
    main()
