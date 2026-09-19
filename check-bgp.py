#!/usr/bin/env python3

import csv
import getpass
import ipaddress
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from netmiko import ConnectHandler

SUMMARY_COMMANDS = [
    "show ip bgp summary vrf all",
    "show ip bgp summary",
]

CONFIG_COMMAND = "show running-config | section bgp"

UNSUPPORTED_COMMAND_MARKERS = (
    "% Invalid",
    "% Incomplete",
    "Invalid command",
    "Invalid input",
    "Ambiguous command",
    "Unknown command",
    "not supported",
)

OUTPUT_CSV = "bgp_idle_neighbors.csv"
OUTPUT_MOP = "BGP_Idle_Neighbor_Shutdown_MOP.csv"
DEFAULT_DEVICE_TYPE = "cisco_ios"
MAX_WORKERS = 10

BGP_STATE_PATTERN = re.compile(
    r"\b(Idle(?:\s+\(Admin\))?|Active|Connect|OpenSent|"
    r"OpenConfirm|Closing|Established)\b",
    re.IGNORECASE,
)

class BgpCollectionError(Exception):
    """Raised when a switch cannot be audited successfully."""

def parse_valid_asn(value):
    """
    Validate and return a decimal or Cisco asdot ASN.

    Valid range:
        1–4,294,967,295
    """

    value = str(value).strip()

    if not value or value.upper() in {"NAN", "UNKNOWN", "NOT_FOUND"}:
        return None

    match = re.fullmatch(
        r"(?:router\s+bgp\s+)?(\d+(?:\.\d+)?)",
        value,
        re.IGNORECASE,
    )

    if not match:
        return None

    asn = match.group(1)

    if re.fullmatch(r"\d+", asn):
        numeric_asn = int(asn)

        if 1 <= numeric_asn <= 4_294_967_295:
            return asn

        return None

    asdot_match = re.fullmatch(r"(\d+)\.(\d+)", asn)

    if not asdot_match:
        return None

    high = int(asdot_match.group(1))
    low = int(asdot_match.group(2))

    if high > 65_535 or low > 65_535:
        return None

    numeric_asn = (high * 65_536) + low

    if 1 <= numeric_asn <= 4_294_967_295:
        return asn

    return None

def get_hostname(connection):
    try:
        return connection.find_prompt().rstrip("#>").strip() or "UNKNOWN"
    except Exception:
        return "UNKNOWN"

def is_ip_address(value):
    value = value.strip().strip("*+sdh>x").rstrip(",")

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def clean_neighbor(value):
    return value.strip().strip("*+sdh>x").rstrip(",")

def extract_vrf(line, current_vrf):
    """Extract VRF names from common IOS and NX-OS summary headers."""

    patterns = [
        r"\bfor\s+VRF\s+[\"']?([^\"',\s]+)",
        r"\bVRF\s*[:=]\s*[\"']?([^\"',\s]+)",
        r"^\s*VRF\s+[\"']([^\"']+)[\"']",
    ]

    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)

        if match:
            return match.group(1).strip()

    return current_vrf

def get_bgp_summary(connection, hostname):
    """Try the all-VRF command, then fall back to the default summary."""

    for command in SUMMARY_COMMANDS:
        try:
            output = connection.send_command(
                command,
                read_timeout=60,
            )
        except Exception:
            continue

        if not output or any(
            marker.lower() in output.lower()
            for marker in UNSUPPORTED_COMMAND_MARKERS
        ):
            continue

        if command != SUMMARY_COMMANDS[0]:
            print(
                f"[INFO] {hostname}: VRF summary unsupported; "
                f"using {command}"
            )

        return command, output

    return None, None

def parse_bgp_summary(hostname, device_ip, output):
    """Parse Idle BGP neighbors from BGP summary output."""

    records = []
    current_vrf = "default"

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        current_vrf = extract_vrf(line, current_vrf)

        fields = line.split()

        if not fields:
            continue

        neighbor = clean_neighbor(fields[0])

        if not is_ip_address(neighbor):
            continue

        if len(fields) < 3:
            continue

        remote_as = fields[2]
        state_text = " ".join(fields[-3:])
        state_match = BGP_STATE_PATTERN.search(state_text)

        if state_match:
            state = state_match.group(1)
            prefixes_received = ""
        elif fields[-1].isdigit():
            state = "Established"
            prefixes_received = fields[-1]
        else:
            state = fields[-1]
            prefixes_received = ""

        if (
            state.lower() != "idle"
            and not state.lower().startswith("idle ")
        ):
            continue

        records.append(
            {
                "device": hostname,
                "management_ip": device_ip,
                "vrf": current_vrf,
                "neighbor": neighbor,
                "remote_as": remote_as,
                "state": state,
                "prefixes_received": prefixes_received,
                "raw_line": line,
            }
        )

    return records

def parse_bgp_config(output):
    """Extract the validated BGP ASN and neighbor contexts."""

    router_bgp = None
    local_asn = None
    neighbor_contexts = defaultdict(set)
    current_context = "global"

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        router_match = re.match(
            r"^router\s+bgp\s+(\d+(?:\.\d+)?)\s*$",
            stripped,
            re.IGNORECASE,
        )

        if router_match:
            candidate_asn = parse_valid_asn(
                router_match.group(1)
            )

            if candidate_asn:
                local_asn = candidate_asn
                router_bgp = f"router bgp {candidate_asn}"
            else:
                router_bgp = None
                local_asn = None

            current_context = "global"
            continue

        address_family_match = re.match(
            r"^address-family\s+(.+)$",
            stripped,
            re.IGNORECASE,
        )

        if address_family_match:
            current_context = (
                f"address-family "
                f"{address_family_match.group(1).strip()}"
            )
            continue

        if re.match(
            r"^exit-address-family\s*$",
            stripped,
            re.IGNORECASE,
        ):
            current_context = "global"
            continue

        neighbor_match = re.match(
            r"^neighbor\s+(\S+)\s+",
            stripped,
            re.IGNORECASE,
        )

        if neighbor_match:
            neighbor = clean_neighbor(
                neighbor_match.group(1)
            )

            if is_ip_address(neighbor):
                neighbor_contexts[neighbor].add(
                    current_context
                )

    return router_bgp, local_asn, neighbor_contexts

def collect_device(device_ip, username, password):
    """Collect BGP summary and configuration from one switch."""

    device = {
        "device_type": DEFAULT_DEVICE_TYPE,
        "host": device_ip,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    connection = None

    try:
        connection = ConnectHandler(**device)
        hostname = get_hostname(connection)

        print(
            f"[INFO] Connected to {hostname} ({device_ip})"
        )

        summary_command, summary_output = get_bgp_summary(
            connection,
            hostname,
        )

        if not summary_output:
            raise BgpCollectionError(
                f"{hostname}: no supported BGP summary command succeeded"
            )

        config_output = connection.send_command(
            CONFIG_COMMAND,
            read_timeout=60,
        )

        idle_neighbors = parse_bgp_summary(
            hostname,
            device_ip,
            summary_output,
        )

        router_bgp, local_asn, neighbor_contexts = parse_bgp_config(
            config_output
        )

        for record in idle_neighbors:
            record["router_bgp"] = (
                router_bgp
                or "NOT_FOUND"
            )

            record["local_asn"] = (
                local_asn
                or "UNKNOWN"
            )

            record["contexts"] = sorted(
                neighbor_contexts.get(
                    record["neighbor"],
                    {"global"},
                )
            )

        return idle_neighbors

    except Exception as exc:
        raise BgpCollectionError(
            f"{device_ip}: {exc}"
        ) from exc

    finally:
        if connection:
            connection.disconnect()

def write_csv(records):
    fieldnames = [
        "device",
        "management_ip",
        "vrf",
        "router_bgp",
        "local_asn",
        "neighbor",
        "remote_as",
        "state",
        "prefixes_received",
        "raw_line",
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for record in records:
            writer.writerow(
                {
                    field: record.get(field, "")
                    for field in fieldnames
                }
            )

def write_mop(records):
    """Write implementation and rollback instructions as CSV rows."""

    grouped_records = defaultdict(list)

    for record in records:
        grouped_records[record["device"]].append(record)

    fieldnames = [
        "section",
        "device",
        "vrf",
        "local_asn",
        "router_bgp",
        "neighbor",
        "remote_as",
        "state",
        "action",
        "command",
        "notes",
    ]

    with open(
        OUTPUT_MOP,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerow(
            {
                "section": "Metadata",
                "action": "Generated",
                "notes": (
                    f"{datetime.now():%Y-%m-%d %H:%M:%S}; "
                    "REPORT ONLY - NO CONFIGURATION CHANGES EXECUTED"
                ),
            }
        )

        writer.writerow(
            {
                "section": "Purpose",
                "action": "Review",
                "notes": (
                    "Identify BGP neighbors reporting Idle and provide "
                    "manual shutdown and rollback commands."
                ),
            }
        )

        pre_change_commands = [
            "show clock",
            "show ip bgp summary vrf all",
            "show ip bgp summary",
            "show running-config | section bgp",
            "show logging last 100",
        ]

        for command in pre_change_commands:
            writer.writerow(
                {
                    "section": "Pre-Change Validation",
                    "action": "Validate",
                    "command": command,
                }
            )

        for record in records:
            writer.writerow(
                {
                    "section": "Idle Neighbor Identified",
                    "device": record["device"],
                    "vrf": record["vrf"],
                    "local_asn": record.get(
                        "local_asn",
                        "",
                    ),
                    "router_bgp": record.get(
                        "router_bgp",
                        "",
                    ),
                    "neighbor": record["neighbor"],
                    "remote_as": record["remote_as"],
                    "state": record["state"],
                    "action": "Review",
                    "notes": record["raw_line"],
                }
            )

        for device in sorted(grouped_records):
            device_records = grouped_records[device]

            local_asns = {
                record.get(
                    "local_asn",
                    "UNKNOWN",
                )
                for record in device_records
            }

            valid_asns = {
                asn
                for asn in local_asns
                if parse_valid_asn(asn)
            }

            if len(valid_asns) != 1:
                writer.writerow(
                    {
                        "section": "Implementation",
                        "device": device,
                        "action": "Manual Review Required",
                        "notes": (
                            "Valid local ASN was not uniquely determined; "
                            "no configuration commands generated."
                        ),
                    }
                )

                writer.writerow(
                    {
                        "section": "Rollback",
                        "device": device,
                        "action": "Manual Review Required",
                        "notes": (
                            "Valid local ASN was not uniquely determined; "
                            "manual rollback required."
                        ),
                    }
                )

                continue

            local_asn = next(iter(valid_asns))
            router_bgp = f"router bgp {local_asn}"

            for record in device_records:
                contexts = record.get(
                    "contexts",
                    ["global"],
                )

                for context in contexts:
                    writer.writerow(
                        {
                            "section": "Implementation",
                            "device": device,
                            "vrf": record["vrf"],
                            "local_asn": local_asn,
                            "router_bgp": router_bgp,
                            "neighbor": record["neighbor"],
                            "remote_as": record["remote_as"],
                            "state": record["state"],
                            "action": "Shutdown",
                            "command": (
                                f"{context}; neighbor "
                                f"{record['neighbor']} shutdown"
                            ),
                            "notes": (
                                "Review before execution. Context was "
                                "inferred from the BGP configuration."
                            ),
                        }
                    )

                    writer.writerow(
                        {
                            "section": "Rollback",
                            "device": device,
                            "vrf": record["vrf"],
                            "local_asn": local_asn,
                            "router_bgp": router_bgp,
                            "neighbor": record["neighbor"],
                            "remote_as": record["remote_as"],
                            "state": record["state"],
                            "action": "Remove Shutdown",
                            "command": (
                                f"{context}; no neighbor "
                                f"{record['neighbor']} shutdown"
                            ),
                            "notes": (
                                "Use only if rollback is approved."
                            ),
                        }
                    )

        post_change_commands = [
            "show ip bgp summary vrf all",
            "show ip bgp summary",
            "show running-config | section bgp",
            "show logging last 100",
        ]

        for command in post_change_commands:
            writer.writerow(
                {
                    "section": "Post-Change Validation",
                    "action": "Validate",
                    "command": command,
                }
            )

        for command in post_change_commands:
            writer.writerow(
                {
                    "section": "Post-Rollback Validation",
                    "action": "Validate",
                    "command": command,
                }
            )

def main():
    print("\n========================================")
    print("BGP Idle Neighbor Audit and MOP Tool")
    print("========================================\n")

    username = input("User ID: ").strip()
    password = getpass.getpass("Password: ")

    switch_input = input(
        "Switch hostnames/IPs, comma-delimited: "
    )

    device_list = [
        device.strip()
        for device in switch_input.split(",")
        if device.strip()
    ]

    if not username:
        print("No user ID provided.")
        return

    if not device_list:
        print("No switches provided.")
        return

    all_records = []
    max_workers = min(
        MAX_WORKERS,
        len(device_list),
    )

    print(
        f"\nStarting collection from {len(device_list)} switch(es) "
        f"using {max_workers} worker(s)...\n"
    )

    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
        futures = {
            executor.submit(
                collect_device,
                device,
                username,
                password,
            ): device
            for device in device_list
        }

        for future in as_completed(futures):
            device = futures[future]

            try:
                all_records.extend(
                    future.result()
                )

            except BgpCollectionError as exc:
                print(f"[ERROR] {exc}")

            except Exception as exc:
                print(f"[ERROR] {device}: {exc}")

    all_records.sort(
        key=lambda record: (
            record["device"],
            record["vrf"],
            record["neighbor"],
        )
    )

    write_csv(all_records)
    write_mop(all_records)

    print("\n========================================")
    print("Collection Complete")
    print("========================================")
    print(f"Idle neighbors found: {len(all_records)}")
    print(f"CSV file created: {OUTPUT_CSV}")
    print(f"MOP file created: {OUTPUT_MOP}")
    print("No configuration changes were executed.")

if __name__ == "__main__":
    main()
