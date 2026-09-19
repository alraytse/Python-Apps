#!/usr/bin/env python3
"""
Report-only VLAN/SVI audit.

Prompts for a CSV export and reports VLANs and SVIs whose traffic, ARP,
and MAC activity are all zero. No network devices are contacted or changed.

The script accepts common column names such as:
  VLAN ID / VLAN / VLAN Number
  VLAN Name
  SVI / SVI Interface / Interface
  Traffic / Traffic Count / RX Bytes / TX Bytes
  ARP / ARP Count / ARP Entries
  MAC / MAC Count / MAC Addresses
"""

from __future__ import annotations

import csv
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


COLUMN_ALIASES = {
    "vlan_id": (
        "vlan id",
        "vlan_id",
        "vlanid",
        "vlan number",
        "vlan_number",
        "vlan",
    ),
    "vlan_name": (
        "vlan name",
        "vlan_name",
        "vlanname",
        "name",
    ),
    "svi": (
        "svi",
        "svi interface",
        "svi_interface",
        "svi name",
        "svi_name",
        "interface",
        "interface name",
        "interface_name",
    ),
    "traffic": (
        "traffic",
        "traffic count",
        "traffic_count",
        "traffic 24h",
        "traffic_24h",
        "traffic bytes",
        "traffic_bytes",
        "bytes",
    ),
    "rx": (
        "rx",
        "rx bytes",
        "rx_bytes",
        "received bytes",
        "received_bytes",
    ),
    "tx": (
        "tx",
        "tx bytes",
        "tx_bytes",
        "transmitted bytes",
        "transmitted_bytes",
    ),
    "arp": (
        "arp",
        "arp count",
        "arp_count",
        "arp entries",
        "arp_entries",
        "arp table count",
        "arp_table_count",
    ),
    "mac": (
        "mac",
        "mac count",
        "mac_count",
        "mac addresses",
        "mac_addresses",
        "mac address count",
        "mac_address_count",
    ),
}

ZERO_TEXT = {
    "",
    "0",
    "0.0",
    "0.00",
    "none",
    "no",
    "false",
    "inactive",
    "down",
    "disabled",
    "not available",
    "n/a",
    "na",
    "-",
}


class AuditError(Exception):
    """Raised for a user-correctable CSV or input problem."""


def normalize(text: str) -> str:
    """Normalize a header or value for comparison."""
    return re.sub(r"[^a-z0-9]+", " ", str(text).strip().lower()).strip()


def clean_entity_value(value: object) -> str:
    """Return an empty string for common placeholder entity values."""
    text = "" if value is None else str(value).strip()
    if normalize(text) in {"", "none", "n a", "na", "not available", "-"}:
        return ""
    return text


def find_column(fieldnames: Sequence[str], aliases: Iterable[str]) -> Optional[str]:
    """Find a CSV column using normalized aliases."""
    normalized = {normalize(name): name for name in fieldnames if name}
    for alias in aliases:
        match = normalized.get(normalize(alias))
        if match:
            return match
    return None


def parse_is_zero(value: object) -> bool:
    """Return True only when a value clearly represents zero/no activity."""
    if value is None:
        return True

    text = str(value).strip().lower()
    if text in ZERO_TEXT:
        return True

    # Handles values such as "0 bytes", "0 packets", and "0.0 entries".
    compact = text.replace(",", "")
    numeric_match = re.fullmatch(r"0+(?:\.0+)?(?:\s*[a-z%/]+)?", compact)
    if numeric_match:
        return True

    # Handles values such as "no traffic" or "0 packets (none)".
    if re.search(r"\b(no|none|zero|inactive|disabled)\b", text):
        return True

    return False


def row_activity_is_zero(row: Dict[str, str], columns: Sequence[str]) -> bool:
    """Require every selected activity column in a row to be zero."""
    return bool(columns) and all(parse_is_zero(row.get(column, "")) for column in columns)


def prompt_for_csv() -> Path:
    """Prompt until the user provides an existing CSV file."""
    while True:
        raw_path = input("Enter the path to the VLAN/SVI CSV file: ").strip().strip('"')
        if not raw_path:
            print("A CSV path is required.")
            continue

        path = Path(raw_path).expanduser()
        if not path.is_file():
            print(f"File not found: {path}")
            continue
        if path.suffix.lower() != ".csv":
            print("The input file must have a .csv extension.")
            continue
        return path


def open_csv_rows(path: Path) -> Tuple[List[str], List[Dict[str, str]]]:
    """Read CSV headers and rows, detecting the delimiter when possible."""
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.read(8192)
            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(handle, dialect=dialect)
            if not reader.fieldnames:
                raise AuditError("The CSV does not contain a header row.")
            rows = [row for row in reader if any(str(value or "").strip() for value in row.values())]
            return list(reader.fieldnames), rows
    except UnicodeDecodeError as exc:
        raise AuditError("The CSV is not UTF-8 encoded. Export it as UTF-8 and try again.") from exc
    except OSError as exc:
        raise AuditError(f"Unable to read the CSV: {exc}") from exc


def build_column_map(fieldnames: Sequence[str]) -> Dict[str, Optional[str]]:
    """Resolve the logical fields used by the audit to actual CSV columns."""
    return {key: find_column(fieldnames, aliases) for key, aliases in COLUMN_ALIASES.items()}


def validate_columns(column_map: Dict[str, Optional[str]]) -> None:
    """Validate that the CSV contains enough fields for the audit."""
    missing = [key.upper() for key in ("vlan_id", "svi", "arp", "mac") if not column_map.get(key)]
    has_traffic = column_map.get("traffic") or (column_map.get("rx") and column_map.get("tx"))
    if not has_traffic:
        missing.append("TRAFFIC (or both RX and TX)")

    if missing:
        missing_text = ", ".join(missing)
        raise AuditError(
            "Required columns were not found: "
            f"{missing_text}.\n"
            "Rename the CSV headers to common names such as VLAN ID, SVI, Traffic, ARP Count, and MAC Count."
        )


def activity_columns(column_map: Dict[str, Optional[str]]) -> Dict[str, List[str]]:
    """Return the actual columns used for each activity type."""
    traffic_columns = [column_map["traffic"]] if column_map.get("traffic") else [
        column_map["rx"],
        column_map["tx"],
    ]
    return {
        "traffic": [column for column in traffic_columns if column],
        "arp": [column_map["arp"]] if column_map.get("arp") else [],
        "mac": [column_map["mac"]] if column_map.get("mac") else [],
    }


def audit_rows(
    rows: Sequence[Dict[str, str]],
    column_map: Dict[str, Optional[str]],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Aggregate rows by VLAN and SVI so any active row prevents a false positive."""
    activity = activity_columns(column_map)
    vlan_results: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
    svi_results: "OrderedDict[str, Dict[str, object]]" = OrderedDict()

    for row_number, row in enumerate(rows, start=2):
        vlan_id = clean_entity_value(row.get(column_map["vlan_id"] or "", ""))
        vlan_name = clean_entity_value(row.get(column_map["vlan_name"] or "", ""))
        svi = clean_entity_value(row.get(column_map["svi"] or "", ""))

        row_state = {
            "traffic_zero": row_activity_is_zero(row, activity["traffic"]),
            "arp_zero": row_activity_is_zero(row, activity["arp"]),
            "mac_zero": row_activity_is_zero(row, activity["mac"]),
        }

        if vlan_id or vlan_name:
            vlan_key = vlan_id or f"name:{vlan_name.lower()}"
            if vlan_key not in vlan_results:
                vlan_results[vlan_key] = {
                    "vlan_id": vlan_id,
                    "vlan_name": vlan_name,
                    "svi": svi,
                    "source_rows": [],
                    **row_state,
                }
            result = vlan_results[vlan_key]
            for key in ("traffic_zero", "arp_zero", "mac_zero"):
                result[key] = bool(result[key]) and bool(row_state[key])
            if not result["vlan_name"] and vlan_name:
                result["vlan_name"] = vlan_name
            if not result["svi"] and svi:
                result["svi"] = svi
            result["source_rows"].append(str(row_number))

        if svi:
            svi_key = svi.lower()
            if svi_key not in svi_results:
                svi_results[svi_key] = {
                    "vlan_id": vlan_id,
                    "vlan_name": vlan_name,
                    "svi": svi,
                    "source_rows": [],
                    **row_state,
                }
            result = svi_results[svi_key]
            for key in ("traffic_zero", "arp_zero", "mac_zero"):
                result[key] = bool(result[key]) and bool(row_state[key])
            if not result["vlan_id"] and vlan_id:
                result["vlan_id"] = vlan_id
            if not result["vlan_name"] and vlan_name:
                result["vlan_name"] = vlan_name
            result["source_rows"].append(str(row_number))

    def only_zero(items: Iterable[Dict[str, object]]) -> List[Dict[str, str]]:
        matches = []
        for item in items:
            if all(item[key] for key in ("traffic_zero", "arp_zero", "mac_zero")):
                matches.append(
                    {
                        "vlan_id": str(item["vlan_id"]),
                        "vlan_name": str(item["vlan_name"]),
                        "svi": str(item["svi"]),
                        "source_rows": ",".join(item["source_rows"]),
                    }
                )
        return matches

    return only_zero(vlan_results.values()), only_zero(svi_results.values())


def write_report(path: Path, vlan_matches: Sequence[Dict[str, str]], svi_matches: Sequence[Dict[str, str]]) -> Path:
    """Write the report-only results beside the input CSV."""
    report_path = path.with_name(f"{path.stem}_unused_vlans_svis.csv")
    fieldnames = ["type", "vlan_id", "vlan_name", "svi", "source_rows"]
    with report_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for match in vlan_matches:
            writer.writerow({"type": "VLAN", **match})
        for match in svi_matches:
            writer.writerow({"type": "SVI", **match})
    return report_path


def print_results(vlan_matches: Sequence[Dict[str, str]], svi_matches: Sequence[Dict[str, str]]) -> None:
    """Print a concise human-readable report."""
    print("\nVLANs with no traffic, no ARP, and no MAC activity:")
    if vlan_matches:
        for match in vlan_matches:
            label = match["vlan_id"] or match["vlan_name"] or "(unnamed VLAN)"
            details = f" - {match['vlan_name']}" if match["vlan_name"] else ""
            print(f"  VLAN {label}{details}")
    else:
        print("  None found.")

    print("\nSVIs with no traffic, no ARP, and no MAC activity:")
    if svi_matches:
        for match in svi_matches:
            print(f"  {match['svi']}")
    else:
        print("  None found.")

    print(f"\nTotal VLANs: {len(vlan_matches)}")
    print(f"Total SVIs:  {len(svi_matches)}")


def main() -> int:
    print("VLAN/SVI zero-activity audit (report-only; no configuration changes)\n")
    input_path = prompt_for_csv()

    try:
        fieldnames, rows = open_csv_rows(input_path)
        column_map = build_column_map(fieldnames)
        validate_columns(column_map)
        vlan_matches, svi_matches = audit_rows(rows, column_map)
        report_path = write_report(input_path, vlan_matches, svi_matches)
    except AuditError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        return 1

    print("\nDetected columns:")
    for key, value in column_map.items():
        if value:
            print(f"  {key}: {value}")
    print_results(vlan_matches, svi_matches)
    print(f"\nCSV report written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
