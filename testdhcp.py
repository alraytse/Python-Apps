#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import re
import sys

DEFAULT_OUTPUT = "filtered_infoblox_dhcp_networks.csv"

IP_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
CIDR_RE = rf"\b{IP_RE}/\d{{1,2}}\b"

DERIVED_FIELDS = [
    "Site Code",
    "IP Range",
    "Gateway",
    "DHCP Range",
    "Network Name or Comment",
    "Network View",
    "Filter Notes",
]

COLUMN_ALIASES = {
    "network": [
        "network",
        "network address",
        "network cidr",
        "cidr",
        "ip range",
        "subnet",
        "network range",
    ],
    "dhcp": [
        "dhcp range",
        "dhcp ranges",
        "range",
        "ranges",
        "dhcp_range",
        "start end",
        "start/end",
    ],
    "dhcp_start": [
        "dhcp start",
        "range start",
        "start ip",
        "start address",
        "start",
    ],
    "dhcp_end": [
        "dhcp end",
        "range end",
        "end ip",
        "end address",
        "end",
    ],
    "name": [
        "network name",
        "name",
        "network name or comment",
        "comment",
        "comments",
        "description",
        "network description",
    ],
    "gateway": [
        "gateway",
        "default gateway",
        "router",
        "routers",
        "default routers",
    ],
    "view": [
        "network view",
        "network_view",
        "view",
    ],
    "site": [
        "site code",
        "site",
        "site name",
    ],
}

def normalize_header(value):
    return re.sub(
        r"[^a-z0-9]+",
        " ",
        value or "",
    ).strip().lower()

def normalize_space(value):
    return re.sub(
        r"\s+",
        " ",
        value or "",
    ).strip()

def parse_ipv4(value):
    return ipaddress.ip_address(value)

def valid_ipv4(value):
    try:
        return parse_ipv4(value).version == 4
    except ValueError:
        return False

def find_column(fieldnames, aliases):
    normalized = {
        normalize_header(field): field
        for field in fieldnames
        if field
    }

    for alias in aliases:
        field = normalized.get(
            normalize_header(alias)
        )

        if field:
            return field

    return ""

def detect_columns(fieldnames):
    return {
        key: find_column(fieldnames, aliases)
        for key, aliases in COLUMN_ALIASES.items()
    }

def row_text(row):
    return " ".join(
        normalize_space(str(value))
        for value in row.values()
        if value is not None
        and normalize_space(str(value))
    )

def extract_cidr(text):
    match = re.search(
        CIDR_RE,
        text or "",
        re.IGNORECASE,
    )

    if not match:
        return ""

    try:
        return str(
            ipaddress.ip_network(
                match.group(0),
                strict=False,
            )
        )
    except ValueError:
        return ""

def extract_first_ip(text):
    for value in re.findall(
        IP_RE,
        text or "",
    ):
        if valid_ipv4(value):
            return value

    return ""

def extract_gateway(row, columns, combined_text):
    gateway_column = columns.get(
        "gateway",
        "",
    )

    if gateway_column:
        gateway = extract_first_ip(
            row.get(gateway_column, "")
        )

        if gateway:
            return gateway

    patterns = [
        rf"(?:default\s+gateway|gateway|routers?|router)"
        rf"\s*[:=]?\s*({IP_RE})",
        rf"({IP_RE})\s*(?:\([^)]*\))?\s*"
        rf"(?:default\s+gateway|gateway|router)\b",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            combined_text,
            re.IGNORECASE,
        )

        if match and valid_ipv4(match.group(1)):
            return match.group(1)

    return ""

def extract_site_code(row, columns, combined_text):
    site_column = columns.get(
        "site",
        "",
    )

    if site_column:
        site_value = normalize_space(
            row.get(site_column, "")
        )

        if site_value:
            return site_value

    labeled_patterns = [
        r"site\s*code\s*[:=]\s*([A-Za-z0-9_-]+)",
        r"site\s*[:=]\s*([A-Za-z0-9_-]+)",
    ]

    for pattern in labeled_patterns:
        match = re.search(
            pattern,
            combined_text,
            re.IGNORECASE,
        )

        if match:
            return match.group(1).strip()

    code_matches = re.findall(
        r"\b[A-Z]{2,8}\d{1,3}\b",
        combined_text.upper(),
    )

    for code in code_matches:
        if code != "USON":
            return code

    match = re.search(
        r"\bUSON[-_ ]([A-Z0-9][A-Z0-9_-]*)",
        combined_text,
        re.IGNORECASE,
    )

    if match:
        return match.group(1).strip("-_")

    return "UNKNOWN"

def extract_network_name(row, columns, combined_text):
    name_column = columns.get(
        "name",
        "",
    )

    if name_column:
        name = normalize_space(
            row.get(name_column, "")
        )

        if name:
            return name

    patterns = [
        r"(?:network\s+name|name|comment|description)"
        r"\s*[:=]\s*([^,;\n]+)",
    ]

    labels = []

    for pattern in patterns:
        for match in re.finditer(
            pattern,
            combined_text,
            re.IGNORECASE,
        ):
            label = normalize_space(
                match.group(1)
            )

            if label and label not in labels:
                labels.append(label)

    return "; ".join(labels)

def extract_network_view(row, columns, combined_text):
    view_column = columns.get(
        "view",
        "",
    )

    if view_column:
        view = normalize_space(
            row.get(view_column, "")
        )

        if view:
            return view

    match = re.search(
        r"(?:network\s+view|network_view)"
        r"\s*[:=]\s*([^\s,;]+)",
        combined_text,
        re.IGNORECASE,
    )

    return match.group(1).strip() if match else ""

def extract_range_pairs(text):
    """Extract IP start/end pairs from a value containing a range."""
    pairs = []

    range_pattern = re.compile(
        rf"({IP_RE})\s*(?:-|–|—|to|through)\s*({IP_RE})",
        re.IGNORECASE,
    )

    for match in range_pattern.finditer(
        text or ""
    ):
        start = match.group(1)
        end = match.group(2)

        if not valid_ipv4(start):
            continue

        if not valid_ipv4(end):
            continue

        if parse_ipv4(start) <= parse_ipv4(end):
            pair = (start, end)

            if pair not in pairs:
                pairs.append(pair)

    return pairs

def format_dhcp_ranges(row, columns, combined_text):
    values = []

    dhcp_column = columns.get(
        "dhcp",
        "",
    )

    if dhcp_column:
        values.append(
            row.get(dhcp_column, "")
        )

    start_column = columns.get(
        "dhcp_start",
        "",
    )

    end_column = columns.get(
        "dhcp_end",
        "",
    )

    if start_column and end_column:
        start = extract_first_ip(
            row.get(start_column, "")
        )

        end = extract_first_ip(
            row.get(end_column, "")
        )

        if start and end:
            values.append(
                f"{start}-{end}"
            )

    if not values:
        for field, value in row.items():
            field_name = normalize_header(field)

            if (
                "dhcp" in field_name
                or "range" in field_name
            ):
                values.append(value)

    if not values:
        values.append(combined_text)

    ranges = []
    seen = set()

    for value in values:
        for start, end in extract_range_pairs(
            str(value)
        ):
            range_value = f"{start}-{end}"

            if range_value not in seen:
                ranges.append(range_value)
                seen.add(range_value)

    return "; ".join(ranges)

def read_csv(filename):
    with open(
        filename,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as csvfile:
        reader = csv.DictReader(csvfile)

        if not reader.fieldnames:
            raise ValueError(
                "The CSV file does not contain a header row."
            )

        rows = list(reader)

    return reader.fieldnames, rows

def filter_rows(
    fieldnames,
    rows,
    match_text,
    require_uson,
    dhcp_contains,
    exclude_text,
):
    columns = detect_columns(fieldnames)
    output_rows = []

    for row in rows:
        combined_text = row_text(row)
        combined_lower = combined_text.lower()

        if match_text.lower() not in combined_lower:
            continue

        if (
            require_uson
            and "uson" not in combined_lower
        ):
            continue

        if (
            exclude_text
            and exclude_text.lower() in combined_lower
        ):
            continue

        dhcp_range = format_dhcp_ranges(
            row,
            columns,
            combined_text,
        )

        if not dhcp_range:
            continue

        if (
            dhcp_contains
            and dhcp_contains.lower()
            not in dhcp_range.lower()
        ):
            continue

        network_column = columns.get(
            "network",
            "",
        )

        ip_range = ""

        if network_column:
            ip_range = extract_cidr(
                row.get(network_column, "")
            )

        if not ip_range:
            ip_range = extract_cidr(
                combined_text
            )

        gateway = extract_gateway(
            row,
            columns,
            combined_text,
        )

        notes = []

        if not network_column:
            notes.append(
                "Network column auto-detected from row text"
            )

        if not gateway:
            notes.append(
                "Gateway not found"
            )

        output_row = dict(row)

        output_row.update(
            {
                "Site Code": extract_site_code(
                    row,
                    columns,
                    combined_text,
                ),
                "IP Range": ip_range,
                "Gateway": gateway,
                "DHCP Range": dhcp_range,
                "Network Name or Comment": (
                    extract_network_name(
                        row,
                        columns,
                        combined_text,
                    )
                ),
                "Network View": extract_network_view(
                    row,
                    columns,
                    combined_text,
                ),
                "Filter Notes": "; ".join(notes),
            }
        )

        output_rows.append(output_row)

    return columns, output_rows

def write_csv(filename, source_fields, rows):
    output_fields = list(source_fields)

    for field in DERIVED_FIELDS:
        if field not in output_fields:
            output_fields.append(field)

    with open(
        filename,
        "w",
        encoding="utf-8",
        newline="",
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=output_fields,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Filter an Infoblox network/DHCP CSV locally "
            "and create a filtered Azure Local DHCP report."
        )
    )

    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        help=(
            f"output CSV filename; "
            f"default: {DEFAULT_OUTPUT}"
        ),
    )

    parser.add_argument(
        "--match",
        default="Azure Local",
        help=(
            'text required somewhere in each row; '
            'default: "Azure Local"'
        ),
    )

    parser.add_argument(
        "--require-uson",
        action="store_true",
        help="also require USON somewhere in each row",
    )

    parser.add_argument(
        "--dhcp-contains",
        default="",
        help=(
            "only include rows whose DHCP range "
            "contains this text"
        ),
    )

    parser.add_argument(
        "--exclude-text",
        default="iDRAC",
        help=(
            'exclude rows containing this text; '
            'use "" to disable; default: "iDRAC"'
        ),
    )

    args = parser.parse_args()

    input_file = input(
        "Infoblox CSV File: "
    ).strip()

    if not input_file:
        print(
            "No Infoblox CSV file was provided.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        fieldnames, rows = read_csv(
            input_file
        )

        columns, filtered_rows = filter_rows(
            fieldnames=fieldnames,
            rows=rows,
            match_text=args.match,
            require_uson=args.require_uson,
            dhcp_contains=args.dhcp_contains,
            exclude_text=args.exclude_text,
        )

        write_csv(
            args.output,
            fieldnames,
            filtered_rows,
        )

    except (OSError, ValueError) as exc:
        print(
            f"Unable to process Infoblox CSV: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"\nInput rows: {len(rows)}")
    print(
        "Matching rows with DHCP ranges: "
        f"{len(filtered_rows)}"
    )
    print(f"Output CSV: {args.output}")
    print("Detected columns:")

    for key, value in columns.items():
        print(
            f"  {key}: {value or 'not found'}"
        )

if __name__ == "__main__":
    main()
