#!/usr/bin/env python3
"""
Prompt for IP subnet ranges, strip the subnet portion, and print the
addresses as a comma-separated list.

Accepts entries separated by commas, spaces, semicolons, or new lines, e.g.:
    192.168.1.0/24, 10.0.0.0/8
    172.16.5.0/255.255.255.0
    2001:db8::/32
Finish input with a blank line.
"""

import ipaddress
import re


def read_input():
    print("Enter IP subnet ranges (one per line or separated by commas/spaces).")
    print("Press Enter on a blank line when finished:\n")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line.strip():
            break
        lines.append(line)
    return " ".join(lines)


def strip_subnets(raw):
    results, invalid = [], []
    seen = set()

    for token in re.split(r"[,\s;]+", raw.strip()):
        if not token:
            continue
        ip_part = token.split("/", 1)[0]  # drop /24 or /255.255.255.0
        try:
            ip = str(ipaddress.ip_address(ip_part))
        except ValueError:
            invalid.append(token)
            continue
        if ip not in seen:  # remove duplicates, keep original order
            seen.add(ip)
            results.append(ip)

    return results, invalid


def main():
    raw = read_input()
    ips, invalid = strip_subnets(raw)

    if invalid:
        print("\nSkipped invalid entries: " + ", ".join(invalid))

    if ips:
        print("\nResult:")
        print(",".join(ips))
    else:
        print("\nNo valid IP addresses found.")


if __name__ == "__main__":
    main()
