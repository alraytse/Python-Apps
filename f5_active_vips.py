#!/usr/bin/env python3
"""
Show active (enabled + available) LTM virtual servers and their statistics
across all partitions on an F5 BIG-IP, using the iControl REST API.

Requires: pip install requests
"""
import csv
import getpass
import re
import sys
from datetime import datetime

import requests

# Most BIG-IPs use a self-signed cert. Set to True (or a CA bundle path) if yours is trusted.
VERIFY_SSL = False
TIMEOUT = 30

if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token(host, user, password):
    """Log in and return an auth token."""
    url = f"https://{host}/mgmt/shared/authn/login"
    payload = {"username": user, "password": password, "loginProviderName": "tmos"}
    r = requests.post(url, json=payload, verify=VERIFY_SSL, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()["token"]["token"]


def get_partitions(session, host):
    """Return a list of partition names."""
    r = session.get(f"https://{host}/mgmt/tm/auth/partition", timeout=TIMEOUT)
    r.raise_for_status()
    return sorted(item["name"] for item in r.json().get("items", []))


def num(stats, key):
    """Get a numeric stat value (0 if missing)."""
    return int(stats.get(key, {}).get("value", 0))


def text(stats, key, default="-"):
    """Get a text stat value."""
    return stats.get(key, {}).get("description", default)


def get_virtual_stats(session, host, partition):
    """Return status and traffic stats for each virtual server in a partition."""
    url = f"https://{host}/mgmt/tm/ltm/virtual/stats"
    params = {"$filter": f"partition eq {partition}"}
    r = session.get(url, params=params, timeout=TIMEOUT)
    r.raise_for_status()

    results = []
    for entry in r.json().get("entries", {}).values():
        s = entry["nestedStats"]["entries"]
        full_name = text(s, "tmName")
        results.append({
            "partition": partition,
            "name": full_name.split("/")[-1],
            "destination": text(s, "destination"),
            "enabled": text(s, "status.enabledState", "unknown"),
            "availability": text(s, "status.availabilityState", "unknown"),
            "cur_conns": num(s, "clientside.curConns"),
            "max_conns": num(s, "clientside.maxConns"),
            "tot_conns": num(s, "clientside.totConns"),
            "bits_in": num(s, "clientside.bitsIn"),
            "bits_out": num(s, "clientside.bitsOut"),
            "pkts_in": num(s, "clientside.pktsIn"),
            "pkts_out": num(s, "clientside.pktsOut"),
        })
    return results


def human(n, unit=""):
    """Format large numbers (1.2K, 3.4M, ...)."""
    n = float(n)
    for suffix in ("", "K", "M", "G", "T"):
        if abs(n) < 1000:
            return f"{n:.0f}{suffix}{unit}" if suffix == "" else f"{n:.1f}{suffix}{unit}"
        n /= 1000
    return f"{n:.1f}P{unit}"


def print_table(rows):
    headers = ["Partition", "Virtual Server", "Destination",
               "CurConn", "MaxConn", "TotConn",
               "Bits In", "Bits Out", "Pkts In", "Pkts Out"]
    table = [[
        r["partition"], r["name"], r["destination"],
        human(r["cur_conns"]), human(r["max_conns"]), human(r["tot_conns"]),
        human(r["bits_in"], "b"), human(r["bits_out"], "b"),
        human(r["pkts_in"]), human(r["pkts_out"]),
    ] for r in rows]

    widths = [max(len(h), *(len(row[i]) for row in table)) for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) if i < 3 else h.rjust(w)
                     for i, (h, w) in enumerate(zip(headers, widths)))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in table:
        print("  ".join(c.ljust(w) if i < 3 else c.rjust(w)
                        for i, (c, w) in enumerate(zip(row, widths))))


CSV_FIELDS = ["host", "collected_at", "partition", "virtual_server", "destination",
              "enabled", "availability", "cur_conns", "max_conns", "tot_conns",
              "bits_in", "bits_out", "pkts_in", "pkts_out"]


def write_csv(host, rows, stamp):
    """Write rows to <host>_<YYYY-MM-DD_HH-MM-SS>.csv and return the filename."""
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    filename = f"{safe_host}_{stamp.strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    collected_at = stamp.strftime("%Y-%m-%d %H:%M:%S")

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_FIELDS)
        for r in rows:
            writer.writerow([
                host, collected_at, r["partition"], r["name"], r["destination"],
                r["enabled"], r["availability"], r["cur_conns"], r["max_conns"],
                r["tot_conns"], r["bits_in"], r["bits_out"], r["pkts_in"], r["pkts_out"],
            ])
    return filename


def process_host(host, user, password):
    """Log in to one F5, print partitions, summary and active virtual server stats."""
    print("\n" + "=" * 100)
    print(f"F5: {host}")
    print("=" * 100)

    try:
        token = get_token(host, user, password)
    except requests.exceptions.RequestException as e:
        print(f"Login failed for {host}: {e}")
        return

    session = requests.Session()
    session.headers.update({"X-F5-Auth-Token": token, "Content-Type": "application/json"})
    session.verify = VERIFY_SSL

    try:
        partitions = get_partitions(session, host)

        print(f"\nAvailable partitions: {len(partitions)}")
        for part in partitions:
            print(f"  - {part}")

        active = []
        summary = {}
        for part in partitions:
            vips = get_virtual_stats(session, host, part)
            part_active = [v for v in vips
                           if v["enabled"] == "enabled" and v["availability"] == "available"]
            summary[part] = (len(part_active), len(vips))
            active.extend(part_active)

        print("\nVirtual servers per partition (active / total)")
        for part, (a, t) in summary.items():
            print(f"  {part:<30} {a} / {t}")

        active.sort(key=lambda v: (v["partition"], v["name"]))

        print("\nActive virtual servers (enabled and available)\n")
        if active:
            print_table(active)
        else:
            print("No active virtual servers found.")
        print(f"\nTotal active virtual servers on {host}: {len(active)}")

        filename = write_csv(host, active, datetime.now())
        print(f"Results written to {filename}")

    except requests.exceptions.RequestException as e:
        print(f"API request failed for {host}: {e}")
    finally:
        try:
            session.delete(f"https://{host}/mgmt/shared/authz/tokens/{token}", timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            pass


def main():
    raw = input("F5 hostnames or IPs (comma delimited): ")
    hosts = list(dict.fromkeys(h.strip() for h in raw.split(",") if h.strip()))
    if not hosts:
        sys.exit("No F5 devices entered.")

    user = input("Username: ").strip()
    password = getpass.getpass("Password (used for all devices): ")

    for host in hosts:
        process_host(host, user, password)


if __name__ == "__main__":
    main()
