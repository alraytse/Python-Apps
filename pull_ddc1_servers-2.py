#!/usr/bin/env python3
"""
Pull DDC1 servers from the ServiceNow CMDB, plus their related REQ / RITM records.

Outputs:
    ddc1_servers.csv  - one row per server (with REQ/RITM numbers joined in)
    ddc1_ritms.csv    - one row per RITM tied to a DDC1 server (with its REQ)

Setup:
    pip install requests truststore

Auth (pick one):
  A) Browser SSO session (use this if basic auth gives a 401):
        export SN_INSTANCE="https://mckesson1.service-now.com"
        export SN_COOKIE='<full Cookie header value from DevTools>'
        export SN_TOKEN='<g_ck value from the browser console>'
  B) Basic auth:
        export SN_INSTANCE="https://mckesson1.service-now.com"
        export SN_USER="your.username"      (password is prompted)

Run:
    python3 pull_ddc1_servers.py
"""

import csv
import os
import sys
from collections import defaultdict
from getpass import getpass

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import requests

# ----------------------------- CONFIG ---------------------------------------
INSTANCE = os.environ.get("SN_INSTANCE", "").rstrip("/")
SITE_CODE = "ddc1"
PAGE_SIZE = 500

SERVER_TABLE = "cmdb_ci_server"
SERVER_OUTPUT = "ddc1_servers.csv"
SERVER_QUERY = (
    f"nameSTARTSWITH{SITE_CODE}"
    f"^ORlocation.nameLIKE{SITE_CODE}"
    f"^ORlocation.full_nameLIKE{SITE_CODE}"
)
SERVER_FIELDS = [
    "name", "fqdn", "ip_address", "os", "os_version", "location",
    "owned_by", "managed_by", "support_group", "install_status",
    "sys_class_name", "last_discovered", "sys_id",
]

RITM_TABLE = "sc_req_item"
RITM_OUTPUT = "ddc1_ritms.csv"
# RITMs whose Configuration Item is a DDC1 server. To also catch RITMs that only
# mention ddc1 in the text, append: ^ORshort_descriptionLIKEddc1
RITM_QUERY = f"cmdb_ci.nameSTARTSWITH{SITE_CODE}"
RITM_FIELDS = [
    "number", "request", "cmdb_ci", "short_description", "cat_item",
    "state", "opened_at", "opened_by", "requested_for", "assignment_group",
    "closed_at", "sys_id",
]
# -----------------------------------------------------------------------------


def configure_auth(session):
    """Use the browser SSO session if SN_COOKIE is set, otherwise basic auth."""
    cookie = os.environ.get("SN_COOKIE", "").strip()
    if cookie:
        session.headers["Cookie"] = cookie
        token = os.environ.get("SN_TOKEN", "").strip()
        if token:
            session.headers["X-UserToken"] = token
        print("Using browser session (cookie) authentication.")
    else:
        user = os.environ.get("SN_USER") or input("ServiceNow username: ")
        password = os.environ.get("SN_PASSWORD") or getpass("ServiceNow password: ")
        session.auth = (user, password)
        print("Using basic authentication.")


def flatten(value):
    """With sysparm_display_value=true, reference fields can come back as dicts."""
    if isinstance(value, dict):
        return value.get("display_value") or value.get("value") or ""
    return value if value is not None else ""


def fetch_all(session, table, query, fields):
    url = f"{INSTANCE}/api/now/table/{table}"
    offset, rows = 0, []

    while True:
        params = {
            "sysparm_query": query,
            "sysparm_fields": ",".join(fields),
            "sysparm_display_value": "true",
            "sysparm_exclude_reference_link": "true",
            "sysparm_limit": PAGE_SIZE,
            "sysparm_offset": offset,
        }
        resp = session.get(url, params=params, timeout=120)

        if resp.status_code == 401:
            sys.exit("Authentication failed (401). If using a cookie, it has probably "
                     "expired: log in again in the browser and re-copy SN_COOKIE / SN_TOKEN. "
                     "If using basic auth, your instance likely requires SSO.")
        if resp.status_code == 403:
            sys.exit(f"Access denied (403) on {table}. Your account may lack read "
                     "access to this table via the API.")
        resp.raise_for_status()

        batch = resp.json().get("result", [])
        if not batch:
            break
        rows.extend(batch)
        print(f"  {table}: fetched {len(rows)} records...")
        if len(batch) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    return rows


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: flatten(row.get(k)) for k in fieldnames})
    print(f"Saved {len(rows)} rows to {path}")


def main():
    if not INSTANCE:
        sys.exit("Set SN_INSTANCE, e.g. https://mckesson1.service-now.com")

    session = requests.Session()
    session.headers.update({"Accept": "application/json"})
    configure_auth(session)

    print("Fetching servers...")
    servers = fetch_all(session, SERVER_TABLE, SERVER_QUERY, SERVER_FIELDS)
    if not servers:
        print("No servers found. Try adjusting SERVER_QUERY.")
        return

    print("Fetching REQ/RITM records...")
    try:
        ritms = fetch_all(session, RITM_TABLE, RITM_QUERY, RITM_FIELDS)
    except SystemExit as e:
        print(f"Skipping RITMs: {e}")
        ritms = []

    # Map server name -> its RITM / REQ numbers
    ritm_by_server = defaultdict(list)
    req_by_server = defaultdict(set)
    for r in ritms:
        ci = flatten(r.get("cmdb_ci"))
        ritm_by_server[ci].append(flatten(r.get("number")))
        req = flatten(r.get("request"))
        if req:
            req_by_server[ci].add(req)

    for s in servers:
        name = flatten(s.get("name"))
        s["ritm_numbers"] = "; ".join(sorted(ritm_by_server.get(name, [])))
        s["req_numbers"] = "; ".join(sorted(req_by_server.get(name, [])))

    write_csv(SERVER_OUTPUT, SERVER_FIELDS + ["ritm_numbers", "req_numbers"], servers)
    if ritms:
        write_csv(RITM_OUTPUT, RITM_FIELDS, ritms)
    else:
        print("No RITMs found for these servers (or no access to sc_req_item).")


if __name__ == "__main__":
    main()
