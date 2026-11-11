#!/usr/bin/env python3
"""
Pull ALL RITMs (with their parent REQ) from ServiceNow into a CSV.

Auth is the same as pull_ddc1_servers.py:
    export SN_INSTANCE="https://mckesson1.service-now.com"
    export SN_COOKIE='<Cookie header value>'
    export SN_TOKEN='<g_ck value>'
  (or SN_USER / SN_PASSWORD for basic auth)

Optional filters via environment variables:
    RITM_DAYS=365        only RITMs opened in the last N days (default: all)
    RITM_EXTRA='...'     extra encoded query, e.g. 'active=true'

Run:
    python3 pull_all_ritms.py
"""

import csv
import os
import sys
from getpass import getpass

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import requests

INSTANCE = os.environ.get("SN_INSTANCE", "").rstrip("/")
OUTPUT = "all_ritms.csv"
PAGE_SIZE = 1000
FIELDS = [
    "number", "request", "cmdb_ci", "short_description", "cat_item",
    "state", "opened_at", "opened_by", "requested_for", "assignment_group",
    "closed_at", "sys_id",
]


def build_query():
    parts = []
    days = os.environ.get("RITM_DAYS", "").strip()
    if days.isdigit():
        parts.append(f"opened_at>=javascript:gs.daysAgoStart({days})")
    extra = os.environ.get("RITM_EXTRA", "").strip()
    if extra:
        parts.append(extra)
    parts.append("ORDERBYDESCopened_at")
    return "^".join(parts)


def flatten(v):
    if isinstance(v, dict):
        return v.get("display_value") or v.get("value") or ""
    return v if v is not None else ""


def configure_auth(session):
    cookie = os.environ.get("SN_COOKIE", "").strip()
    if cookie:
        session.headers["Cookie"] = cookie
        token = os.environ.get("SN_TOKEN", "").strip()
        if token:
            session.headers["X-UserToken"] = token
        print("Using browser session (cookie) authentication.")
    else:
        user = os.environ.get("SN_USER") or input("ServiceNow username: ")
        pw = os.environ.get("SN_PASSWORD") or getpass("ServiceNow password: ")
        session.auth = (user, pw)
        print("Using basic authentication.")


def main():
    if not INSTANCE:
        sys.exit("Set SN_INSTANCE, e.g. https://mckesson1.service-now.com")

    session = requests.Session()
    session.headers["Accept"] = "application/json"
    configure_auth(session)

    url = f"{INSTANCE}/api/now/table/sc_req_item"
    query = build_query()
    offset, total = 0, 0

    with open(OUTPUT, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()

        while True:
            params = {
                "sysparm_query": query,
                "sysparm_fields": ",".join(FIELDS),
                "sysparm_display_value": "true",
                "sysparm_exclude_reference_link": "true",
                "sysparm_limit": PAGE_SIZE,
                "sysparm_offset": offset,
            }
            resp = session.get(url, params=params, timeout=180)
            if resp.status_code == 401:
                sys.exit("401: session/credentials rejected. Re-copy SN_COOKIE / SN_TOKEN.")
            if resp.status_code == 403:
                sys.exit("403: your account can't read sc_req_item through the API.")
            resp.raise_for_status()

            batch = resp.json().get("result", [])
            if not batch:
                break
            for row in batch:
                writer.writerow({k: flatten(row.get(k)) for k in FIELDS})
            total += len(batch)
            print(f"Fetched {total} RITMs...")
            if len(batch) < PAGE_SIZE:
                break
            offset += PAGE_SIZE

    print(f"Saved {total} RITMs to {OUTPUT}")


if __name__ == "__main__":
    main()
