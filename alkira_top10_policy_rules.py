#!/usr/bin/env python3
"""
Login to the Alkira portal and display the top 10 policy rules.

Auth:
  Alkira uses a session-based login. You POST your credentials to
  /api/sessions and reuse the returned session cookie for later calls.
  An API key (Bearer token) is also supported as an alternative.

Credentials are read from environment variables (preferred) or prompted:
  ALKIRA_PORTAL    e.g. mycompany  -> https://mycompany.portal.alkira.com
  ALKIRA_USERNAME  portal username / email
  ALKIRA_PASSWORD  portal password
  ALKIRA_API_KEY   (optional) use instead of username/password

Usage:
  export ALKIRA_PORTAL=mycompany
  export ALKIRA_USERNAME=alex@example.com
  export ALKIRA_PASSWORD='...'
  python3 alkira_top10_policy_rules.py
"""

import os
import sys
import getpass
import requests


def build_base_url(portal):
    """Accept either a bare tenant name or a full URL and normalize it."""
    portal = portal.strip().rstrip("/")
    if portal.startswith("http://") or portal.startswith("https://"):
        base = portal
    else:
        base = f"https://{portal}.portal.alkira.com"
    if base.endswith("/api"):
        base = base[: -len("/api")]
    return base


def login(session, base_url, username, password):
    """Session-based login. Returns once the session cookie is set."""
    url = f"{base_url}/api/sessions"
    payload = {"userName": username, "password": password}
    resp = session.post(url, json=payload, timeout=30)
    if resp.status_code not in (200, 201, 204):
        raise RuntimeError(
            f"Login failed ({resp.status_code}): {resp.text[:300]}"
        )
    # Session cookie (e.g. JSESSIONID) is now stored on the session object.
    if not session.cookies:
        raise RuntimeError("Login succeeded but no session cookie was returned.")
    print("Authenticated to Alkira portal.")


def get_tenant_network_id(session, base_url):
    """Resolve the tenant network id used to scope policy resources."""
    url = f"{base_url}/api/tenantnetworks"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    # Response may be a list of tenant networks, or a wrapper object.
    if isinstance(data, dict):
        data = data.get("tenantNetworks") or data.get("content") or [data]
    if not data:
        raise RuntimeError("No tenant networks found for this account.")

    tenant = data[0]
    tenant_id = tenant.get("id") or tenant.get("tenantNetworkId")
    if tenant_id is None:
        raise RuntimeError(f"Could not determine tenant network id from: {tenant}")

    print(f"Using tenant network id: {tenant_id}")
    return tenant_id


def get_policy_rules(session, base_url, tenant_id):
    """Fetch all policy rules for the tenant network."""
    url = f"{base_url}/api/tenantnetworks/{tenant_id}/policyrules"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, dict):
        data = data.get("content") or data.get("items") or data.get("rules") or []
    return data


def display_top_rules(rules, limit=10):
    if not rules:
        print("No policy rules returned.")
        return

    total = len(rules)
    top = rules[:limit]

    print("\n" + "=" * 78)
    print(f"Top {len(top)} policy rules (of {total} total)")
    print("=" * 78)
    print(f"{'#':<3} {'ID':<10} {'Name':<32} {'Description':<30}")
    print("-" * 78)

    for index, rule in enumerate(top, start=1):
        rule_id = str(rule.get("id", ""))[:10]
        name = str(rule.get("name", ""))[:32]
        description = str(rule.get("description", ""))[:30]
        print(f"{index:<3} {rule_id:<10} {name:<32} {description:<30}")

    print("=" * 78)


def main():
    portal = os.getenv("ALKIRA_PORTAL") or input("Alkira portal (tenant or URL): ").strip()
    base_url = build_base_url(portal)

    api_key = os.getenv("ALKIRA_API_KEY")
    session = requests.Session()
    session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    try:
        if api_key:
            # API key auth: skip session login, send a bearer token instead.
            session.headers.update({"Authorization": f"Bearer {api_key}"})
            print("Using API key authentication.")
        else:
            username = os.getenv("ALKIRA_USERNAME") or input("Username: ").strip()
            password = os.getenv("ALKIRA_PASSWORD") or getpass.getpass("Password: ")
            login(session, base_url, username, password)

        tenant_id = get_tenant_network_id(session, base_url)
        rules = get_policy_rules(session, base_url, tenant_id)
        display_top_rules(rules, limit=10)

    except requests.exceptions.RequestException as exc:
        print(f"HTTP error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
