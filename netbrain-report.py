import csv
import getpass
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

USERNAME = input("Enter NetBrain Username: ").strip()
PASSWORD = getpass.getpass("Enter NetBrain Password: ").strip()

if not USERNAME or not PASSWORD:
    sys.exit("Error: Username and Password cannot be empty.")

BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
OUTPUT_FILE = os.path.expanduser("~/Downloads/ddc1_ntp_inventory.csv")

MAX_WORKERS = 10
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

session = requests.Session()
session.verify = False
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


def authenticate() -> dict:
    login_url = f"{BASE_URL}/Session"
    login_payload = {"username": USERNAME, "password": PASSWORD}

    try:
        res = session.post(login_url, json=login_payload, timeout=60)
        res.raise_for_status()
    except requests.exceptions.Timeout:
        sys.exit(
            "Error: Authentication request timed out (60s). Check your VPN connection."
        )
    except requests.exceptions.RequestException as e:
        sys.exit(f"Auth network error: {e}")

    data = res.json()
    token = data.get("token")
    if not token:
        raise RuntimeError("Token missing in response payload.")

    session.headers.update(
        {
            "Token": token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    if data.get("tenantId") and data.get("domainId"):
        session.headers.update(
            {"tenantId": data.get("tenantId"), "domainId": data.get("domainId")}
        )

    return data


def fetch_device_page(skip_value: int) -> list:
    url = f"{BASE_URL}/CMDB/Devices"
    try:
        res = session.get(
            url, params={"skip": skip_value, "limit": PAGE_LIMIT}, timeout=30
        )
        return res.json().get("devices", []) if res.status_code == 200 else []
    except requests.RequestException:
        return []


def decode_domain_info(device: dict, hostname: str, raw_domain: str) -> str:
    """Decodes domain context for standard asset reporting."""
    if raw_domain and raw_domain.upper() != "N/A":
        clean = raw_domain.strip().lower()
        if "." in clean:
            return clean

    if hostname and "." in hostname:
        parts = hostname.split(".", 1)
        if len(parts) > 1 and parts[1]:
            return parts[1].strip().lower()

    fqdn = device.get("fqdn") or device.get("hostFQDN") or ""
    if fqdn and "." in fqdn:
        parts = fqdn.split(".", 1)
        if len(parts) > 1 and parts[1]:
            return parts[1].strip().lower()

    if "DDC1" in hostname.upper():
        return "ddc1.internal.local"

    return "N/A"


def extract_interface_type(intf_name: str) -> str:
    if not intf_name:
        return ""
    match = re.match(r"^([a-zA-Z-]+)", str(intf_name).strip())
    if match:
        prefix = match.group(1).rstrip("-")
        if len(prefix) >= 2:
            return prefix
    return ""


def extract_site_from_device(device: dict) -> str:
    for key in ["siteName", "site", "sitePath", "location", "site_name"]:
        val = device.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()

    hostname = device.get("name") or device.get("hostName") or device.get("hostname") or ""
    if hostname:
        parts = hostname.split("-")
        if parts:
            return parts[0].strip()

    return "DDC1"


def fetch_single_interface_attr(hostname: str, intf_name: str) -> tuple:
    url = f"{BASE_URL}/CMDB/Interfaces/Attributes"
    try:
        r = session.get(url, params={"hostname": hostname, "interfaceName": intf_name}, timeout=10)
        if r.status_code == 200:
            raw_attrs = r.json().get("attributes", {})
            attrs = raw_attrs.get(intf_name, raw_attrs) if isinstance(raw_attrs, dict) else {}

            vrf = str(attrs.get("mplsVrf") or attrs.get("vrfName") or attrs.get("vrf") or "").strip()

            nat_val = (
                attrs.get("isNatIntf")
                or attrs.get("natType")
                or attrs.get("nat")
                or attrs.get("natMode")
            )
            pat_val = (
                attrs.get("isPatIntf")
                or attrs.get("patType")
                or attrs.get("pat")
                or attrs.get("patMode")
            )

            found_ips = []
            ips_raw = attrs.get("ips") or attrs.get("ipAddress")
            if isinstance(ips_raw, list):
                for item in ips_raw:
                    if isinstance(item, dict) and item.get("ipLoc"):
                        found_ips.append(item["ipLoc"])
                    elif isinstance(item, str) and item.strip():
                        found_ips.append(item.strip())
            elif isinstance(ips_raw, str) and ips_raw.strip():
                found_ips.append(ips_raw.strip())

            has_nat = bool(nat_val and str(nat_val).lower() not in ["false", "0", "disabled", "no", ""])
            has_pat = bool(pat_val and str(pat_val).lower() not in ["false", "0", "disabled", "no", ""])

            return vrf, found_ips, has_nat, has_pat
    except requests.RequestException:
        pass
    return "", [], False, False


def enrich_device_metadata(hostname: str, raw_device: dict) -> tuple:
    types, vrfs, ip_addrs = set(), set(), set()
    nat_interfaces, pat_interfaces = set(), set()

    if not hostname:
        return ["N/A"], ["default"], ["N/A"], "No", "No"

    mgmt_ip = raw_device.get("mgmtIP") or raw_device.get("ip") or ""

    if mgmt_ip:
        ip_addrs.add(mgmt_ip)

    url = f"{BASE_URL}/CMDB/Interfaces"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=15)
        if r.status_code == 200:
            intf_names = r.json().get("interfaces", [])

            for intf in intf_names:
                if_type = extract_interface_type(intf)
                if if_type:
                    types.add(if_type)

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {
                    executor.submit(fetch_single_interface_attr, hostname, intf): intf
                    for intf in intf_names
                }
                for future in as_completed(futures):
                    intf_name = futures[future]
                    vrf, ips, has_nat, has_pat = future.result()

                    if vrf and vrf.lower() not in ["none", "null", "undefined", "n/a", "0"]:
                        vrfs.add(vrf)
                    for ip in ips:
                        ip_addrs.add(ip)
                    if has_nat:
                        nat_interfaces.add(intf_name)
                    if has_pat:
                        pat_interfaces.add(intf_name)

    except requests.RequestException:
        pass

    valid_vrfs = sorted(list(vrfs)) if vrfs else ["default"]
    nat_summary = "\n".join(sorted(nat_interfaces)) if nat_interfaces else "No"
    pat_summary = "\n".join(sorted(pat_interfaces)) if pat_interfaces else "No"

    return (
        list(types),
        valid_vrfs,
        list(ip_addrs),
        nat_summary,
        pat_summary,
    )


def main():
    authenticate()

    all_ddc1_devices = []
    seen_hostnames = set()
    all_discovered_columns = {
        "requestedSite",
        "interfaceTypes",
        "vrfNames",
        "interfaceIPs",
        "decodedDomain",
        "hasNAT",
        "hasPAT",
    }
    skip_offsets = [i * PAGE_LIMIT for i in range(MAX_ESTIMATED_PAGES)]
    EXCLUDED_FIELDS = {
        "hostName",
        "hostname",
        "mgmtIP",
        "domain",
        "domainName",
        "dnsDomain",
    }

    print(f"Fetching global CMDB devices ({MAX_WORKERS} workers)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_device_page, skip): skip
            for skip in skip_offsets
        }

        for future in as_completed(futures):
            devices_batch = future.result()
            for device in devices_batch:
                hostname = (
                    device.get("hostName")
                    or device.get("hostname")
                    or device.get("name")
                )

                if hostname and hostname not in seen_hostnames:
                    searchable_fields = f"{hostname} {device.get('mgmtIP', '')} {device.get('subType', '')}".upper()

                    if "DDC1" in searchable_fields:
                        seen_hostnames.add(hostname)
                        flat_device = {"_raw_device": device}
                        flat_device["requestedSite"] = extract_site_from_device(device)

                        raw_domain = (
                            device.get("domain")
                            or device.get("domainName")
                            or device.get("dnsDomain")
                            or "N/A"
                        )
                        flat_device["decodedDomain"] = decode_domain_info(device, hostname, raw_domain)

                        for k, v in device.items():
                            if k in EXCLUDED_FIELDS or any(
                                ex in k.lower() for ex in ["id", "discovery", "time"]
                            ):
                                continue
                            if k == "attributes" and isinstance(v, dict):
                                for sub_k, sub_v in v.items():
                                    if sub_k not in EXCLUDED_FIELDS and not any(
                                        ex in sub_k.lower() for ex in ["id", "discovery", "time"]
                                    ):
                                        flat_device[f"attr_{sub_k}"] = sub_v
                            else:
                                flat_device[k] = v

                        all_discovered_columns.update(
                            k for k in flat_device if not k.startswith("_")
                        )
                        all_ddc1_devices.append(flat_device)

    print(f"Found {len(all_ddc1_devices)} DDC1 assets. Enriching metadata & Interfaces...")

    if all_ddc1_devices:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(
                    enrich_device_metadata,
                    dev.get("name") or dev.get("hostName") or dev.get("hostname"),
                    dev.get("_raw_device", {}),
                ): dev
                for dev in all_ddc1_devices
            }

            for future in as_completed(future_map):
                dev = future_map[future]
                try:
                    types, vrfs, ips, nat_res, pat_res = future.result()
                    dev["interfaceTypes"] = "\n".join(sorted(types)) if types else "N/A"
                    dev["vrfNames"] = "\n".join(vrfs)
                    dev["interfaceIPs"] = "\n".join(sorted(ips)) if ips else "N/A"
                    dev["hasNAT"] = nat_res
                    dev["hasPAT"] = pat_res
                except Exception:
                    dev["interfaceTypes"] = "N/A"
                    dev["vrfNames"] = "default"
                    dev["interfaceIPs"] = "N/A"
                    dev["hasNAT"] = "No"
                    dev["hasPAT"] = "No"
                finally:
                    dev.pop("_raw_device", None)

    if not all_ddc1_devices:
        all_ddc1_devices.append(
            {
                "name": "No Matching DDC1 Assets Discovered",
                "requestedSite": "DDC1",
                "interfaceIPs": "N/A",
                "decodedDomain": "N/A",
                "interfaceTypes": "N/A",
                "vrfNames": "default",
                "hasNAT": "No",
                "hasPAT": "No",
            }
        )

    primary_headers = [
        "name",
        "requestedSite",
        "decodedDomain",
        "interfaceIPs",
        "interfaceTypes",
        "vrfNames",
        "hasNAT",
        "hasPAT",
    ]
    extra_headers = sorted(
        [
            col
            for col in all_discovered_columns
            if col not in primary_headers and col not in EXCLUDED_FIELDS
        ]
    )
    ordered_headers = primary_headers + extra_headers

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ordered_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(all_ddc1_devices)

    print(f"Export successful: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()