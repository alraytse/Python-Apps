import csv
import getpass
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests


BASE_URL = os.getenv(
    "NETBRAIN_BASE_URL",
    "https://netbrain.mckesson.com/ServicesAPI/API/V1",
).rstrip("/")
OUTPUT_FILE = os.path.expanduser(
    os.getenv("NETBRAIN_OUTPUT_FILE", "~/Downloads/ddc1_network_inventory.csv")
)

PAGE_LIMIT = int(os.getenv("NETBRAIN_PAGE_LIMIT", "100"))
MAX_PAGES = int(os.getenv("NETBRAIN_MAX_PAGES", "100"))
DEVICE_WORKERS = int(os.getenv("NETBRAIN_DEVICE_WORKERS", "5"))
INTERFACE_WORKERS = int(os.getenv("NETBRAIN_INTERFACE_WORKERS", "5"))
DEVICE_TIMEOUT = int(os.getenv("NETBRAIN_DEVICE_TIMEOUT", "30"))
INTERFACE_TIMEOUT = int(os.getenv("NETBRAIN_INTERFACE_TIMEOUT", "15"))
ATTRIBUTE_TIMEOUT = int(os.getenv("NETBRAIN_ATTRIBUTE_TIMEOUT", "10"))
VERIFY_TLS = os.getenv("NETBRAIN_VERIFY_TLS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# These paths are configurable because NetBrain deployments can expose different
# CMDB resource paths. They default to the paths used by the original script.
INTERFACES_PATH = os.getenv("NETBRAIN_INTERFACES_PATH", "/CMDB/Interfaces")
INTERFACE_ATTRIBUTES_PATH = os.getenv(
    "NETBRAIN_INTERFACE_ATTRIBUTES_PATH", "/CMDB/Interfaces/Attributes"
)

PRIMARY_HEADERS = [
    "name",
    "requestedSite",
    "interfaceIPs",
    "interfaceTypes",
    "vrfNames",
    "hasNAT",
    "hasPAT",
]

EXCLUDED_FIELDS = {
    "hostname",
    "hostName",
    "mgmtIP",
    "mgmtIp",
    "managementIP",
    "managementIp",
}
EXCLUDED_FIELDS_LOWER = {field.lower() for field in EXCLUDED_FIELDS}

AUTH_HEADERS: Dict[str, str] = {}
THREAD_LOCAL = threading.local()
WARNING_LOCK = threading.Lock()
WARNED_MESSAGES: Set[str] = set()

requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class NetBrainApiError(RuntimeError):
    """Raised when a NetBrain API call fails or returns invalid JSON."""



def warn_once(message: str) -> None:
    with WARNING_LOCK:
        if message in WARNED_MESSAGES:
            return
        WARNED_MESSAGES.add(message)
    print(f"[WARN] {message}", file=sys.stderr)



def get_thread_session() -> requests.Session:
    """Return one HTTP session per worker thread."""
    session = getattr(THREAD_LOCAL, "session", None)
    if session is None:
        session = requests.Session()
        session.verify = VERIFY_TLS
        session.headers.update(AUTH_HEADERS)
        THREAD_LOCAL.session = session
    elif AUTH_HEADERS:
        session.headers.update(AUTH_HEADERS)
    return session



def response_preview(response: requests.Response) -> str:
    try:
        payload = response.json()
        return json.dumps(payload, ensure_ascii=False)[:600]
    except ValueError:
        return response.text.replace("\n", " ")[:600]



def api_request(
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    timeout: int,
    operation: str,
) -> Any:
    url = f"{BASE_URL}/{path.lstrip('/')}"
    try:
        response = get_thread_session().request(
            method,
            url,
            params=params,
            json=json_body,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise NetBrainApiError(f"{operation} request failed: {exc}") from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise NetBrainApiError(
            f"{operation} returned HTTP {response.status_code}: "
            f"{response_preview(response)}"
        )

    try:
        return response.json()
    except ValueError as exc:
        raise NetBrainApiError(
            f"{operation} returned non-JSON content: {response_preview(response)}"
        ) from exc



def authenticate(username: str, password: str) -> Dict[str, Any]:
    global AUTH_HEADERS

    login_url = f"{BASE_URL}/Session"
    session = requests.Session()
    session.verify = VERIFY_TLS

    try:
        response = session.post(
            login_url,
            json={"username": username, "password": password},
            timeout=20,
        )
    except requests.RequestException as exc:
        raise NetBrainApiError(f"Authentication request failed: {exc}") from exc

    if response.status_code != 200:
        raise NetBrainApiError(
            f"Authentication failed with HTTP {response.status_code}: "
            f"{response_preview(response)}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise NetBrainApiError(
            f"Authentication returned non-JSON content: {response_preview(response)}"
        ) from exc

    token = data.get("token") if isinstance(data, dict) else None
    if not token:
        raise NetBrainApiError("Authentication succeeded but no token was returned.")

    AUTH_HEADERS = {
        "Token": str(token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for header_name, payload_key in (("tenantId", "tenantId"), ("domainId", "domainId")):
        value = data.get(payload_key) if isinstance(data, dict) else None
        if value is not None and str(value).strip():
            AUTH_HEADERS[header_name] = str(value)

    return data



def first_value(mapping: Dict[str, Any], keys: Iterable[str]) -> Any:
    lowered = {str(key).lower(): value for key, value in mapping.items()}
    for key in keys:
        if key.lower() in lowered:
            value = lowered[key.lower()]
            if value not in (None, ""):
                return value
    return None



def extract_records(payload: Any, preferred_keys: Iterable[str]) -> List[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []

    for key in preferred_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value

    for value in payload.values():
        if isinstance(value, list):
            return value

    return []



def canonical_hostname(device: Dict[str, Any]) -> str:
    value = first_value(device, ("hostName", "hostname", "name"))
    return str(value).strip() if value is not None else ""



def stable_device_key(device: Dict[str, Any]) -> str:
    device_id = first_value(device, ("id", "deviceId", "deviceID", "hostId"))
    if device_id not in (None, ""):
        return f"id:{device_id}"

    hostname = canonical_hostname(device).lower()
    management_ip = first_value(device, ("mgmtIP", "managementIP", "managementIp"))
    if hostname or management_ip:
        return f"device:{hostname}|{str(management_ip or '').lower()}"

    return "json:" + json.dumps(device, sort_keys=True, default=str)



def contains_ddc1(value: Any) -> bool:
    if value is None:
        return False
    return re.search(r"(?<![A-Z0-9])DDC1(?![A-Z0-9])", str(value), re.IGNORECASE) is not None



def device_matches_site(device: Dict[str, Any]) -> bool:
    preferred_fields = (
        "siteName",
        "site",
        "sitePath",
        "site_name",
        "location",
        "locationName",
        "domainName",
    )
    for field in preferred_fields:
        value = first_value(device, (field,))
        if contains_ddc1(value):
            return True

    attributes = first_value(device, ("attributes",))
    if isinstance(attributes, dict):
        for field in preferred_fields:
            value = first_value(attributes, (field,))
            if contains_ddc1(value):
                return True

    fallback_fields = (
        "hostName",
        "hostname",
        "name",
        "mgmtIP",
        "managementIP",
        "subType",
    )
    return any(contains_ddc1(first_value(device, (field,))) for field in fallback_fields)



def extract_site_from_device(device: Dict[str, Any]) -> str:
    fields = ("siteName", "site", "sitePath", "location", "site_name", "locationName")
    for field in fields:
        value = first_value(device, (field,))
        if isinstance(value, str) and value.strip():
            return value.strip()

    attributes = first_value(device, ("attributes",))
    if isinstance(attributes, dict):
        for field in fields:
            value = first_value(attributes, (field,))
            if isinstance(value, str) and value.strip():
                return value.strip()

    hostname = canonical_hostname(device)
    if hostname:
        return hostname.split("-", 1)[0].strip()

    return "DDC1"



def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return value



def flatten_device(device: Dict[str, Any]) -> Dict[str, Any]:
    flattened: Dict[str, Any] = {
        "_lookup_hostname": canonical_hostname(device),
        "requestedSite": extract_site_from_device(device),
    }

    for key, value in device.items():
        key_text = str(key)
        key_lower = key_text.lower()

        if key_text in EXCLUDED_FIELDS or key_lower in EXCLUDED_FIELDS_LOWER:
            continue
        if any(excluded in key_lower for excluded in ("id", "discovery", "time")):
            continue
        if key_text == "attributes" and isinstance(value, dict):
            for sub_key, sub_value in value.items():
                sub_key_text = str(sub_key)
                sub_key_lower = sub_key_text.lower()
                if sub_key_text in EXCLUDED_FIELDS or sub_key_lower in EXCLUDED_FIELDS_LOWER:
                    continue
                if any(excluded in sub_key_lower for excluded in ("id", "discovery", "time")):
                    continue
                flattened[f"attr_{sub_key_text}"] = csv_value(sub_value)
        else:
            flattened[key_text] = csv_value(value)

    return flattened



def fetch_device_page(skip_value: int) -> List[Dict[str, Any]]:
    payload = api_request(
        "GET",
        "/CMDB/Devices",
        params={"skip": skip_value, "limit": PAGE_LIMIT},
        timeout=DEVICE_TIMEOUT,
        operation=f"device page skip={skip_value}",
    )
    records = extract_records(payload, ("devices", "data", "results", "items"))
    return [record for record in records if isinstance(record, dict)]



def fetch_all_ddc1_devices() -> List[Dict[str, Any]]:
    selected: Dict[str, Dict[str, Any]] = {}
    seen_page_keys: Set[str] = set()

    print(f"Fetching CMDB devices with bounded pagination (limit={PAGE_LIMIT})...")

    for page_number in range(MAX_PAGES):
        skip_value = page_number * PAGE_LIMIT
        try:
            devices = fetch_device_page(skip_value)
        except NetBrainApiError as exc:
            warn_once(str(exc))
            break

        if not devices:
            break

        new_page_devices = 0
        for device in devices:
            key = stable_device_key(device)
            if key not in seen_page_keys:
                seen_page_keys.add(key)
                new_page_devices += 1

            if device_matches_site(device):
                selected[key] = flatten_device(device)

        print(
            f"  page {page_number + 1}: received {len(devices)}, "
            f"new {new_page_devices}, DDC1 total {len(selected)}"
        )

        # This protects against deployments that ignore skip/limit and repeat pages.
        if new_page_devices == 0:
            warn_once("The device API returned no new records; stopping pagination.")
            break
        if len(devices) < PAGE_LIMIT:
            break

    return list(selected.values())



def normalize_interface_name(item: Any) -> str:
    if isinstance(item, str):
        return item.strip()
    if isinstance(item, dict):
        value = first_value(item, ("interfaceName", "name", "interface", "ifName"))
        return str(value).strip() if value is not None else ""
    return ""



def fetch_interface_names(hostname: str) -> List[str]:
    payload = api_request(
        "GET",
        INTERFACES_PATH,
        params={"hostname": hostname},
        timeout=INTERFACE_TIMEOUT,
        operation=f"interfaces for {hostname}",
    )
    raw_interfaces = extract_records(
        payload, ("interfaces", "interfaceList", "data", "results", "items")
    )
    names = {normalize_interface_name(item) for item in raw_interfaces}
    return sorted(name for name in names if name)



def extract_attribute_record(payload: Any, interface_name: str) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    attributes = payload.get("attributes")
    if isinstance(attributes, dict):
        direct = attributes.get(interface_name)
        if isinstance(direct, dict):
            return direct
        if all(not isinstance(value, dict) for value in attributes.values()):
            return attributes

    if isinstance(attributes, list):
        for item in attributes:
            if isinstance(item, dict):
                name = normalize_interface_name(item)
                if name == interface_name:
                    return item

    for key in ("attribute", "interfaceAttribute", "data", "result"):
        value = payload.get(key)
        if isinstance(value, dict):
            return value

    return {}



def truthy_attribute(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() not in {
        "",
        "false",
        "0",
        "disabled",
        "no",
        "none",
        "null",
        "undefined",
        "n/a",
    }



def extract_ips(attrs: Dict[str, Any]) -> List[str]:
    raw_ips = first_value(attrs, ("ips", "ipAddresses", "addresses", "ipAddress", "ip"))
    if raw_ips is None:
        return []

    values = raw_ips if isinstance(raw_ips, list) else [raw_ips]
    results: Set[str] = set()
    for item in values:
        if isinstance(item, dict):
            value = first_value(item, ("ipLoc", "ipAddress", "address", "ip"))
        else:
            value = item
        if value not in (None, ""):
            results.add(str(value).strip())
    return sorted(results)



def fetch_single_interface_attr(
    hostname: str, interface_name: str
) -> Tuple[str, str, List[str], bool, bool, Optional[str]]:
    try:
        payload = api_request(
            "GET",
            INTERFACE_ATTRIBUTES_PATH,
            params={"hostname": hostname, "interfaceName": interface_name},
            timeout=ATTRIBUTE_TIMEOUT,
            operation=f"attributes for {hostname} {interface_name}",
        )
        attrs = extract_attribute_record(payload, interface_name)
        if not attrs:
            return interface_name, "", [], False, False, "empty attribute payload"

        vrf = first_value(attrs, ("mplsVrf", "vrf", "vrfName", "vpnName"))
        nat_value = first_value(attrs, ("isNatIntf", "natType", "nat", "natMode"))
        pat_value = first_value(attrs, ("isPatIntf", "patType", "pat", "patMode"))

        return (
            interface_name,
            str(vrf).strip() if vrf not in (None, "") else "",
            extract_ips(attrs),
            truthy_attribute(nat_value),
            truthy_attribute(pat_value),
            None,
        )
    except Exception as exc:
        return interface_name, "", [], False, False, str(exc)



def enrich_device_metadata(hostname: str) -> Tuple[List[str], List[str], List[str], str, str]:
    if not hostname:
        return ["N/A"], ["default"], ["N/A"], "No", "No"

    try:
        interface_names = fetch_interface_names(hostname)
    except NetBrainApiError as exc:
        warn_once(str(exc))
        return ["N/A"], ["default"], ["N/A"], "No", "No"

    if not interface_names:
        warn_once(f"No interfaces returned for {hostname}.")
        return ["N/A"], ["default"], ["N/A"], "No", "No"

    types: Set[str] = set()
    vrfs: Set[str] = set()
    ip_addresses: Set[str] = set()
    nat_interfaces: Set[str] = set()
    pat_interfaces: Set[str] = set()
    failed_attributes = 0

    for interface_name in interface_names:
        match = re.match(r"^([A-Za-z][A-Za-z-]*)", interface_name)
        if match and len(match.group(1)) >= 2:
            types.add(match.group(1).rstrip("-"))

    worker_count = max(1, min(INTERFACE_WORKERS, len(interface_names)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(
                fetch_single_interface_attr, hostname, interface_name
            ): interface_name
            for interface_name in interface_names
        }
        for future in as_completed(futures):
            interface_name = futures[future]
            try:
                _, vrf, ips, has_nat, has_pat, error = future.result()
            except Exception as exc:
                error = str(exc)
                vrf, ips, has_nat, has_pat = "", [], False, False

            if error:
                failed_attributes += 1
                warn_once(
                    f"Attribute lookup failed for {hostname} {interface_name}: {error}"
                )
                continue

            if vrf and vrf.lower() not in {"none", "null", "undefined", "n/a", "0"}:
                vrfs.add(vrf)
            ip_addresses.update(ips)
            if has_nat:
                nat_interfaces.add(interface_name)
            if has_pat:
                pat_interfaces.add(interface_name)

    if failed_attributes:
        print(
            f"  {hostname}: {len(interface_names)} interfaces, "
            f"{failed_attributes} attribute failures"
        )

    return (
        sorted(types) if types else ["N/A"],
        sorted(vrfs) if vrfs else ["default"],
        sorted(ip_addresses) if ip_addresses else ["N/A"],
        "\n".join(sorted(nat_interfaces)) if nat_interfaces else "No",
        "\n".join(sorted(pat_interfaces)) if pat_interfaces else "No",
    )



def enrich_devices(devices: List[Dict[str, Any]]) -> None:
    if not devices:
        return

    print(f"Found {len(devices)} DDC1 assets. Enriching metadata...")
    worker_count = max(1, min(DEVICE_WORKERS, len(devices)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(enrich_device_metadata, device.get("_lookup_hostname", "")): device
            for device in devices
        }

        for future in as_completed(future_map):
            device = future_map[future]
            try:
                types, vrfs, ips, nat_summary, pat_summary = future.result()
            except Exception as exc:
                warn_once(
                    f"Unexpected enrichment failure for "
                    f"{device.get('_lookup_hostname', 'unknown device')}: {exc}"
                )
                types, vrfs, ips, nat_summary, pat_summary = (
                    ["N/A"],
                    ["default"],
                    ["N/A"],
                    "No",
                    "No",
                )

            device["interfaceTypes"] = "\n".join(types)
            device["vrfNames"] = "\n".join(vrfs)
            device["interfaceIPs"] = "\n".join(ips)
            device["hasNAT"] = nat_summary
            device["hasPAT"] = pat_summary
            device.pop("_lookup_hostname", None)



def write_csv(devices: List[Dict[str, Any]]) -> None:
    if not devices:
        devices = [
            {
                "name": "No Matching DDC1 Assets Discovered",
                "requestedSite": "DDC1",
                "interfaceIPs": "N/A",
                "interfaceTypes": "N/A",
                "vrfNames": "default",
                "hasNAT": "No",
                "hasPAT": "No",
            }
        ]

    discovered_columns: Set[str] = set(PRIMARY_HEADERS)
    for device in devices:
        discovered_columns.update(
            key for key in device if not key.startswith("_")
        )

    extra_headers = sorted(
        column
        for column in discovered_columns
        if column not in PRIMARY_HEADERS
        and column.lower() not in EXCLUDED_FIELDS_LOWER
    )
    headers = PRIMARY_HEADERS + extra_headers

    output_directory = os.path.dirname(OUTPUT_FILE)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=headers,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(devices)

    print(f"Export successful: {OUTPUT_FILE}")



def main() -> int:
    username = input("Enter NetBrain Username: ").strip()
    password = getpass.getpass("Enter NetBrain Password: ").strip()

    if not username or not password:
        print("Error: Username and Password cannot be empty.", file=sys.stderr)
        return 1

    if not VERIFY_TLS:
        print(
            "[WARN] TLS certificate verification is disabled. "
            "Set NETBRAIN_VERIFY_TLS=true when the certificate is trusted.",
            file=sys.stderr,
        )

    try:
        authenticate(username, password)
        devices = fetch_all_ddc1_devices()
        enrich_devices(devices)
        write_csv(devices)
        return 0
    except NetBrainApiError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
