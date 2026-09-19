#!/usr/bin/env python3
"""NetBrain R12 switch/interface/IP report.

Logs in to NetBrain R12, discovers switch devices in a site, retrieves every
interface returned by the configured interface API, classifies physical and
virtual/logical interfaces, extracts all IPv4/IPv6 addresses, and writes CSV.

The report is read-only. It does not change NetBrain or network devices.

Dependencies:
    python -m pip install requests

Example:
    python ddc1_netbrain_switch_interfaces.py \
        --base-url https://netbrain.mckesson.com \
        --site-name DDC1 \
        --insecure
"""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
DEFAULT_BASE_URL = "https://netbrain.mckesson.com"
DEFAULT_SITE_NAME = "DDC1"
DEFAULT_CSV_FILE = "ddc1_switch_interfaces.csv"
DEFAULT_WORKERS = 15
DEFAULT_PAGE_SIZE = 50
DEFAULT_MAX_PAGES = 200
DEFAULT_TIMEOUT = 60

DEVICE_ID_KEYS = (
    "id", "deviceId", "deviceID", "entityId", "entityID", "uuid", "device_id",
)
DEVICE_NAME_KEYS = (
    "name", "deviceName", "hostname", "hostName", "displayName",
)
DEVICE_IP_KEYS = (
    "mgmtIP", "managementIP", "managementIp", "management_ip",
    "managementAddress", "ipAddress", "ip",
)
DEVICE_TYPE_KEYS = (
    "assetType", "deviceType", "subTypeName", "type", "category", "platform", "role",
)
DEVICE_MODEL_KEYS = ("model", "modelName", "platform", "hardwareModel")
DEVICE_VENDOR_KEYS = ("vendor", "manufacturer", "vendorName")
DEVICE_SITE_KEYS = ("siteName", "site", "location", "locationName", "containerName", "sitePath")
INTERFACE_ID_KEYS = ("id", "interfaceId", "interfaceID", "entityId", "entityID", "uuid")
INTERFACE_NAME_KEYS = (
    "name", "interfaceName", "ifName", "portName", "interface", "port", "displayName",
)
INTERFACE_DESCRIPTION_KEYS = (
    "description", "interfaceDescription", "alias", "portDescription", "desc",
)
INTERFACE_ADMIN_KEYS = (
    "adminStatus", "administrativeStatus", "admin_state", "adminState",
)
INTERFACE_OPER_KEYS = (
    "operStatus", "operationalStatus", "status", "linkStatus", "state",
)
INTERFACE_SPEED_KEYS = ("speed", "bandwidth", "interfaceSpeed", "speedMbps")
INTERFACE_VLAN_KEYS = ("vlan", "vlanId", "vlanID", "accessVlan", "nativeVlan")
INTERFACE_TYPE_KEYS = (
    "interfaceType", "ifType", "type", "category", "kind", "mediaType", "isVirtual",
)

CSV_FIELDS = [
    "Device",
    "Management_IP",
    "Device_ID",
    "Vendor",
    "Model",
    "Device_Type",
    "Site",
    "Interface_ID",
    "Interface",
    "Interface_Type",
    "Description",
    "Admin_Status",
    "Operational_Status",
    "Speed",
    "VLAN",
    "All_IP_Addresses",
    "Collection_Status",
    "Error",
]


class NetBrainClient:
    def __init__(self, args: argparse.Namespace, username: str, password: str) -> None:
        self.base_url = args.base_url.rstrip("/")
        self.timeout = args.timeout
        self.login_path = args.login_path
        self.devices_path = args.devices_path
        self.interfaces_path_template = args.interfaces_path_template
        self.devices_method = args.devices_method.upper()
        self.interfaces_method = args.interfaces_method.upper()
        self.site_name = args.site_name
        self.tenant_name = args.tenant_name
        self.domain_name = args.domain_name
        self.page_size = args.page_size
        self.max_pages = args.max_pages
        self.session = requests.Session()
        self.session.verify = not args.insecure
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.username = username
        self.password = password

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"Request failed for {method} {url}: {exc}") from exc

        if not response.ok:
            detail = response.text[:1000].replace("\n", " ").replace("\r", " ")
            raise RuntimeError(f"HTTP {response.status_code} from {method} {url}: {detail}")

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError as exc:
            detail = response.text[:1000].replace("\n", " ").replace("\r", " ")
            if "html" in response.headers.get("Content-Type", "").lower() or detail.lstrip().startswith("<"):
                raise RuntimeError(
                    f"NetBrain returned HTML instead of JSON from {url}. "
                    "Verify the R12 application-server URL, protocol, and API path."
                ) from exc
            raise RuntimeError(f"Non-JSON response from {url}: {detail}") from exc

    def login(self) -> None:
        payload: Dict[str, Any] = {
            "username": self.username,
            "password": self.password,
        }
        if self.tenant_name:
            payload["tenantName"] = self.tenant_name
        if self.domain_name:
            payload["domainName"] = self.domain_name

        response = self.request("POST", self.login_path, json_body=payload)
        token = find_token(response)
        if not token:
            raise RuntimeError(
                "Login returned no session token. Response: "
                + json.dumps(response, indent=2, default=str)[:3000]
            )

        self.session.headers.update({
            "Token": token,
            "Authorization": f"Bearer {token}",
        })

    def get_devices(self) -> List[Dict[str, Any]]:
        all_records: List[Dict[str, Any]] = []
        previous_signature: Optional[Tuple[str, ...]] = None

        for page in range(1, self.max_pages + 1):
            query = {
                "siteName": self.site_name,
                "assetType": "Switch",
                "page": page,
                "pageNo": page,
                "pageSize": self.page_size,
                "limit": self.page_size,
            }
            body = dict(query)
            response = self.request(
                self.devices_method,
                self.devices_path,
                params=query if self.devices_method == "GET" else None,
                json_body=body if self.devices_method != "GET" else None,
            )
            records = find_records(response, ("devices", "items", "records", "results"))
            if not records:
                break

            signature = tuple(
                first_value(record, DEVICE_ID_KEYS + DEVICE_NAME_KEYS + DEVICE_IP_KEYS, "")
                for record in records
            )
            if signature == previous_signature:
                break
            previous_signature = signature
            all_records.extend(records)

            has_more = find_bool(response, ("hasMore", "hasNext", "more"))
            next_page = first_value(response, ("nextPage", "nextPageNo", "pageNext"), "")
            if str(next_page).isdigit():
                next_page_number = int(next_page)
                if next_page_number <= page:
                    break
            elif has_more is False:
                break
            elif has_more is None and len(records) < self.page_size:
                break

            if len(records) < self.page_size and has_more is not True and not str(next_page).isdigit():
                break

        normalized = [normalize_device(record) for record in all_records]
        return deduplicate_devices(normalized)

    def get_interfaces(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        path = build_path(self.interfaces_path_template, device)
        query = {
            "deviceId": device["id"],
            "deviceName": device["name"],
            "managementIP": device["management_ip"],
        }
        response = self.request(
            self.interfaces_method,
            path,
            params=query if self.interfaces_method == "GET" else None,
            json_body=query if self.interfaces_method != "GET" else None,
        )
        records = find_records(
            response,
            ("interfaces", "ports", "interfaceList", "items", "records", "results"),
        )
        return [record for record in records if isinstance(record, dict)]


def normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def clean(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value).strip()


def first_value(record: Any, keys: Sequence[str], default: Any = "") -> Any:
    if not isinstance(record, dict):
        return default
    normalized = {normalize_key(key): value for key, value in record.items()}
    for key in keys:
        value = normalized.get(normalize_key(key))
        if value not in (None, "", []):
            return value
    return default


def find_records(payload: Any, preferred_keys: Iterable[str]) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    preferred = {normalize_key(key) for key in preferred_keys}
    for key, value in payload.items():
        if normalize_key(key) in preferred and isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    for key in ("data", "result", "response", "payload", "content"):
        value = payload.get(key)
        if isinstance(value, (dict, list)):
            records = find_records(value, preferred_keys)
            if records:
                return records

    for key, value in payload.items():
        if isinstance(value, dict):
            records = find_records(value, preferred_keys)
            if records:
                return records

    if payload and any(
        first_value(payload, keys, "")
        for keys in (DEVICE_NAME_KEYS, DEVICE_ID_KEYS, INTERFACE_NAME_KEYS)
    ):
        return [payload]
    return []


def find_token(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in ("token", "Token", "accessToken", "access_token", "sessionToken", "jwt"):
            value = payload.get(key)
            if value:
                return clean(value)
        for value in payload.values():
            token = find_token(value)
            if token:
                return token
    elif isinstance(payload, list):
        for value in payload:
            token = find_token(value)
            if token:
                return token
    return ""


def find_bool(payload: Any, keys: Sequence[str]) -> Optional[bool]:
    if isinstance(payload, dict):
        normalized = {normalize_key(key): value for key, value in payload.items()}
        for key in keys:
            value = normalized.get(normalize_key(key))
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {"true", "false"}:
                return value.lower() == "true"
        for value in payload.values():
            result = find_bool(value, keys)
            if result is not None:
                return result
    elif isinstance(payload, list):
        for value in payload:
            result = find_bool(value, keys)
            if result is not None:
                return result
    return None


def build_path(template: str, device: Dict[str, str]) -> str:
    replacements = {
        "device_id": quote(device["id"], safe=""),
        "id": quote(device["id"], safe=""),
        "device_name": quote(device["name"], safe=""),
        "name": quote(device["name"], safe=""),
        "management_ip": quote(device["management_ip"], safe=""),
    }
    try:
        return template.format(**replacements)
    except KeyError as exc:
        raise ValueError(
            f"Unsupported interface path placeholder {{{exc.args[0]}}}. "
            "Use {device_id}, {id}, {device_name}, {name}, or {management_ip}."
        ) from exc


def normalize_device(record: Dict[str, Any]) -> Dict[str, str]:
    return {
        "id": clean(first_value(record, DEVICE_ID_KEYS)),
        "name": clean(first_value(record, DEVICE_NAME_KEYS)),
        "management_ip": clean(first_value(record, DEVICE_IP_KEYS)),
        "vendor": clean(first_value(record, DEVICE_VENDOR_KEYS)),
        "model": clean(first_value(record, DEVICE_MODEL_KEYS)),
        "device_type": clean(first_value(record, DEVICE_TYPE_KEYS)),
        "site": clean(first_value(record, DEVICE_SITE_KEYS)),
        "raw": record,
    }


def deduplicate_devices(devices: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    unique: Dict[str, Dict[str, str]] = {}
    for device in devices:
        key = (device["id"] or device["management_ip"] or device["name"]).lower()
        if key and key not in unique:
            unique[key] = device
    return list(unique.values())


def device_matches_site(device: Dict[str, str], site_name: str) -> bool:
    if not site_name or site_name.lower() in {"*", "all"}:
        return True
    site_text = device.get("site", "")
    if not site_text:
        # The API request already included siteName; do not discard records
        # when the response omits the site field.
        return True
    return site_name.lower() in site_text.lower()


def device_is_switch(device: Dict[str, str]) -> bool:
    text = " ".join(
        device.get(field, "")
        for field in ("device_type", "vendor", "model", "name")
    ).lower()
    if any(term in text for term in ("router", "firewall", "load balancer", "wireless controller")):
        return "switch" in text
    return True


def extract_ip_tokens(text: str) -> List[str]:
    candidates = re.findall(r"(?<![A-Za-z0-9])[0-9A-Fa-f:.]+(?:/\d{1,3})?(?![A-Za-z0-9])", text)
    found: List[str] = []
    for candidate in candidates:
        candidate = candidate.strip(".,;()[]{}<>")
        try:
            value = ipaddress.ip_interface(candidate) if "/" in candidate else ipaddress.ip_address(candidate)
        except ValueError:
            continue
        normalized = str(value)
        if normalized not in found:
            found.append(normalized)
    return found


def collect_all_ips(value: Any) -> List[str]:
    found: List[str] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
        elif item is not None:
            for address in extract_ip_tokens(str(item)):
                if address not in found:
                    found.append(address)

    visit(value)
    return found


def classify_interface(interface: Dict[str, Any], name: str) -> str:
    explicit = clean(first_value(interface, INTERFACE_TYPE_KEYS)).lower()
    if explicit in {"true", "yes", "1"}:
        return "Virtual"
    if explicit in {"false", "no", "0"}:
        return "Physical"
    if explicit:
        if any(term in explicit for term in ("physical", "ethernet", "fiber", "copper")):
            return "Physical"
        if any(term in explicit for term in ("virtual", "logical", "svi", "loopback", "tunnel")):
            return "Virtual"

    normalized = name.lower().replace(" ", "")
    if normalized.startswith((
        "ethernet", "eth", "gigabitethernet", "gi", "tengigabitethernet",
        "te", "fortygigabitethernet", "fo", "hundredgigabitethernet", "hu",
        "fastethernet", "fa", "fiberchannel", "fc",
    )):
        return "Physical"
    if normalized.startswith((
        "vlan", "svi", "loopback", "lo", "tunnel", "tun", "bdi", "nve",
        "irb", "bridge", "management", "mgmt",
    )):
        return "Virtual"
    if normalized.startswith(("port-channel", "portchannel", "po", "bundle", "ae")):
        return "Logical"
    return "Unknown"


def normalize_interface(interface: Dict[str, Any]) -> Dict[str, str]:
    name = clean(first_value(interface, INTERFACE_NAME_KEYS))
    return {
        "id": clean(first_value(interface, INTERFACE_ID_KEYS)),
        "name": name,
        "interface_type": classify_interface(interface, name),
        "description": clean(first_value(interface, INTERFACE_DESCRIPTION_KEYS)),
        "admin_status": clean(first_value(interface, INTERFACE_ADMIN_KEYS)),
        "oper_status": clean(first_value(interface, INTERFACE_OPER_KEYS)),
        "speed": clean(first_value(interface, INTERFACE_SPEED_KEYS)),
        "vlan": clean(first_value(interface, INTERFACE_VLAN_KEYS)),
        "all_ips": "; ".join(collect_all_ips(interface)),
    }


def collect_device(
    client: NetBrainClient,
    device: Dict[str, str],
) -> Dict[str, Any]:
    try:
        raw_interfaces = client.get_interfaces(device)
        interfaces = [normalize_interface(interface) for interface in raw_interfaces]
        return {"device": device, "interfaces": interfaces, "error": ""}
    except Exception as exc:
        return {"device": device, "interfaces": [], "error": str(exc)}


def flatten_results(results: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for result in results:
        device = result["device"]
        base = {
            "Device": device["name"],
            "Management_IP": device["management_ip"],
            "Device_ID": device["id"],
            "Vendor": device["vendor"],
            "Model": device["model"],
            "Device_Type": device["device_type"],
            "Site": device["site"],
        }
        if result["error"]:
            rows.append({
                **base,
                "Interface_ID": "",
                "Interface": "",
                "Interface_Type": "",
                "Description": "",
                "Admin_Status": "",
                "Operational_Status": "",
                "Speed": "",
                "VLAN": "",
                "All_IP_Addresses": "",
                "Collection_Status": "FAILED",
                "Error": result["error"],
            })
            continue

        if not result["interfaces"]:
            rows.append({
                **base,
                "Interface_ID": "",
                "Interface": "",
                "Interface_Type": "",
                "Description": "",
                "Admin_Status": "",
                "Operational_Status": "",
                "Speed": "",
                "VLAN": "",
                "All_IP_Addresses": "",
                "Collection_Status": "NO_INTERFACES_RETURNED",
                "Error": "",
            })
            continue

        for interface in result["interfaces"]:
            rows.append({
                **base,
                "Interface_ID": interface["id"],
                "Interface": interface["name"],
                "Interface_Type": interface["interface_type"],
                "Description": interface["description"],
                "Admin_Status": interface["admin_status"],
                "Operational_Status": interface["oper_status"],
                "Speed": interface["speed"],
                "VLAN": interface["vlan"],
                "All_IP_Addresses": interface["all_ips"],
                "Collection_Status": "SUCCESS",
                "Error": "",
            })
    return rows


def write_csv(rows: Iterable[Dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def display_summary(rows: List[Dict[str, str]], device_count: int) -> None:
    successful = [row for row in rows if row["Collection_Status"] == "SUCCESS"]
    physical = sum(row["Interface_Type"] == "Physical" for row in successful)
    virtual = sum(row["Interface_Type"] == "Virtual" for row in successful)
    logical = sum(row["Interface_Type"] == "Logical" for row in successful)
    ip_rows = sum(bool(row["All_IP_Addresses"]) for row in successful)
    failed = sum(row["Collection_Status"] == "FAILED" for row in rows)

    print("\n" + "=" * 100)
    print("NETBRAIN SWITCH / INTERFACE / IP REPORT")
    print("=" * 100)
    print(f"Switches discovered       : {device_count}")
    print(f"Interface rows returned   : {len(successful)}")
    print(f"Physical interfaces       : {physical}")
    print(f"Virtual interfaces        : {virtual}")
    print(f"Logical interfaces        : {logical}")
    print(f"Interfaces with IP data   : {ip_rows}")
    print(f"Device collection failures: {failed}")
    print("=" * 100)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report all NetBrain R12 switch interfaces and interface IP addresses."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="NetBrain application-server URL.")
    parser.add_argument("--site-name", default=DEFAULT_SITE_NAME, help="Site filter. Use all to query all sites.")
    parser.add_argument("--tenant-name", default="", help="Optional tenant name for login.")
    parser.add_argument("--domain-name", default="", help="Optional domain name for login.")
    parser.add_argument("--login-path", default=LOGIN_PATH, help=f"Login API path. Default: {LOGIN_PATH}")
    parser.add_argument("--devices-path", default=DEVICES_PATH, help=f"Device API path. Default: {DEVICES_PATH}")
    parser.add_argument(
        "--interfaces-path-template",
        default=DEFAULT_INTERFACES_PATH,
        help=(
            "Interface API path template. Supported placeholders: "
            "{device_id}, {id}, {device_name}, {name}, {management_ip}."
        ),
    )
    parser.add_argument("--devices-method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--interfaces-method", choices=("GET", "POST"), default="GET")
    parser.add_argument("--csv-file", type=Path, default=Path(DEFAULT_CSV_FILE))
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"Parallel interface workers. Default: {DEFAULT_WORKERS}")
    parser.add_argument("--page-size", type=int, default=DEFAULT_PAGE_SIZE)
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.workers < 1 or args.page_size < 1 or args.max_pages < 1 or args.timeout < 1:
        print("workers, page-size, max-pages, and timeout must be positive.", file=sys.stderr)
        return 2

    username = input("NetBrain username: ").strip()
    password = getpass.getpass("NetBrain password: ")
    if not username or not password:
        print("Username and password are required.", file=sys.stderr)
        return 2

    client = NetBrainClient(args, username, password)
    try:
        print("Logging in to NetBrain...")
        client.login()
        print(f"Retrieving switch devices for site {args.site_name}...")
        devices = [
            device for device in client.get_devices()
            if device_matches_site(device, args.site_name) and device_is_switch(device)
        ]
        if not devices:
            print("No switch devices were returned. Verify site, API paths, and permissions.", file=sys.stderr)
            return 1

        worker_count = min(args.workers, len(devices))
        print(f"Found {len(devices)} switch device(s); using {worker_count} worker(s).")
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(collect_device, client, device): device
                for device in devices
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                device = result["device"]
                label = device["name"] or device["management_ip"] or device["id"]
                if result["error"]:
                    print(f"FAILED {label}: {result['error']}", file=sys.stderr)
                else:
                    print(f"COLLECTED {label}: {len(result['interfaces'])} interface(s)")

        rows = flatten_results(results)
        rows.sort(key=lambda row: (row["Device"].lower(), row["Interface"].lower()))
        write_csv(rows, args.csv_file)
        display_summary(rows, len(devices))
        print(f"CSV report saved to: {args.csv_file}")
        return 0
    except Exception as exc:
        print(f"NetBrain report failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
