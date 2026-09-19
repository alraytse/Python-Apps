#!/usr/bin/env python3
"""NetBrain R12 DDC1 inventory collector and report generator.

The script can either query NetBrain live or process an existing raw JSON file.
It preserves all device JSON fields, deduplicates by device ID, audits repeated
API pages, and optionally collects interfaces for the resulting unique devices.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import getpass
import hashlib
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    requests = None

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    urllib3 = None

DEFAULT_BASE_URL = "https://netbrain.mckesson.com"
DEFAULT_SITE_FILTER = "DDC1"
LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
INTERFACE_REPORT_FIELDS = [
    "Management IP",
    "Device Name",
    "Display Name",
    "Device Type",
    "Device Category",
    "Requested Site",
    "Interface Type",
    "VRF Name",
]

class NetBrainClient:
    def __init__(self, base_url: str, insecure: bool = True, timeout: int = 60):
        if requests is None:
            raise RuntimeError("The requests package is required for live NetBrain collection. Use --input-json-file for offline processing.")
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = not insecure
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._thread_sessions = {}
        import threading
        self._owner_thread_id = threading.get_ident()

    def _get_thread_session(self):
        """Use the login session on the owner thread and copy cookies to workers."""
        import threading
        thread_id = threading.get_ident()
        if thread_id == self._owner_thread_id:
            return self.session
        if thread_id not in self._thread_sessions:
            session = requests.Session()
            session.verify = self.session.verify
            session.headers.update(dict(self.session.headers))
            session.cookies.update(self.session.cookies)
            self._thread_sessions[thread_id] = session
        return self._thread_sessions[thread_id]

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = path if path.startswith(("http://", "https://")) else self.base_url + path
        response = self._get_thread_session().request(method, url, timeout=60, **kwargs)
        if not response.ok:
            body = response.text[:1500].replace("\n", " ")
            raise RuntimeError(f"HTTP {response.status_code} from {url}: {body}")
        if not response.text.strip():
            return {}
        try:
            return response.json()
        except ValueError as error:
            raise RuntimeError(f"Non-JSON response from {url}: {response.text[:1500]}") from error

    def login(self, username: str, password: str, tenant_name: str = "", domain_name: str = "") -> None:
        payload = {"username": username, "password": password}
        if tenant_name:
            payload["tenantName"] = tenant_name
        if domain_name:
            payload["domainName"] = domain_name
        response = self.request("POST", LOGIN_PATH, json=payload)
        token = first_value(response, (
            "token", "accessToken", "access_token", "data.token", "data.accessToken",
            "result.token", "result.accessToken",
        ))
        if not token:
            raise RuntimeError("Login returned no token:\n" + json.dumps(response, indent=2)[:5000])
        self.session.headers.update({
            "Token": str(token),
            "Authorization": f"Bearer {token}",
        })
        print("Successfully authenticated")

    def collect_raw_pages(
        self,
        page_size: int = 50,
        max_pages: int = 500,
        page_param: str = "pageNo",
        page_size_param: str = "pageSize",
        workers: int = 30,
    ) -> List[Any]:
        """Collect pages while deduplicating records and stopping repeated patterns."""
        raw_pages: List[Any] = []
        seen_ids: Set[str] = set()
        seen_signatures: Set[str] = set()

        def absorb(response: Any, label: str) -> Tuple[int, int, str]:
            records = extract_records(response, ("devices", "deviceList", "records", "items", "results", "data"))
            records = [record for record in records if isinstance(record, dict)]
            ids = [device_identity(record) for record in records]
            signature = hashlib.sha1("|".join(sorted(ids)).encode()).hexdigest()[:12]
            new_count = 0
            for identity in ids:
                if identity not in seen_ids:
                    seen_ids.add(identity)
                    new_count += 1
            print(f"{label}: {len(records)} records, {new_count} new, {len(seen_ids)} unique total")
            return len(records), new_count, signature

        first = self.request("GET", DEVICES_PATH)
        raw_pages.append(first)
        first_count, _, first_signature = absorb(first, "Initial device page")
        seen_signatures.add(first_signature)

        candidates = [
            ("configured pageNo/pageSize", lambda n: {page_param: n, page_size_param: page_size}, 2),
            ("pageNo/pageSize zero-based", lambda n: {"pageNo": n, "pageSize": page_size}, 1),
            ("pageIndex/pageSize", lambda n: {"pageIndex": n, "pageSize": page_size}, 1),
            ("page/pageSize", lambda n: {"page": n, "pageSize": page_size}, 2),
            ("offset/limit", lambda n: {"offset": n, "limit": page_size}, page_size),
            ("start/limit", lambda n: {"start": n, "limit": page_size}, page_size),
            ("skip/limit", lambda n: {"skip": n, "limit": page_size}, page_size),
        ]

        if first_count == 0:
            return raw_pages

        for label, builder, first_value in candidates:
            try:
                response = self.request("GET", DEVICES_PATH, params=builder(first_value))
            except Exception as error:
                print(f"Pagination probe failed ({label}): {error}")
                continue

            raw_pages.append(response)
            page_count, new_count, signature = absorb(response, f"{label} probe")
            if new_count == 0:
                continue
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)

            def fetch_page(value: int):
                return value, self.request("GET", DEVICES_PATH, params=builder(value))

            stop = False
            next_value = first_value + 1
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for batch_start in range(next_value, first_value + max_pages, workers):
                    batch_values = list(range(batch_start, min(batch_start + workers, first_value + max_pages)))
                    futures = [executor.submit(fetch_page, value) for value in batch_values]
                    batch_results = []
                    for future in as_completed(futures):
                        try:
                            batch_results.append(future.result())
                        except Exception as error:
                            print(f"Pagination worker failed ({label}): {error}")
                    for value, page in sorted(batch_results, key=lambda item: item[0]):
                        raw_pages.append(page)
                        page_count, new_count, signature = absorb(page, f"{label} value={value}")
                        if signature in seen_signatures or page_count == 0 or new_count == 0:
                            stop = True
                            break
                        seen_signatures.add(signature)
                        if page_count < page_size:
                            stop = True
                            break
                    if stop:
                        break

        if first_count == page_size and len(seen_ids) <= page_size:
            print(
                "WARNING: NetBrain returned a full first page but pagination did not "
                "produce additional unique devices. Review the page audit CSV."
            )
        return raw_pages


def re_key(value: Any) -> str:
    return "".join(character.lower() for character in str(value) if character.isalnum())


def first_value(obj: Any, paths: Iterable[str], default: Any = None) -> Any:
    for path in paths:
        value = obj
        found = True
        for part in path.split("."):
            if not isinstance(value, dict):
                found = False
                break
            if part in value:
                value = value[part]
                continue
            target = re_key(part)
            matching_key = next((key for key in value if re_key(key) == target), None)
            if matching_key is None:
                found = False
                break
            value = value[matching_key]
        if found and value not in (None, ""):
            return value
    return default


def extract_records(response: Any, preferred_keys: Iterable[str]) -> List[Any]:
    if isinstance(response, list):
        return response
    if not isinstance(response, dict):
        return []
    preferred = {re_key(key) for key in preferred_keys}
    for key, value in response.items():
        if re_key(key) in preferred:
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = extract_records(value, preferred_keys)
                if nested:
                    return nested
    for key in ("result", "response", "payload", "data"):
        nested = response.get(key)
        if isinstance(nested, (dict, list)):
            found = extract_records(nested, preferred_keys)
            if found:
                return found
    return []


def flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for nested in value.values():
            yield from flatten_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from flatten_strings(nested)
    elif value not in (None, ""):
        yield str(value)


def flatten_json(value: Any, prefix: str = "") -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if isinstance(value, dict):
        for key, nested in value.items():
            column = f"{prefix}.{key}" if prefix else str(key)
            result.update(flatten_json(nested, column))
    elif isinstance(value, list):
        result[prefix] = json.dumps(value, ensure_ascii=False, default=str)
    else:
        result[prefix] = "" if value is None else value
    return result


def device_identity(device: Dict[str, Any]) -> str:
    value = first_value(device, ("id", "deviceId", "deviceID", "uuid"))
    if value not in (None, ""):
        return f"id:{value}"
    value = first_value(device, ("mgmtIP", "managementIP", "ipAddress", "ip"))
    if value not in (None, ""):
        return f"ip:{value}"
    value = first_value(device, ("name", "deviceName", "hostName", "hostname"))
    if value not in (None, ""):
        return f"name:{value}"
    return "raw:" + hashlib.sha1(json.dumps(device, sort_keys=True, default=str).encode()).hexdigest()


def device_id(device: Dict[str, Any]) -> str:
    return str(first_value(device, ("id", "deviceId", "deviceID", "uuid"), ""))


def device_name(device: Dict[str, Any]) -> str:
    return str(first_value(device, ("name", "deviceName", "hostName", "hostname", "displayName"), ""))


def management_ip(device: Dict[str, Any]) -> str:
    return str(first_value(device, ("mgmtIP", "managementIP", "ipAddress", "ip"), ""))


def interface_type(interface: Dict[str, Any]) -> str:
    return str(first_value(interface, (
        "interfaceType", "ifType", "portType", "mediaType",
        "interfaceKind", "interfaceClass", "subTypeName", "type",
    ), ""))


def interface_name(interface: Dict[str, Any]) -> str:
    return str(first_value(interface, (
        "name", "interfaceName", "ifName", "portName", "port", "displayName",
    ), ""))


def vrf_name(interface: Dict[str, Any]) -> str:
    value = first_value(interface, (
        "vrfName", "vrf", "vrf_name", "virtualRoutingAndForwarding",
        "routingInstance", "routingDomain", "forwardingInstance",
    ), "")
    if isinstance(value, dict):
        value = first_value(value, ("name", "vrfName", "value", "id"), "")
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def site_values(device: Dict[str, Any]) -> List[str]:
    values = []
    wanted = {re_key(name) for name in (
        "site", "siteName", "sitePath", "location", "locationName", "group",
        "groupName", "container", "containerName", "domain", "domainName",
    )}
    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if re_key(key) in wanted:
                    values.extend(flatten_strings(nested))
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
    walk(device)
    return list(dict.fromkeys(values))


def site_match_status(device: Dict[str, Any], site_filter: str) -> str:
    values = site_values(device)
    if not values:
        return "UNKNOWN_NO_SITE_FIELD"
    return "MATCHED" if site_filter.casefold() in " ".join(values).casefold() else "NOT_MATCHED"


def category(subtype: Any) -> str:
    value = str(subtype or "").casefold()
    if "switch" in value:
        return "Switch"
    if "firewall" in value:
        return "Firewall"
    if "router" in value:
        return "Router"
    if "virtual machine" in value or value == "vm":
        return "Virtual Machine"
    if "printer" in value:
        return "Printer"
    if "unclassified" in value:
        return "Unclassified"
    return "Other"


def ip_metadata(value: Any) -> Tuple[str, str, str]:
    try:
        address = ipaddress.ip_address(str(value))
        version = f"IPv{address.version}"
        scope = "Private" if address.is_private else "Public"
        return version, scope, "VALID"
    except ValueError:
        return "", "", "INVALID_OR_MISSING"


def name_type(name: Any) -> str:
    value = str(name or "")
    if not value or value == "(none)":
        return "MISSING"
    try:
        ipaddress.ip_address(value)
        return "IP_ADDRESS"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", value):
        return "UUID_LIKE"
    if "." in value:
        return "FQDN_OR_HOSTNAME"
    return "HOSTNAME_OR_LABEL"


def discovery_recency(value: Any) -> Tuple[str, Any]:
    timestamp = parse_time(value)
    if not timestamp:
        return "UNKNOWN", ""
    age_hours = round((datetime.now(timezone.utc) - timestamp).total_seconds() / 3600, 1)
    if age_hours < 0:
        status = "FUTURE_OR_CLOCK_SKEW"
    elif age_hours <= 24:
        status = "WITHIN_24_HOURS"
    elif age_hours <= 168:
        status = "WITHIN_7_DAYS"
    else:
        status = "OLDER_THAN_7_DAYS"
    return status, age_hours


def parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def load_raw_pages(path: Path) -> List[Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace")) if path.exists() else []


def deduplicate_devices(raw_pages: List[Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    occurrences: Dict[str, List[Tuple[int, Dict[str, Any]]]] = defaultdict(list)
    audit: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for page_no, page in enumerate(raw_pages, 1):
        devices = extract_records(page, ("devices", "deviceList", "records", "items", "results", "data"))
        devices = [device for device in devices if isinstance(device, dict)]
        page_ids = [device_identity(device) for device in devices]
        new_count = sum(1 for identity in page_ids if identity not in seen)
        seen.update(page_ids)
        signature = hashlib.sha1("|".join(sorted(page_ids)).encode()).hexdigest()[:12]
        audit.append({
            "Page": page_no,
            "RecordsReturned": len(devices),
            "UniqueIDsOnPage": len(set(page_ids)),
            "NewUniqueDevices": new_count,
            "DuplicateOnlyPage": "YES" if devices and new_count == 0 else "NO",
            "PageSignature": signature,
            "StatusCode": page.get("statusCode", "") if isinstance(page, dict) else "",
            "StatusDescription": page.get("statusDescription", "") if isinstance(page, dict) else "",
        })
        for device in devices:
            occurrences[device_identity(device)].append((page_no, device))

    inventory: List[Dict[str, Any]] = []
    for identity, items in sorted(occurrences.items()):
        representative = max(
            items,
            key=lambda item: parse_time(first_value(item[1], ("lDiscoveryTime",), ""))
            or datetime.min.replace(tzinfo=timezone.utc),
        )[1]
        subtype = first_value(representative, ("subTypeName", "deviceType", "type"), "")
        first_time = first_value(representative, ("fDiscoveryTime", "firstDiscoveryTime"), "")
        last_time = first_value(representative, ("lDiscoveryTime", "lastDiscoveryTime"), "")
        first_dt = parse_time(first_time)
        last_dt = parse_time(last_time)
        pages_seen = sorted({page_no for page_no, _ in items})
        raw_ip = management_ip(representative)
        raw_name = device_name(representative)
        ip_version, ip_scope, ip_status = ip_metadata(raw_ip)
        recency_status, age_hours = discovery_recency(last_time)
        site_values_found = site_values(representative)
        site_status = site_match_status(representative, DEFAULT_SITE_FILTER)
        issues = []
        if not raw_name or raw_name == "(none)":
            issues.append("MISSING_NAME")
        if ip_status != "VALID":
            issues.append("INVALID_OR_MISSING_IP")
        if category(subtype) == "Unclassified":
            issues.append("UNCLASSIFIED_DEVICE")
        if len(items) > 1:
            issues.append("REPEATED_API_RECORD")
        if not site_values_found:
            issues.append("NO_SITE_FIELD")
        row = flatten_json(representative)
        row.update({
            # Friendly report columns.
            "DeviceID": device_id(representative),
            "ManagementIP": raw_ip,
            "DeviceName": raw_name,
            "DisplayName": raw_ip if raw_name in ("", "(none)") else raw_name,
            "DeviceType": subtype,
            "DeviceCategory": category(subtype),
            "ClassificationStatus": "UNCLASSIFIED" if category(subtype) == "Unclassified" else "CLASSIFIED",
            "LikelyNetworkDevice": "YES" if category(subtype) in {"Switch", "Firewall", "Router"} else "NO",
            "NameType": name_type(raw_name),
            "IPVersion": ip_version,
            "IPScope": ip_scope,
            "IPValidation": ip_status,
            "FirstDiscoveryUTC": first_time,
            "LastDiscoveryUTC": last_time,
            "DiscoveryRecency": recency_status,
            "LastDiscoveryAgeHours": age_hours,
            "DiscoverySpanDays": round((last_dt - first_dt).total_seconds() / 86400, 2) if first_dt and last_dt else "",
            "RawOccurrenceCount": len(items),
            "UniquePageCount": len(pages_seen),
            "FirstPageSeen": pages_seen[0],
            "LastPageSeen": pages_seen[-1],
            "RepeatedAcrossPages": "YES" if len(items) > 1 else "NO",
            "RequestedSite": DEFAULT_SITE_FILTER,
            "SiteFieldPresent": "YES" if site_values_found else "NO",
            "SiteValues": "; ".join(site_values_found),
            "SiteMatchStatus": site_status,
            "DataQualityStatus": "OK" if not issues else "REVIEW_REQUIRED",
            "DataQualityIssues": ";".join(issues),
            # Backward-compatible internal report columns.
            "_identity": identity,
            "_raw_occurrence_count": len(items),
            "_unique_page_count": len(pages_seen),
            "_first_page_seen": pages_seen[0],
            "_last_page_seen": pages_seen[-1],
            "_repeated_across_pages": "YES" if len(items) > 1 else "NO",
            "_display_name": raw_ip if raw_name in ("", "(none)") else raw_name,
            "_device_category": category(subtype),
            "_classification_status": "UNCLASSIFIED" if category(subtype) == "Unclassified" else "CLASSIFIED",
            "_likely_network_device": "YES" if category(subtype) in {"Switch", "Firewall", "Router"} else "NO",
            "_first_last_discovery_span_days": round((last_dt - first_dt).total_seconds() / 86400, 2) if first_dt and last_dt else "",
            "_requested_site": DEFAULT_SITE_FILTER,
            "_site_values": "; ".join(site_values_found),
            "_site_match_status": site_status,
        })
        inventory.append(row)
    return inventory, audit


def write_dict_csv(
    path: Path,
    rows: List[Dict[str, Any]],
    field_order: Optional[List[str]] = None,
) -> None:
    fields: List[str] = list(field_order or [])
    if not rows and not fields:
        path.write_text("", encoding="utf-8")
        return
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_raw_csv(path: Path, raw_pages: List[Any]) -> int:
    rows: List[Dict[str, Any]] = []
    for page_no, page in enumerate(raw_pages, 1):
        devices = extract_records(page, ("devices", "deviceList", "records", "items", "results", "data"))
        for record_no, device in enumerate(devices, 1):
            if isinstance(device, dict):
                row = {"_source_page": page_no, "_source_record": record_no}
                row.update(flatten_json(device))
                rows.append(row)
    write_dict_csv(path, rows)
    return len(rows)


def collect_interfaces(
    client: NetBrainClient,
    devices: List[Dict[str, Any]],
    path_template: str,
    workers: int = 30,
) -> List[Dict[str, Any]]:
    def fetch_one(index: int, device: Dict[str, Any]):
        identity = device_identity(device)
        device_id_value = first_value(device, ("id", "deviceId", "deviceID", "uuid"), "")
        if not device_id_value:
            return index, [], f"Interface {index}/{len(devices)} skipped: {identity} has no device ID"
        path = path_template.format(
            device_id=device_id_value,
            id=device_id_value,
            name=device_name(device),
        )
        try:
            response = client.request("GET", path)
            interfaces = extract_records(
                response,
                ("interfaces", "ports", "interfaceList", "records", "items", "results", "data"),
            )
            rows = []
            for interface in interfaces:
                if isinstance(interface, dict):
                    subtype = first_value(device, ("subTypeName", "deviceType", "type"), "")
                    raw_name = device_name(device)
                    rows.append({
                        "Management IP": management_ip(device),
                        "Device Name": raw_name,
                        "Display Name": management_ip(device) if raw_name in ("", "(none)") else raw_name,
                        "Device Type": str(subtype),
                        "Device Category": category(subtype),
                        "Requested Site": DEFAULT_SITE_FILTER,
                        "Interface Type": interface_type(interface),
                        "VRF Name": vrf_name(interface),
                    })
            return index, rows, f"Interfaces {index}/{len(devices)}: {device_name(device) or device_id_value} -> {len(interfaces)}"
        except Exception as error:
            return index, [], f"Interface lookup failed for {device_name(device) or device_id_value}: {error}"

    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch_one, index, device) for index, device in enumerate(devices, 1)]
        for future in as_completed(futures):
            results.append(future.result())

    rows: List[Dict[str, Any]] = []
    for _, result_rows, message in sorted(results, key=lambda item: item[0]):
        print(message)
        rows.extend(result_rows)
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect and analyze the NetBrain DDC1 device inventory.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    security = parser.add_mutually_exclusive_group()
    security.add_argument("--secure", dest="insecure", action="store_false", help="Enable TLS verification.")
    security.add_argument("--insecure", dest="insecure", action="store_true", help="Disable TLS verification (default).")
    parser.set_defaults(insecure=True)
    parser.add_argument("--tenant-name", default="")
    parser.add_argument("--domain-name", default="", help="Optional NetBrain domain; DDC1 is not assumed to be a domain.")
    parser.add_argument("--site-filter", default=DEFAULT_SITE_FILTER)
    parser.add_argument("--input-json-file", default="", help="Process an existing raw JSON file instead of querying NetBrain.")
    parser.add_argument("--raw-json-file", default="netbrain_devices_raw.json")
    parser.add_argument("--raw-csv-file", default="netbrain_devices_all_records.csv")
    parser.add_argument("--inventory-csv-file", default="netbrain_device_inventory.csv")
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--max-pages", type=int, default=500)
    parser.add_argument("--workers", type=int, default=30, help="Concurrent API workers. Default: 30")
    parser.add_argument("--page-param", default="pageNo")
    parser.add_argument("--page-size-param", default="pageSize")
    interface_group = parser.add_mutually_exclusive_group()
    interface_group.add_argument(
        "--collect-interfaces",
        dest="collect_interfaces",
        action="store_true",
        help="Collect interface records (default for live runs).",
    )
    interface_group.add_argument(
        "--skip-interfaces",
        dest="collect_interfaces",
        action="store_false",
        help="Skip interface collection.",
    )
    parser.set_defaults(collect_interfaces=True)
    parser.add_argument("--interfaces-csv-file", default="netbrain_interface_report.csv")
    parser.add_argument("--interfaces-path-template", default=DEFAULT_INTERFACES_PATH)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.page_size <= 0 or args.max_pages <= 0 or args.workers <= 0:
        print("page-size, max-pages, and workers must be positive", file=sys.stderr)
        return 2

    client: Optional[NetBrainClient] = None
    if args.input_json_file:
        input_path = Path(args.input_json_file)
        if not input_path.exists():
            print(f"Input JSON file not found: {input_path}", file=sys.stderr)
            return 2
        raw_pages = load_raw_pages(input_path)
        print(f"Processing offline JSON: {input_path}")
    else:
        client = NetBrainClient(args.base_url, insecure=args.insecure)
        print(f"NetBrain URL: {args.base_url}")
        print(f"TLS certificate verification: {'disabled' if args.insecure else 'enabled'}")
        try:
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            client.login(username, password, args.tenant_name, args.domain_name)
            raw_pages = client.collect_raw_pages(
                page_size=args.page_size,
                max_pages=args.max_pages,
                page_param=args.page_param,
                page_size_param=args.page_size_param,
                workers=args.workers,
            )
        except Exception as error:
            print(f"NetBrain collection failed: {error}", file=sys.stderr)
            return 1

    raw_path = Path(args.raw_json_file)
    raw_path.write_text(json.dumps(raw_pages, indent=2, default=str), encoding="utf-8")
    raw_count = write_raw_csv(Path(args.raw_csv_file), raw_pages)
    inventory, audit = deduplicate_devices(raw_pages)
    write_dict_csv(Path(args.inventory_csv_file), inventory)
    write_dict_csv(Path(args.inventory_csv_file).with_name("netbrain_page_audit.csv"), audit)

    status_counts = defaultdict(int)
    for row in audit:
        status_counts[str(row.get("StatusCode", ""))] += 1
    site_status_counts = defaultdict(int)
    subtype_counts = defaultdict(int)
    for row in inventory:
        site_status_counts[str(row.get("_site_match_status", ""))] += 1
        subtype_counts[str(row.get("subTypeName", ""))] += 1

    print("\nNetBrain inventory result")
    print(f"API pages: {len(raw_pages)}")
    print(f"Raw device records: {raw_count}")
    print(f"Unique devices: {len(inventory)}")
    print(f"Repeated records removed: {raw_count - len(inventory)}")
    print(f"Subtype counts: {dict(subtype_counts)}")
    print(f"Site match status: {dict(site_status_counts)}")
    print(f"Raw JSON: {raw_path}")
    print(f"All-record CSV: {args.raw_csv_file}")
    print(f"Deduplicated inventory CSV: {args.inventory_csv_file}")
    print("Page audit CSV: netbrain_page_audit.csv")

    if site_status_counts.get("UNKNOWN_NO_SITE_FIELD"):
        print(
            "WARNING: The device JSON has no site/location field. The inventory is "
            "not asserted to be DDC1; use the page audit and NetBrain domain/site API "
            "to establish the authoritative DDC1 scope."
        )

    if args.collect_interfaces:
        if client is None:
            write_dict_csv(
                Path(args.interfaces_csv_file),
                [],
                INTERFACE_REPORT_FIELDS,
            )
            print(
                "Offline JSON has no interface records; created a header-only "
                f"interface CSV: {args.interfaces_csv_file}"
            )
        else:
            # Reconstruct minimal device dictionaries from the deduplicated rows.
            devices = []
            for row in inventory:
                devices.append({
                    "id": row.get("id", ""),
                    "mgmtIP": row.get("mgmtIP", ""),
                    "name": row.get("name", ""),
                })
            interface_rows = collect_interfaces(client, devices, args.interfaces_path_template, args.workers)
            write_dict_csv(Path(args.interfaces_csv_file), interface_rows, INTERFACE_REPORT_FIELDS)
            print(f"Interface CSV: {args.interfaces_csv_file} ({len(interface_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
