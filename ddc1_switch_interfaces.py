#!/usr/bin/env python3
"""Display all DDC1 switches and their interfaces through NetBrain REST API.

This script intentionally keeps the NetBrain paths configurable because API
paths can differ between NetBrain releases and deployments.

Typical usage:
    python3 ddc1_switch_interfaces.py \
        --base-url https://netbrain.example.com \
        --tenant-name MyTenant \
        --domain-name MyDomain

Dependencies:
    pip install requests
"""

import argparse
import csv
import getpass
import re
import sys
from pathlib import Path
from urllib.parse import quote

import requests

DEFAULT_SITE_NAME = "DDC1"
DEFAULT_LOGIN_PATH = "/ServicesAPI/API/V1/Session"
DEFAULT_DEVICES_PATH = "/ServicesAPI/API/V1/CMDB/Devices"
DEFAULT_INTERFACES_PATH = (
    "/ServicesAPI/API/V1/CMDB/Devices/{device_id}/Interfaces"
)
DEFAULT_CSV_FILE = "ddc1_netbrain_switch_interfaces.csv"
DEFAULT_PAGE_SIZE = 1000
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_PAGES = 100

DEVICE_NAME_KEYS = (
    "name",
    "deviceName",
    "hostname",
    "hostName",
    "displayName",
)
DEVICE_ID_KEYS = (
    "id",
    "deviceId",
    "deviceID",
    "entityId",
    "entityID",
)
DEVICE_IP_KEYS = (
    "managementIP",
    "managementIp",
    "management_ip",
    "ipAddress",
    "managementAddress",
    "ip",
)
DEVICE_TYPE_KEYS = (
    "assetType",
    "deviceType",
    "type",
    "category",
    "platform",
    "role",
)
DEVICE_SITE_KEYS = (
    "siteName",
    "site",
    "location",
    "containerName",
)
INTERFACE_NAME_KEYS = (
    "name",
    "interfaceName",
    "ifName",
    "portName",
    "interface",
)
INTERFACE_DESCRIPTION_KEYS = (
    "description",
    "interfaceDescription",
    "alias",
    "portDescription",
)
INTERFACE_STATUS_KEYS = (
    "status",
    "operStatus",
    "operationalStatus",
    "linkStatus",
    "state",
)
INTERFACE_ADMIN_KEYS = (
    "adminStatus",
    "administrativeStatus",
    "admin_state",
    "adminState",
)
INTERFACE_SPEED_KEYS = (
    "speed",
    "bandwidth",
    "interfaceSpeed",
)
INTERFACE_VLAN_KEYS = (
    "vlan",
    "vlanId",
    "accessVlan",
    "nativeVlan",
)


def clean(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value).strip()


def normalized_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def get_value(record, keys):
    """Return the first matching value from a case/style-insensitive record."""
    if not isinstance(record, dict):
        return ""

    normalized_record = {
        normalized_key(key): value
        for key, value in record.items()
    }

    for key in keys:
        value = normalized_record.get(normalized_key(key), "")
        if value not in (None, "", []):
            return clean(value)

    return ""


def find_records(payload, preferred_keys):
    """Extract a list of records from common NetBrain response envelopes."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    preferred = {normalized_key(key) for key in preferred_keys}
    for key, value in payload.items():
        if normalized_key(key) in preferred and isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    for key in (
        "data",
        "result",
        "results",
        "items",
        "records",
        "content",
        "devices",
        "interfaces",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = find_records(value, preferred_keys)
            if nested:
                return nested

    if any(
        get_value(payload, keys)
        for keys in (DEVICE_NAME_KEYS, INTERFACE_NAME_KEYS)
    ):
        return [payload]

    return []


def find_token(payload):
    """Find a session token in common response structures."""
    if isinstance(payload, dict):
        for key in (
            "token",
            "accessToken",
            "sessionToken",
            "jwt",
        ):
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


def find_bool(payload, keys):
    if isinstance(payload, dict):
        normalized_payload = {
            normalized_key(key): value
            for key, value in payload.items()
        }
        for key in keys:
            value = normalized_payload.get(normalized_key(key))
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in {"true", "false"}:
                return value.lower() == "true"

        for value in payload.values():
            found = find_bool(value, keys)
            if found is not None:
                return found

    elif isinstance(payload, list):
        for value in payload:
            found = find_bool(value, keys)
            if found is not None:
                return found

    return None


def build_path(template, device):
    replacements = {
        "device_id": quote(device["id"], safe=""),
        "device_name": quote(device["name"], safe=""),
        "management_ip": quote(device["management_ip"], safe=""),
    }

    try:
        return template.format(**replacements)
    except KeyError as error:
        raise ValueError(
            f"Unsupported path placeholder: {{{error.args[0]}}}. "
            "Use {device_id}, {device_name}, or {management_ip}."
        ) from error


def is_ddc1_device(device, site_name):
    site = device.get("site", "")
    if not site:
        return True
    return site_name.lower() in site.lower()


def is_switch(device):
    device_type = device.get("device_type", "")
    if not device_type:
        return True

    type_text = device_type.lower()
    if "switch" in type_text:
        return True
    if any(
        excluded in type_text
        for excluded in (
            "router",
            "firewall",
            "load balancer",
            "server",
            "wireless controller",
            "access point",
        )
    ):
        return False

    return True


def normalize_device(record):
    return {
        "id": get_value(record, DEVICE_ID_KEYS),
        "name": get_value(record, DEVICE_NAME_KEYS),
        "management_ip": get_value(record, DEVICE_IP_KEYS),
        "device_type": get_value(record, DEVICE_TYPE_KEYS),
        "site": get_value(record, DEVICE_SITE_KEYS),
        "raw": record,
    }


def normalize_interface(record):
    return {
        "interface": get_value(record, INTERFACE_NAME_KEYS),
        "description": get_value(record, INTERFACE_DESCRIPTION_KEYS),
        "admin_status": get_value(record, INTERFACE_ADMIN_KEYS),
        "operational_status": get_value(record, INTERFACE_STATUS_KEYS),
        "speed": get_value(record, INTERFACE_SPEED_KEYS),
        "vlan": get_value(record, INTERFACE_VLAN_KEYS),
        "raw": record,
    }


def deduplicate_devices(devices):
    unique = {}
    for device in devices:
        key = (
            device["id"]
            or device["management_ip"]
            or device["name"]
        ).lower()
        if not key:
            continue
        if key not in unique:
            unique[key] = device
    return list(unique.values())


class NetBrainClient:
    def __init__(self, args, username, password):
        self.base_url = args.base_url.rstrip("/")
        self.login_path = args.login_path
        self.devices_path = args.devices_path
        self.interfaces_path_template = args.interfaces_path_template
        self.tenant_name = args.tenant_name
        self.domain_name = args.domain_name
        self.site_name = args.site_name
        self.page_size = args.page_size
        self.timeout = args.timeout
        self.max_pages = args.max_pages
        self.devices_method = args.devices_method
        self.interfaces_method = args.interfaces_method
        self.session = requests.Session()
        self.session.verify = not args.insecure
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.username = username
        self.password = password

    def request(self, method, path, *, params=None, json_body=None):
        url = path if path.startswith("http") else self.base_url + path
        response = self.session.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            timeout=self.timeout,
        )

        if not response.ok:
            detail = response.text[:500].replace("\n", " ")
            raise RuntimeError(
                f"NetBrain API returned HTTP {response.status_code} for "
                f"{method} {path}: {detail}"
            )

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError as error:
            raise RuntimeError(
                f"NetBrain returned non-JSON content for {method} {path}."
            ) from error

    def login(self):
        payload = {
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
                "NetBrain login succeeded at HTTP level, but no session token "
                "was found in the response. Check the login endpoint or response schema."
            )

        # NetBrain deployments commonly use Token; Authorization is also set
        # to support deployments fronted by an API gateway.
        self.session.headers.update({
            "Token": token,
            "Authorization": f"Bearer {token}",
        })

    def get_devices(self):
        devices = []
        page = 1

        for _ in range(self.max_pages):
            params = {
                "siteName": self.site_name,
                "assetType": "Switch",
                "page": page,
                "pageNo": page,
                "pageSize": self.page_size,
                "limit": self.page_size,
            }
            body = {
                "siteName": self.site_name,
                "assetType": "Switch",
                "page": page,
                "pageNo": page,
                "pageSize": self.page_size,
                "limit": self.page_size,
            }

            response = self.request(
                self.devices_method,
                self.devices_path,
                params=params if self.devices_method == "GET" else None,
                json_body=body if self.devices_method != "GET" else None,
            )
            records = find_records(response, ("devices", "items", "records"))
            normalized = [normalize_device(record) for record in records]
            devices.extend(normalized)

            has_more = find_bool(
                response,
                ("hasMore", "hasNext", "more", "nextPage"),
            )
            next_page = get_value(
                response,
                ("nextPage", "nextPageNo", "pageNext"),
            )

            if next_page.isdigit():
                page = int(next_page)
            elif has_more is True:
                page += 1
            elif len(records) >= self.page_size:
                page += 1
            else:
                break

            if not records:
                break

        devices = [
            device
            for device in deduplicate_devices(devices)
            if is_ddc1_device(device, self.site_name)
            and is_switch(device)
            and (
                device["id"]
                or device["name"]
                or device["management_ip"]
            )
        ]
        return devices

    def get_interfaces(self, device):
        path = build_path(self.interfaces_path_template, device)
        params = {
            "deviceId": device["id"],
            "deviceName": device["name"],
            "managementIP": device["management_ip"],
        }
        body = {
            "deviceId": device["id"],
            "deviceName": device["name"],
            "managementIP": device["management_ip"],
        }

        response = self.request(
            self.interfaces_method,
            path,
            params=params if self.interfaces_method == "GET" else None,
            json_body=body if self.interfaces_method != "GET" else None,
        )
        records = find_records(
            response,
            ("interfaces", "ports", "items", "records"),
        )
        return [normalize_interface(record) for record in records]


def collect_device(client, device):
    try:
        interfaces = client.get_interfaces(device)
        return {
            "device": device,
            "interfaces": interfaces,
            "error": "",
        }
    except Exception as error:
        return {
            "device": device,
            "interfaces": [],
            "error": str(error),
        }


def flatten_results(results):
    rows = []
    for result in results:
        device = result["device"]
        base = {
            "Device": device["name"],
            "Device_ID": device["id"],
            "Management_IP": device["management_ip"],
            "Device_Type": device["device_type"],
            "Site": device["site"],
        }

        if result["error"]:
            rows.append({
                **base,
                "Interface": "",
                "Description": "",
                "Admin_Status": "",
                "Operational_Status": "",
                "Speed": "",
                "VLAN": "",
                "Collection_Status": "FAILED",
                "Error": result["error"],
            })
            continue

        if not result["interfaces"]:
            rows.append({
                **base,
                "Interface": "",
                "Description": "",
                "Admin_Status": "",
                "Operational_Status": "",
                "Speed": "",
                "VLAN": "",
                "Collection_Status": "NO_INTERFACES_RETURNED",
                "Error": "",
            })
            continue

        for interface in result["interfaces"]:
            rows.append({
                **base,
                "Interface": interface["interface"],
                "Description": interface["description"],
                "Admin_Status": interface["admin_status"],
                "Operational_Status": interface["operational_status"],
                "Speed": interface["speed"],
                "VLAN": interface["vlan"],
                "Collection_Status": "SUCCESS",
                "Error": "",
            })

    return rows


def write_csv(rows, csv_file):
    fields = [
        "Device",
        "Device_ID",
        "Management_IP",
        "Device_Type",
        "Site",
        "Interface",
        "Description",
        "Admin_Status",
        "Operational_Status",
        "Speed",
        "VLAN",
        "Collection_Status",
        "Error",
    ]

    with Path(csv_file).open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def display_results(results):
    print("\n" + "=" * 140)
    print("NETBRAIN DDC1 SWITCH AND INTERFACE REPORT")
    print("=" * 140)

    interface_count = 0
    failed_count = 0

    for result in sorted(
        results,
        key=lambda item: (
            item["device"]["name"]
            or item["device"]["management_ip"]
        ).lower(),
    ):
        device = result["device"]
        device_name = device["name"] or device["management_ip"] or "Unnamed device"
        print(
            f"\nSwitch: {device_name} | "
            f"Management IP: {device['management_ip']} | "
            f"Type: {device['device_type']}"
        )
        print(f"NetBrain device ID: {device['id']}")
        print("-" * 140)

        if result["error"]:
            failed_count += 1
            print("INTERFACE COLLECTION FAILED: " + result["error"])
            continue

        if not result["interfaces"]:
            print("No interfaces were returned by NetBrain.")
            continue

        print(
            f"{'Interface':<28}"
            f"{'Admin':<18}"
            f"{'Operational':<20}"
            f"{'Speed':<14}"
            f"{'VLAN':<12}"
            "Description"
        )
        print("-" * 140)

        for interface in result["interfaces"]:
            print(
                f"{interface['interface']:<28}"
                f"{interface['admin_status']:<18}"
                f"{interface['operational_status']:<20}"
                f"{interface['speed']:<14}"
                f"{interface['vlan']:<12}"
                f"{interface['description']}"
            )
            interface_count += 1

    print("\n" + "=" * 140)
    print(f"Switches queried    : {len(results)}")
    print(f"Switches failed     : {failed_count}")
    print(f"Interfaces returned : {interface_count}")
    print("=" * 140)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Query NetBrain for all switches in DDC1, display their interfaces, "
            "and save the results to CSV."
        )
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="NetBrain server base URL, for example https://netbrain.example.com",
    )
    parser.add_argument(
        "--tenant-name",
        default="",
        help="NetBrain tenant name, if required by the deployment.",
    )
    parser.add_argument(
        "--domain-name",
        default="",
        help="NetBrain domain name, if required by the deployment.",
    )
    parser.add_argument(
        "--site-name",
        default=DEFAULT_SITE_NAME,
        help=f"NetBrain site to query. Default: {DEFAULT_SITE_NAME}",
    )
    parser.add_argument(
        "--csv-file",
        default=DEFAULT_CSV_FILE,
        help=f"CSV output file. Default: {DEFAULT_CSV_FILE}",
    )
    parser.add_argument(
        "--login-path",
        default=DEFAULT_LOGIN_PATH,
        help=f"NetBrain login path. Default: {DEFAULT_LOGIN_PATH}",
    )
    parser.add_argument(
        "--devices-path",
        default=DEFAULT_DEVICES_PATH,
        help=f"NetBrain device-list path. Default: {DEFAULT_DEVICES_PATH}",
    )
    parser.add_argument(
        "--interfaces-path-template",
        default=DEFAULT_INTERFACES_PATH,
        help=(
            "Interface path template. Placeholders: {device_id}, "
            "{device_name}, {management_ip}."
        ),
    )
    parser.add_argument(
        "--devices-method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method for device-list requests. Default: GET",
    )
    parser.add_argument(
        "--interfaces-method",
        choices=("GET", "POST"),
        default="GET",
        help="HTTP method for interface requests. Default: GET",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help=f"Requested device page size. Default: {DEFAULT_PAGE_SIZE}",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=f"Maximum device pages to request. Default: {DEFAULT_MAX_PAGES}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification for internal/self-signed NetBrain endpoints.",
    )
    return parser


def main():
    args = build_parser().parse_args()

    if args.page_size < 1 or args.max_pages < 1 or args.timeout < 1:
        print("Error: page size, max pages, and timeout must be positive.")
        return 2

    print("Username: ", end="", flush=True)
    username = input()
    password = getpass.getpass("Password: ")

    try:
        client = NetBrainClient(args, username, password)
        print("Logging in to NetBrain...")
        client.login()
        print(f"Querying switches in NetBrain site {args.site_name}...")
        devices = client.get_devices()
    except Exception as error:
        print(f"NetBrain query failed: {error}")
        return 1

    if not devices:
        print(
            "No DDC1 switch devices were returned. Verify the site name, "
            "API paths, tenant/domain, and NetBrain permissions."
        )
        return 1

    print(f"Found {len(devices)} unique switch devices")
    results = []
    for index, device in enumerate(devices, start=1):
        device_name = device["name"] or device["management_ip"] or device["id"]
        print(f"[{index}/{len(devices)}] Collecting interfaces from {device_name}...")
        results.append(collect_device(client, device))

    rows = flatten_results(results)
    write_csv(rows, args.csv_file)
    display_results(results)
    print(f"\nCSV report saved to: {args.csv_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
