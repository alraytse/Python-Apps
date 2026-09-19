import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration ---
BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
USERNAME = "skk30ws"
PASSWORD = "c@2OpW@PUDZy%aW;ROShF"

OUTPUT_FILE = "/Users/alex.raytselsky/Downloads/ddc1_network_inventory.csv"

MAX_WORKERS = 50
PAGE_LIMIT = 100
MAX_ESTIMATED_PAGES = 100

DEFAULT_VRFS = {
    "default",
    "mgmt",
    "management",
    "global",
    "none",
    "null",
    "",
}

EXCLUDED_REPORT_COLUMNS = {
    "managementip",
    "mgmtip",
}

def is_excluded_field(field_name):
    name = str(field_name).strip().lower()

    return (
        "id" in name
        or "discovery" in name
        or "time" in name
        or name in EXCLUDED_REPORT_COLUMNS
    )

def extract_interface_records(payload):
    """Extract interface records from common NetBrain response formats."""
    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        return []

    for key in ("interfaces", "data", "results", "items"):
        value = payload.get(key)

        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            nested_records = extract_interface_records(value)

            if nested_records:
                return nested_records

    return []

def get_interface_value(record, field_names):
    """Read a field from top-level or nested interface data."""
    if not isinstance(record, dict):
        return None

    containers = [record]

    for nested_key in ("interface", "attributes", "data"):
        nested_value = record.get(nested_key)

        if isinstance(nested_value, dict):
            containers.append(nested_value)

    normalized_names = {
        str(field).strip().lower()
        for field in field_names
    }

    for container in containers:
        for key, value in container.items():
            if str(key).strip().lower() in normalized_names:
                if value is not None and str(value).strip():
                    return value

    return None

def classify_interface_type(record):
    """
    Return Physical, Virtual, or the API-provided interface type.
    """
    raw_type = get_interface_value(
        record,
        (
            "interfaceType",
            "intfType",
            "interfaceCategory",
            "category",
            "type",
        ),
    )

    interface_name = get_interface_value(
        record,
        (
            "interfaceName",
            "ifName",
            "intfName",
            "interface",
            "name",
            "displayName",
        ),
    )

    values_to_check = []

    if raw_type:
        values_to_check.append(str(raw_type))

    if interface_name:
        values_to_check.append(str(interface_name))

    physical_patterns = (
        r"^(gi|gigabitethernet)",
        r"^(te|tengigabitethernet)",
        r"^(eth|ethernet)",
        r"^(fa|fastethernet)",
        r"^(fo|fortygigabitethernet)",
        r"^(hu|hundredgigabitethernet)",
        r"^(twe|twentyfivegigabitethernet)",
        r"^(tw|twentygigabitethernet)",
        r"^(fourhundredgigabitethernet)",
        r"^(mgmt|management)",
        r"^(serial|se|pos)",
    )

    virtual_patterns = (
        r"^(vlan|svi)",
        r"^(loopback|lo)",
        r"^(port-channel|portchannel|po)",
        r"^(etherchannel)",
        r"^(tunnel|tu)",
        r"^(nve)",
        r"^(bdi)",
        r"^(null)",
        r"^(dialer)",
    )

    for value in values_to_check:
        normalized = re.sub(r"[\s_\-]", "", value.lower())

        if (
            "physical" in normalized
            or any(
                re.match(pattern, normalized)
                for pattern in physical_patterns
            )
        ):
            return "Physical"

        if (
            "virtual" in normalized
            or any(
                re.match(pattern, normalized)
                for pattern in virtual_patterns
            )
        ):
            return "Virtual"

    if raw_type:
        return str(raw_type).strip()

    return None

def fetch_interface_records(device_id, hostname):
    """
    Try the supported query forms and return actual interface records.
    """
    candidates = []

    interface_url = f"{BASE_URL}/CMDB/Devices/Interfaces"

    if device_id:
        candidates.append(
            (
                interface_url,
                {"deviceId": device_id},
                "deviceId",
            )
        )

        candidates.append(
            (
                f"{BASE_URL}/CMDB/Devices/{device_id}/Interfaces",
                {},
                "device path",
            )
        )

    if hostname:
        candidates.append(
            (
                interface_url,
                {"hostname": str(hostname).lower()},
                "hostname",
            )
        )

    statuses = []

    for url, params, lookup_method in candidates:
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=20,
            )

            statuses.append(
                f"{lookup_method}={response.status_code}"
            )

            if response.status_code != 200:
                continue

            records = extract_interface_records(response.json())

            if records:
                return records, ""

        except Exception as error:
            statuses.append(
                f"{lookup_method}=error:{type(error).__name__}"
            )

    return [], (
        "No interface records returned "
        f"({', '.join(statuses)})"
    )

def fetch_device_page(skip_value):
    url = f"{BASE_URL}/CMDB/Devices"

    try:
        response = requests.get(
            url,
            headers=headers,
            params={
                "skip": skip_value,
                "limit": PAGE_LIMIT,
            },
            verify=False,
            timeout=30,
        )

        if response.status_code == 200:
            return response.json().get("devices", [])

    except Exception:
        pass

    return []

def enrich_device_metadata(device_id, hostname):
    interface_types = set()
    vrfs = set()
    protocols = set()

    interface_records, interface_error = (
        fetch_interface_records(device_id, hostname)
    )

    for interface in interface_records:
        interface_type = classify_interface_type(interface)

        if interface_type:
            interface_types.add(interface_type)

        vrf_name = get_interface_value(
            interface,
            ("vrf", "vrfName", "vrf_name"),
        )

        if (
            vrf_name
            and str(vrf_name).strip().lower()
            not in DEFAULT_VRFS
        ):
            vrfs.add(str(vrf_name).strip())

    routing_url = f"{BASE_URL}/CMDB/Devices/Routing/Protocols"

    query_params = (
        {"deviceId": device_id}
        if device_id
        else {"hostname": str(hostname).lower()}
    )

    try:
        response = requests.get(
            routing_url,
            headers=headers,
            params=query_params,
            verify=False,
            timeout=15,
        )

        if response.status_code == 200:
            for protocol in response.json().get("protocols", []):
                protocol_name = (
                    protocol.get("protocolName")
                    or protocol.get("name")
                    or protocol.get("type")
                )

                if protocol_name:
                    protocols.add(str(protocol_name).upper())

    except Exception:
        pass

    return (
        list(interface_types),
        list(vrfs),
        list(protocols),
        interface_error,
    )

# 1. Authenticate
login_url = f"{BASE_URL}/Session"

response = requests.post(
    login_url,
    json={
        "username": USERNAME,
        "password": PASSWORD,
    },
    verify=False,
    timeout=30,
)

if response.status_code != 200:
    raise Exception(
        f"Authentication failed ({response.status_code}): "
        f"{response.text}"
    )

login_data = response.json()
token = login_data.get("token")

if not token:
    raise Exception("Token not found in login response.")

headers = {
    "Token": token,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

if login_data.get("tenantId") and login_data.get("domainId"):
    headers["tenantId"] = login_data["tenantId"]
    headers["domainId"] = login_data["domainId"]

# 2. Collect DDC1 devices
all_ddc1_devices = []
seen_hostnames = set()
all_discovered_columns = {
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
}

skip_offsets = [
    index * PAGE_LIMIT
    for index in range(MAX_ESTIMATED_PAGES)
]

print(f"Collecting devices with {MAX_WORKERS} workers...")

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_skip = {
        executor.submit(fetch_device_page, skip): skip
        for skip in skip_offsets
    }

    for future in as_completed(future_to_skip):
        try:
            for device in future.result():
                hostname = (
                    device.get("hostName")
                    or device.get("hostname")
                    or device.get("name")
                )

                if not hostname or hostname in seen_hostnames:
                    continue

                if "DDC1" not in str(device).upper():
                    continue

                seen_hostnames.add(hostname)

                flat_device = {
                    "_internal_processing_id": (
                        device.get("id")
                        or device.get("deviceId")
                    )
                }

                for key, value in device.items():
                    if key == "attributes" and isinstance(value, dict):
                        for sub_key, sub_value in value.items():
                            if not is_excluded_field(sub_key):
                                flat_device[f"attr_{sub_key}"] = sub_value
                    elif not is_excluded_field(key):
                        flat_device[key] = value

                for key in flat_device:
                    if (
                        key != "_internal_processing_id"
                        and not is_excluded_field(key)
                    ):
                        all_discovered_columns.add(key)

                all_ddc1_devices.append(flat_device)

        except Exception:
            pass

print(
    f"Found {len(all_ddc1_devices)} unique DDC1 devices."
)

# 3. Enrich devices with actual interface information
interface_errors = []

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_device = {}

    for device in all_ddc1_devices:
        hostname = (
            device.get("hostName")
            or device.get("hostname")
            or device.get("name")
        )

        if hostname:
            future = executor.submit(
                enrich_device_metadata,
                device.get("_internal_processing_id"),
                hostname,
            )

            future_to_device[future] = device

    for future in as_completed(future_to_device):
        device = future_to_device[future]

        try:
            (
                interface_types,
                vrfs,
                protocols,
                interface_error,
            ) = future.result()

            device["interfaceTypes"] = (
                ", ".join(sorted(interface_types))
                if interface_types
                else "No Interface Data"
            )

            device["vrfNames"] = (
                ", ".join(sorted(vrfs))
                if vrfs
                else "None"
            )

            device["routingProtocols"] = (
                ", ".join(sorted(protocols))
                if protocols
                else "None"
            )

            if interface_error:
                interface_errors.append(interface_error)

        except Exception:
            device["interfaceTypes"] = "Interface Lookup Error"
            device["vrfNames"] = "Error"
            device["routingProtocols"] = "Error"

        finally:
            device.pop("_internal_processing_id", None)

# 4. Create fallback row
if not all_ddc1_devices:
    all_ddc1_devices.append(
        {
            "hostName": "No Matching DDC1 Assets Discovered",
            "interfaceTypes": "No Interface Data",
            "vrfNames": "None",
            "routingProtocols": "None",
        }
    )

# 5. Write CSV
primary_headers = [
    "hostName",
    "hostname",
    "name",
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
]

dynamic_headers = [
    column
    for column in sorted(all_discovered_columns)
    if column not in primary_headers
    and not is_excluded_field(column)
]

ordered_headers = primary_headers + dynamic_headers

with open(
    OUTPUT_FILE,
    mode="w",
    newline="",
    encoding="utf-8",
) as csv_file:
    writer = csv.DictWriter(
        csv_file,
        fieldnames=ordered_headers,
        extrasaction="ignore",
    )

    writer.writeheader()

    for device in all_ddc1_devices:
        writer.writerow(device)

print(f"CSV created: {OUTPUT_FILE}")

if interface_errors:
    print(
        "\nInterface collection warnings detected. "
        "The API returned no usable interface records for some devices."
    )
    print(interface_errors[0])
