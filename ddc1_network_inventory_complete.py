import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL certificate verification warnings
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


def extract_records(payload):
    """Extract records from common NetBrain response formats."""
    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        return []

    for key in ("interfaces", "data", "results", "items"):
        value = payload.get(key)

        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            records = extract_records(value)
            if records:
                return records

    return []


def get_interface_value(record, field_names):
    """Read an interface field from top-level or nested data."""
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


def classify_interface_text(value):
    """Return a readable interface type from an API type or interface name."""
    if not value:
        return None

    text = str(value).strip()
    normalized = re.sub(r"[\s_\-]", "", text.lower())

    if normalized.startswith(("loopback", "lo")):
        return "Loopback"

    if normalized.startswith(("tunnel", "tu")):
        return "Tunnel"

    if normalized.startswith(("vlan", "svi")):
        return "VLAN"

    if normalized.startswith(("portchannel", "etherchannel", "po")):
        return "Port-channel"

    if normalized.startswith("nve"):
        return "NVE"

    if normalized.startswith("bdi"):
        return "BDI"

    if normalized.startswith(
        (
            "gigabitethernet",
            "tengigabitethernet",
            "fastethernet",
            "fortygigabitethernet",
            "hundredgigabitethernet",
            "twentyfivegigabitethernet",
            "twentygigabitethernet",
            "fourhundredgigabitethernet",
            "ethernet",
            "eth",
            "gi",
            "te",
            "fa",
            "fo",
            "hu",
            "twe",
        )
    ):
        return "Ethernet"

    if normalized.startswith(("mgmt", "management")):
        return "Management"

    if normalized.startswith(("serial", "se")):
        return "Serial"

    if normalized.startswith("null"):
        return "Null"

    if normalized.startswith("dialer"):
        return "Dialer"

    if normalized.startswith("cellular"):
        return "Cellular"

    return None


def normalize_interface_type(record):
    """Return actual types such as Ethernet, Loopback, or Tunnel."""
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

    raw_type_text = str(raw_type).strip().lower() if raw_type else ""
    generic_types = {"physical", "virtual", "l2", "l3", "layer2", "layer3"}

    if raw_type and raw_type_text not in generic_types:
        actual_type = classify_interface_text(raw_type)
        if actual_type:
            return actual_type

    actual_type = classify_interface_text(interface_name)
    if actual_type:
        return actual_type

    if raw_type and raw_type_text not in generic_types:
        return str(raw_type).strip()

    return "Unknown"


def fetch_interface_records(device_id, hostname):
    """Try interface lookup formats and return actual interface records."""
    interface_url = f"{BASE_URL}/CMDB/Devices/Interfaces"
    candidates = []

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

    attempts = []

    for url, params, lookup_method in candidates:
        try:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=False,
                timeout=20,
            )

            if response.status_code != 200:
                attempts.append(
                    f"{lookup_method}={response.status_code}"
                )
                continue

            records = extract_records(response.json())

            if records:
                return records, ""

            attempts.append(f"{lookup_method}=200-empty")

        except Exception as error:
            attempts.append(
                f"{lookup_method}=error:{type(error).__name__}"
            )

    return [], "No interface records returned: " + ", ".join(attempts)


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

    interface_records, interface_error = fetch_interface_records(
        device_id,
        hostname,
    )

    for interface in interface_records:
        interface_type = normalize_interface_type(interface)

        if interface_type:
            interface_types.add(interface_type)

        vrf_name = get_interface_value(
            interface,
            ("vrf", "vrfName", "vrf_name"),
        )

        if (
            vrf_name
            and str(vrf_name).strip().lower() not in DEFAULT_VRFS
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


# 1. Authenticate with NetBrain
login_url = f"{BASE_URL}/Session"
login_payload = {
    "username": USERNAME,
    "password": PASSWORD,
}

print("Logging into NetBrain (External Auth)...")

response = requests.post(
    login_url,
    json=login_payload,
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
    raise Exception("Token not found in login response payload.")

headers = {
    "Token": token,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

if login_data.get("tenantId") and login_data.get("domainId"):
    headers["tenantId"] = login_data["tenantId"]
    headers["domainId"] = login_data["domainId"]


# 2. Collect DDC1 device records
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

print(f"Initializing {MAX_WORKERS} collection workers...")

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

print(f"Found {len(all_ddc1_devices)} unique DDC1 devices.")


# 3. Enrich devices with interface types, VRFs, and protocols
interface_errors = []

if all_ddc1_devices:
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


# 4. Create fallback record if no devices were found
if not all_ddc1_devices:
    all_ddc1_devices.append(
        {
            "hostName": "No Matching DDC1 Assets Discovered",
            "interfaceTypes": "No Interface Data",
            "vrfNames": "None",
            "routingProtocols": "None",
        }
    )


# 5. Generate CSV report
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
        filtered_device = {
            key: value
            for key, value in device.items()
            if str(key).strip().lower()
            not in EXCLUDED_REPORT_COLUMNS
        }

        writer.writerow(filtered_device)

print(f"CSV created: {OUTPUT_FILE}")

if interface_errors:
    print("\nInterface lookup diagnostics:")
    for error in sorted(set(interface_errors))[:10]:
        print(f"- {error}")

print("Logging out...")
