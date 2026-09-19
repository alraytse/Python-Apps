import requests
import csv
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL certificate verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- Configuration Section ---
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

# Exclude all case variants of these columns from the CSV report.
EXCLUDED_REPORT_COLUMNS = {
    "managementip",
    "mgmtip",
}

def is_excluded_field(field_name):
    """Determine whether a field should be excluded from the report."""
    field_name_lower = str(field_name).strip().lower()

    return (
        "id" in field_name_lower
        or "discovery" in field_name_lower
        or "time" in field_name_lower
        or field_name_lower in EXCLUDED_REPORT_COLUMNS
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
        f"Authentication failed ({response.status_code}): {response.text}"
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

# 2. Pull basic device records
def fetch_device_page(skip_value):
    url = f"{BASE_URL}/CMDB/Devices"

    query_params = {
        "skip": skip_value,
        "limit": PAGE_LIMIT,
    }

    try:
        res = requests.get(
            url,
            headers=headers,
            params=query_params,
            verify=False,
            timeout=30,
        )

        if res.status_code == 200:
            return res.json().get("devices", [])

        return []

    except Exception:
        return []

# 3. Enrich devices with interface, VRF, and routing data
def enrich_device_metadata(device_id, hostname):
    types = set()
    vrfs = set()
    protocols = set()

    query_params_id = (
        {"deviceId": device_id}
        if device_id
        else {"hostname": str(hostname).lower()}
    )

    query_params_fallback = {
        "hostname": str(hostname).lower()
    }

    try:
        intf_url = f"{BASE_URL}/CMDB/Devices/Interfaces"

        res_intf = requests.get(
            intf_url,
            headers=headers,
            params=query_params_id,
            verify=False,
            timeout=15,
        )

        if (
            res_intf.status_code != 200
            or not res_intf.json().get("interfaces")
        ):
            res_intf = requests.get(
                intf_url,
                headers=headers,
                params=query_params_fallback,
                verify=False,
                timeout=15,
            )

        if res_intf.status_code == 200:
            interfaces = res_intf.json().get("interfaces", [])

            for intf in interfaces:
                if_type = (
                    intf.get("interfaceType")
                    or intf.get("type")
                    or intf.get("intfType")
                )

                if if_type:
                    types.add(str(if_type))

                vrf_name = (
                    intf.get("vrf")
                    or intf.get("vrfName")
                    or intf.get("vrf_name")
                )

                if (
                    vrf_name
                    and str(vrf_name).strip().lower()
                    not in DEFAULT_VRFS
                ):
                    vrfs.add(str(vrf_name).strip())

    except Exception:
        pass

    try:
        rt_url = f"{BASE_URL}/CMDB/Devices/Routing/Protocols"

        res_rt = requests.get(
            rt_url,
            headers=headers,
            params=query_params_id,
            verify=False,
            timeout=15,
        )

        if (
            res_rt.status_code != 200
            or not res_rt.json().get("protocols")
        ):
            res_rt = requests.get(
                rt_url,
                headers=headers,
                params=query_params_fallback,
                verify=False,
                timeout=15,
            )

        if res_rt.status_code == 200:
            proto_list = res_rt.json().get("protocols", [])

            for proto in proto_list:
                p_name = (
                    proto.get("protocolName")
                    or proto.get("name")
                    or proto.get("type")
                )

                if p_name:
                    protocols.add(str(p_name).upper())

    except Exception:
        pass

    return list(types), list(vrfs), list(protocols)

# 4. Global device collection
all_ddc1_devices = []
seen_hostnames = set()
all_discovered_columns = {
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
}

skip_offsets = [
    i * PAGE_LIMIT
    for i in range(MAX_ESTIMATED_PAGES)
]

print(
    f"\nInitializing ThreadPoolExecutor with "
    f"{MAX_WORKERS} workers..."
)
print(
    "Pulling inventory globally and compiling "
    "DDC1 device profiles..."
)

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_to_skip = {
        executor.submit(fetch_device_page, skip): skip
        for skip in skip_offsets
    }

    for future in as_completed(future_to_skip):
        try:
            devices_batch = future.result()

            if devices_batch:
                for device in devices_batch:
                    hostname = (
                        device.get("hostName")
                        or device.get("hostname")
                        or device.get("name")
                    )

                    if not hostname or hostname in seen_hostnames:
                        continue

                    device_str = str(device).upper()

                    if "DDC1" not in device_str:
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
                                if is_excluded_field(sub_key):
                                    continue

                                flat_device[f"attr_{sub_key}"] = sub_value
                        else:
                            if is_excluded_field(key):
                                continue

                            flat_device[key] = value

                    for flat_key in flat_device.keys():
                        if (
                            flat_key != "_internal_processing_id"
                            and not is_excluded_field(flat_key)
                        ):
                            all_discovered_columns.add(flat_key)

                    all_ddc1_devices.append(flat_device)

        except Exception:
            pass

print(
    f"\n[DEBUG LOG] Phase 1 finished. "
    f"Found a total of {len(all_ddc1_devices)} "
    f"unique DDC1 devices."
)

# 5. Device enrichment
if all_ddc1_devices:
    print(
        f"Gathering interface types, production VRFs, "
        f"and routing protocols for "
        f"{len(all_ddc1_devices)} devices..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as enrichment_executor:

        future_to_device = {}

        for dev in all_ddc1_devices:
            hostname = (
                dev.get("hostName")
                or dev.get("hostname")
                or dev.get("name")
            )

            device_id_context = dev.get(
                "_internal_processing_id"
            )

            if hostname:
                future = enrichment_executor.submit(
                    enrich_device_metadata,
                    device_id_context,
                    hostname,
                )

                future_to_device[future] = dev

        for future in as_completed(future_to_device):
            device_ref = future_to_device[future]

            try:
                (
                    unique_types,
                    unique_vrfs,
                    unique_protocols,
                ) = future.result()

                device_ref["interfaceTypes"] = (
                    ", ".join(sorted(unique_types))
                    if unique_types
                    else "N/A"
                )

                device_ref["vrfNames"] = (
                    ", ".join(sorted(unique_vrfs))
                    if unique_vrfs
                    else "None"
                )

                device_ref["routingProtocols"] = (
                    ", ".join(sorted(unique_protocols))
                    if unique_protocols
                    else "None"
                )

            except Exception:
                device_ref["interfaceTypes"] = "Error"
                device_ref["vrfNames"] = "Error"
                device_ref["routingProtocols"] = "Error"

            finally:
                device_ref.pop("_internal_processing_id", None)

# 6. Generate CSV report
print("\nProcessing compilation data...")

if not all_ddc1_devices:
    all_ddc1_devices.append(
        {
            "hostName": "No Matching DDC1 Assets Discovered",
            "interfaceTypes": "N/A",
            "vrfNames": "None",
            "routingProtocols": "None",
        }
    )

    all_discovered_columns.update(
        {
            "hostName",
            "interfaceTypes",
            "vrfNames",
            "routingProtocols",
        }
    )

primary_headers = [
    "hostName",
    "hostname",
    "name",
    "interfaceTypes",
    "vrfNames",
    "routingProtocols",
]

sorted_all_columns = sorted(all_discovered_columns)

dynamic_extra_headers = [
    column
    for column in sorted_all_columns
    if column not in primary_headers
    and not is_excluded_field(column)
]

ordered_headers = primary_headers + dynamic_extra_headers

# Final protection against management IP columns.
ordered_headers = [
    column
    for column in ordered_headers
    if str(column).strip().lower()
    not in EXCLUDED_REPORT_COLUMNS
]

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

    for ddc1_device in all_ddc1_devices:
        filtered_device = {
            key: value
            for key, value in ddc1_device.items()
            if str(key).strip().lower()
            not in EXCLUDED_REPORT_COLUMNS
        }

        writer.writerow(filtered_device)

print(
    f"✅ Success! File generation routine complete: "
    f"{OUTPUT_FILE}"
)

# 7. Gracefully terminate session
print("\nLogging out...")
