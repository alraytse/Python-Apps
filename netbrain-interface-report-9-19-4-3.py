"""
NetBrain Interface Report
==========================

Generates a per-interface CSV audit report for devices at a given NetBrain
site, using the NetBrain REST API (CMDB/Devices and CMDB/Interfaces
endpoints).

Interface
---------
Inputs (interactive prompts):
    NetBrain Username   - str, required. NetBrain login username.
    NetBrain Password   - str, required (hidden input). NetBrain login password.
    Target Site         - str, optional. Site code to filter devices by
                           (matched against hostname, mgmt IP, and subtype).
                           Defaults to "DDC1" if left blank.
    IP Addresses        - str, optional. Comma-delimited list of IPs to
                           investigate, e.g. "203.0.113.5, 198.51.100.2"
                           (spaces/semicolons also accepted; see "IP address
                           investigation" below). Duplicates are removed;
                           re-prompts if any entry is invalid; leave blank
                           to skip.

Device type scope:
    Only devices whose type/family/vendor/model metadata matches one of the
    categories in TARGET_DEVICE_TYPES (constant, edit in source) are included.
    Currently set to {"all"}, which includes every device at the site. Set it
    to e.g. {"firewall", "router", "switch", "load_balancer"} to filter.
    See DEVICE_TYPE_KEYWORDS for the keyword lists used for each category.

Configuration (constants, edit in source to change):
    BASE_URL       - NetBrain Services API base URL.
    MAX_WORKERS    - Thread pool size for concurrent device enrichment (default 10).
    PAGE_LIMIT     - Page size when paginating the CMDB Devices endpoint (default 100).
    LIMIT_DEVICES  - Max number of matching devices to process (default 100000,
                     i.e. effectively unlimited).

Output:
    A CSV file written to:
        ~/Downloads/{TARGET_SITE}.netbrain.interface.report.{TIMESTAMP}.csv
    One row per device interface, with columns including:
        name, requestedSite, serialNumber, hardwareModel,
        interfaceName, interfaceDescription, interfaceSpeed, resolvedIP,
        vrfNames, securityZone, plus any additional device attributes
        discovered from the API response.
        securityZone is populated only for devices detected as firewalls
        (see FIREWALL_KEYWORDS / is_firewall_device); it is "N/A" for
        all other device types.

    Interface status columns (every row):
        interfaceStatus        - Active (up/up) / Shutdown (admin down) /
                                 Down (not shut, link/protocol down) /
                                 Not shut (oper state unknown) / Unknown
        interfaceAdminStatus   - up / down / unknown
        interfaceOperStatus    - up / down / unknown
        interfaceStatusSource  - which NetBrain attribute(s) and/or
                                 running-config line the status came from
      Admin state uses the Cisco running-config "shutdown" line where the
      config was retrieved; otherwise NetBrain interface attributes. This
      reflects NetBrain's last discovery/benchmark, not a real-time poll.

    IP address investigation (only when IP Addresses were entered):
      Each interface row gets:
        matchedIPs     - which of the entered addresses matched this
                         interface in any way ("None" if none)
        ipMatchDetail  - "No", or how each address matched: assigned to the
                         interface, inside its connected subnet, or
                         referenced by a NAT rule (Cisco "ip nat
                         inside/outside source" rules incl. "ip nat pool"
                         ranges; PAN-OS translate-to values)
        ipMatchStatus  - interfaceStatus of the matching interface
      Matching rows are sorted to the top of the report. A companion
      summary CSV is also written to:
        ~/Downloads/{TARGET_SITE}.netbrain.ipcheck.{TIMESTAMP}.csv
      containing an overview (status counts, management-IP matches across
      ALL sites) followed by one row per entered address: status (ACTIVE /
      SHUTDOWN / DOWN / NAT ONLY / IN CONNECTED SUBNET ONLY / DEVICE
      MANAGEMENT IP / NOT FOUND), where it's assigned, NAT references,
      connected subnet + network/broadcast flag, reverse DNS (up to
      PUBLIC_IP_RDNS_MAX = 256 addresses), and a live probe FROM THIS
      WORKSTATION (ping + TCP to PUBLIC_IP_PROBE_PORTS, up to
      PUBLIC_IP_PROBE_MAX = 32 addresses). Set NETBRAIN_PUBLIC_IP_PROBE=0
      to skip the live probe. Interface/NAT matching only covers devices
      at TARGET_SITE.

    Switch public IP space evaluation (only when Switch Hostnames were entered
    at the last prompt -- comma-delimited, case-insensitive, short or FQDN):
      The run is scoped to exactly those devices (any site). Every interface
      carrying public (globally routable) address space gets:
        publicSubnets        - public prefixes on the interface
        publicSpaceVerdict   - ACTIVE - IN USE / CAN BE SHUTDOWN /
                               ALREADY SHUTDOWN / DOWN - STILL REFERENCED /
                               ACTIVE - VERIFY USAGE / REVIEW
        publicSpaceReason    - why
        publicSpaceEvidence  - ARP neighbors in the subnet (excluding the
                               switch's own and HSRP/VRRP addresses), ip nat
                               inside/outside, static-route/BGP next hops in
                               the subnet
      Usage evidence comes from NetBrain's stored running-config and
      "show ip arp" (+ "show ip arp vrf <name>"). Up/up with no evidence ->
      CAN BE SHUTDOWN only when both ARP and config were retrieved,
      otherwise ACTIVE - VERIFY USAGE. A per-switch rollup is written to:
        ~/Downloads/{TARGET_SITE}.netbrain.switch.publicip.{TIMESTAMP}.csv

    When NETBRAIN_DEBUG=1 is set, a separate debug log file is written to:
        ~/Downloads/{TARGET_SITE}.netbrain.debug.{TIMESTAMP}.log
    containing per-device/per-interface diagnostics (firewall detection,
    NAT/PAT rulebase fetch HTTP status + response previews, raw interface
    attribute dumps). Console output stays limited to progress messages
    (fetching/enriching/export status) -- all [DEBUG]-level detail goes to
    this file instead of the terminal.

Usage:
    python netbrain-interface-report.py

Requires network access to the NetBrain API host and valid NetBrain
credentials. SSL certificate verification is disabled for API requests.
"""

import csv
import getpass
import ipaddress
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests
import urllib3

# Disable insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set NETBRAIN_DEBUG=1 in the environment to write diagnostic info about
# firewall detection, NAT/PAT rulebase fetches, and raw interface attribute
# keys/values as returned by the NetBrain API to a dedicated debug log file
# (see DEBUG_LOG_FILE below), rather than the console. Use this to confirm
# the real field names for security zone data if securityZone is coming
# back as "N/A" unexpectedly, or to diagnose why NAT/PAT lookups are failing.
DEBUG_ZONES = os.environ.get("NETBRAIN_DEBUG", "").strip().lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Interactive Inputs & Configuration
# ---------------------------------------------------------------------------
USERNAME = input("Enter NetBrain Username: ").strip()
PASSWORD = getpass.getpass("Enter NetBrain Password: ").strip()

site_input = input("Enter Target Site [default: DDC1]: ").strip().upper()
TARGET_SITE = site_input if site_input else "DDC1"

if not USERNAME or not PASSWORD:
    sys.exit("Error: Username and Password cannot be empty.")

# Optional list of IP addresses to investigate, comma-delimited (spaces,
# semicolons, or newlines also work as separators), e.g.
#   203.0.113.5, 203.0.113.6, 198.51.100.2
# When provided, every interface row in the report is checked against each
# address (assigned to the interface, inside its connected subnet, or
# referenced by a NAT rule/pool), the matching interface's admin/oper state
# is reported, and a companion summary CSV is written with one row per
# address (ACTIVE / SHUTDOWN / DOWN / NAT ONLY / IN CONNECTED SUBNET ONLY /
# DEVICE MANAGEMENT IP / NOT FOUND) plus a live reachability probe from
# this workstation. Leave blank to skip.
PUBLIC_IPS = []
while True:
    _ips_input = input(
        "Enter IP Addresses to investigate, comma-delimited "
        "(e.g. 203.0.113.5, 198.51.100.2) [optional, press Enter to skip]: "
    ).strip()
    if not _ips_input:
        break
    _tokens = [t.strip() for t in re.split(r"[,;\s]+", _ips_input) if t.strip()]
    _parsed, _invalid = [], []
    for _tok in _tokens:
        try:
            _parsed.append(ipaddress.ip_address(_tok))
        except ValueError:
            _invalid.append(_tok)
    if _invalid:
        print(
            f"  Not valid IP address(es): {', '.join(_invalid)} -- please re-enter the list "
            f"(individual addresses only, no subnets/ranges)."
        )
        continue
    PUBLIC_IPS = list(dict.fromkeys(_parsed))  # de-duplicate, keep input order
    if len(PUBLIC_IPS) < len(_parsed):
        print(f"  Note: removed {len(_parsed) - len(PUBLIC_IPS)} duplicate address(es).")
    _non_public = [str(ip) for ip in PUBLIC_IPS if not ip.is_global]
    if _non_public:
        print(
            f"  Warning: not public (globally routable): {', '.join(_non_public)}. "
            f"Investigating anyway."
        )
    print(f"  {len(PUBLIC_IPS)} address(es) to investigate.")
    break

# Optional list of switch hostnames whose public IP space should be
# evaluated, comma-delimited (spaces/semicolons also work), e.g.
#   DDC1-CORE-SW1, DDC1-CORE-SW2
# When provided, the run is scoped to exactly these devices (matched
# case-insensitively against NetBrain hostnames across ALL sites; the
# short name before the first "." also matches) instead of every device at
# TARGET_SITE. Every interface carrying public (globally routable) address
# space gets a verdict -- ACTIVE - IN USE / CAN BE SHUTDOWN / ALREADY
# SHUTDOWN / DOWN - STILL REFERENCED / ACTIVE - VERIFY USAGE / REVIEW --
# and a companion summary CSV is written (see SWITCH_PUBLIC_FILE).
SWITCH_HOSTNAMES = []
_HOSTNAME_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
while True:
    _sw_input = input(
        "Enter switch hostnames to evaluate public IP space, comma-delimited "
        "(e.g. DDC1-SW1, DDC1-SW2) [optional, press Enter to skip]: "
    ).strip()
    if not _sw_input:
        break
    _sw_tokens = [t.strip() for t in re.split(r"[,;\s]+", _sw_input) if t.strip()]
    _sw_invalid = [t for t in _sw_tokens if not _HOSTNAME_TOKEN_RE.match(t)]
    if _sw_invalid:
        print(f"  Not valid hostname(s): {', '.join(_sw_invalid)} -- please re-enter the list.")
        continue
    SWITCH_HOSTNAMES = list(dict.fromkeys(_sw_tokens))
    print(
        f"  {len(SWITCH_HOSTNAMES)} switch(es) to evaluate -- the run is limited to these "
        f"devices (site filter not applied to device selection)."
    )
    break

# lowercased full name AND short name (before the first ".") -> name as entered
SWITCH_HOSTNAME_LOOKUP = {}
for _h in SWITCH_HOSTNAMES:
    SWITCH_HOSTNAME_LOOKUP.setdefault(_h.lower(), _h)
    SWITCH_HOSTNAME_LOOKUP.setdefault(_h.lower().split(".")[0], _h)


def requested_switch_name(hostname) -> str:
    """Returns the hostname as the user entered it if `hostname` is one of
    the requested switches (full or short-name match), else ""."""
    if not SWITCH_HOSTNAMES or not hostname:
        return ""
    h = str(hostname).strip().lower()
    return SWITCH_HOSTNAME_LOOKUP.get(h) or SWITCH_HOSTNAME_LOOKUP.get(h.split(".")[0]) or ""

# Set NETBRAIN_PUBLIC_IP_PROBE=0 to skip the live ping/TCP reachability
# probe (e.g. if outbound ICMP/TCP from this workstation is blocked or not
# permitted). The NetBrain-side investigation still runs.
PUBLIC_IP_LIVE_PROBE = os.environ.get("NETBRAIN_PUBLIC_IP_PROBE", "1").strip().lower() not in ("0", "false", "no")
PUBLIC_IP_PROBE_PORTS = [443, 80, 22]
# Live probe only runs when at most this many addresses were entered;
# reverse DNS is looked up for at most PUBLIC_IP_RDNS_MAX addresses.
PUBLIC_IP_PROBE_MAX = 32
PUBLIC_IP_RDNS_MAX = 256

if PUBLIC_IPS and PUBLIC_IP_LIVE_PROBE and len(PUBLIC_IPS) > PUBLIC_IP_PROBE_MAX:
    print(
        f"  Note: {len(PUBLIC_IPS)} addresses exceeds PUBLIC_IP_PROBE_MAX ({PUBLIC_IP_PROBE_MAX}) -- "
        f"the live probe will be skipped; NetBrain checks still cover every address."
    )

BASE_URL = "https://netbrain.mckesson.com/ServicesAPI/API/V1"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = os.path.expanduser(
    f"~/Downloads/{TARGET_SITE}.netbrain.interface.report.{TIMESTAMP}.csv"
)
DEBUG_LOG_FILE = os.path.expanduser(
    f"~/Downloads/{TARGET_SITE}.netbrain.debug.{TIMESTAMP}.log"
)
PUBLIC_IP_SUMMARY_FILE = (
    os.path.expanduser(f"~/Downloads/{TARGET_SITE}.netbrain.ipcheck.{TIMESTAMP}.csv")
    if PUBLIC_IPS
    else None
)
SWITCH_PUBLIC_FILE = (
    os.path.expanduser(f"~/Downloads/{TARGET_SITE}.netbrain.switch.publicip.{TIMESTAMP}.csv")
    if SWITCH_HOSTNAMES
    else None
)

# Dedicated logger for [DEBUG] diagnostics -- kept separate from the console
# progress messages (print statements) so debug output goes to its own file
# instead of cluttering the terminal. logging.FileHandler is thread-safe
# (it acquires an internal lock per emit), which matters here since debug
# calls happen concurrently across the ThreadPoolExecutor workers.
debug_logger = logging.getLogger("netbrain_debug")
debug_logger.setLevel(logging.DEBUG if DEBUG_ZONES else logging.CRITICAL + 1)
debug_logger.propagate = False
if DEBUG_ZONES:
    _debug_handler = logging.FileHandler(DEBUG_LOG_FILE, mode="w", encoding="utf-8")
    _debug_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    debug_logger.addHandler(_debug_handler)
    print(f"Debug logging enabled -> {DEBUG_LOG_FILE}")

MAX_WORKERS = 10
PAGE_LIMIT = 100
LIMIT_DEVICES = 100000 # Effectively unlimited -- was hardcoded to 30 (stale comment said "3 devices"), which silently truncated every run regardless of site size. Now that TARGET_DEVICE_TYPES = {"all"}, that cap would defeat the purpose. Lower this back down if you want to limit a run.

# NAT rulebase fetch (fetch_nat_policy_raw) configuration -- overridable via
# environment variables so alternate NetBrain DeviceRawData parameters can be
# tried without editing source.
#
# CONFIRMED (via NETBRAIN_DEBUG testing against this NetBrain instance):
#   - dataType is only valid in the range 0-2 (dataType=4 -> NetBrain error
#     792005 "'dataType' should be between 0 and 2 inclusive").
#   - dataType=1 expects a 'tableName' parameter instead of 'cmd' -- it's a
#     structured table lookup, not a CLI passthrough, so it's not usable
#     for arbitrary commands like this (NetBrain error 791001).
#   - dataType=2 (the default, and the type this docstring originally
#     assumed was "CLI command") returns HTTP 200 but "Device Data Not
#     Found" (NetBrain error 791006) for "show running nat-policy" on every
#     device tested -- the command likely isn't in NetBrain's cached Live
#     Access command set for this device type in this environment.
#   - dataType=0 returns HTTP 200 but silently ignores 'cmd' and returns an
#     unrelated canned raw-data dump instead (observed: a "show system
#     info" transcript, not the requested command) -- see the cmd-echo
#     validation in fetch_nat_policy_raw, which now catches and rejects
#     this rather than misreporting it as real NAT data.
#   None of 0/1/2/4 actually retrieved the NAT rulebase in testing. This
#   looks like it needs a NetBrain-side fix (adding "show running
#   nat-policy" to the cached Live Access command set for Palo Alto
#   devices) rather than a different dataType value -- but the knobs below
#   are kept in case a different command string or a newly-added dataType
#   ends up working.
#
#   NETBRAIN_NAT_CMD                 - CLI command string sent as 'cmd'.
#                                       Default: "show running nat-policy"
#   NETBRAIN_NAT_DATATYPE_CANDIDATES - comma-separated list of 'dataType'
#                                       values to try, in order, per device
#                                       (valid range: 0-2). The first one
#                                       that returns HTTP 200 AND echoes
#                                       NAT_CMD in its content is used for
#                                       that device; others are skipped as
#                                       mismatches/failures. Default: "2"
#                                       (preserves original single-attempt
#                                       behavior). Example:
#                                       NETBRAIN_NAT_DATATYPE_CANDIDATES="2,1,0"
NAT_CMD = os.environ.get("NETBRAIN_NAT_CMD", "show running nat-policy")
_nat_datatype_raw = os.environ.get("NETBRAIN_NAT_DATATYPE_CANDIDATES", "2")
NAT_DATATYPE_CANDIDATES = [
    int(v.strip()) for v in _nat_datatype_raw.split(",") if v.strip().lstrip("-").isdigit()
] or [2]


if DEBUG_ZONES and len(NAT_DATATYPE_CANDIDATES) > 1:
    print(
        f"Testing {len(NAT_DATATYPE_CANDIDATES)} dataType candidates for NAT rulebase "
        f"fetch: {NAT_DATATYPE_CANDIDATES} (cmd={NAT_CMD!r}) -- see debug log for per-attempt results."
    )

session = requests.Session()
session.verify = False

# Optimize HTTP connection pool
adapter = requests.adapters.HTTPAdapter(
    pool_connections=50, 
    pool_maxsize=50, 
    max_retries=2
)
session.mount("https://", adapter)
session.mount("http://", adapter)

DNS_CACHE = {}


def authenticate() -> dict:
    login_url = f"{BASE_URL}/Session"
    login_payload = {"username": USERNAME, "password": PASSWORD}

    try:
        res = session.post(login_url, json=login_payload, timeout=60)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        sys.exit(f"Auth error: {e}")

    data = res.json()
    token = data.get("token") or data.get("tokenID")
    if not token:
        sys.exit("Error: Token missing in response payload.")

    session.headers.update({
        "Token": token,
        "Content-Type": "application/json",
        "Accept": "application/json"
    })

    if "tenantId" in data and "domainId" in data:
        session.headers.update({
            "tenantId": str(data["tenantId"]),
            "domainId": str(data["domainId"])
        })
    return data


def fetch_all_devices() -> list:
    """Dynamically paginates through NetBrain CMDB devices until limit or end is reached."""
    all_devices = []
    skip = 0

    while True:
        url = f"{BASE_URL}/CMDB/Devices"
        try:
            res = session.get(url, params={"skip": skip, "limit": PAGE_LIMIT}, timeout=30)
            if res.status_code != 200:
                break
            
            devices = res.json().get("devices", [])
            if not devices:
                break

            all_devices.extend(devices)
            skip += PAGE_LIMIT
            
            if len(devices) < PAGE_LIMIT:
                break
        except requests.RequestException:
            break

    return all_devices


def fetch_device_attributes(hostname: str) -> dict:
    """Queries CMDB Device Attributes passing attributeNames=sn,model."""
    url = f"{BASE_URL}/CMDB/Devices/Attributes"
    params = {
        "hostname": hostname,
        "attributeNames": "sn,serialNumber,model"
    }
    try:
        res = session.get(url, params=params, timeout=15)
        if res.status_code == 200:
            return res.json().get("attributes", {})
    except requests.RequestException:
        pass
    return {}


def fetch_all_interface_attrs(hostname: str) -> dict:
    """Retrieves all interface attributes for a given hostname in a single API call."""
    url = f"{BASE_URL}/CMDB/Interfaces/Attributes"
    try:
        r = session.get(url, params={"hostname": hostname}, timeout=15)
        if r.status_code == 200:
            return r.json().get("attributes", {})
    except requests.RequestException:
        pass
    return {}


def fetch_device_raw_data(hostname: str, cmd: str, datatype_candidates: list = None, echo_indicators: list = None) -> str:
    """Fetches raw CLI output for `hostname` via NetBrain's DeviceRawData
    passthrough (CMDB/Devices/DeviceRawData), running `cmd`.

    Generic version of the original fetch_nat_policy_raw, parameterized so
    it can be reused for other commands/device types (e.g. Cisco IOS
    "show running-config" for router NAT-interface reporting) without
    duplicating the dataType-candidate/cmd-echo-validation logic.

    `echo_indicators` (optional): a list of substrings, any ONE of which
    (case-insensitive) is accepted as proof the response actually
    corresponds to `cmd`, instead of requiring `cmd` itself to appear
    verbatim. This matters because some devices echo an abbreviated form
    of the command rather than what was literally requested (observed:
    a Cisco IOS router asked to run "show running-config" echoed "show
    run" instead -- the real command's standard abbreviation -- which
    would otherwise cause a correct, real response to be wrongly
    discarded as a mismatch). Defaults to [cmd] when not given, preserving
    the original strict-match behavior.

    Tries each dataType value in `datatype_candidates` (defaults to
    NAT_DATATYPE_CANDIDATES) in order, stopping at the first HTTP 200
    response whose content actually appears to correspond to `cmd` (see
    the cmd-echo check below) -- regardless of whether the resulting
    content is otherwise empty, since a matched 200 means NetBrain
    accepted and executed that dataType/cmd combination for this device.
    Non-200 responses are treated as "this dataType didn't work for this
    device" and the next candidate is tried.

    IMPORTANT -- cmd-echo validation: some dataType values (observed:
    dataType=0 on this NetBrain instance) return HTTP 200 but silently
    ignore the 'cmd' parameter, instead returning an unrelated canned raw
    data dump rather than actually running `cmd`. Trusting that response
    would misreport results for things that were never actually checked.
    To guard against this, a 200 response is only accepted if `cmd`'s
    text actually appears (case-insensitively) somewhere in the returned
    content; otherwise it's logged as a mismatch and the next candidate
    (if any) is tried, exactly like a non-200 response.

    Returns "" if every candidate fails or mismatches (unreachable,
    unsupported command, bad response, cmd not echoed). Callers MUST treat
    "" as "lookup unavailable" and must NOT interpret it as a confirmed
    negative result -- those are different facts.

    With NETBRAIN_DEBUG=1 set, logs the HTTP status code, a preview of the
    response body, and any exception encountered, per hostname and per
    dataType candidate tried.
    """
    url = f"{BASE_URL}/CMDB/Devices/DeviceRawData"
    candidates = datatype_candidates if datatype_candidates is not None else NAT_DATATYPE_CANDIDATES
    indicators = echo_indicators if echo_indicators is not None else [cmd]

    for data_type in candidates:
        params = {"hostname": hostname, "dataType": data_type, "cmd": cmd}
        try:
            res = session.get(url, params=params, timeout=30)

            if DEBUG_ZONES:
                body_preview = res.text[:300].replace("\n", " ") if res.text else "(empty body)"
                debug_logger.debug(
                    f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}, dataType={data_type}): "
                    f"HTTP {res.status_code} | body_preview={body_preview!r}"
                )

            if res.status_code == 200:
                content = res.json().get("content", "") or ""
                content_lower = content.lower()

                if not any(ind.lower() in content_lower for ind in indicators):
                    if DEBUG_ZONES:
                        content_preview = content[:300].replace("\n", " ") if content else "(empty content field)"
                        debug_logger.debug(
                            f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}, dataType={data_type}): "
                            f"HTTP 200 but none of {indicators!r} found/echoed in "
                            f"content (content_length={len(content)}) -- NetBrain likely "
                            f"ignored 'cmd' and returned unrelated data for this dataType; "
                            f"discarding and trying next candidate if any "
                            f"| content_preview={content_preview!r}"
                        )
                    continue

                if DEBUG_ZONES:
                    content_preview = content[:300].replace("\n", " ") if content else "(empty content field)"
                    debug_logger.debug(
                        f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}, dataType={data_type}): "
                        f"SUCCEEDED (cmd echoed, stopping candidate search) | "
                        f"content_length={len(content)} | content_preview={content_preview!r}"
                    )
                return content

            if DEBUG_ZONES:
                debug_logger.debug(
                    f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}, dataType={data_type}): "
                    f"non-200 status ({res.status_code}) -- trying next candidate if any"
                )
        except (requests.RequestException, ValueError) as e:
            if DEBUG_ZONES:
                debug_logger.debug(
                    f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}, dataType={data_type}): "
                    f"EXCEPTION {type(e).__name__}: {e} -- trying next candidate if any"
                )

    if DEBUG_ZONES:
        debug_logger.debug(
            f"[DEBUG] fetch_device_raw_data({hostname}, cmd={cmd!r}): ALL {len(candidates)} "
            f"dataType candidate(s) failed or mismatched -- treating as lookup unavailable"
        )
    return ""


def fetch_nat_policy_raw(hostname: str) -> str:
    """Fetches the live PAN-OS NAT rulebase for a firewall. Thin wrapper
    around fetch_device_raw_data using the module's NAT_CMD/
    NAT_DATATYPE_CANDIDATES settings -- kept for backward compatibility
    with existing call sites.
    """
    return fetch_device_raw_data(hostname, NAT_CMD, NAT_DATATYPE_CANDIDATES)


# Cisco IOS "show running-config" command used to look up per-interface
# NAT direction ("ip nat inside" / "ip nat outside") for router devices.
CISCO_NAT_CMD = "show running-config"


def fetch_cisco_running_config_raw(hostname: str) -> str:
    """Fetches a Cisco IOS router's running-config via the same
    DeviceRawData passthrough used for PAN-OS NAT policy, reusing the same
    dataType-candidate/cmd-echo-validation machinery.

    Uses a generous echo_indicators list rather than requiring the literal
    "show running-config" text: Cisco IOS commonly echoes the standard
    abbreviated form "show run" instead of what was actually requested
    (observed on this NetBrain instance), and the output's own header
    lines ("Building configuration...", "Current configuration") are
    unambiguous proof of a genuine running-config response regardless of
    how the command itself got echoed.
    """
    return fetch_device_raw_data(
        hostname,
        CISCO_NAT_CMD,
        NAT_DATATYPE_CANDIDATES,
        echo_indicators=[
            "show running-config",
            "show run",
            "building configuration",
            "current configuration",
            # Some devices return an SNMP-generated config dump instead of
            # a live CLI transcript -- no command echo at all, just this
            # header comment. Still genuine config content, just a
            # different retrieval path (observed: DDC1-IDFE1-TSV1).
            "this config file is generated via snmp",
        ],
    )


# Cisco IOS-XE SD-WAN (cEdge) command showing the device's active policy
# as pushed from the vSmart controller -- used as a fallback source for
# "policy lists prefix-list <name> ..." definitions that reference a name
# used in "ip nat inside source list <name> ..." but aren't found in the
# device's own local running-config (observed: DDC1-USONME-GRT1/GRT2,
# where "Viptela-Underlay-NAT" is referenced but never defined locally --
# centrally-managed SD-WAN policy objects are often only visible this way,
# not via "show running-config").
VIPTELA_POLICY_CMD = "show sdwan policy from-vsmart"


def fetch_viptela_policy_raw(hostname: str) -> str:
    """Fetches a Cisco SD-WAN (cEdge) router's active vSmart-pushed policy
    via the same DeviceRawData passthrough, reusing the same
    dataType-candidate/cmd-echo-validation machinery. This is an
    opportunistic, best-effort fetch: if the device doesn't support this
    command (e.g. it isn't actually SD-WAN-enabled), it will simply fail
    validation like any unsupported command and return "" -- callers
    should treat that as "no supplementary data available", not an error.
    """
    return fetch_device_raw_data(
        hostname,
        VIPTELA_POLICY_CMD,
        NAT_DATATYPE_CANDIDATES,
        echo_indicators=[
            "show sdwan policy",
            "show policy from-vsmart",
            "from-vsmart policy",
        ],
    )


# Matches one PAN-OS NAT rule block, e.g.:
#   "Meraki_Public-to-intraf-34-1; index: 1" {
#           nat-type ipv4;
#           from buINTRAFUSION;
#           ...
#           translate-to "src: 143.112.197.34 (static-ip) (pool idx: 1)";
#           terminal no;
#   }
_NAT_RULE_BLOCK_RE = re.compile(r'"([^"]+);\s*index:\s*(\d+)"\s*\{(.*?)\n\}', re.DOTALL)
_NAT_FIELD_RE = re.compile(r'^\s*([\w-]+)\s+(.*?);\s*$', re.MULTILINE)


def _format_detail_list(items: list, max_items: int = 3) -> str:
    """Joins a list of rule/detail strings with '; ', deduplicated
    (order-preserving) and capped at max_items so a zone or interface with
    dozens/hundreds of matching rules doesn't produce an unreadable,
    unbounded CSV cell full of repeats. When truncated after
    deduplication, appends '...and N more' so the count of hidden unique
    items is still visible. Pass max_items=None to disable the cap
    entirely (still deduplicates) -- used for lists the caller wants
    shown in full, e.g. ACL IP addresses.
    Returns "" for an empty list (caller decides the appropriate fallback
    text, e.g. "No NAT rules").
    """
    if not items:
        return ""
    seen = set()
    unique_items = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique_items.append(item)
    shown = unique_items if max_items is None else unique_items[:max_items]
    remaining = len(unique_items) - len(shown)
    joined = "; ".join(shown)
    if remaining > 0:
        joined += f"; ...and {remaining} more"
    return joined


def _format_acl_refs(acl_refs: list) -> str:
    """Formats a list of (acl_id, [addresses]) pairs (from
    parse_cisco_nat_config's "interface_acl_refs") into a display string
    with the ACL name/number included, e.g.:
        "ACL 10: 10.5.5.0 0.0.0.255; 10.5.5.99"
    Multiple ACLs referencing the same interface are joined with '; ',
    each still labeled with its own ACL id. Addresses within an ACL are
    deduplicated (order-preserving) via _format_detail_list, shown in
    full (no cap), since the point of this column is the complete
    address list.
    """
    if not acl_refs:
        return ""
    groups = []
    for acl_id, addrs in acl_refs:
        addr_text = _format_detail_list(addrs, max_items=None)
        if addr_text:
            groups.append(f"ACL {acl_id}: {addr_text}")
    return "; ".join(groups)


def _split_zone_list(raw: str) -> list:
    """Parses a PAN-OS 'from'/'to' field value, which may be a single zone
    name, an 'any', or a bracketed list like '[ zoneA zoneB ]'."""
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        return [z for z in raw[1:-1].split() if z]
    if raw and raw.lower() != "any":
        return [raw]
    return []


def _clean_nat_value(raw: str) -> str:
    """Cleans a raw PAN-OS field value (e.g. translate-to) for human-
    readable display. PAN-OS sometimes represents a value as a bracketed
    list of quoted sub-values, e.g.:
        [ "src: ae2.52 192.168.158.222 (dynamic-ip-and-port) (pool idx: 1)" "dst: 10.44.35.78" ]
    which is exact CLI syntax but reads poorly in a CSV cell. This strips
    the brackets/quotes and joins the sub-values with ', ' instead:
        src: ae2.52 192.168.158.222 (dynamic-ip-and-port) (pool idx: 1), dst: 10.44.35.78
    A plain (non-bracketed) value passes through with just its own
    surrounding quotes stripped, unchanged otherwise.
    """
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        parts = re.findall(r'"([^"]*)"', inner)
        if parts:
            return ", ".join(p.strip() for p in parts if p.strip())
        return inner.strip('"')
    return s.strip('"')


# NetBrain's dataType=0 raw-data dump returns one giant transcript
# containing the concatenated output of MANY "show ..." commands (system
# info, security-policy, nat-policy, etc.), not just the one command we
# asked for via 'cmd'. PAN-OS uses the identical '"RuleName; index: N" { }'
# block syntax for every policy type (security, NAT, QoS, ...), so running
# _NAT_RULE_BLOCK_RE against the *entire* transcript indiscriminately picks
# up rule blocks from unrelated sections (observed: real security-policy
# rules with source/destination/application/action fields, misidentified
# as empty/malformed NAT rules because they have no translate-to field).
#
# This regex matches a command's echoed prompt line, e.g.:
#   dm9q0yx@DDC1-B2B-FW5 vsys1(active)> show running nat-policy
# capturing the command text that follows '>' on that line, so the
# transcript can be split into per-command sections at each prompt.
_PROMPT_CMD_RE = re.compile(r'\S+@\S+[^\r\n>]*>\s*(show[^\r\n]*)', re.IGNORECASE)


def _extract_command_section(content: str, cmd: str):
    """Isolates the output belonging to `cmd` from a raw multi-command CLI
    transcript, using the prompt-echo boundaries matched by _PROMPT_CMD_RE.

    Returns:
      - the isolated section text, if `cmd`'s prompt echo was found.
      - the full `content` unchanged, if NO prompt echoes were found at all
        (i.e. this doesn't look like a multi-command transcript -- treat it
        as if it were already just this command's own output, preserving
        compatibility with a dataType that returns a single command's
        output directly rather than a bundled transcript).
      - None, if prompt echoes WERE found but none of them match `cmd` --
        meaning the requested command was never actually run in this
        transcript, so there's nothing legitimate to parse.
    """
    if not content:
        return content

    matches = list(_PROMPT_CMD_RE.finditer(content))
    if not matches:
        return content

    cmd_norm = cmd.strip().lower()
    for i, m in enumerate(matches):
        echoed_cmd = m.group(1).strip().lower()
        if echoed_cmd == cmd_norm or echoed_cmd.startswith(cmd_norm + " "):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            return content[start:end]

    return None


def parse_nat_policy(raw_text: str, hostname: str = "") -> list:
    """Parses PAN-OS 'show running nat-policy' CLI output into rule dicts:
    {name, index, from_zones, to_zones, translate_to, is_nat, is_pat}.

    is_nat: True if the rule performs any source/destination translation
            (a non-empty translate-to field).
    is_pat: True specifically when translate-to indicates port-overloaded
            translation ("dynamic-ip-and-port") -- i.e. true PAT, as
            opposed to a static 1:1 NAT or a non-overloaded dynamic-ip pool.
    """
    rules = []

    section_text = _extract_command_section(raw_text, NAT_CMD)

    if DEBUG_ZONES:
        if section_text is None:
            debug_logger.debug(
                f"[DEBUG] parse_nat_policy({hostname}): _extract_command_section -> None "
                f"(prompts found in transcript, but none matched {NAT_CMD!r})"
            )
        elif section_text is raw_text:
            debug_logger.debug(
                f"[DEBUG] parse_nat_policy({hostname}): _extract_command_section -> "
                f"UNCHANGED fallback (no prompts detected at all in "
                f"{len(raw_text)}-char transcript; treating entire raw_text as this "
                f"command's own output)"
            )
        else:
            debug_logger.debug(
                f"[DEBUG] parse_nat_policy({hostname}): _extract_command_section -> "
                f"isolated {len(section_text)}-char section out of "
                f"{len(raw_text)}-char full transcript | section starts with: "
                f"{section_text[:200]!r}"
            )

    if section_text is None:
        # Prompt echoes were found in the transcript, but none of them
        # matched NAT_CMD -- the requested command was never actually run
        # here, so there's nothing legitimate to parse. Returning zero
        # rules (rather than falling back to the whole transcript) avoids
        # re-introducing the original bug: matching rule blocks from an
        # unrelated command's section (e.g. security-policy) and
        # misreporting them as NAT data.
        if DEBUG_ZONES:
            debug_logger.debug(
                f"[DEBUG] parse_nat_policy({hostname}): transcript contains other "
                f"command prompts but not {NAT_CMD!r} -- can't isolate a nat-policy "
                f"section, returning zero rules rather than risk parsing an "
                f"unrelated command's output"
            )
        return rules

    # PAN-OS's own built-in default rules ("intrazone-default",
    # "interzone-default") genuinely have no from/to zones and no
    # translation by design -- that's not a parsing gap. Any other rule
    # name that comes back fully empty (no from/to/translate-to matched
    # at all) is suspicious: real, deliberately-named rules almost never
    # have zero zones and zero translation. Log a sample of the raw block
    # text for a couple of those (capped, so a rulebase with hundreds of
    # suspiciously-empty rules doesn't flood the debug log) so the actual
    # formatting can be inspected and the field regex fixed if needed.
    _KNOWN_ZONELESS_DEFAULTS = {"intrazone-default", "interzone-default"}
    _unexplained_empty_logged = 0

    for match in _NAT_RULE_BLOCK_RE.finditer(section_text or ""):
        name, index, body = match.group(1), match.group(2), match.group(3)
        fields = dict(_NAT_FIELD_RE.findall(body))

        from_zones = _split_zone_list(fields.get("from", ""))
        to_zones = _split_zone_list(fields.get("to", ""))
        translate_to = _clean_nat_value(fields.get("translate-to", ""))

        if (
            DEBUG_ZONES
            and not translate_to
            and not from_zones
            and not to_zones
            and name not in _KNOWN_ZONELESS_DEFAULTS
            and _unexplained_empty_logged < 2
        ):
            _unexplained_empty_logged += 1
            debug_logger.debug(
                f"[DEBUG] parse_nat_policy({hostname}): rule '{name}' (index {index}) parsed "
                f"as fully empty (no from/to/translate-to matched) but isn't a known "
                f"zoneless default rule -- likely a field-regex/formatting mismatch for "
                f"this rule's actual raw text, not a genuinely empty rule. "
                f"Raw block body (first 800 chars): {body[:800]!r}"
            )

        rules.append({
            "name": name,
            "index": index,
            "from_zones": from_zones,
            "to_zones": to_zones,
            "translate_to": translate_to,
            "is_nat": bool(translate_to),
            "is_pat": "dynamic-ip-and-port" in translate_to.lower(),
        })
    return rules


def build_zone_nat_map(rules: list) -> dict:
    """Aggregates parsed NAT rules into {zone_name_lower: {'nat': bool, 'pat': bool}}.

    A zone appearing as either the 'from' or 'to' side of a translating rule
    is considered NAT/PAT-associated. Zones that never appear (or appear
    only in non-translating rules) map to {'nat': False, 'pat': False},
    which callers can confidently report as "No" -- since this map is only
    built from a rulebase we successfully retrieved in full.
    """
    zone_map = {}
    for rule in rules:
        for zone in rule["from_zones"] + rule["to_zones"]:
            key = zone.strip().lower()
            if not key:
                continue
            entry = zone_map.setdefault(key, {"nat": False, "pat": False})
            entry["nat"] = entry["nat"] or rule["is_nat"]
            entry["pat"] = entry["pat"] or rule["is_pat"]
    return zone_map


def _strip_dst_suffix(value: str) -> str:
    """Drops a ', dst: ...' suffix from a cleaned translate-to value when a
    'src:' portion is also present, so that many rules sharing the same
    source translation/pool (e.g. the same "dynamic-ip-and-port" pool)
    don't show up as spurious near-duplicates in natInterfaceDetail merely
    because each rule targets a different destination. A value with only
    a destination component (no accompanying 'src:') is left unchanged,
    since in that case the destination IS the actual translation, not
    incidental per-rule variation.
    """
    if "src:" in value.lower():
        return re.split(r",\s*dst:", value, maxsplit=1, flags=re.IGNORECASE)[0].strip()
    return value


def build_zone_nat_details(rules: list) -> dict:
    """Aggregates parsed NAT rules into
    {zone_name_lower: {'nat_details': [str, ...], 'pat_details': [str, ...]}}.

    Each detail string is the raw translate-to value for every translating
    rule touching that zone (as either the 'from' or 'to' side), with a
    redundant destination suffix stripped when a source translation is
    also present (see _strip_dst_suffix) so repeated use of the same
    source pool across many rules collapses into one entry after
    deduplication instead of appearing once per distinct destination.
    This gives the actual NAT/PAT translation info (e.g. the static IP or
    dynamic-ip-and-port pool), rather than just a Yes/No flag. Zones with no
    translating rules map to empty lists.
    """
    zone_details = {}
    for rule in rules:
        for zone in rule["from_zones"] + rule["to_zones"]:
            key = zone.strip().lower()
            if not key:
                continue
            entry = zone_details.setdefault(key, {"nat_details": [], "pat_details": []})
            if rule["is_nat"]:
                detail = _strip_dst_suffix(rule["translate_to"])
                entry["nat_details"].append(detail)
                if rule["is_pat"]:
                    entry["pat_details"].append(detail)
    return zone_details


# Matches one "interface X ... !" block in a Cisco IOS running-config, e.g.:
#   interface GigabitEthernet0/1
#    description WAN
#    ip address 203.0.113.1 255.255.255.0
#    ip nat outside
#   !
_CISCO_INTERFACE_BLOCK_RE = re.compile(
    r"^interface\s+(\S+)\s*\n(.*?)(?=^interface\s+\S|\Z)", re.MULTILINE | re.DOTALL
)
_CISCO_NAT_INSIDE_IFACE_RE = re.compile(r"^\s*ip nat inside\s*$", re.MULTILINE | re.IGNORECASE)
_CISCO_NAT_OUTSIDE_IFACE_RE = re.compile(r"^\s*ip nat outside\s*$", re.MULTILINE | re.IGNORECASE)

# Matches global NAT rule statements, e.g.:
#   ip nat inside source list 1 interface GigabitEthernet0/1 overload
#   ip nat inside source list NAT-ACL interface GigabitEthernet0/1 overload
#   ip nat inside source static 10.1.1.5 203.0.113.10
#   ip nat outside source static 203.0.113.20 10.1.1.20
_CISCO_NAT_INSIDE_SOURCE_RE = re.compile(r"^\s*(ip nat inside source .*)$", re.MULTILINE | re.IGNORECASE)
_CISCO_NAT_OUTSIDE_SOURCE_RE = re.compile(r"^\s*(ip nat outside source .*)$", re.MULTILINE | re.IGNORECASE)

# Extracts the ACL identifier (number or name) referenced by an
# "ip nat inside source list <ACL> ..." statement.
_CISCO_NAT_ACL_REF_RE = re.compile(r"ip nat inside source list (\S+)", re.IGNORECASE)

# Matches a numbered standard/extended ACL entry, e.g.:
#   access-list 1 permit 10.1.1.0 0.0.0.255
#   access-list 1 permit host 10.1.1.5
#   access-list 101 permit ip 10.1.1.0 0.0.0.255 any   (extended ACL --
#     optional protocol keyword between 'permit' and the address)
_CISCO_NUMBERED_ACL_RE = re.compile(
    r"^\s*access-list\s+(\S+)\s+permit\s+(?:ip|tcp|udp|icmp)?\s*(?:host\s+)?(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?",
    re.MULTILINE | re.IGNORECASE,
)

# Matches a named ACL block, e.g.:
#   ip access-list standard NAT-ACL
#    permit 10.1.1.0 0.0.0.255
#    permit host 10.1.1.5
# capturing the ACL name and its body (all indented lines that follow,
# up to the next non-indented line).
_CISCO_NAMED_ACL_BLOCK_RE = re.compile(
    r"^ip access-list (?:standard|extended)\s+(\S+)\s*\n((?:\s+\S.*\n?)*)",
    re.MULTILINE | re.IGNORECASE,
)
_CISCO_NAMED_ACL_PERMIT_RE = re.compile(
    r"permit\s+(?:ip|tcp|udp|icmp)?\s*(?:host\s+)?(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?",
    re.IGNORECASE,
)


def parse_cisco_acl_addresses(raw_text: str) -> dict:
    """Parses a Cisco IOS running-config for ACL definitions (both
    numbered standard/extended ACLs and named "ip access-list ..."
    blocks), returning {acl_id: [ip_or_ip/wildcard strings]}.

    Each address is formatted as "IP" for a host/exact entry, or
    "IP wildcard" when a wildcard mask is present (e.g. a /24-style
    network entry) -- kept in the ACL's own wildcard-mask notation rather
    than converted to CIDR, since that's what's actually in the config.
    """
    acl_addresses = {}

    for acl_id, ip, wildcard in _CISCO_NUMBERED_ACL_RE.findall(raw_text or ""):
        addr = f"{ip} {wildcard}" if wildcard else ip
        acl_addresses.setdefault(acl_id, []).append(addr)

    for acl_name, body in _CISCO_NAMED_ACL_BLOCK_RE.findall(raw_text or ""):
        for ip, wildcard in _CISCO_NAMED_ACL_PERMIT_RE.findall(body):
            addr = f"{ip} {wildcard}" if wildcard else ip
            acl_addresses.setdefault(acl_name, []).append(addr)

    return acl_addresses


# Cisco SD-WAN (Viptela/vEdge/cEdge) devices define address matching
# criteria through their own "policy lists prefix-list <name> ...
# ip-prefix <CIDR> ..." construct, rather than the classic IOS
# "access-list"/"ip access-list" syntax -- even when a legacy-style
# "ip nat inside source list <name> ..." command references that name
# for backward compatibility. Matches a prefix-list block, e.g.:
#   policy
#    lists
#     prefix-list Viptela-Underlay-NAT
#      ip-prefix 10.0.0.0/24
#      ip-prefix 10.0.1.0/24
#     !
#    !
#   !
_VIPTELA_PREFIX_LIST_BLOCK_RE = re.compile(
    r"^[ \t]*prefix-list\s+(\S+)\s*\n((?:[ \t]+\S.*\n?)*?)^[ \t]*!",
    re.MULTILINE,
)
_VIPTELA_IP_PREFIX_RE = re.compile(r"ip-prefix\s+(\S+)", re.IGNORECASE)


def parse_viptela_prefix_lists(raw_text: str) -> dict:
    """Parses a Cisco SD-WAN (Viptela) running-config for
    'policy lists prefix-list <name> ... ip-prefix <CIDR> ...' blocks,
    returning {prefix_list_name: [cidr_strings]}.

    Used as a fallback address source for NAT ACL resolution: an
    "ip nat inside source list <name> ..." rule on an SD-WAN device may
    reference a name that's defined here rather than as a classic ACL.
    """
    prefix_lists = {}
    for name, body in _VIPTELA_PREFIX_LIST_BLOCK_RE.findall(raw_text or ""):
        prefixes = _VIPTELA_IP_PREFIX_RE.findall(body)
        if prefixes:
            prefix_lists.setdefault(name, []).extend(prefixes)
    return prefix_lists



def parse_cisco_nat_config(raw_text: str, hostname: str = "") -> dict:
    """Parses a Cisco IOS 'show running-config' transcript for NAT-relevant
    lines: which interfaces are marked 'ip nat inside' / 'ip nat outside',
    the global 'ip nat inside source ...' / 'ip nat outside source ...'
    statements that define the actual translation rules, and -- for any
    inside-source rule that references an ACL ("ip nat inside source list
    <ACL> interface <intf> ...") -- the actual IP addresses permitted by
    that ACL, resolved from its definition elsewhere in the same config.

    Returns:
      {
        "interfaces": {interface_name_lower: {"inside": bool, "outside": bool}},
        "inside_source_rules": [raw statement strings],
        "outside_source_rules": [raw statement strings],
        "has_overload": bool,  # True if any inside-source rule uses PAT
                                # ("overload" keyword -- Cisco's port-
                                # overloaded dynamic NAT, the PAT equivalent)
        "interface_acl_refs": {
            interface_name_lower: [(acl_id, [ip_or_ip/wildcard, ...]), ...]
        },  # ACL id + its addresses for inside-source rules tied to a
            # specific "interface <X>" clause, keyed by that interface.
            # Callers format this as e.g. "ACL 10: 10.5.5.0 0.0.0.255; 10.5.5.99".
      }

    An interface_name that never appears with 'ip nat inside'/'ip nat
    outside' is simply absent from "interfaces" -- callers should treat
    that as "not a NAT interface" (No), the same "unavailable vs. no"
    distinction used throughout this script: only call it "No" when the
    config was actually retrieved and parsed, never on lookup failure.
    """
    interfaces = {}
    for match in _CISCO_INTERFACE_BLOCK_RE.finditer(raw_text or ""):
        intf_name, body = match.group(1), match.group(2)
        inside = bool(_CISCO_NAT_INSIDE_IFACE_RE.search(body))
        outside = bool(_CISCO_NAT_OUTSIDE_IFACE_RE.search(body))
        if inside or outside:
            interfaces[intf_name.strip().lower()] = {"inside": inside, "outside": outside}

    inside_source_rules = [m.strip() for m in _CISCO_NAT_INSIDE_SOURCE_RE.findall(raw_text or "")]
    outside_source_rules = [m.strip() for m in _CISCO_NAT_OUTSIDE_SOURCE_RE.findall(raw_text or "")]
    has_overload = any("overload" in r.lower() for r in inside_source_rules)

    acl_addresses = parse_cisco_acl_addresses(raw_text or "")
    viptela_prefix_lists = parse_viptela_prefix_lists(raw_text or "")
    # {interface_name_lower: [(acl_id, [addr, ...]), ...]} -- a list of
    # (ACL identifier, its addresses) pairs rather than a flat address
    # list, so the ACL name/number can be shown alongside its addresses
    # (e.g. "ACL 10: 10.5.5.0 0.0.0.255; 10.5.5.99") instead of just bare
    # IPs with no indication of which ACL they came from.
    interface_acl_refs = {}
    for rule in inside_source_rules:
        acl_match = _CISCO_NAT_ACL_REF_RE.search(rule)
        if not acl_match:
            continue
        acl_id = acl_match.group(1)
        addrs = acl_addresses.get(acl_id, []) or viptela_prefix_lists.get(acl_id, [])
        if not addrs:
            if DEBUG_ZONES:
                # The rule references an ACL/prefix-list by name/number,
                # but neither parse_cisco_acl_addresses nor
                # parse_viptela_prefix_lists resolved it to any
                # addresses. Check whether that name even appears in the
                # raw config at all, and if so, show a snippet -- this
                # tells us whether it's genuinely absent (defined via yet
                # another mechanism we haven't accounted for) or present
                # in a format our regexes still aren't matching.
                idx = (raw_text or "").find(acl_id)
                if idx == -1:
                    debug_logger.debug(
                        f"[DEBUG] parse_cisco_nat_config({hostname}): rule references "
                        f"{acl_id!r} but that string doesn't appear anywhere else in the "
                        f"{len(raw_text or '')}-char config -- its definition is genuinely "
                        f"absent from this fetch (possibly defined via yet another "
                        f"mechanism, or truncated/not included in this raw-data dump)"
                    )
                else:
                    snippet = (raw_text or "")[max(0, idx - 100):idx + 500]
                    debug_logger.debug(
                        f"[DEBUG] parse_cisco_nat_config({hostname}): rule references "
                        f"{acl_id!r}, found at index {idx} in the config, but neither the "
                        f"classic-ACL nor Viptela-prefix-list parser extracted any "
                        f"addresses from it -- likely still a formatting mismatch. "
                        f"Snippet around first occurrence: {snippet!r}"
                    )
            continue

        intf_match = re.search(r"\binterface\s+(\S+)", rule, re.IGNORECASE)
        if intf_match:
            # "ip nat inside source list X interface Y overload": Y's own
            # IP address is used as the translated address -- attach the
            # ACL to that specific interface.
            intf_key = intf_match.group(1).strip().lower()
            interface_acl_refs.setdefault(intf_key, []).append((acl_id, addrs))
        else:
            # "ip nat inside source list X pool Y overload" (or a static
            # pool without "overload"): no specific outside interface is
            # named -- the pool applies to traffic entering from any
            # "ip nat inside" interface, so attach the ACL to every
            # interface already marked "ip nat inside" above.
            for candidate_intf, flags in interfaces.items():
                if flags.get("inside"):
                    interface_acl_refs.setdefault(candidate_intf, []).append((acl_id, addrs))

    # If we found NOTHING at all (no NAT-marked interfaces, no global
    # rules), that's ambiguous the same way an empty PAN-OS zone_nat_map
    # was: it could genuinely mean this router doesn't do NAT, or it
    # could mean the literal string "ip nat" is present in the config but
    # our regexes (interface block boundaries, line anchoring) aren't
    # matching this device's actual formatting. Check directly for "ip
    # nat" anywhere in the raw text and log a snippet if found, so this
    # can be told apart without guessing.
    if DEBUG_ZONES and not interfaces and not inside_source_rules and not outside_source_rules:
        idx = (raw_text or "").lower().find("ip nat")
        if idx == -1:
            debug_logger.debug(
                f"[DEBUG] parse_cisco_nat_config({hostname}): no interfaces/rules parsed, "
                f"and the literal string 'ip nat' does not appear anywhere in the "
                f"{len(raw_text or '')}-char config -- this router genuinely appears "
                f"to have no NAT configuration"
            )
        else:
            snippet = (raw_text or "")[max(0, idx - 100):idx + 300]
            debug_logger.debug(
                f"[DEBUG] parse_cisco_nat_config({hostname}): no interfaces/rules parsed, "
                f"but the literal string 'ip nat' DOES appear in the config at index {idx} "
                f"-- likely a regex/formatting mismatch, not genuine absence of NAT. "
                f"Snippet around first occurrence: {snippet!r}"
            )

    return {
        "interfaces": interfaces,
        "inside_source_rules": inside_source_rules,
        "outside_source_rules": outside_source_rules,
        "has_overload": has_overload,
        "interface_acl_refs": interface_acl_refs,
    }


FIREWALL_KEYWORDS = [
    "firewall", "asa", "fortigate", "fortinet", "palo alto", "paloalto",
    "panorama", "checkpoint", "check point", "srx firewall", "ngfw",
]

SWITCH_KEYWORDS = [
    "switch", "catalyst", "nexus", "l2 switch", "l3 switch", "access switch",
    "distribution switch", "core switch", "ex series", "qfx", "arista switch",
    # Big Switch Networks devices sometimes appear as "big switch controller"
    # (already caught by "switch" above) but also as "Big Monitoring Fabric"
    # or "BMF", neither of which contains "switch" -- listed explicitly.
    "big switch", "bmf", "big monitoring fabric", "big cloud fabric",
]

ROUTER_KEYWORDS = [
    "router", "asr", "isr", "mx series", "juniper mx", "cisco router",
    "edge router", "core router", "csr1000v", "cat8000v",
]

LOAD_BALANCER_KEYWORDS = [
    "load balancer", "loadbalancer", "load-balancer", "f5", "big-ip", "bigip",
    "netscaler", "adc", "ltm", "gtm", "avi vantage", "a10 thunder",
]

# Category name -> keyword list, used both for filtering the run to specific
# device types and (for firewalls) for the existing NAT/zone enrichment logic.
DEVICE_TYPE_KEYWORDS = {
    "firewall": FIREWALL_KEYWORDS,
    "switch": SWITCH_KEYWORDS,
    "router": ROUTER_KEYWORDS,
    "load_balancer": LOAD_BALANCER_KEYWORDS,
}

# Device categories this run should include. Edit this set to change scope.
# "all" bypasses the device-type keyword filter entirely (see
# matches_target_device_type) -- every device found at TARGET_SITE is
# included, regardless of type/vendor (servers, access points, NAC
# appliances, controllers, etc., not just recognized network-
# infrastructure categories). Firewalls and routers still get dedicated
# NAT/PAT rulebase lookups (PAN-OS "show running nat-policy" / Cisco IOS
# "show running-config"); everything else falls back to the generic
# interface-attribute-based NAT guess (isNatIntf/natType/nat).
# To go back to a filtered subset, replace with e.g.
# {"firewall", "router", "switch", "load_balancer"}.
TARGET_DEVICE_TYPES = {"all"}


def _device_candidate_values(device: dict) -> list:
    """Collects lowercased type/family/vendor/model strings from a device
    payload (top-level and nested 'attributes'), used for keyword matching."""
    candidate_values = []
    for key in ["subType", "sub_type", "subTypeName", "sub_type_name", "family", "type", "deviceType", "vendor", "model"]:
        val = device.get(key)
        if val and isinstance(val, str):
            candidate_values.append(val.lower())

    attrs = device.get("attributes")
    if isinstance(attrs, dict):
        for key in ["subType", "subTypeName", "family", "type", "deviceType", "vendor", "model"]:
            val = attrs.get(key)
            if val and isinstance(val, str):
                candidate_values.append(val.lower())

    return candidate_values


def is_firewall_device(device: dict) -> bool:
    """Best-effort detection of firewall devices based on type/family/vendor metadata."""
    candidate_values = _device_candidate_values(device)
    combined = " ".join(candidate_values)
    result = any(kw in combined for kw in FIREWALL_KEYWORDS)

    if DEBUG_ZONES:
        hostname_dbg = device.get("hostName") or device.get("hostname") or device.get("name") or "?"
        debug_logger.debug(
            f"[DEBUG] is_firewall_device({hostname_dbg}) -> {result} "
            f"| candidate_values={candidate_values}"
        )

    return result


def is_router_device(device: dict) -> bool:
    """Best-effort detection of router devices based on type/family/vendor
    metadata, used to decide whether to run the Cisco IOS
    "ip nat inside"/"ip nat outside" running-config lookup
    (parse_cisco_nat_config) for this device.
    """
    candidate_values = _device_candidate_values(device)
    combined = " ".join(candidate_values)
    result = any(kw in combined for kw in ROUTER_KEYWORDS)

    if DEBUG_ZONES:
        hostname_dbg = device.get("hostName") or device.get("hostname") or device.get("name") or "?"
        debug_logger.debug(
            f"[DEBUG] is_router_device({hostname_dbg}) -> {result} "
            f"| candidate_values={candidate_values}"
        )

    return result


def is_switch_device(device: dict) -> bool:
    """Best-effort detection of switch devices based on type/family/vendor
    metadata. Layer-3-capable Cisco switches can run the same "ip nat
    inside"/"ip nat outside" IOS NAT configuration as routers, so switches
    get the same Cisco running-config NAT lookup (parse_cisco_nat_config)
    as routers, plus ACL-address resolution for "ip nat inside source
    list <ACL> ..." rules (see resolve_acl_addresses).
    """
    candidate_values = _device_candidate_values(device)
    combined = " ".join(candidate_values)
    result = any(kw in combined for kw in SWITCH_KEYWORDS)

    if DEBUG_ZONES:
        hostname_dbg = device.get("hostName") or device.get("hostname") or device.get("name") or "?"
        debug_logger.debug(
            f"[DEBUG] is_switch_device({hostname_dbg}) -> {result} "
            f"| candidate_values={candidate_values}"
        )

    return result


def matches_target_device_type(device: dict) -> bool:
    """Returns True if the device's type/family/vendor/model metadata matches
    any of the categories in TARGET_DEVICE_TYPES (firewall/switch/router/
    load_balancer), based on the keyword lists above.

    If TARGET_DEVICE_TYPES contains "all", the keyword filter is bypassed
    entirely and every device is matched, regardless of type/vendor --
    used to include every device found at the site, not just recognized
    network-infrastructure categories.
    """
    if "all" in TARGET_DEVICE_TYPES:
        if DEBUG_ZONES:
            hostname_dbg = device.get("hostName") or device.get("hostname") or device.get("name") or "?"
            debug_logger.debug(
                f"[DEBUG] matches_target_device_type({hostname_dbg}) -> True "
                f"(TARGET_DEVICE_TYPES contains 'all' -- device-type filter bypassed)"
            )
        return True

    candidate_values = _device_candidate_values(device)
    combined = " ".join(candidate_values)

    result = any(
        kw in combined
        for category in TARGET_DEVICE_TYPES
        for kw in DEVICE_TYPE_KEYWORDS.get(category, [])
    )

    if DEBUG_ZONES:
        hostname_dbg = device.get("hostName") or device.get("hostname") or device.get("name") or "?"
        debug_logger.debug(
            f"[DEBUG] matches_target_device_type({hostname_dbg}) -> {result} "
            f"| candidate_values={candidate_values}"
        )

    return result


def extract_site_from_device(device: dict) -> str:
    """Extracts site location metadata from device payload, falling back to TARGET_SITE."""
    for key in ["siteName", "site", "sitePath", "location", "site_name"]:
        val = device.get(key)
        if val and isinstance(val, str) and val.strip():
            return val.strip()

    return TARGET_SITE


def clean_ip(val) -> str:
    """Strips subnet masks, CIDR notation, and whitespace to isolate raw IP for DNS queries."""
    if not val or not isinstance(val, str):
        return ""
    ip_only = val.split("/")[0].strip()
    return ip_only if ip_only.upper() != "N/A" else ""


def resolve_ptr(ip_str: str, hostname_fallback: str = "") -> tuple:
    """Performs reverse DNS lookup returning (ip_with_mask, dns_name) separately."""
    clean_ip_addr = clean_ip(ip_str)
    raw_ip_entry = str(ip_str).strip() if ip_str else "N/A"
    if not clean_ip_addr:
        return ("N/A", "N/A")

    if clean_ip_addr in DNS_CACHE:
        _, cached_dns = DNS_CACHE[clean_ip_addr]
        return (raw_ip_entry, cached_dns)

    try:
        dns_name, _, _ = socket.gethostbyaddr(clean_ip_addr)
        result = (raw_ip_entry, dns_name)
    except Exception:
        fallback_dns = hostname_fallback if hostname_fallback and hostname_fallback.upper() != "N/A" else "N/A"
        result = (raw_ip_entry, fallback_dns)

    DNS_CACHE[clean_ip_addr] = result
    return result


# ---------------------------------------------------------------------------
# Public IP investigation + interface status helpers
# ---------------------------------------------------------------------------
_IPV4_TOKEN_RE = re.compile(
    r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})"           # an IPv4 address...
    r"(?:\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})|/(\d{1,2}))?"  # ...optionally a range end or /prefix
    r"(?![\d.])"
)
_CISCO_NAT_POOL_RE = re.compile(
    r"^\s*ip nat pool\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.MULTILINE | re.IGNORECASE,
)
_CISCO_NAT_POOL_REF_RE = re.compile(r"\bpool\s+(\S+)", re.IGNORECASE)
_CISCO_SHUTDOWN_RE = re.compile(r"^\s*shutdown\s*$", re.MULTILINE | re.IGNORECASE)
_CISCO_IFACE_IPV4_RE = re.compile(
    r"^\s*ip address\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.MULTILINE | re.IGNORECASE,
)
_CISCO_IFACE_IPV6_RE = re.compile(
    r"^\s*ipv6 address\s+([0-9a-fA-F:]+/\d{1,3})", re.MULTILINE | re.IGNORECASE
)

# NetBrain interface attribute names that may carry admin/oper state. The
# exact names vary by NetBrain version/vendor, so several candidates are
# tried in order; only values that normalize to a recognizable up/down
# state are used. Run with NETBRAIN_DEBUG=1 to see the real status-like
# attribute names this instance returns (logged once per device) and add
# them here if interfaceStatus comes back "Unknown" unexpectedly.
_ADMIN_STATUS_KEYS = (
    "adminStatus", "ifAdminStatus", "adminState", "intfAdminStatus", "admin_status",
)
_OPER_STATUS_KEYS = (
    "operStatus", "ifOperStatus", "operState", "intfOperStatus", "oper_status",
    "lineProtocol", "protocolStatus", "protocolState", "linkStatus", "linkState",
)
_COMBINED_STATUS_KEYS = ("intfStatus", "interfaceStatus", "ifStatus", "status", "state")

_UP_VALUES = {"up", "1", "true", "enabled", "enable", "connected", "active", "running"}
_DOWN_VALUES = {
    "down", "2", "false", "disabled", "disable", "notconnect", "not connected",
    "inactive", "lowerlayerdown", "notpresent", "err-disabled",
}
_ADMIN_DOWN_TOKENS = ("administratively down", "admin down", "admin-down", "shutdown")


def _normalize_state(val) -> str:
    """Normalizes a raw status value to 'up', 'down', or '' (unrecognized)."""
    s = str(val).strip().lower() if val is not None else ""
    if not s:
        return ""
    if s in _UP_VALUES or s.startswith("up"):
        return "up"
    if s in _DOWN_VALUES or s.startswith("down") or any(t in s for t in _ADMIN_DOWN_TOKENS):
        return "down"
    return ""


def _interface_status_from_attrs(attrs: dict) -> tuple:
    """Returns (admin_state, oper_state, source_text) from NetBrain interface
    attributes. Each state is 'up', 'down', or '' when unknown."""
    admin, oper, sources = "", "", []

    for key in _ADMIN_STATUS_KEYS:
        norm = _normalize_state(attrs.get(key))
        if norm:
            admin = norm
            sources.append(f"{key}={attrs.get(key)}")
            break

    for key in _OPER_STATUS_KEYS:
        norm = _normalize_state(attrs.get(key))
        if norm:
            oper = norm
            sources.append(f"{key}={attrs.get(key)}")
            break

    if not admin or not oper:
        for key in _COMBINED_STATUS_KEYS:
            raw = attrs.get(key)
            if raw in (None, ""):
                continue
            s = str(raw).strip().lower()
            if "administratively down" in s or "admin down" in s:
                a, o = "down", "down"
            elif "/" in s:
                # Cisco-style "up/up", "up/down", "down/down"
                first, second = (p.strip() for p in s.split("/", 1))
                a, o = _normalize_state(first), _normalize_state(second)
            else:
                # A single value describes operational state only.
                a, o = "", _normalize_state(s)
            if not a and not o:
                continue
            admin = admin or a
            oper = oper or o
            sources.append(f"{key}={raw}")
            break

    return admin, oper, ", ".join(sources)


def _summarize_interface_status(admin: str, oper: str) -> str:
    """Collapses admin/oper state into a single human-readable status."""
    if admin == "down":
        return "Shutdown (admin down)"
    if oper == "up":
        return "Active (up/up)" if admin == "up" else "Active (oper up)"
    if oper == "down":
        return "Down (not shut, link/protocol down)" if admin == "up" else "Down (oper down)"
    if admin == "up":
        return "Not shut (oper state unknown)"
    return "Unknown"


def parse_cisco_interface_state(raw_text: str) -> dict:
    """Parses a Cisco running-config for per-interface 'shutdown' and
    configured IP addresses (primary + secondary, IPv4 + IPv6).

    Returns {interface_name_lower: {"shutdown": bool, "ips": [ip_interface, ...]}}.
    Each interface body is cut at the first non-indented line so that
    global config following the last interface block isn't misattributed.
    """
    result = {}
    for match in _CISCO_INTERFACE_BLOCK_RE.finditer(raw_text or ""):
        intf_name, body = match.group(1), match.group(2)
        body_lines = []
        for line in body.splitlines():
            if line.strip() and not line[:1].isspace():
                break
            body_lines.append(line)
        body = "\n".join(body_lines)

        ips = []
        for ip_str, mask in _CISCO_IFACE_IPV4_RE.findall(body):
            try:
                ips.append(ipaddress.ip_interface(f"{ip_str}/{mask}"))
            except ValueError:
                pass
        for v6 in _CISCO_IFACE_IPV6_RE.findall(body):
            try:
                ips.append(ipaddress.ip_interface(v6))
            except ValueError:
                pass

        result[intf_name.strip().lower()] = {
            "shutdown": bool(_CISCO_SHUTDOWN_RE.search(body)),
            "ips": ips,
        }
    return result


def _interface_networks_from_attrs(attrs: dict) -> list:
    """Returns every IP configured on an interface (as ip_interface objects,
    with prefix where known) from NetBrain interface attributes -- all
    addresses, not just the first one used for the resolvedIP column."""
    nets = []
    for key in ("ips", "ipAddress", "ipv6s", "ipv6Address"):
        raw = attrs.get(key)
        if not raw:
            continue
        for item in (raw if isinstance(raw, list) else [raw]):
            if isinstance(item, dict):
                ip_str = item.get("ipLoc") or item.get("ip") or item.get("ipAddress")
                mask = (
                    item.get("mask") or item.get("subnetMask")
                    or item.get("maskLen") or item.get("prefixLength")
                )
            else:
                ip_str, mask = item, None
            ip_str = str(ip_str or "").strip()
            if not ip_str or ip_str.upper() == "N/A":
                continue
            candidates = []
            if mask not in (None, "") and "/" not in ip_str:
                candidates.append(f"{ip_str}/{mask}")
            candidates += [ip_str, ip_str.split("/")[0]]
            for candidate in candidates:
                try:
                    nets.append(ipaddress.ip_interface(candidate))
                    break
                except ValueError:
                    continue
    return nets


def _min_meaningful_prefix(version: int) -> int:
    """Shortest prefix treated as a real, specific block (shorter ones such
    as 0.0.0.0/0 'any' are ignored so catch-alls don't count as matches)."""
    return 8 if version == 4 else 32


_IPV6_TOKEN_RE = re.compile(
    r"(?<![0-9A-Za-z:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?:/(\d{1,3}))?(?![0-9A-Za-z:])"
)


def _text_address_spans(text: str, version: int):
    """Yields (lo, hi) spans for every single address, a.b.c.d-e.f.g.h
    range, or CIDR block of the given IP version found in `text`."""
    if not text:
        return
    if version == 4:
        for m in _IPV4_TOKEN_RE.finditer(text):
            start, end, prefix = m.groups()
            try:
                if end:
                    yield ipaddress.ip_address(start), ipaddress.ip_address(end)
                elif prefix:
                    if int(prefix) >= _min_meaningful_prefix(4):
                        n = ipaddress.ip_network(f"{start}/{prefix}", strict=False)
                        yield n.network_address, n.broadcast_address
                else:
                    a = ipaddress.ip_address(start)
                    yield a, a
            except ValueError:
                continue
    else:
        for m in _IPV6_TOKEN_RE.finditer(text):
            token, prefix = m.groups()
            try:
                if prefix:
                    if int(prefix) >= _min_meaningful_prefix(6):
                        n = ipaddress.ip_network(f"{token}/{prefix}", strict=False)
                        yield n.network_address, n.broadcast_address
                else:
                    a = ipaddress.IPv6Address(token)
                    yield a, a
            except ValueError:
                continue


def _text_refs_ips(text: str, ips: list) -> set:
    """Returns the subset of `ips` referenced by `text` (a NAT rule or
    translate-to value) as a single address, an a.b.c.d-e.f.g.h range, or
    a CIDR block (catch-alls shorter than /8 are ignored)."""
    hits = set()
    if not text or not ips:
        return hits
    for version in {ip.version for ip in ips}:
        spans = list(_text_address_spans(text, version))
        if not spans:
            continue
        for ip in ips:
            if ip.version == version and any(lo <= ip <= hi for lo, hi in spans):
                hits.add(ip)
    return hits


def _match_ips_on_interface(ips: list, networks: list) -> tuple:
    """Compares an interface's configured IPs against the investigated
    addresses.

    Returns (reasons, assigned, connected):
      reasons   - human-readable match descriptions, one per matched address
      assigned  - set of investigated addresses configured on this interface
      connected - {address: connected_network} for investigated addresses
                  inside one of this interface's connected subnets
                  (including assigned ones -- used to label network/
                  broadcast addresses in the summary)
    """
    reasons, assigned, connected = [], set(), {}
    for ip in ips:
        same_version = [n for n in networks if n.version == ip.version]
        exact = next((n for n in same_version if n.ip == ip), None)
        containing = next(
            (
                n for n in same_version
                if _min_meaningful_prefix(n.version) <= n.network.prefixlen < n.max_prefixlen
                and ip in n.network
            ),
            None,
        )
        if containing is not None:
            connected[ip] = containing.network
        if exact is not None:
            assigned.add(ip)
            reasons.append(f"{ip}: assigned to interface ({exact.with_prefixlen})")
        elif containing is not None:
            reasons.append(
                f"{ip}: in connected subnet {containing.network} (interface IP {containing.ip})"
            )
    return reasons, assigned, connected


def _cisco_nat_hits_for_ips(ips: list, raw_text: str, nat_cfg: dict) -> dict:
    """Finds Cisco 'ip nat inside/outside source' rules that reference any
    investigated address, directly or via an 'ip nat pool' whose range
    contains it.

    Returns {interface_name_lower: [(reason, matched_ips_set), ...]}. A rule
    naming an 'interface X' is attached to X; otherwise to the 'ip nat
    outside' interface(s) (where translated public addresses live), falling
    back to 'ip nat inside' interfaces, and finally to the key "__device__"
    when the device has no NAT-marked interfaces at all.
    """
    hits = {}
    if not ips or not raw_text or not nat_cfg:
        return hits

    pools = {}
    for name, lo, hi in _CISCO_NAT_POOL_RE.findall(raw_text):
        try:
            pools[name.lower()] = (ipaddress.ip_address(lo), ipaddress.ip_address(hi))
        except ValueError:
            pass

    flags = nat_cfg.get("interfaces", {})
    default_targets = (
        [k for k, f in flags.items() if f.get("outside")]
        or [k for k, f in flags.items() if f.get("inside")]
        or ["__device__"]
    )

    for rule in nat_cfg.get("inside_source_rules", []) + nat_cfg.get("outside_source_rules", []):
        matched = _text_refs_ips(rule, ips)
        reason = f"NAT rule: {rule}" if matched else ""
        pool_match = _CISCO_NAT_POOL_REF_RE.search(rule)
        if pool_match:
            rng = pools.get(pool_match.group(1).lower())
            if rng:
                in_pool = {ip for ip in ips if ip.version == rng[0].version and rng[0] <= ip <= rng[1]}
                if in_pool:
                    matched |= in_pool
                    reason = f"NAT rule via pool {pool_match.group(1)} ({rng[0]}-{rng[1]}): {rule}"
        if not matched:
            continue
        intf_match = re.search(r"\binterface\s+(\S+)", rule, re.IGNORECASE)
        for t in ([intf_match.group(1).lower()] if intf_match else default_targets):
            hits.setdefault(t, []).append((reason, matched))
    return hits


def _pan_zone_hits_for_ips(ips: list, parsed_rules) -> dict:
    """Finds PAN-OS NAT rules whose translate-to references any investigated
    address. Returns {zone_name_lower: [(reason, matched_ips_set), ...]}."""
    hits = {}
    if not ips or not parsed_rules:
        return hits
    for rule in parsed_rules:
        matched = _text_refs_ips(rule.get("translate_to", ""), ips)
        if not matched:
            continue
        detail = _clean_nat_value(rule["translate_to"]) or rule["translate_to"]
        reason = f"NAT rule '{rule['name']}': {detail}"
        for zone in rule.get("from_zones", []) + rule.get("to_zones", []):
            if zone.strip():
                hits.setdefault(zone.strip().lower(), []).append((reason, matched))
    return hits


def probe_address(target) -> dict:
    """Live reachability check of one address FROM THIS WORKSTATION: ICMP
    ping plus TCP connects to PUBLIC_IP_PROBE_PORTS. A TCP reset
    ("refused") still means something at/in front of the address answered.
    Returns {"ping": str, "tcp": {port: str}, "responding": bool}."""
    ip_s = str(target)
    is_windows = platform.system().lower() == "windows"
    result = {"ping": "Not run", "tcp": {}, "responding": False}

    if is_windows:
        cmd = ["ping", "-n", "2", "-w", "2000"] + (["-6"] if target.version == 6 else []) + [ip_s]
    else:
        ping_bin = "ping6" if target.version == 6 and shutil.which("ping6") else "ping"
        cmd = [ping_bin, "-c", "2", ip_s]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        # On Windows, "Destination host unreachable" from an intermediate
        # router can still return exit code 0 -- require a real TTL reply.
        ping_ok = proc.returncode == 0 and (not is_windows or "ttl=" in proc.stdout.lower())
        result["ping"] = "Reply received" if ping_ok else "No reply"
        result["responding"] = ping_ok
    except FileNotFoundError:
        result["ping"] = "ping command not available"
    except subprocess.TimeoutExpired:
        result["ping"] = "No reply (timed out)"

    for port in PUBLIC_IP_PROBE_PORTS:
        try:
            with socket.create_connection((ip_s, port), timeout=3):
                state = "open"
            result["responding"] = True
        except ConnectionRefusedError:
            state = "closed (reset received -- something answered)"
            result["responding"] = True
        except socket.timeout:
            state = "no response (filtered or down)"
        except OSError as e:
            state = f"error ({e.strerror or e})"
        result["tcp"][port] = state

    return result


def investigate_ips_live(ips: list, run_probe: bool) -> dict:
    """Background task: reverse DNS for each address (up to
    PUBLIC_IP_RDNS_MAX) and, if run_probe, a live probe of each address (up
    to PUBLIC_IP_PROBE_MAX). Returns
    {"rdns": {ip_str: name}, "rdns_note": str,
     "probe": {ip_str: probe_dict}, "probe_note": str}."""
    out = {"rdns": {}, "rdns_note": "", "probe": {}, "probe_note": ""}

    def _ptr(addr):
        try:
            return socket.gethostbyaddr(str(addr))[0]
        except Exception:
            return "No PTR record"

    if len(ips) <= PUBLIC_IP_RDNS_MAX:
        with ThreadPoolExecutor(max_workers=16) as ex:
            out["rdns"] = dict(zip(map(str, ips), ex.map(_ptr, ips)))
    else:
        out["rdns_note"] = f"Skipped: {len(ips)} addresses exceeds PUBLIC_IP_RDNS_MAX ({PUBLIC_IP_RDNS_MAX})"

    if not run_probe:
        out["probe_note"] = "Skipped (NETBRAIN_PUBLIC_IP_PROBE=0)"
    elif len(ips) > PUBLIC_IP_PROBE_MAX:
        out["probe_note"] = f"Skipped: {len(ips)} addresses exceeds PUBLIC_IP_PROBE_MAX ({PUBLIC_IP_PROBE_MAX})"
    else:
        with ThreadPoolExecutor(max_workers=16) as ex:
            out["probe"] = dict(zip(map(str, ips), ex.map(probe_address, ips)))
    return out


# ---------------------------------------------------------------------------
# Switch public IP space evaluation (only used when SWITCH_HOSTNAMES given)
# ---------------------------------------------------------------------------
# Usage evidence for an interface's public subnet(s), strongest first:
#   1. ARP neighbors inside the public subnet (other than the switch's own
#      / HSRP-VRRP virtual addresses) -- hosts are actually using it.
#   2. "ip nat inside" / "ip nat outside" on the interface.
#   3. Static routes or BGP neighbors whose next hop sits in the subnet --
#      the space is carrying routed traffic to something behind it.
# ARP comes from NetBrain's DeviceRawData ("show ip arp", plus
# "show ip arp vrf <name>" for non-default VRFs), i.e. NetBrain's last
# retrieval, not a live poll. If ARP can't be retrieved, an up/up
# interface is reported ACTIVE - VERIFY USAGE rather than CAN BE SHUTDOWN.
ARP_CMD = "show ip arp"
_ARP_ECHO_INDICATORS = ["show ip arp", "show arp", "hardware addr", "ip arp table"]
_MAC_RE = re.compile(
    r"\b([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b",
    re.IGNORECASE,
)
_PLAIN_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d./])")
_ROUTE_REF_LINE_RE = re.compile(
    r"^\s*(?:ip route\b|ipv6 route\b|.*\bneighbor\s+\d{1,3}(?:\.\d{1,3}){3}\b)",
    re.IGNORECASE,
)

PUBLIC_SPACE_VERDICTS = [
    "ACTIVE - IN USE", "DOWN - STILL REFERENCED", "ACTIVE - VERIFY USAGE",
    "REVIEW", "CAN BE SHUTDOWN", "ALREADY SHUTDOWN",
]


def fetch_arp_raw(hostname: str, vrf: str = "", config_raw: str = "") -> str:
    """Fetches the ARP table (global, or for `vrf`) via DeviceRawData.
    Returns "" when unavailable. A response byte-identical to the
    running-config is discarded (canned-content guard, same as the SD-WAN
    policy fetch)."""
    cmd = f"{ARP_CMD} vrf {vrf}" if vrf else ARP_CMD
    raw = fetch_device_raw_data(
        hostname, cmd, NAT_DATATYPE_CANDIDATES, echo_indicators=_ARP_ECHO_INDICATORS
    )
    if raw and config_raw and raw == config_raw:
        return ""
    return raw


def parse_arp_entries(raw_text: str) -> list:
    """Parses Cisco IOS/IOS-XE/NX-OS ARP output.

    Returns [(ip_address, mac, is_self), ...]. Incomplete entries (no MAC)
    are skipped. is_self is True for IOS entries with age "-" (the
    switch's own interface addresses and HSRP/VRRP virtual IPs)."""
    entries = []
    for line in (raw_text or "").splitlines():
        mac_m = _MAC_RE.search(line)
        ip_m = _PLAIN_IPV4_RE.search(line)
        if not mac_m or not ip_m or ip_m.start() > mac_m.start():
            continue
        try:
            ip = ipaddress.ip_address(ip_m.group(1))
        except ValueError:
            continue
        between = line[ip_m.end():mac_m.start()].split()
        is_self = bool(between) and between[0] == "-"
        entries.append((ip, mac_m.group(1).lower(), is_self))
    return entries


def config_route_reference_lines(config_raw: str) -> list:
    """Static route and BGP-neighbor lines from a running-config."""
    return [
        line.strip() for line in (config_raw or "").splitlines()
        if _ROUTE_REF_LINE_RE.match(line)
    ]


def _host_in_public_nets(ip, nets: list, own_ips: set) -> bool:
    """True if `ip` is a usable host address inside one of `nets` and is not
    one of the switch's own addresses."""
    if ip in own_ips:
        return False
    for n in nets:
        net = n.network
        if ip.version != net.version or ip not in net:
            continue
        if net.version == 4 and net.prefixlen < 31 and ip in (net.network_address, net.broadcast_address):
            continue
        return True
    return False


def _route_refs_for_nets(lines: list, nets: list, own_ips: set) -> list:
    """Config lines with a next hop / neighbor address inside `nets`."""
    hits = []
    for line in lines:
        for tok in _PLAIN_IPV4_RE.findall(line):
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                continue
            if _host_in_public_nets(ip, nets, own_ips):
                hits.append(line)
                break
    return hits


def public_space_verdict(admin: str, oper: str, arp_ok: bool, arp_hosts: list,
                         nat_role: str, route_refs: list, config_ok: bool) -> tuple:
    """Decides whether an interface's public IP space is in use.
    Returns (verdict, reason)."""
    refs = []
    if nat_role:
        refs.append(f"{nat_role} configured")
    if route_refs:
        refs.append(f"{len(route_refs)} static route/BGP neighbor(s) with a next hop in the subnet")
    usage = ([f"{len(arp_hosts)} ARP neighbor(s) in the public subnet"] if arp_hosts else []) + refs

    if admin == "down":
        if refs:
            return ("ALREADY SHUTDOWN",
                    "Interface is admin down, but still referenced (" + "; ".join(refs) +
                    ") -- clean those up before reclaiming the space")
        return ("ALREADY SHUTDOWN",
                "Interface is admin down -- public space not in use here; config/space can be reclaimed")
    if oper == "up":
        if usage:
            return "ACTIVE - IN USE", "Up/up with " + "; ".join(usage) + " -- do not shut down"
        missing = []
        if not arp_ok:
            missing.append("ARP table")
        if not config_ok:
            missing.append("running-config (NAT/route checks)")
        if not missing:
            return ("CAN BE SHUTDOWN",
                    "Up/up but no ARP neighbors, NAT, or static-route/BGP next hops in the "
                    "public subnet(s) -- nothing appears to be using it")
        return ("ACTIVE - VERIFY USAGE",
                "Up/up and no usage evidence found, but " + " and ".join(missing) +
                " could not be retrieved from NetBrain -- check on the device before shutting")
    if oper == "down":
        if refs:
            return ("DOWN - STILL REFERENCED",
                    "Link/protocol down, but still referenced (" + "; ".join(refs) +
                    ") -- review before shutting")
        return ("CAN BE SHUTDOWN",
                "Not shut, but link/protocol is down (not passing traffic) and nothing "
                "references the public subnet(s)")
    return ("REVIEW",
            "Interface admin/oper state unknown in NetBrain" +
            (f"; evidence: {'; '.join(usage)}" if usage else "") +
            " -- check on the device")


def _placeholder_interface_row(reason: str = "N/A") -> dict:
    """Row used when a device has no interface data (or enrichment failed)."""
    return {
        "interfaceName": "N/A", "interfaceDescription": "N/A", "interfaceSpeed": "N/A",
        "resolvedIP": "N/A", "vrfNames": "default",
        "securityZone": "N/A",
        "interfaceStatus": "Unknown", "interfaceAdminStatus": "unknown",
        "interfaceOperStatus": "unknown", "interfaceStatusSource": "N/A",
        "matchedIPs": "N/A",
        "ipMatchDetail": f"N/A ({reason})" if reason != "N/A" else "N/A",
        "ipMatchStatus": "N/A",
        "_ip_assigned": set(), "_ip_connected": {}, "_ip_nat_pairs": [],
    }


def _matched_ips_text(entry: dict) -> str:
    """Comma-separated investigated addresses that matched an interface in
    any way (assigned, connected subnet, or NAT reference)."""
    if not PUBLIC_IPS:
        return "N/A"
    matched = set(entry.get("ip_assigned", set())) | set(entry.get("ip_connected", {}).keys())
    for _, ips in entry.get("ip_nat_pairs", []):
        matched |= set(ips)
    return ", ".join(str(ip) for ip in PUBLIC_IPS if ip in matched) or "None"


_FHRP_VIP_RE = re.compile(
    r"^\s*(?:standby\s+\d+\s+ip|vrrp\s+\d+\s+(?:ip|address)|ip\s+vrrp\s+\d+|hsrp\s+\d+\s+ip)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE | re.MULTILINE,
)


def _evaluate_switch_public_space(hostname: str, intf_data: dict, config_raw: str,
                                  nat_cfg, arp_raw_global: str) -> tuple:
    """Evaluates every interface on a requested switch that carries public
    (globally routable) address space.

    Returns ({interface_name: {publicSubnets, publicSpaceVerdict,
    publicSpaceReason, publicSpaceEvidence}}, device_note)."""
    # The switch's own addresses (every interface IP + HSRP/VRRP VIPs) are
    # never counted as "neighbors".
    own_ips = {n.ip for d in intf_data.values() for n in d.get("networks", [])}
    for vip in _FHRP_VIP_RE.findall(config_raw or ""):
        try:
            own_ips.add(ipaddress.ip_address(vip))
        except ValueError:
            pass

    public_by_intf = {}
    for name, d in intf_data.items():
        seen, nets = set(), []
        for n in d.get("networks", []):
            if n.ip.is_global and n.with_prefixlen not in seen:
                seen.add(n.with_prefixlen)
                nets.append(n)
        if nets:
            public_by_intf[name] = nets

    config_ok = bool(config_raw) and nat_cfg is not None
    if not public_by_intf:
        note = "No interfaces with public IP space found in NetBrain interface data" + (
            "" if config_raw else " (running-config not retrieved)"
        )
        return {}, note

    # ARP: global table, plus one fetch per non-default VRF that holds
    # public space.
    arp_by_vrf = {"default": arp_raw_global}
    for name in public_by_intf:
        vrf = intf_data[name].get("vrf", "default")
        if vrf != "default" and vrf not in arp_by_vrf:
            arp_by_vrf[vrf] = fetch_arp_raw(hostname, vrf, config_raw)
    arp_entries = {vrf: parse_arp_entries(raw) for vrf, raw in arp_by_vrf.items()}
    route_lines = config_route_reference_lines(config_raw)

    if DEBUG_ZONES:
        debug_logger.debug(
            f"[DEBUG] {hostname}: public-space eval | public interfaces="
            f"{ {k: [n.with_prefixlen for n in v] for k, v in public_by_intf.items()} } "
            f"| ARP fetched per VRF={ {k: len(v) for k, v in arp_by_vrf.items()} } chars "
            f"| ARP entries per VRF={ {k: len(v) for k, v in arp_entries.items()} } "
            f"| own_ips={len(own_ips)} | route/BGP lines={len(route_lines)}"
        )

    results = {}
    for name, nets in public_by_intf.items():
        d = intf_data[name]
        vrf = d.get("vrf", "default")
        v4_nets = [n for n in nets if n.version == 4]
        arp_ok = bool(arp_by_vrf.get(vrf)) and len(v4_nets) == len(nets)

        arp_hosts = sorted({
            ip for ip, _mac, is_self in arp_entries.get(vrf, [])
            if not is_self and _host_in_public_nets(ip, v4_nets, own_ips)
        })
        flags = (nat_cfg or {}).get("interfaces", {}).get(name.lower(), {})
        nat_role = "ip nat outside" if flags.get("outside") else "ip nat inside" if flags.get("inside") else ""
        route_refs = _route_refs_for_nets(route_lines, nets, own_ips)

        verdict, reason = public_space_verdict(
            d.get("admin_state", "unknown"), d.get("oper_state", "unknown"),
            arp_ok, arp_hosts, nat_role, route_refs, config_ok,
        )

        evidence = [
            f"ARP: {len(arp_hosts)} neighbor(s)"
            + (f" ({_format_detail_list([str(ip) for ip in arp_hosts], max_items=5)})" if arp_hosts else "")
            if arp_by_vrf.get(vrf) else f"ARP: not retrieved (vrf {vrf})",
        ]
        if len(v4_nets) < len(nets):
            evidence.append("IPv6 neighbor table not checked")
        evidence.append(f"NAT: {nat_role}" if nat_role else ("NAT: none" if config_ok else "NAT: config not retrieved"))
        if route_refs:
            evidence.append("Routes/BGP: " + _format_detail_list(route_refs, max_items=3))
        elif config_ok:
            evidence.append("Routes/BGP: none")

        results[name] = {
            "publicSubnets": ", ".join(n.with_prefixlen for n in nets),
            "publicSpaceVerdict": verdict,
            "publicSpaceReason": reason,
            "publicSpaceEvidence": " | ".join(evidence),
        }

    sources = [
        "running-config " + ("retrieved" if config_raw else "NOT retrieved"),
        "ARP " + ", ".join(f"{v}: {'retrieved' if r else 'NOT retrieved'}" for v, r in arp_by_vrf.items()),
    ]
    return results, "; ".join(sources)


def enrich_device_metadata(hostname: str, raw_device: dict) -> tuple:
    """Enriches device metadata, returning a per-interface row list plus device-level attributes."""
    intf_data = {}

    site_name = extract_site_from_device(raw_device)

    device_is_firewall = is_firewall_device(raw_device)
    device_is_router = is_router_device(raw_device)
    device_is_switch = is_switch_device(raw_device)
    # Switches get the same Cisco IOS NAT-interface lookup as routers
    # (L3-capable switches can run identical "ip nat inside"/"ip nat
    # outside" config), plus ACL-address resolution.
    device_is_cisco_nat_capable = device_is_router or device_is_switch

    # Requested switch (public IP space evaluation): always pull the
    # running-config and ARP table, even if the type keywords didn't
    # classify it as a switch/router.
    requested_switch = requested_switch_name(hostname)
    if requested_switch:
        device_is_cisco_nat_capable = True

    if not hostname:
        return [_placeholder_interface_row("no hostname")], "N/A", "N/A", site_name

    # Fetch device attributes, interface attributes, and (for firewalls,
    # routers, or switches) the live NAT-relevant config concurrently.
    with ThreadPoolExecutor(max_workers=4) as inner_executor:
        future_attrs = inner_executor.submit(fetch_device_attributes, hostname)
        future_intf_attrs = inner_executor.submit(fetch_all_interface_attrs, hostname)
        future_nat_policy = (
            inner_executor.submit(fetch_nat_policy_raw, hostname)
            if device_is_firewall else None
        )
        future_cisco_config = (
            inner_executor.submit(fetch_cisco_running_config_raw, hostname)
            if device_is_cisco_nat_capable else None
        )
        future_arp = (
            inner_executor.submit(fetch_arp_raw, hostname)
            if requested_switch else None
        )

        dev_attrs = future_attrs.result()
        all_intf_attrs = future_intf_attrs.result()
        nat_policy_raw = future_nat_policy.result() if future_nat_policy else ""
        cisco_config_raw = future_cisco_config.result() if future_cisco_config else ""
        arp_raw_global = future_arp.result() if future_arp else ""
    if arp_raw_global and cisco_config_raw and arp_raw_global == cisco_config_raw:
        arp_raw_global = ""  # canned-content guard

    # cisco_nat_config is None when the running-config couldn't be
    # retrieved -- callers must fall back to N/A, not "No", in that case
    # (same "unavailable vs. no" distinction used for PAN-OS NAT above).
    cisco_nat_config = parse_cisco_nat_config(cisco_config_raw, hostname) if cisco_config_raw else None

    # If the device has NAT rules that reference an ACL/list by name, but
    # NONE of those references resolved to any addresses (neither via
    # classic ACL syntax nor a Viptela prefix-list block already present
    # in the local running-config), opportunistically try the SD-WAN
    # "show sdwan policy from-vsmart" command -- centrally-managed policy
    # objects on Cisco SD-WAN (cEdge) devices are sometimes only visible
    # there, not in the device's own local config (observed:
    # DDC1-USONME-GRT1/GRT2's "Viptela-Underlay-NAT" reference). This is
    # best-effort: if the device doesn't support the command, the fetch
    # simply returns "" (via the same cmd-echo validation used
    # elsewhere) and cisco_nat_config is left unchanged.
    needs_viptela_fallback = (
        device_is_cisco_nat_capable
        and cisco_nat_config is not None
        and cisco_nat_config["inside_source_rules"]
        and not cisco_nat_config["interface_acl_refs"]
    )
    viptela_policy_raw = ""
    if needs_viptela_fallback:
        viptela_policy_raw = fetch_viptela_policy_raw(hostname)
        if viptela_policy_raw and viptela_policy_raw == cisco_config_raw:
            # Unmistakable sign this is the SAME canned dump as the
            # regular running-config fetch, not genuine SD-WAN policy
            # output -- some dataType/NetBrain combinations return fixed
            # content regardless of which 'cmd' was requested. Treat as
            # "no new data", even though an echo_indicator matched
            # somewhere in it (a large running-config can easily contain
            # an unrelated line like "ip prefix-list" for BGP filtering).
            if DEBUG_ZONES:
                debug_logger.debug(
                    f"[DEBUG] {hostname}: supplementary 'show sdwan policy from-vsmart' "
                    f"fetch returned content byte-identical to the regular running-config "
                    f"fetch -- this NetBrain/device combination appears to return fixed "
                    f"content regardless of the requested command; discarding as a false "
                    f"match rather than treating it as genuine SD-WAN policy data"
                )
            viptela_policy_raw = ""
        elif viptela_policy_raw:
            cisco_nat_config = parse_cisco_nat_config(
                cisco_config_raw + "\n" + viptela_policy_raw, hostname
            )
        if DEBUG_ZONES:
            debug_logger.debug(
                f"[DEBUG] {hostname}: unresolved NAT ACL reference(s) detected in local "
                f"running-config -- tried supplementary 'show sdwan policy from-vsmart' "
                f"fetch: {'got ' + str(len(viptela_policy_raw)) + ' chars, re-parsed' if viptela_policy_raw else 'no data returned (command unsupported or not SD-WAN-enabled)'} "
                f"| cisco_nat_config after fallback={cisco_nat_config}"
            )

    # Per-interface shutdown state + configured IPs from the running-config
    # (None when no config was retrieved), and any NAT rules referencing
    # any of the investigated IP addresses.
    cisco_intf_state = parse_cisco_interface_state(cisco_config_raw) if cisco_config_raw else None
    cisco_ip_hits = _cisco_nat_hits_for_ips(PUBLIC_IPS, cisco_config_raw, cisco_nat_config)

    if DEBUG_ZONES and device_is_cisco_nat_capable:
        debug_logger.debug(
            f"[DEBUG] {hostname}: Cisco running-config fetch "
            f"{'succeeded' if cisco_config_raw else 'FAILED/empty'} "
            f"| raw_content_length={len(cisco_config_raw) if cisco_config_raw else 0} "
            f"| cisco_nat_config={cisco_nat_config}"
        )

    # zone_nat_map is None when the NAT rulebase couldn't be retrieved (wrong
    # vendor, no permissions, API error) -- callers must fall back to the
    # interface-attribute-based guess (and ultimately N/A) in that case,
    # rather than assume "no NAT". It's {} (falsy-but-not-None) when we did
    # retrieve a rulebase and it genuinely has zero rules touching a zone.
    parsed_nat_rules = parse_nat_policy(nat_policy_raw, hostname) if nat_policy_raw else None
    zone_nat_map = build_zone_nat_map(parsed_nat_rules) if parsed_nat_rules is not None else None
    zone_nat_details = build_zone_nat_details(parsed_nat_rules) if parsed_nat_rules is not None else None
    pan_ip_hits = _pan_zone_hits_for_ips(PUBLIC_IPS, parsed_nat_rules)

    if DEBUG_ZONES and device_is_firewall:
        rule_count = len(parsed_nat_rules) if parsed_nat_rules is not None else "N/A (no content returned)"
        debug_logger.debug(
            f"[DEBUG] {hostname}: NAT policy fetch {'succeeded' if nat_policy_raw else 'FAILED/empty'} "
            f"| raw_content_length={len(nat_policy_raw) if nat_policy_raw else 0} "
            f"| parsed_rule_count={rule_count} "
            f"| zone_nat_map={zone_nat_map}"
        )

        # When rules were parsed (rule_count > 0) but zone_nat_map came back
        # empty, that's ambiguous from the summary line alone: it could mean
        # every parsed rule is genuinely zone-less (default/boilerplate
        # rules, or rules using "any" for both from/to -- _split_zone_list
        # intentionally excludes "any" since it isn't a specific zone), or
        # it could mean the from/to field regex isn't matching this device's
        # actual output formatting. Log a sample of the raw parsed
        # from_zones/to_zones/translate_to for the first few rules so this
        # can be told apart without guessing.
        if parsed_nat_rules and not zone_nat_map:
            sample_rules = [
                {
                    "name": r["name"],
                    "from_zones": r["from_zones"],
                    "to_zones": r["to_zones"],
                    "translate_to": r["translate_to"],
                    "is_nat": r["is_nat"],
                    "is_pat": r["is_pat"],
                }
                for r in parsed_nat_rules[:3]
            ]
            debug_logger.debug(
                f"[DEBUG] {hostname}: zone_nat_map is empty despite {rule_count} parsed rule(s) "
                f"-- sample of first {len(sample_rules)} rule(s)' from/to/translate-to fields "
                f"(empty from_zones/to_zones on all of these would mean the rules are "
                f"genuinely zone-less/boilerplate or use 'any'; non-empty lists here would "
                f"instead point at a zone-mapping bug elsewhere): {sample_rules}"
            )

    sn_val = dev_attrs.get("sn") or dev_attrs.get("serialNumber") or "N/A"
    model_val = dev_attrs.get("model") or "N/A"

    if DEBUG_ZONES and device_is_firewall and all_intf_attrs:
        sample_intf_name = next(iter(all_intf_attrs))
        debug_logger.debug(
            f"[DEBUG] {hostname}: sample interface '{sample_intf_name}' raw attrs = "
            f"{all_intf_attrs[sample_intf_name]}"
        )

    if DEBUG_ZONES and all_intf_attrs:
        sample_intf_name = next(iter(all_intf_attrs))
        sample_attrs = all_intf_attrs[sample_intf_name]
        if isinstance(sample_attrs, dict):
            status_like = {
                k: v for k, v in sample_attrs.items()
                if any(t in k.lower() for t in ("status", "state", "admin", "oper", "protocol", "link", "shut"))
            }
            debug_logger.debug(
                f"[DEBUG] {hostname}: status-like attrs on sample interface "
                f"'{sample_intf_name}' = {status_like} | all attr keys = {sorted(sample_attrs.keys())}"
            )

    for intf_name, attrs in all_intf_attrs.items():
        if not intf_name:
            continue

        clean_intf = str(intf_name).strip()

        if isinstance(attrs, dict):
            speed_val = attrs.get("speed") or attrs.get("bandwidth") or attrs.get("interfaceSpeed")
            clean_speed = str(speed_val).strip() if speed_val and str(speed_val).strip() else "N/A"

            descr_val = attrs.get("descr") or attrs.get("description") or attrs.get("interfaceDescription")
            clean_descr = str(descr_val).strip() if descr_val and str(descr_val).strip() else "N/A"

            vrf_val = str(attrs.get("mplsVrf") or attrs.get("vrfName") or attrs.get("vrf") or "").strip()
            clean_vrf = vrf_val if vrf_val and vrf_val.lower() not in ["none", "null", "undefined", "n/a", "0"] else "default"

            if device_is_firewall:
                zone_val = str(
                    attrs.get("securityZone")
                    or attrs.get("zoneName")
                    or attrs.get("zone")
                    or attrs.get("nameif")
                    or ""
                ).strip()
                if not zone_val or zone_val.lower() in ["none", "null", "undefined", "n/a"]:
                    # NetBrain appears to surface the firewall zone name through
                    # the same VRF-style attribute used for routers (e.g. it's
                    # empty/"default" on physical/HA interfaces and set to the
                    # real zone name on zone-assigned subinterfaces).
                    zone_val = vrf_val
                clean_zone = (
                    zone_val
                    if zone_val and zone_val.lower() not in ["none", "null", "undefined", "n/a", "0", "default"]
                    else "N/A"
                )
            else:
                clean_zone = "N/A"

            # NetBrain only populates isNatIntf/natType/nat (and the PAT
            # equivalents) for some platforms; on others (e.g. Palo Alto)
            # the key is present but always blank, or absent entirely,
            # because NAT/PAT is a policy construct rather than an
            # interface attribute there. A blank/missing key is NOT the
            # same as "confirmed no NAT" -- treat it as unknown ("N/A")
            # on firewalls, same as securityZone already does, rather than
            # silently reporting "No". This is the fallback used when we
            # don't have (or couldn't parse) an actual NAT rulebase below.
            nat_keys_present = any(
                attrs.get(k) not in (None, "")
                for k in ("isNatIntf", "natType", "nat")
            )
            pat_keys_present = any(
                attrs.get(k) not in (None, "")
                for k in ("isPatIntf", "patType", "pat")
            )

            nat_val = attrs.get("isNatIntf") or attrs.get("natType") or attrs.get("nat")
            pat_val = attrs.get("isPatIntf") or attrs.get("patType") or attrs.get("pat")

            if device_is_firewall and not nat_keys_present:
                is_nat = "N/A"
            else:
                is_nat = "Yes" if nat_val and str(nat_val).lower() not in ["false", "0", "disabled", "no", ""] else "No"

            if device_is_firewall and not pat_keys_present:
                is_pat = "N/A"
            else:
                is_pat = "Yes" if pat_val and str(pat_val).lower() not in ["false", "0", "disabled", "no", ""] else "No"

            # Authoritative override: if we successfully retrieved and parsed
            # this firewall's real NAT rulebase (zone_nat_map is not None),
            # trust that over the interface-attribute guess above -- it's
            # policy ground truth, keyed by the interface's own zone.
            # A zone with a known-empty rulebase correctly reports "No" here,
            # since the absence of NAT is now a confirmed fact, not a guess.
            nat_detail = "N/A"
            pat_detail = "N/A"
            if device_is_firewall and zone_nat_map is not None and clean_zone != "N/A":
                zone_entry = zone_nat_map.get(clean_zone.lower())
                is_nat = "Yes" if zone_entry and zone_entry["nat"] else "No"
                is_pat = "Yes" if zone_entry and zone_entry["pat"] else "No"

                zone_detail_entry = (zone_nat_details or {}).get(clean_zone.lower())
                if zone_detail_entry:
                    nat_detail = _format_detail_list(zone_detail_entry["nat_details"]) or "No NAT rules"
                    pat_detail = _format_detail_list(zone_detail_entry["pat_details"]) or "No PAT rules"
                else:
                    nat_detail = "No NAT rules"
                    pat_detail = "No PAT rules"

            # Authoritative override for routers: if we successfully
            # retrieved and parsed this router's running-config
            # (cisco_nat_config is not None), report the actual
            # "ip nat inside"/"ip nat outside" marking for this specific
            # interface, plus the relevant global "ip nat inside source"/
            # "ip nat outside source" statement(s) as detail text. PAT
            # ("Yes") is reported only for an "ip nat inside" interface
            # when at least one inside-source rule uses "overload" (Cisco's
            # port-overloaded dynamic NAT -- the PAT equivalent); a static
            # 1:1 inside-source rule is NAT without PAT, matching the same
            # NAT-vs-PAT distinction already used for PAN-OS zones.
            # Applies to routers AND switches (device_is_cisco_nat_capable)
            # since L3-capable switches can run identical IOS NAT config.
            acl_ip_addresses = "N/A"
            if device_is_cisco_nat_capable:
                if cisco_nat_config is None:
                    is_nat = "N/A"
                    is_pat = "N/A"
                    nat_detail = "N/A"
                    pat_detail = "N/A"
                    acl_ip_addresses = "N/A"
                else:
                    intf_key = clean_intf.lower()
                    iface_entry = cisco_nat_config["interfaces"].get(intf_key)
                    acl_refs_for_intf = cisco_nat_config["interface_acl_refs"].get(intf_key, [])
                    acl_ip_addresses = _format_acl_refs(acl_refs_for_intf) or "No ACL"

                    if iface_entry and iface_entry["inside"]:
                        is_nat = "Yes"
                        is_pat = "Yes" if cisco_nat_config["has_overload"] else "No"
                        nat_detail = (
                            "ip nat inside; " + _format_detail_list(cisco_nat_config["inside_source_rules"])
                            if cisco_nat_config["inside_source_rules"]
                            else "ip nat inside (no matching 'ip nat inside source' statement found)"
                        )
                        pat_detail = nat_detail if is_pat == "Yes" else "No PAT rules"
                    elif iface_entry and iface_entry["outside"]:
                        is_nat = "Yes" if cisco_nat_config["outside_source_rules"] else "No"
                        is_pat = "No"  # Cisco "outside source" NAT is not port-overloaded PAT
                        nat_detail = (
                            "ip nat outside; " + _format_detail_list(cisco_nat_config["outside_source_rules"])
                            if cisco_nat_config["outside_source_rules"]
                            else "ip nat outside (no matching 'ip nat outside source' statement found)"
                        )
                        pat_detail = "No PAT rules"
                    else:
                        is_nat = "No"
                        is_pat = "No"
                        nat_detail = "No NAT rules"
                        pat_detail = "No PAT rules"

            if DEBUG_ZONES:
                nat_pat_candidates = {
                    k: v for k, v in attrs.items()
                    if any(tok in k.lower() for tok in ["nat", "pat"])
                }
                debug_logger.debug(
                    f"[DEBUG] {hostname}/{clean_intf}: zone={clean_zone!r} "
                    f"nat_val={nat_val!r} -> {is_nat} | "
                    f"pat_val={pat_val!r} -> {is_pat} | "
                    f"nat/pat-like raw attrs={nat_pat_candidates}"
                )

            intf_ip = "N/A"
            ips_raw = attrs.get("ips") or attrs.get("ipAddress")
            raw_list = ips_raw if isinstance(ips_raw, list) else [ips_raw]

            for item in raw_list:
                ip_str = item.get("ipLoc") if isinstance(item, dict) else item
                mask_val = item.get("mask") or item.get("subnetMask") if isinstance(item, dict) else ""

                c_ip = clean_ip(ip_str)
                if c_ip:
                    # Construct full IP with subnet mask if available separately
                    if mask_val and "/" not in str(ip_str):
                        full_ip_with_mask = f"{ip_str}/{mask_val}"
                    else:
                        full_ip_with_mask = str(ip_str).strip()

                    resolved_ip, _ = resolve_ptr(full_ip_with_mask, hostname)
                    intf_ip = resolved_ip
                    break  # one resolved IP per interface

            # Interface admin/oper status: NetBrain attributes, with the
            # running-config's "shutdown" line (Cisco) as authoritative for
            # admin state when the config was retrieved.
            admin_state, oper_state, status_source = _interface_status_from_attrs(attrs)
            cfg_entry = (cisco_intf_state or {}).get(clean_intf.lower())
            if cfg_entry is not None:
                if cfg_entry["shutdown"]:
                    admin_state = "down"
                    status_source = "; ".join(filter(None, ["running-config: shutdown", status_source]))
                elif not admin_state:
                    admin_state = "up"
                    status_source = "; ".join(filter(None, ["running-config: no shutdown", status_source]))
            intf_status = _summarize_interface_status(admin_state, oper_state)

            # IP address investigation for this interface.
            ip_match_detail = "N/A"
            ip_assigned, ip_connected, ip_nat_pairs = set(), {}, []
            networks = _interface_networks_from_attrs(attrs)
            if cfg_entry is not None:
                networks += cfg_entry["ips"]
            if PUBLIC_IPS:
                reasons, ip_assigned, ip_connected = _match_ips_on_interface(PUBLIC_IPS, networks)
                ip_nat_pairs = list(cisco_ip_hits.get(clean_intf.lower(), []))
                ip_nat_pairs += [(f"{r} (device-level)", m) for r, m in cisco_ip_hits.get("__device__", [])]
                if clean_zone != "N/A":
                    ip_nat_pairs += pan_ip_hits.get(clean_zone.lower(), [])
                nat_reasons = [
                    f"{', '.join(str(ip) for ip in sorted(m))}: {r}" for r, m in ip_nat_pairs
                ]
                ip_match_detail = _format_detail_list(reasons + nat_reasons, max_items=10) or "No"

            intf_data[clean_intf] = {
                "name": clean_intf,
                "description": clean_descr,
                "speed": clean_speed,
                "vrf": clean_vrf,
                "nat": is_nat,
                "pat": is_pat,
                "nat_detail": nat_detail,
                "pat_detail": pat_detail,
                "acl_ip_addresses": acl_ip_addresses,
                "ip": intf_ip,
                "zone": clean_zone,
                "admin_state": admin_state or "unknown",
                "oper_state": oper_state or "unknown",
                "status": intf_status,
                "status_source": status_source or "N/A",
                "ip_match_detail": ip_match_detail,
                "ip_assigned": ip_assigned,
                "ip_connected": ip_connected,
                "ip_nat_pairs": ip_nat_pairs,
                "networks": networks,
            }
        else:
            intf_data[clean_intf] = {
                "name": clean_intf,
                "description": "N/A",
                "speed": "N/A",
                "vrf": "default",
                "nat": "No",
                "pat": "No",
                "nat_detail": "N/A",
                "pat_detail": "N/A",
                "acl_ip_addresses": "N/A",
                "ip": "N/A",
                "zone": "N/A",
                "admin_state": "unknown",
                "oper_state": "unknown",
                "status": "Unknown",
                "status_source": "N/A",
                "ip_match_detail": "No" if PUBLIC_IPS else "N/A",
                "ip_assigned": set(),
                "ip_connected": {},
                "ip_nat_pairs": [],
                "networks": [],
            }

    # Public IP space evaluation for requested switches.
    public_eval = {}
    public_device_note = ""
    if requested_switch:
        public_eval, public_device_note = _evaluate_switch_public_space(
            hostname, intf_data, cisco_config_raw, cisco_nat_config, arp_raw_global
        )

    sorted_intfs = sorted(intf_data.keys())
    if sorted_intfs:
        interfaces_list = [
            {
                "interfaceName": intf_data[intf]["name"],
                "interfaceDescription": intf_data[intf]["description"],
                "interfaceSpeed": intf_data[intf]["speed"],
                "resolvedIP": intf_data[intf]["ip"],
                "vrfNames": intf_data[intf]["vrf"],
                "securityZone": intf_data[intf]["zone"],
                "interfaceStatus": intf_data[intf]["status"],
                "interfaceAdminStatus": intf_data[intf]["admin_state"],
                "interfaceOperStatus": intf_data[intf]["oper_state"],
                "interfaceStatusSource": intf_data[intf]["status_source"],
                "matchedIPs": _matched_ips_text(intf_data[intf]),
                "ipMatchDetail": intf_data[intf]["ip_match_detail"],
                "ipMatchStatus": (
                    intf_data[intf]["status"]
                    if intf_data[intf]["ip_match_detail"] not in ("No", "N/A")
                    else "N/A"
                ),
                # Underscore-prefixed fields feed the per-address summary;
                # they're not CSV columns (DictWriter ignores them).
                "_ip_assigned": intf_data[intf]["ip_assigned"],
                "_ip_connected": intf_data[intf]["ip_connected"],
                "_ip_nat_pairs": intf_data[intf]["ip_nat_pairs"],
                **public_eval.get(intf, {
                    "publicSubnets": "None",
                    "publicSpaceVerdict": "No public IP space" if requested_switch else "N/A",
                    "publicSpaceReason": "-",
                    "publicSpaceEvidence": "-",
                }),
                "_public_device_note": public_device_note,
            }
            for intf in sorted_intfs
        ]
    else:
        interfaces_list = [_placeholder_interface_row("no interface data")]
        interfaces_list[0]["_public_device_note"] = public_device_note

    return (
        interfaces_list,
        sn_val,
        model_val,
        site_name,
    )


def _is_ip_match(value) -> bool:
    """True if an ipMatchDetail cell represents an actual match."""
    v = str(value or "")
    return bool(v) and v != "No" and not v.startswith("N/A")


def _rollup_status(statuses: list) -> str:
    """Collapses several interface statuses into one keyword."""
    if any(st.startswith("Active") for st in statuses):
        return "ACTIVE"
    if statuses and all(st.startswith("Shutdown") for st in statuses):
        return "SHUTDOWN"
    if any(st.startswith("Down") for st in statuses):
        return "DOWN"
    if any(st.startswith("Shutdown") for st in statuses):
        return "PARTLY SHUTDOWN"
    return "STATUS UNKNOWN"


def _format_probe(probe: dict) -> str:
    if not probe:
        return "Not probed"
    def _short(state):
        if state.startswith("open"):
            return "open"
        if state.startswith("closed"):
            return "closed/reset"
        if state.startswith("no response"):
            return "no-response"
        return "error"
    tcp = ", ".join(f"TCP/{p} {_short(st)}" for p, st in probe.get("tcp", {}).items())
    head = "RESPONDING" if probe.get("responding") else "NO RESPONSE"
    return f"{head} (ping: {probe.get('ping', 'N/A')}; {tcp})"


IP_CHECK_COLUMNS = [
    "address", "addressType", "status", "assignedTo", "natReferences",
    "connectedOn", "subnetRole", "managementIpOf", "reverseDNS", "liveProbe",
]


def build_ip_summary(final_rows: list, mgmt_matches: list, live: dict) -> tuple:
    """Builds the IP-list summary.

    Returns (verdict, field_rows, address_rows):
      field_rows   - [(field, value), ...] overview
      address_rows - one dict per investigated address (IP_CHECK_COLUMNS keys)
    """
    live = live or {}
    rdns = live.get("rdns", {})
    probes = live.get("probe", {})
    matched = [r for r in final_rows if _is_ip_match(r.get("ipMatchDetail"))]

    address_rows = []
    for ip in PUBLIC_IPS:
        a = str(ip)
        assigned = [r for r in matched if ip in r.get("_ip_assigned", set())]
        nat = [
            (r, reason) for r in matched
            for reason, ips in r.get("_ip_nat_pairs", []) if ip in ips
        ]
        connected = [r for r in matched if ip in r.get("_ip_connected", {})]
        mgmt = [f"{h} ({site})" for h, site, m_ip in mgmt_matches if m_ip == ip]

        if assigned:
            status = _rollup_status([str(r.get("interfaceStatus", "Unknown")) for r in assigned])
            if status == "STATUS UNKNOWN":
                status = "ASSIGNED - STATUS UNKNOWN"
        elif mgmt:
            status = "DEVICE MANAGEMENT IP"
        elif nat:
            egress = _rollup_status([str(r.get("interfaceStatus", "Unknown")) for r, _ in nat])
            status = f"NAT ONLY (egress interface {egress})"
        elif connected:
            status = "IN CONNECTED SUBNET ONLY (not assigned to a discovered interface)"
        else:
            status = "NOT FOUND"

        # Flag addresses that are the network/broadcast address of the
        # connected subnet they sit in -- usually a data-entry mistake.
        roles = []
        for r in connected:
            net = r["_ip_connected"][ip]
            if net.version == 4 and net.prefixlen <= 30:
                if ip == net.network_address:
                    roles.append(f"network address of {net}")
                elif ip == net.broadcast_address:
                    roles.append(f"broadcast address of {net}")
                else:
                    roles.append(f"host in {net}")
            else:
                roles.append(f"in {net}")

        address_rows.append({
            "address": a,
            "addressType": "Public" if ip.is_global else "Not public",
            "status": status,
            "assignedTo": "; ".join(
                f"{r.get('name', 'N/A')} {r.get('interfaceName', 'N/A')} [{r.get('interfaceStatus', 'Unknown')}]"
                for r in assigned
            ) or "-",
            "natReferences": _format_detail_list(
                [f"{r.get('name', 'N/A')} {r.get('interfaceName', 'N/A')}: {reason}" for r, reason in nat],
                max_items=3,
            ) or "-",
            "connectedOn": _format_detail_list(
                [f"{r.get('name', 'N/A')} {r.get('interfaceName', 'N/A')}" for r in connected],
                max_items=3,
            ) or "-",
            "subnetRole": _format_detail_list(roles, max_items=3) or "-",
            "managementIpOf": "; ".join(mgmt) or "-",
            "reverseDNS": rdns.get(a, "Not looked up"),
            "liveProbe": _format_probe(probes.get(a)) if probes else "Not probed",
        })

    # Overall verdict: per-status counts across the investigated addresses.
    counts = {}
    for ar in address_rows:
        key = ar["status"].split(" (")[0]
        counts[key] = counts.get(key, 0) + 1
    order = [
        "ACTIVE", "DOWN", "SHUTDOWN", "PARTLY SHUTDOWN", "ASSIGNED - STATUS UNKNOWN",
        "DEVICE MANAGEMENT IP", "NAT ONLY", "IN CONNECTED SUBNET ONLY", "NOT FOUND",
    ]
    verdict = f"{len(address_rows)} address(es) checked: " + "; ".join(
        f"{k} {counts[k]}" for k in sorted(counts, key=lambda k: order.index(k) if k in order else len(order))
    )
    if probes:
        responding = sum(1 for p in probes.values() if p.get("responding"))
        verdict += f" | live probe from this workstation: {responding} of {len(probes)} responding"

    rows = [
        ("Investigated addresses", ", ".join(str(ip) for ip in PUBLIC_IPS)),
        ("Address count", str(len(PUBLIC_IPS))),
        ("Target site searched", TARGET_SITE),
        ("Report generated", TIMESTAMP),
        ("Overall verdict", verdict),
    ]
    if live.get("rdns_note"):
        rows.append(("Reverse DNS", live["rdns_note"]))
    if live.get("probe_note"):
        rows.append(("Live probe", live["probe_note"]))
    elif probes:
        rows.append((
            "Live probe - caveat",
            "Results reflect reachability from this workstation only. If your network uses a "
            "transparent web proxy, TCP/80 and TCP/443 can show 'open' for any address; ping "
            "and TCP/22 are more reliable in that case.",
        ))
    rows.append((
        "NetBrain device management IP matches (all sites)",
        "; ".join(f"{h} ({site}) = {ip}" for h, site, ip in mgmt_matches) or "None",
    ))
    rows.append(("Matching interfaces", str(len(matched))))
    rows.append((
        "Note",
        "Interface status comes from NetBrain's last discovery/benchmark data (and the device "
        "running-config where retrieved), not a real-time poll. Only devices at the target site "
        "were searched for interface/NAT matches; the management-IP check covers all sites. "
        "See the main interface report (matching rows sorted to the top) for full per-interface detail.",
    ))
    return verdict, rows, address_rows


SWITCH_SUMMARY_COLUMNS = [
    "switch", "netbrainHostname", "verdict", "publicInterfaces", "inUse", "canBeShutdown",
    "alreadyShutdown", "needsReview", "dataSources",
]
SWITCH_INTF_COLUMNS = [
    "switch", "interfaceName", "interfaceDescription", "publicSubnets", "interfaceStatus",
    "vrfNames", "publicSpaceVerdict", "publicSpaceReason", "publicSpaceEvidence",
]


def build_switch_public_summary(final_rows: list, found_hostnames: set) -> tuple:
    """Rolls up per-interface public-space verdicts into one row per
    requested switch. Returns (switch_rows, interface_rows)."""
    found_by_request = {}
    for h in found_hostnames:
        req = requested_switch_name(h)
        if req:
            found_by_request.setdefault(req, h)

    switch_rows, intf_rows = [], []
    for req in SWITCH_HOSTNAMES:
        nb_host = found_by_request.get(req)
        if not nb_host:
            switch_rows.append({
                "switch": req, "netbrainHostname": "-", "verdict": "NOT FOUND IN NETBRAIN",
                "publicInterfaces": 0, "inUse": 0, "canBeShutdown": 0, "alreadyShutdown": 0,
                "needsReview": 0, "dataSources": "-",
            })
            continue
        rows = [r for r in final_rows if r.get("_hostname") == nb_host]
        pub = [r for r in rows if r.get("publicSpaceVerdict") in PUBLIC_SPACE_VERDICTS]
        note = next((r.get("_public_device_note") for r in rows if r.get("_public_device_note")), "")
        for r in pub:
            intf_rows.append({"switch": req, **{c: r.get(c, "") for c in SWITCH_INTF_COLUMNS if c != "switch"}})

        verdicts = [r["publicSpaceVerdict"] for r in pub]
        in_use = verdicts.count("ACTIVE - IN USE")
        can_shut = verdicts.count("CAN BE SHUTDOWN")
        already = verdicts.count("ALREADY SHUTDOWN")
        review = len(verdicts) - in_use - can_shut - already

        if all(r.get("interfaceName") == "N/A" for r in rows):
            verdict = "NO INTERFACE DATA IN NETBRAIN"
        elif not pub:
            verdict = "NO PUBLIC IP SPACE FOUND"
        elif in_use:
            verdict = f"ACTIVE - IN USE ({in_use} of {len(pub)} public interface(s) in use)"
        elif review:
            verdict = f"REVIEW ({review} of {len(pub)} public interface(s) need verification)"
        elif can_shut:
            verdict = "CAN BE SHUTDOWN" + (f" ({already} already shut)" if already else "")
        else:
            verdict = "ALREADY SHUTDOWN"

        switch_rows.append({
            "switch": req, "netbrainHostname": nb_host, "verdict": verdict,
            "publicInterfaces": len(pub), "inUse": in_use, "canBeShutdown": can_shut,
            "alreadyShutdown": already, "needsReview": review, "dataSources": note or "-",
        })
    return switch_rows, intf_rows


def main():
    authenticate()

    site_devices = []
    seen_hostnames = set()
    all_discovered_columns = {
        "requestedSite",
        "serialNumber",
        "hardwareModel",
        "interfaceDescription",
        "interfaceSpeed",
        "vrfNames",
        "resolvedIP",
        "interfaceStatus",
        "interfaceAdminStatus",
        "interfaceOperStatus",
        "interfaceStatusSource",
    }
    
    EXCLUDED_FIELDS = {
        "hostName",
        "hostname",
        "mgmtIP",
        "domain",
        "domainName",
        "dnsDomain",
    }

    if SWITCH_HOSTNAMES:
        print(f"Fetching global CMDB devices to locate {len(SWITCH_HOSTNAMES)} requested switch(es)...")
    else:
        print(
            f"Fetching global CMDB devices for target site '{TARGET_SITE}' "
            f"(device types: {', '.join(sorted(TARGET_DEVICE_TYPES))})..."
        )
    raw_devices = fetch_all_devices()

    # IP list: start reverse DNS + live probe in the background while
    # NetBrain data is processed, and check every device's management IP
    # (all sites) against the list.
    live_executor = None
    live_future = None
    mgmt_ip_matches = []  # [(hostname, site, ip_address), ...]
    if PUBLIC_IPS:
        print(f"Investigating {len(PUBLIC_IPS)} IP address(es)...")
        live_executor = ThreadPoolExecutor(max_workers=1)
        live_future = live_executor.submit(investigate_ips_live, PUBLIC_IPS, PUBLIC_IP_LIVE_PROBE)
        public_ip_set = set(PUBLIC_IPS)
        for device in raw_devices:
            mgmt = clean_ip(str(device.get("mgmtIP") or ""))
            try:
                mgmt_addr = ipaddress.ip_address(mgmt) if mgmt else None
            except ValueError:
                continue
            if mgmt_addr is not None and mgmt_addr in public_ip_set:
                # Don't use extract_site_from_device here -- it falls back
                # to TARGET_SITE, which would mislabel other-site devices.
                device_site = next(
                    (str(device.get(k)).strip() for k in ("siteName", "site", "sitePath", "location", "site_name")
                     if isinstance(device.get(k), str) and device.get(k).strip()),
                    "site unknown",
                )
                mgmt_ip_matches.append((
                    device.get("hostName") or device.get("hostname") or device.get("name") or "?",
                    device_site,
                    mgmt_addr,
                ))

    for device in raw_devices:
        if len(site_devices) >= LIMIT_DEVICES:
            break

        hostname = (
            device.get("hostName")
            or device.get("hostname")
            or device.get("name")
        )

        if hostname and hostname not in seen_hostnames:
            searchable_fields = f"{hostname} {device.get('mgmtIP', '')} {device.get('subType', '')}".upper()

            if SWITCH_HOSTNAMES:
                selected = bool(requested_switch_name(hostname))
            else:
                selected = TARGET_SITE in searchable_fields and matches_target_device_type(device)
            if selected:
                seen_hostnames.add(hostname)
                flat_device = {"_raw_device": device, "_hostname": hostname}
                flat_device["requestedSite"] = extract_site_from_device(device)

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

                # hostName/hostname are excluded above, so make sure the
                # "name" column (and enrichment) still gets the hostname
                # when the device payload has no separate "name" field.
                flat_device.setdefault("name", hostname)

                all_discovered_columns.update(
                    k for k in flat_device if not k.startswith("_")
                )
                site_devices.append(flat_device)

    print(f"Limiting audit to {len(site_devices)} assets. Enriching metadata ({MAX_WORKERS} workers)...")

    if site_devices:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_map = {
                executor.submit(
                    enrich_device_metadata,
                    dev.get("_hostname") or dev.get("name"),
                    dev.get("_raw_device", {}),
                ): dev
                for dev in site_devices
            }

            for future in as_completed(future_map):
                dev = future_map[future]
                try:
                    (
                        interfaces_list,
                        sn_res,
                        model_res,
                        site_res,
                    ) = future.result()

                    dev["_interfaces"] = interfaces_list
                    dev["serialNumber"] = sn_res
                    dev["hardwareModel"] = model_res
                    dev["requestedSite"] = site_res
                except Exception:
                    dev["_interfaces"] = [_placeholder_interface_row("device data unavailable")]
                    dev["serialNumber"] = "N/A"
                    dev["hardwareModel"] = "N/A"
                    dev["requestedSite"] = TARGET_SITE
                finally:
                    dev.pop("_raw_device", None)

    primary_headers = [
        "name",
        "requestedSite",
        "serialNumber",
        "hardwareModel",
        "interfaceName",
        "interfaceDescription",
        "interfaceSpeed",
        "resolvedIP",
        "interfaceStatus",
        "interfaceAdminStatus",
        "interfaceOperStatus",
        "interfaceStatusSource",
        "vrfNames",
        "securityZone",
    ]
    if PUBLIC_IPS:
        # Investigation columns go right after the interface name so
        # matches are easy to spot.
        idx = primary_headers.index("interfaceName") + 1
        primary_headers[idx:idx] = ["matchedIPs", "ipMatchDetail", "ipMatchStatus"]
    if SWITCH_HOSTNAMES:
        idx = primary_headers.index("interfaceStatusSource") + 1
        primary_headers[idx:idx] = [
            "publicSubnets", "publicSpaceVerdict", "publicSpaceReason", "publicSpaceEvidence",
        ]
    extra_headers = sorted(
        [
            col
            for col in all_discovered_columns
            if col not in primary_headers and col not in EXCLUDED_FIELDS
        ]
    )
    ordered_headers = primary_headers + extra_headers

    # Expand each device into one row per interface, repeating device-level fields.
    final_rows = []
    for dev in site_devices:
        interfaces = dev.pop("_interfaces", None) or [_placeholder_interface_row("no interface data")]
        for intf_row in interfaces:
            row = {**dev, **intf_row}
            final_rows.append(row)

    if SWITCH_HOSTNAMES:
        # Interfaces with public space first, most important verdicts on top
        # (stable sort -- the IP-match sort below still wins if both apply).
        _vorder = {v: i for i, v in enumerate(PUBLIC_SPACE_VERDICTS)}
        final_rows.sort(key=lambda r: _vorder.get(r.get("publicSpaceVerdict"), len(_vorder)))

    ip_verdict = None
    ip_field_rows, ip_address_rows = [], []
    if PUBLIC_IPS:
        # Matching interfaces first (stable sort keeps the rest in order).
        final_rows.sort(key=lambda r: not _is_ip_match(r.get("ipMatchDetail")))
        live_result = {}
        if live_future is not None:
            if PUBLIC_IP_LIVE_PROBE and len(PUBLIC_IPS) <= PUBLIC_IP_PROBE_MAX:
                print("Waiting for live probe to finish...")
            try:
                live_result = live_future.result()
            except Exception as e:
                live_result = {"probe_note": f"Live checks failed ({e})"}
            finally:
                live_executor.shutdown(wait=False)
        ip_verdict, ip_field_rows, ip_address_rows = build_ip_summary(
            final_rows, mgmt_ip_matches, live_result
        )

    output_dir = os.path.dirname(OUTPUT_FILE)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file, fieldnames=ordered_headers, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(final_rows)

    print(f"Export successful: {OUTPUT_FILE}")

    if PUBLIC_IPS:
        with open(PUBLIC_IP_SUMMARY_FILE, mode="w", newline="", encoding="utf-8") as summary_file:
            writer = csv.writer(summary_file)
            writer.writerow(["field", "value"])
            writer.writerows(ip_field_rows)
            writer.writerow([])
            writer.writerow(IP_CHECK_COLUMNS)
            for ar in ip_address_rows:
                writer.writerow([ar[c] for c in IP_CHECK_COLUMNS])
        print(f"IP check: {ip_verdict}")
        if len(ip_address_rows) <= 25:
            width = max(len(ar["address"]) for ar in ip_address_rows)
            for ar in ip_address_rows:
                print(f"  {ar['address']:<{width}}  {ar['status']}")
        print(f"IP check summary written to: {PUBLIC_IP_SUMMARY_FILE}")
    if SWITCH_HOSTNAMES:
        switch_rows, intf_rows = build_switch_public_summary(final_rows, seen_hostnames)
        with open(SWITCH_PUBLIC_FILE, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(SWITCH_SUMMARY_COLUMNS)
            for sr in switch_rows:
                writer.writerow([sr[c] for c in SWITCH_SUMMARY_COLUMNS])
            writer.writerow([])
            writer.writerow(SWITCH_INTF_COLUMNS)
            for ir in intf_rows:
                writer.writerow([ir.get(c, "") for c in SWITCH_INTF_COLUMNS])
            writer.writerow([])
            writer.writerow(["Note", (
                "Verdicts use NetBrain's last discovery/benchmark data (interface state, running-config, "
                "ARP table), not a real-time poll. CAN BE SHUTDOWN means no usage evidence was found -- "
                "confirm on the device (e.g. 'show ip arp', 'show interface' counters) and follow change "
                "control before shutting anything."
            )])
        print("Switch public IP space:")
        for sr in switch_rows:
            print(f"  {sr['switch']}: {sr['verdict']}")
            for ir in intf_rows:
                if ir["switch"] == sr["switch"]:
                    print(f"      {ir['interfaceName']:<24} {ir['publicSubnets']:<22} {ir['publicSpaceVerdict']}")
        print(f"Switch public IP summary written to: {SWITCH_PUBLIC_FILE}")
    if DEBUG_ZONES:
        print(f"Debug log written to: {DEBUG_LOG_FILE}")


if __name__ == "__main__":
    main()