# testit.py — updated script with previous-run diffing

import os
import time
import json
import csv
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import glob
import difflib
import re
from typing import Optional, List, Tuple

try:
    import paramiko
except ImportError as e:
    raise SystemExit("Missing dependency 'paramiko'. Install with: pip install paramiko") from e

# ========= CONFIG =========
LOG_DIR = 'logs'
ARTIFACTS_DIR = 'artifacts'
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# Per-run timestamp tag
RUN_TS = datetime.now().strftime('%Y%m%d_%H%M%S')

# Configure logging with timestamp
log_path = os.path.join(LOG_DIR, f'validation_log_{RUN_TS}.txt')
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logging.getLogger().addHandler(console)

# -------- Devices & Commands --------
# NOTE: Credentials intentionally not embedded. Use environment variables:
#   Global fallbacks: COR_USER / COR_PASS (or DEVICE_USER / DEVICE_PASS)
#   Per device (override): <DEVICE_NAME>_USER / <DEVICE_NAME>_PASS  (non-alphanumeric -> '_')
# Example: export COR_USER=myuser; export COR_PASS='mypassword'

devices = {
    "NEW_DDC1-MDFE1-COR1": {"host": "NEW_DDC1-MDFE1-COR1", "username": "ekk30ws", "password": "New42day123!@#$%"},
    "NEW_DDC1-MDFE1-COR2": {"host": "NEW_DDC1-MDFE1-COR2", "username": "ekk30ws", "password": "New42day123!@#$%"}
}

# Validate Aruba Edge Connect / SD-WAN environment
commands = {
    "NEW_DDC1-MDFE1-COR1": [
    "!**********Validate Aruba Edge Connect / SD-WAN environment*********",
        "show int e3/35 | i rate",
        "sleep 1",
        "show int e3/36 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.50.66.58 | no-more",
        "show ip bgp 10.50.66.62 | no-more",
        "show ip bgp neighbors 10.50.66.58 | no-more",
        "show ip bgp neighbors 10.50.66.62 | no-more",
        "show ip route bgp int e3/35 | no-more",
        "show ip route bgp int e3/36 | no-more",
        "show ip route | no-more",
        "show int e3/28 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.255.132.137 | no-more",
        "show ip bgp neighbors 10.255.132.137 | no-more",
        "show ip route bgp int e3/28 | no-more",
        "show ip route | no-more",
        # Additional test commands (duplicated per the original intent)
        "show int e3/28 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.255.132.137 | no-more",
        "show ip bgp neighbors 10.255.132.137 | no-more",
        "show ip route bgp int e3/28 | no-more",
        "show ip route | no-more",
    ],
    "NEW_DDC1-MDFE1-COR2": [
        "show int e3/35 | i rate",
        "sleep 1",
        "show int e3/36 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.50.66.66 | no-more",
        "show ip bgp 10.50.66.70 | no-more",
        "show ip bgp neighbors 10.50.66.66 | no-more",
        "show ip bgp neighbors 10.50.66.70 | no-more",
        "show ip route bgp int e3/35 | no-more",
        "show ip route bgp int e3/36 | no-more",
        "show ip route | no-more",
        "show int e3/28 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.255.132.117 | no-more",
        "show ip bgp neighbors 10.255.132.117 | no-more",
        "show ip route bgp int e3/28 | no-more",
        "show ip route | no-more",
        # Additional test commands (duplicated per the original intent)
        "show int e3/28 | i rate",
        "sleep 1",
        "show ip bgp sum | no-more",
        "show ip bgp 10.255.132.117 | no-more",
        "show ip bgp neighbors 10.255.132.117 | no-more",
        "show ip route bgp int e3/28 | no-more",
        "show ip route | no-more",
    ],
}
# ========= ADDITIONAL TEST COMMANDS =========
# Validate sd-wan Viptela environment
commands["NEW_DDC1-MDFE1-COR1"].extend([
    "!****************VALIDATE FOR VIPTELA SD WAN *****************",
    "show int e3/28 | i rate",
    "sleep 1",
    "show ip bgp sum | no-more",
    "show ip bgp 10.255.132.137 | no-more",
    "show ip bgp neighbors 10.255.132.137 | no-more",
    "show ip route bgp int e3/28 | no-more",
    "show ip route | no-more"
])

commands["NEW_DDC1-MDFE1-COR2"].extend([
    "show int e3/28 | i rate",
    "sleep 1",
    "show ip bgp sum | no-more",
    "show ip bgp 10.255.132.117 | no-more",
    "show ip bgp neighbors 10.255.132.117 | no-more",
    "show ip route bgp int e3/28 | no-more",
    "show ip route | no-more"
])

# ========= HELPERS =========

def _env_key(name: str) -> str:
    """Sanitize device name to an ENV key (alnum + '_')."""
    return re.sub(r'[^A-Za-z0-9_]', '_', name)


def safe_str(s: str) -> str:
    return (s or "").replace('\r', '').replace('\x1b', '')  # strip CR and ANSI if any


def connect_ssh(host, username, password, port=22, timeout=15, banner_timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Avoid using local SSH agent or keys unless you want that behavior
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=timeout,
        banner_timeout=banner_timeout,
        allow_agent=False,
        look_for_keys=False
    )
    return client


def run_exec(client: paramiko.SSHClient, cmd: str, read_timeout: float = 30.0):
    """
    Run a single command via exec_command with a read timeout.
    Returns (exit_status, stdout_text, stderr_text, elapsed_sec).
    """
    start = time.time()
    stdin, stdout, stderr = client.exec_command(cmd, timeout=read_timeout)
    # Set channel timeout for reads
    stdout.channel.settimeout(read_timeout)
    stderr.channel.settimeout(read_timeout)

    out = ""
    err = ""
    try:
        out = stdout.read().decode(errors='replace')
    except Exception as e:
        err += f"\n[stdout timeout/read error: {e}]"
    try:
        err += stderr.read().decode(errors='replace')
    except Exception as e:
        err += f"\n[stderr timeout/read error: {e}]"
    # Ensure we grab exit status
    try:
        exit_status = stdout.channel.recv_exit_status()
    except Exception:
        # Fallback if channel already closed unexpectedly
        exit_status = -1

    elapsed = time.time() - start
    return exit_status, safe_str(out), safe_str(err), elapsed


def _resolve_credentials(device_name: str, device_info: dict) -> Tuple[Optional[str], Optional[str]]:
    """Resolve credentials from device_info or environment variables."""
    # device-specific env overrides
    env_prefix = _env_key(device_name)
    username = (
        device_info.get('username')
        or os.getenv(f'{env_prefix}_USER')
        or os.getenv('COR_USER')
        or os.getenv('DEVICE_USER')
    )
    password = (
        device_info.get('password')
        or os.getenv(f'{env_prefix}_PASS')
        or os.getenv('COR_PASS')
        or os.getenv('DEVICE_PASS')
    )
    return username, password


def execute_commands(device_name: str, device_info: dict, command_list: list, max_retries: int = 2):
    host = device_info['host']
    username, password = _resolve_credentials(device_name, device_info)
    port = device_info.get('port', 22)

    if not username or not password or username == "REPLACE_ME" or password == "REPLACE_ME":
        msg = (
            f"[{device_name}] Missing credentials (set env COR_USER/COR_PASS or DEVICE_USER/DEVICE_PASS, "
            f"or { _env_key(device_name) }_USER/{ _env_key(device_name) }_PASS)."
        )
        logging.error(msg)
        return {"device": device_name, "host": host, "status": "failed", "reason": msg, "results": []}

    logging.info(f"Connecting to {device_name} ({host})")
    attempt = 0
    client = None
    last_exc = None

    while attempt <= max_retries:
        try:
            client = connect_ssh(host, username, password, port=port)
            break
        except Exception as e:
            last_exc = e
            attempt += 1
            logging.warning(f"[{device_name}] Connect attempt {attempt} failed: {e}")
            time.sleep(min(2 ** attempt, 10))

    if client is None:
        reason = f"Failed to connect to {device_name}: {last_exc}"
        logging.error(reason)
        return {"device": device_name, "host": host, "status": "failed", "reason": str(last_exc), "results": []}

    per_device_artifact = os.path.join(ARTIFACTS_DIR, f"{device_name}_{RUN_TS}.txt")
    results_csv = os.path.join(ARTIFACTS_DIR, f"{device_name}_{RUN_TS}.csv")
    results_rows = []

    try:
        with open(per_device_artifact, 'w', encoding='utf-8') as outf:
            outf.write(f"==== Device: {device_name} ({host}) Run: {RUN_TS} ====\n")
            for cmd in command_list:
                if cmd.startswith("sleep"):
                    # Support "sleep N"
                    try:
                        delay = int(cmd.split()[1])
                    except Exception:
                        delay = 1
                    logging.info(f"[{device_name}] Sleeping for {delay} seconds")
                    time.sleep(delay)
                    continue

                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"[{device_name}] [{ts}] Executing: {cmd}")
                exit_status, out, err, elapsed = run_exec(client, cmd, read_timeout=60.0)

                # Log results
                if out.strip():
                    logging.info(f"[{device_name}] Output ({len(out)} bytes)")
                if err.strip():
                    logging.error(f"[{device_name}] Error: {err.strip()}")

                # Write to per-device text artifact
                outf.write(f"\n--- {ts} :: {cmd} ---\n")
                if out:
                    outf.write(out if out.endswith('\n') else out + '\n')
                if err:
                    outf.write(f"[stderr] {err if err.endswith('\n') else err + '\n'}")

                # Collect CSV row
                results_rows.append({
                    "timestamp": ts,
                    "device": device_name,
                    "host": host,
                    "command": cmd,
                    "exit_status": exit_status,
                    "duration_ms": int(elapsed * 1000),
                    "stdout_bytes": len(out),
                    "stderr_bytes": len(err)
                })
    finally:
        try:
            client.close()
        except Exception:
            pass
        logging.info(f"Disconnected from {device_name}")

    # Write CSV summary
    fieldnames = ["timestamp", "device", "host", "command", "exit_status", "duration_ms", "stdout_bytes", "stderr_bytes"]
    with open(results_csv, 'w', newline='', encoding='utf-8') as fcsv:
        writer = csv.DictWriter(fcsv, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results_rows)

    return {"device": device_name, "host": host, "status": "ok", "results_file": per_device_artifact, "csv": results_csv}


def run_all(devices: dict, commands: dict, max_workers: int = 4):
    futures = []
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for device_name, device_info in devices.items():
            cmd_list = commands.get(device_name, [])
            futures.append(pool.submit(execute_commands, device_name, device_info, cmd_list))
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as e:
                res = {"device": "unknown", "status": "failed", "reason": str(e), "results": []}
            results.append(res)

    # Save a run summary JSON
    summary_path = os.path.join(ARTIFACTS_DIR, f"run_summary_{RUN_TS}.json")
    with open(summary_path, 'w', encoding='utf-8') as js:
        json.dump(results, js, indent=2)
    logging.info(f"Run summary written to {summary_path}")
    return results

# ========= DIFF HELPERS (previous run comparison) =========

def _extract_run_ts_from_artifact(path: str) -> Optional[str]:
    """
    Extract run timestamp (YYYYMMDD_HHMMSS) from artifact filename.
    Expected pattern: <device>_<RUN_TS>.txt
    """
    m = re.search(r'_(\d{8}_\d{6})\.txt$', os.path.basename(path))
    return m.group(1) if m else None


def _preprocess_lines_for_diff(text: str) -> List[str]:
    """
    Normalize volatile values (timestamps, run tags) to reduce noisy diffs,
    then return splitlines().
    """
    # Replace per-command timestamps like "2025-09-18 15:02:15"
    text = re.sub(r'\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b', '<TS>', text)
    # Replace run tag timestamps like "20250918_150215"
    text = re.sub(r'\b\d{8}_\d{6}\b', '<RUN_TS>', text)
    # Optional: collapse CRs/ANSI just in case (safe_str already helps)
    text = text.replace('\r', '')
    return text.splitlines()


def _find_previous_artifact(device: str, current_artifact: str, artifacts_dir: str, current_run_ts: str
                           ) -> Tuple[Optional[str], Optional[str]]:
    """
    Among <device>_*.txt in artifacts_dir, pick the most recent file older than current_run_ts.
    Returns (previous_artifact_path, previous_run_ts)
    """
    pattern = os.path.join(artifacts_dir, f"{device}_*.txt")
    candidates = []
    for path in glob.glob(pattern):
        ts = _extract_run_ts_from_artifact(path)
        if ts and ts < current_run_ts and os.path.abspath(path) != os.path.abspath(current_artifact):
            candidates.append((ts, path))
    if not candidates:
        return None, None
    # lexicographically largest timestamp is the latest older file
    candidates.sort(key=lambda x: x[0])
    prev_ts, prev_path = candidates[-1]
    return prev_path, prev_ts


def diff_artifacts_against_previous_run(
    artifacts_dir: str = ARTIFACTS_DIR,
    run_ts: str = RUN_TS,
    device_names: Optional[List[str]] = None,
    normalize_timestamps: bool = True
) -> str:
    """
    For each device artifact from the current run, find the most recent prior artifact
    for the same device and write a unified diff to <device>_diff_<prev>_to_<current>.diff.
    Also writes an aggregated summary file: diff_summary_<RUN_TS>.txt
    Returns the path to the aggregated diff summary file.
    """
    if device_names is None:
        device_names = list(devices.keys())

    summary_path = os.path.join(artifacts_dir, f"diff_summary_{run_ts}.txt")
    with open(summary_path, 'w', encoding='utf-8') as summary:
        summary.write(f"==== Diff summary for run {run_ts} ====\n")

    for device in device_names:
        current_art = os.path.join(artifacts_dir, f"{device}_{run_ts}.txt")
        if not os.path.exists(current_art):
            logging.warning(f"[{device}] No current artifact found to diff: {current_art}")
            with open(summary_path, 'a', encoding='utf-8') as summary:
                summary.write(f"\n--- {device} ---\nNo current artifact found: {os.path.basename(current_art)}\n")
            continue

        prev_art, prev_ts = _find_previous_artifact(device, current_art, artifacts_dir, run_ts)
        if not prev_art:
            logging.info(f"[{device}] No previous artifact to diff against.")
            with open(summary_path, 'a', encoding='utf-8') as summary:
                summary.write(f"\n--- {device} ---\nNo previous artifact found.\n")
            continue

        # Read and preprocess (to reduce noise from timestamps)
        with open(prev_art, 'r', encoding='utf-8', errors='replace') as f_prev, \
             open(current_art, 'r', encoding='utf-8', errors='replace') as f_curr:
            if normalize_timestamps:
                prev_lines = _preprocess_lines_for_diff(f_prev.read())
                curr_lines = _preprocess_lines_for_diff(f_curr.read())
            else:
                prev_lines = f_prev.read().splitlines()
                curr_lines = f_curr.read().splitlines()

        diff_lines = list(difflib.unified_diff(
            prev_lines, curr_lines,
            fromfile=os.path.basename(prev_art),
            tofile=os.path.basename(current_art),
            lineterm=''
        ))

        if diff_lines:
            per_device_diff = os.path.join(
                artifacts_dir, f"{device}_diff_{prev_ts}_to_{run_ts}.diff"
            )
            with open(per_device_diff, 'w', encoding='utf-8') as df:
                df.write("\n".join(diff_lines) + "\n")
            logging.info(f"[{device}] Differences written to {per_device_diff}")

            with open(summary_path, 'a', encoding='utf-8') as summary:
                summary.write(
                    "\n".join([
                        f"\n--- {device} ---",
                        f"previous: {os.path.basename(prev_art)}",
                        f"current:  {os.path.basename(current_art)}",
                        ""
                    ] + diff_lines + [""])
                )
        else:
            logging.info(f"[{device}] No differences found.")
            with open(summary_path, 'a', encoding='utf-8') as summary:
                summary.write(
                    f"\n--- {device} ---\nNo differences between {os.path.basename(prev_art)} and {os.path.basename(current_art)}.\n"
                )

    logging.info(f"Diff summary written to {summary_path}")
    return summary_path


if __name__ == "__main__":
    # Kick off the run
    summary = run_all(devices, commands, max_workers=min(8, len(devices)))

    # Optional: print a quick summary to console
    ok = [r for r in summary if r.get("status") == "ok"]
    fail = [r for r in summary if r.get("status") != "ok"]
    logging.info(f"Completed. Success: {len(ok)} Failed: {len(fail)}")

    # NEW: write diffs against the previous run's artifacts (timestamp-normalized by default)
    diff_summary_path = diff_artifacts_against_previous_run()
    logging.info(f"Diffs completed. Summary: {diff_summary_path}")

