import os
import time
import json
import csv
import logging
import getpass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

# ========= CONFIG =========
LOG_DIR = 'logs'
ARTIFACTS_DIR = 'artifacts'
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

RUN_TS = datetime.now().strftime('%Y%m%d_%H%M%S')

# ========= SECURE CREDENTIAL PROMPT =========
DEVICE_USERNAME = input("Enter device username: ").strip()
DEVICE_PASSWORD = getpass.getpass("Enter device password: ").strip()

if not DEVICE_USERNAME or not DEVICE_PASSWORD:
    raise ValueError("Username and password must not be empty.")

# ========= DEVICE PROMPT =========
raw_devices = input(
    "Enter device hostnames (comma-separated): "
).strip()

if not raw_devices:
    raise ValueError("At least one device hostname must be provided.")

device_list = [d.strip() for d in raw_devices.split(",") if d.strip()]

if not device_list:
    raise ValueError("No valid device hostnames parsed.")

devices = {device: {"host": device} for device in device_list}

print("\nDevices selected:")
for d in devices:
    print(f" - {d}")
print()

# ========= LOGGING =========
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

# ========= COMMANDS =========
commands = {
    device: [
        "show vrf azprv",
        "show ip route vrf azprv",
        "show interface eth1/49.2011",
        "show interface po3.451",
        "show ip bgp vrf azprv summary",
        "show ip bgp vrf azprv"
        
    ]
    for device in devices
}

# ========= HELPERS =========
def safe_str(s: str) -> str:
    return (s or "").replace('\r', '').replace('\x1b', '')

def connect_ssh(host, port=22, timeout=15, banner_timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=DEVICE_USERNAME,
        password=DEVICE_PASSWORD,
        timeout=timeout,
        banner_timeout=banner_timeout,
        allow_agent=False,
        look_for_keys=False
    )
    return client

def run_exec(client: paramiko.SSHClient, cmd: str, read_timeout: float = 60.0):
    start = time.time()
    stdin, stdout, stderr = client.exec_command(cmd, timeout=read_timeout)
    stdout.channel.settimeout(read_timeout)
    stderr.channel.settimeout(read_timeout)

    try:
        out = stdout.read().decode(errors='replace')
    except Exception as e:
        out = f"[stdout read error: {e}]"

    try:
        err = stderr.read().decode(errors='replace')
    except Exception as e:
        err = f"[stderr read error: {e}]"

    try:
        exit_status = stdout.channel.recv_exit_status()
    except Exception:
        exit_status = -1

    elapsed = time.time() - start
    return exit_status, safe_str(out), safe_str(err), elapsed

def execute_commands(device_name: str, device_info: dict, command_list: list, max_retries: int = 2):
    host = device_info['host']
    port = device_info.get('port', 22)

    logging.info(f"Connecting to {device_name} ({host})")

    client = None
    attempt = 0
    last_exc = None

    while attempt <= max_retries:
        try:
            client = connect_ssh(host, port=port)
            break
        except Exception as e:
            last_exc = e
            attempt += 1
            logging.warning(f"[{device_name}] Connection attempt {attempt} failed: {e}")
            time.sleep(min(2 ** attempt, 10))

    if client is None:
        logging.error(f"[{device_name}] Failed to connect: {last_exc}")
        return {"device": device_name, "host": host, "status": "failed", "reason": str(last_exc)}

    artifact_txt = os.path.join(ARTIFACTS_DIR, f"{device_name}_{RUN_TS}.txt")
    artifact_csv = os.path.join(ARTIFACTS_DIR, f"{device_name}_{RUN_TS}.csv")

    rows = []

    try:
        with open(artifact_txt, 'w', encoding='utf-8') as outf:
            outf.write(f"==== Device: {device_name} ({host}) | Run: {RUN_TS} ====\n")

            for cmd in command_list:
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                logging.info(f"[{device_name}] Executing: {cmd}")

                exit_status, out, err, elapsed = run_exec(client, cmd)

                outf.write(f"\n--- {ts} :: {cmd} ---\n")
                if out:
                    outf.write(out + '\n')
                if err:
                    outf.write(f"[stderr] {err}\n")

                rows.append({
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
        client.close()
        logging.info(f"Disconnected from {device_name}")

    if rows:
        with open(artifact_csv, 'w', newline='', encoding='utf-8') as fcsv:
            writer = csv.DictWriter(fcsv, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    return {"device": device_name, "host": host, "status": "ok"}

def run_all(devices: dict, commands: dict, max_workers: int = 4):
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(execute_commands, d, info, commands[d]): d
            for d, info in devices.items()
        }

        for fut in as_completed(future_map):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({"device": future_map[fut], "status": "failed", "reason": str(e)})

    summary_path = os.path.join(ARTIFACTS_DIR, f"run_summary_{RUN_TS}.json")
    with open(summary_path, 'w', encoding='utf-8') as js:
        json.dump(results, js, indent=2)

    logging.info(f"Run summary written to {summary_path}")
    return results

# ========= MAIN =========
if __name__ == "__main__":
    summary = run_all(devices, commands, max_workers=len(devices))

    ok = [r for r in summary if r.get("status") == "ok"]
    fail = [r for r in summary if r.get("status") != "ok"]

    logging.info(f"Completed. Success: {len(ok)} | Failed: {len(fail)}")

    DEVICE_PASSWORD = None  # clear from memory