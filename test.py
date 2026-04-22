import os
import time
import json
import csv
import logging
import getpass
import shutil
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko

# ========= RUN MODE =========
RUN_MODE = input("Run mode (pre/post): ").strip().lower()
if RUN_MODE not in {"pre", "post"}:
    raise ValueError("Run mode must be 'pre' or 'post'")

RUN_TS = datetime.now().strftime('%Y%m%d_%H%M%S')

# ========= DIRECTORIES =========
LOG_DIR = 'logs'
BASE_ARTIFACTS_DIR = 'artifacts'
ARTIFACTS_DIR = os.path.join(BASE_ARTIFACTS_DIR, RUN_MODE)

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

# ========= CREDENTIALS =========
DEVICE_USERNAME = input("Enter device username: ").strip()
DEVICE_PASSWORD = getpass.getpass("Enter device password: ").strip()

if not DEVICE_USERNAME or not DEVICE_PASSWORD:
    raise ValueError("Username and password must not be empty.")

# ========= DEVICES =========
raw_devices = input("Enter device hostnames (comma-separated): ").strip()
if not raw_devices:
    raise ValueError("At least one device hostname must be provided.")

device_list = [d.strip() for d in raw_devices.split(",") if d.strip()]
devices = {device: {"host": device} for device in device_list}

# ========= LOGGING =========
log_path = os.path.join(LOG_DIR, f'validation_{RUN_MODE}_{RUN_TS}.log')
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger()
if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console)

# ========= START STATUS =========
logging.info("=" * 72)
logging.info("SCRIPT STARTED")
logging.info(f"Run mode        : {RUN_MODE.upper()}")
logging.info(f"Run timestamp   : {RUN_TS}")
logging.info(f"Devices total   : {len(devices)}")
logging.info("Script is running — device outputs are being collected and logged")
logging.info("=" * 72)
print("\n>>> Script is running. Outputs are being logged. Do NOT interrupt.\n")

# ========= COMMANDS =========
commands = {
    device: [
        "terminal length 0",
        "show clock",
        "show version",
        "show ip route summary",
        "show ip route summary vrf all",
        "show ip bgp summary",
        "show interface status",
        "show ip interface brief",
        "show ip interface brief vrf all",
        "show interface description",
        "show route-map",
        "show ip prefix-list",
        "show logging last 50",
        "show ip route vrf all",
        "show ip bgp vrf all"
    ]
    for device in devices
}

# ========= HELPERS =========
def safe_str(s: str) -> str:
    return (s or "").replace("\r", "").replace("\x1b", "")

def connect_ssh(host, timeout=15):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        username=DEVICE_USERNAME,
        password=DEVICE_PASSWORD,
        timeout=timeout,
        allow_agent=False,
        look_for_keys=False
    )
    return client

def run_exec(client, cmd, read_timeout=60):
    start = time.time()
    stdin, stdout, stderr = client.exec_command(cmd, timeout=read_timeout)
    stdout.channel.settimeout(read_timeout)

    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")

    try:
        status = stdout.channel.recv_exit_status()
    except Exception:
        status = -1

    return status, safe_str(out), safe_str(err), time.time() - start

# ========= PRE → POST COPY =========
def copy_pre_artifacts_if_post():
    if RUN_MODE != "post":
        return

    pre_dir = os.path.join(BASE_ARTIFACTS_DIR, "pre")
    if not os.path.isdir(pre_dir):
        raise FileNotFoundError("PRE artifacts not found — run PRE first.")

    logging.info("POST run detected — copying PRE artifacts as-is")
    for fname in os.listdir(pre_dir):
        if fname.endswith(".txt"):
            shutil.copy2(
                os.path.join(pre_dir, fname),
                os.path.join(ARTIFACTS_DIR, f"PRE_COPY_{fname}")
            )
            logging.info(f"Copied PRE artifact: {fname}")

# ========= EXECUTION =========
def execute_commands(device, info, command_list, index, total):
    device_start = time.time()
    host = info["host"]

    logging.info(f"[{index}/{total}] {device} — connecting")
    client = connect_ssh(host)

    artifact_txt = os.path.join(ARTIFACTS_DIR, f"{device}_{RUN_TS}.txt")
    artifact_csv = os.path.join(ARTIFACTS_DIR, f"{device}_{RUN_TS}.csv")

    logging.info(f"[{device}] Writing output to {artifact_txt}")

    rows = []

    try:
        with open(artifact_txt, "w", encoding="utf-8") as outf:
            outf.write(f"==== {RUN_MODE.upper()} | {device} | {RUN_TS} ====\n")

            for i, cmd in enumerate(command_list, 1):
                logging.info(f"[{device}] Command {i}/{len(command_list)}: {cmd}")
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                status, out, err, elapsed = run_exec(client, cmd)

                outf.write(f"\n--- {ts} :: {cmd} ---\n{out}\n")

                rows.append({
                    "timestamp": ts,
                    "device": device,
                    "command": cmd,
                    "exit_status": status,
                    "duration_ms": int(elapsed * 1000)
                })
    finally:
        client.close()

    with open(artifact_csv, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    elapsed = time.time() - device_start
    logging.info(f"[{device}] Completed in {elapsed:.1f}s")

    return {"device": device, "status": "ok", "duration_sec": round(elapsed, 1)}

# ========= RUN ALL =========
def run_all():
    results = []
    total = len(devices)

    with ThreadPoolExecutor(max_workers=total) as pool:
        futures = {
            pool.submit(execute_commands, d, devices[d], commands[d], i + 1, total): d
            for i, d in enumerate(devices)
        }

        for fut in as_completed(futures):
            results.append(fut.result())

    summary_path = os.path.join(ARTIFACTS_DIR, f"run_summary_{RUN_TS}.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logging.info(f"Summary written to {summary_path}")
    return results

# ========= MAIN =========
if __name__ == "__main__":
    copy_pre_artifacts_if_post()
    summary = run_all()

    ok = len([r for r in summary if r["status"] == "ok"])

    logging.info("=" * 72)
    logging.info("SCRIPT COMPLETED")
    logging.info(f"Devices successful : {ok}/{len(devices)}")
    logging.info(f"Artifacts directory: {ARTIFACTS_DIR}")
    logging.info("=" * 72)

    print("\n>>> Script completed successfully.\n")
    DEVICE_PASSWORD = None