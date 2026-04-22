import subprocess
import platform
from tqdm import tqdm
from datetime import datetime
import ipaddress

def sweep_ping(cidr):
    # Parse CIDR into a network object
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print("Invalid CIDR format. Example: 192.168.1.0/24")
        return

    log_file = "sweep_log.txt"

    # Start log file
    with open(log_file, "w") as f:
        f.write(f"Sweep started on {cidr} at {datetime.now()}\n\n")

    print(f"\nStarting sweep on {cidr}\n")

    # Detect OS ping parameter
    param = "-n" if platform.system().lower() == "windows" else "-c"

    # Open log file once for efficiency
    with open(log_file, "a") as f:
        # Iterate through usable hosts only (skips network & broadcast)
        for ip in tqdm(network.hosts(), desc="Pinging hosts", unit="host"):
            ip_str = str(ip)

            result = subprocess.run(
                ["ping", param, "1", ip_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            status = "SUCCESS" if result.returncode == 0 else "FAILURE"

            # Print alive hosts to screen
            if status == "SUCCESS":
                print(f"[+] Host alive: {ip_str}")

            # Log to file
            f.write(f"{datetime.now()} - {ip_str} - {status}\n")

        f.write(f"\nSweep completed at {datetime.now()}\n")

    print(f"\nDone! Full results written to {log_file}")

if __name__ == "__main__":
    cidr = input("Enter CIDR to sweep (example: 192.168.1.0/24): ").strip()
    sweep_ping(cidr)
