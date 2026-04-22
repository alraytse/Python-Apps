import platform
import subprocess
import ipaddress

def ping_host(ip):
    # Pick the right parameters for Windows or Linux/macOS
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_val = "1"

    result = subprocess.run(
        ["ping", count_flag, "1", timeout_flag, timeout_val, str(ip)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.returncode == 0

def sweep_network():
    # Ask the user for input
    network_input = input("Enter network in CIDR (e.g., 192.168.1.0/24): ").strip()
    try:
        net = ipaddress.ip_network(network_input, strict=False)
    except ValueError:
        print("Invalid network format.")
        return

    print(f"🔍 Scanning {net}...\n")
    for host in net.hosts():
        if ping_host(host):
            print(f"[+] Host {host} is up")
        else:
            print(f"[-] Host {host} is down")

if __name__ == "__main__":
    sweep_network()
