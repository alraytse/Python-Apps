import csv
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reverse_lookup(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.rstrip('.').lower()
    except Exception:
        return None

def main(input_csv, output_file="dns_out.txt", workers=64):
    # Read IPs from CSV and deduplicate
    with open(input_csv, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        ips = []
        seen = set()
        for row in reader:
            for cell in row:
                ip = cell.strip()
                if ip and ip not in seen and is_valid_ip(ip):
                    seen.add(ip)
                    ips.append(ip)

    seen_fqdns = set()
    with open(output_file, "w", encoding="utf-8") as out:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(reverse_lookup, ip): ip for ip in ips}
            for future in tqdm(as_completed(futures), total=len(futures), desc="🔍 Resolving", unit="IP"):
                fqdn = future.result()
                if fqdn and fqdn not in seen_fqdns:
                    out.write(f"{fqdn}\n")
                    seen_fqdns.add(fqdn)

    print(f"✅ Done! FQDNs saved to {output_file}")

if __name__ == "__main__":
    input_csv = input("📄 Enter the path to the CSV file with IP addresses: ").strip()
    main(input_csv)
