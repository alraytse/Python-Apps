import re
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def extract_ips_from_file(filename):
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b')
    ips = []
    try:
        with open(filename.strip(), 'r') as file:
            for line in file:
                ips.extend(ipv4_pattern.findall(line))
                ips.extend(ipv6_pattern.findall(line))
    except FileNotFoundError:
        print(f"File not found: {filename}")
    return ips

def ping_ip(ip, retries=3):
    for attempt in range(1, retries + 1):
        try:
            ping_cmd = ['ping', '-c', '10', ip] if ':' not in ip else ['ping6', '-c', '10', ip]
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                return ip, "Success", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                time.sleep(1)
        except Exception as e:
            return ip, f"Error: {str(e)}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return ip, "Failure", datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    file_input = input("Enter file names separated by commas: ")
    file_list = file_input.split(',')

    all_ips = []
    for file_name in file_list:
        all_ips.extend(extract_ips_from_file(file_name))

    all_ips = list(set(all_ips))  # Remove duplicates

    print(f"🔍 Starting parallel ping for {len(all_ips)} IPs...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(ping_ip, ip) for ip in all_ips]
        with open('ip.csv', 'w') as output_file:
            output_file.write("Timestamp,IP Address,Status\n")
            for future in tqdm(as_completed(futures), total=len(futures), desc="Pinging IPs"):
                ip, status, timestamp = future.result()
                output_file.write(f"{timestamp},{ip},{status}\n")

    print(f"✅ Ping results saved to ip.csv.")

if __name__ == "__main__":
    main()
