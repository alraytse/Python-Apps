import subprocess
import csv
import os

def get_hostnames_from_ips(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            for ip in row:
                ip = ip.strip()
                if ip:
                    try:
                        result = subprocess.run(['nslookup', ip], capture_output=True, text=True)
                        print(f"\nLookup for IP: {ip}")
                        print(result.stdout)
                    except Exception as e:
                        print(f"Error looking up {ip}: {e}")

if __name__ == "__main__":
    file_path = input("Enter the path to the CSV file with IP addresses: ").strip()
    get_hostnames_from_ips(file_path)

