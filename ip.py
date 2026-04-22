import re
import subprocess

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

def ping_ip(ip):
    try:
        # Use ping for IPv4 and IPv6 appropriately
        ping_cmd = ['ping', '-c', '10', ip] if ':' not in ip else ['ping6', '-c', '10', ip]
        result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return "Success" if result.returncode == 0 else "Failure"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    file_input = input("Enter file names separated by commas: ")
    file_list = file_input.split(',')
    print("Please Note: extracting correct IP addresses will take sometime")
    all_ips = []
    for file_name in file_list:
        all_ips.extend(extract_ips_from_file(file_name))

    with open('ip.csv', 'w') as output_file:
        output_file.write("IP Address,Status\n")
        for ip in all_ips:
            status = ping_ip(ip)
            output_file.write(f"{ip},{status}\n")

    print(f"Ping results for {len(all_ips)} IP addresses saved to ip.csv.")

if __name__ == "__main__":
    main()

