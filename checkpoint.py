import paramiko
import getpass
import logging

import logging

# Configure logging
logging.basicConfig(
    filename='checkpoint_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def ssh_and_checkpoint(hostname, eid, password, change_number):
    try:
        print(f"🔗 Connecting to {hostname}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=eid, password=password, timeout=10)

        checkpoint_cmd = f"checkpoint b4_{change_number}"
        stdin, stdout, stderr = ssh.exec_command(checkpoint_cmd)

        output = stdout.read().decode()
        error = stderr.read().decode()

        if output:
            print(f"✅ Output from {hostname}:\n{output}")
        if error:
            print(f"⚠️ Error from {hostname}:\n{error}")

        ssh.close()
    except Exception as e:
        print(f"❌ Failed to connect to {hostname}: {e}")

def main():
    # Prompt for hostnames
    host_input = input("🔧 Enter switch hostnames (comma-separated): ").strip()
    hostnames = [host.strip() for host in host_input.split(",") if host.strip()]

    # Prompt for credentials
    eid = input("👤 Enter your EID: ").strip()
    password = getpass.getpass("🔐 Enter your password: ")

    # Prompt for change number
    change_number = input("📄 Enter the change number: ").strip()

    # SSH and run checkpoint
    for host in hostnames:
        ssh_and_checkpoint(host, eid, password, change_number)

if __name__ == "__main__":
    main()
