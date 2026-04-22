import requests
import getpass

def login_to_nexus_dashboard_tacacs():
    # Prompt for inputs
    nd_ip = input("Enter Nexus Dashboard IP or FQDN: ")
    username = input("Enter TACACS username: ")
    password = getpass.getpass("Enter TACACS password: ")

    # Login URL for Nexus Dashboard
    login_url = f"https://{nd_ip}/api/v1/auth/login"

    payload = {
        "userName": username,
        "userPasswd": password
    }

    headers = {
        "Content-Type": "application/json"
    }

    # Disable SSL warnings for self-signed certs (use verify=True for production)
    requests.packages.urllib3.disable_warnings()

    try:
        response = requests.post(login_url, json=payload, headers=headers, verify=False, timeout=20)
        response.raise_for_status()

        if 'token' in response.json():
            token = response.json()['token']
            print("\n✅ TACACS login successful.")
            print(f"Your JWT Token: {token}")
            return token
        else:
            print("\n⚠️ Login failed. No token received.")
            print(response.json())

    except requests.exceptions.RequestException as err:
        print(f"\n❌ Error during login: {err}")

# Run the function
login_to_nexus_dashboard_tacacs()
