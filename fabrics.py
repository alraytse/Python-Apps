import requests

import getpass

import urllib3
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
def get_auth_token(hostname, username, password):

    url = f"https://{hostname}/login"

    payload = {"userName": username, "userPasswd": password}

    headers = {"Content-Type": "application/json"}
 
    try:

        response = requests.post(url, json=payload, headers=headers, verify=False)

        response.raise_for_status()

        token = response.headers.get("Dcnm-Token")

        if token:

            return token

        else:

            raise Exception("Token not found in response.")

    except Exception as e:

        print(f"❌ Authentication failed: {e}")

        return None
 
def get_fabrics(hostname, token):

    url = f"https://{hostname}/appcenter/cisco/ndfc/api/v1/fabrics"

    headers = {

        "Content-Type": "application/json",

        "Dcnm-Token": token

    }
 
    try:

        response = requests.get(url, headers=headers, verify=False)

        response.raise_for_status()

        fabrics = response.json()

        print("✅ Fabrics Retrieved:\n")

        for fabric in fabrics:

            print(f"- {fabric['fabricName']} (type: {fabric['fabricTechnology']})")

    except Exception as e:

        print(f"❌ Failed to get fabrics: {e}")
 
def main():

    hostname = input("Enter DCNM/NDFC hostname or IP: ").strip()

    username = input("Enter your username: ").strip()

    password = getpass.getpass("Enter your password: ").strip()
 
    token = get_auth_token(hostname, username, password)

    if token:

        get_fabrics(hostname, token)
 
if __name__ == "__main__":

    main()

 