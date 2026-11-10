#!/usr/bin/env python3

"""
Infoblox Lookup Tool

Features
--------
- Prompt for Grid Manager hostname/IP
- Prompt for WAPI version
- Prompt for EID/password
- List all IPv4 networks
- Search IP address
- Search subnet (exact or partial)
- Export networks to CSV
- Detailed API error reporting

Requirements
------------
pip install requests
"""

import csv
import getpass
import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(
    InsecureRequestWarning
)


def api_get(url, eid, password):

    response = requests.get(
        url,
        auth=HTTPBasicAuth(eid, password),
        verify=False,
        timeout=60
    )

    if response.status_code not in [200, 201]:

        print("\n" + "=" * 80)
        print("API ERROR")
        print("=" * 80)
        print(f"URL: {url}")
        print(f"Status Code: {response.status_code}")
        print(f"Response:\n{response.text}")
        print("=" * 80)

        response.raise_for_status()

    return response.json()


def get_networks(gridmaster, eid, password, wapi_version):

    url = (
        f"https://{gridmaster}"
        f"/wapi/{wapi_version}/network"
        f"?_max_results=10000"
    )

    return api_get(
        url,
        eid,
        password
    )


def search_ip(
    gridmaster,
    eid,
    password,
    wapi_version,
    ip
):

    url = (
        f"https://{gridmaster}"
        f"/wapi/{wapi_version}/ipv4address"
        f"?ip_address={ip}"
        f"&_return_fields="
        f"ip_address,names,network,"
        f"mac_address,status"
    )

    return api_get(
        url,
        eid,
        password
    )


def search_subnet(
    gridmaster,
    eid,
    password,
    wapi_version,
    subnet
):

    subnet = subnet.strip()

    networks = get_networks(
        gridmaster,
        eid,
        password,
        wapi_version
    )

    matches = []

    for network in networks:

        network_cidr = network.get(
            "network",
            ""
        )

        if subnet.lower() in network_cidr.lower():
            matches.append(network)

    return matches


def display_networks(networks):

    if not networks:
        print("\nNo matching networks found.")
        return

    print("\n" + "=" * 140)

    print(
        f"{'Subnet':<25}"
        f"{'Network View':<25}"
        f"{'Comment':<80}"
    )

    print("=" * 140)

    for network in networks:

        subnet = network.get(
            "network",
            ""
        )

        network_view = network.get(
            "network_view",
            ""
        )

        comment = network.get(
            "comment",
            ""
        )

        print(
            f"{subnet:<25}"
            f"{network_view:<25}"
            f"{comment[:80]:<80}"
        )

    print("=" * 140)
    print(f"Total Networks: {len(networks)}")


def display_ip_results(results):

    if not results:
        print("\nNo matching IP found.")
        return

    print("\n" + "=" * 140)

    print(
        f"{'IP Address':<18}"
        f"{'Hostname':<40}"
        f"{'Network':<25}"
        f"{'MAC Address':<20}"
        f"{'Status':<15}"
    )

    print("=" * 140)

    for item in results:

        hostname = ",".join(
            item.get("names", [])
        )

        print(
            f"{item.get('ip_address',''):<18}"
            f"{hostname[:40]:<40}"
            f"{item.get('network',''):<25}"
            f"{item.get('mac_address',''):<20}"
            f"{item.get('status',''):<15}"
        )

    print("=" * 140)


def export_networks_csv(networks):

    filename = "infoblox_networks.csv"

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow(
            [
                "Subnet",
                "Network View",
                "Comment"
            ]
        )

        for network in networks:

            writer.writerow(
                [
                    network.get(
                        "network",
                        ""
                    ),
                    network.get(
                        "network_view",
                        ""
                    ),
                    network.get(
                        "comment",
                        ""
                    )
                ]
            )

    print(f"\nCSV written: {filename}")


def main():

    print("\nInfoblox Lookup Tool")
    print("=" * 60)

    gridmaster = input(
        "\nGrid Manager Hostname/IP: "
    ).strip()

    wapi_version = input(
        "WAPI Version [v2.13]: "
    ).strip()

    if not wapi_version:
        wapi_version = "v2.13"

    eid = input(
        "EID: "
    ).strip()

    password = getpass.getpass(
        "Password: "
    )

    while True:

        print("\nOptions")
        print("-" * 60)
        print("1 - List All Networks")
        print("2 - Search IP Address")
        print("3 - Search Subnet")
        print("4 - Export All Networks to CSV")
        print("5 - Exit")

        choice = input(
            "\nSelect option: "
        ).strip()

        try:

            if choice == "1":

                networks = get_networks(
                    gridmaster,
                    eid,
                    password,
                    wapi_version
                )

                display_networks(
                    networks
                )

            elif choice == "2":

                ip = input(
                    "\nIP Address: "
                ).strip()

                results = search_ip(
                    gridmaster,
                    eid,
                    password,
                    wapi_version,
                    ip
                )

                display_ip_results(
                    results
                )

            elif choice == "3":

                subnet = input(
                    "\nSubnet Search: "
                ).strip()

                results = search_subnet(
                    gridmaster,
                    eid,
                    password,
                    wapi_version,
                    subnet
                )

                display_networks(
                    results
                )

            elif choice == "4":

                networks = get_networks(
                    gridmaster,
                    eid,
                    password,
                    wapi_version
                )

                export_networks_csv(
                    networks
                )

            elif choice == "5":

                print("\nExiting.")
                break

            else:

                print(
                    "\nInvalid selection."
                )

        except requests.exceptions.HTTPError as exc:

            print(
                f"\nHTTP Error: {exc}"
            )

        except requests.exceptions.ConnectionError:

            print(
                "\nConnection Error: "
                "Unable to reach Grid Manager."
            )

        except requests.exceptions.Timeout:

            print(
                "\nConnection timed out."
            )

        except Exception as exc:

            print(
                f"\nUnexpected Error: {exc}"
            )


if __name__ == "__main__":
    main()