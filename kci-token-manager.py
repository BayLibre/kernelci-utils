#!/usr/bin/env python2

import sys
import requests
import json
import argparse

def print_error_msg(status_code):
    print 'Error in request, return code: {}'.format(status_code)


def get_token_from_oid(oid):
    url = BACKEND_URL + "/token"
    payload = {
        "_id": oid,
    }
    response = requests.get(url, headers=headers, params=payload)
    if response.status_code != 200:
        print_error_msg(response.status_code)
    token_entry = response.json()
    return token_entry["result"][0]["token"]


def kci_show_all_tokens():
    url = BACKEND_URL + "/token"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print_error_msg(response.status_code)
        return
    token_list = response.json()
    for token_entry in token_list["result"]:
        print '{0:30} {1:10}'.format(token_entry["username"], token_entry["token"])
        # print(str(token_entry["username"]) + ": \t" + str(token_entry["token"]))
        # print(json.dumps(rjson, indent=4))


def kci_show_labs():
    url = BACKEND_URL + "/lab"
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print_error_msg(response.status_code)
        return
    lab_list = response.json()
    for lab_entry in lab_list["result"]:
        token_value = get_token_from_oid(lab_entry["token"]["$oid"])
        print '{0:30} {1:} ({2:})'.format(lab_entry["name"],
                                          token_value,
                                          lab_entry["contact"]["email"])


def kci_add_lab_token():
    print("Adding a lab token, be careful no typo allowed")
    lab_name = raw_input("Lab name: ")
    lab_mail = raw_input("Lab mail: ")
    print "Adding lab {}({})".format(lab_name, lab_mail)
    payload = {
        "name": lab_name, "contact": {
            "name": lab_mail, "surname": lab_mail, "email": lab_mail
        }
    }
    url = BACKEND_URL + "/lab"
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        print_error_msg(response.status_code)
        print response
    print(response.json())

def kci_create_new_token():
    print("Creating a new token- please answer.")
    token_email = raw_input("Email: ").lower()
    token_username = raw_input("Username: ").lower()
    
    admin_token = True if (raw_input("Admin token - it automatically sets GET/DELETE/POST/PUT operations ? y/[N] ").lower() or "N")[0] == "y" else False
    if (not admin_token):
        superuser_token = True if (raw_input("Superuser token - a super user cannot create new tokens, but can perform GET/DELETE/POST/PUT operations ? y/[N] ").lower() or "N")[0] == "y" else False
    if (not admin_token) and (not superuser_token):
        get_token = True if (raw_input("GET token - If the token can perform GET operations ? y/[N] ").lower() or "N")[0] == "y" else False
        post_token = True if (raw_input("POST token - If the token can perform POST/PUT operations ? y/[N] ").lower() or "N")[0] == "y" else False
        delete_token = True if (raw_input("DELETE token - If the token can perform DELETE operations ? y/[N] ").lower() or "N")[0] == "y" else False
    else:
        get_token = True
        post_token = True
        delete_token = True
    upload_token = True if (raw_input("UPLOAD token - If the token can be used to upload files ? y/[N] ").lower() or "N")[0] == "y" else False
    
    ip_restricted = True if (raw_input("IP restricted - If the token is restricted to be used on certain IP addresses ? y/[N] ").lower() or "N")[0] == "y" else False
    if ip_restricted:
        ip_address = []
        ip_address.append(raw_input("IP address: ").lower())

    lab_token = True if (raw_input("Lab token - If the token is a boot lab one ? y/[N] ").lower() or "N")[0] == "y" else False
    test_lab_token = True if (raw_input("Test Lab token - If the token is a test lab one ? y/[N] ").lower() or "N")[0] == "y" else False

    if ip_restricted:
        payload = {
            "email": token_email,
            "username": token_username,
            "admin": admin_token,
            "superuser": superuser_token,
            "get": get_token,
            "post": post_token,
            "delete": delete_token,
            "upload": upload_token,
            "lab": lab_token,
            "test_lab": test_lab_token,
            "ip_restricted": ip_restricted,
            "ip_address": ip_address
        }
    else:
        payload = {
            "email": token_email,
            "username": token_username,
            "admin": admin_token,
            "superuser": superuser_token,
            "get": get_token,
            "post": post_token,
            "delete": delete_token,
            "upload": upload_token,
            "lab": lab_token,
            "test_lab": test_lab_token,
        }
    url = BACKEND_URL + "/token"
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code != 201:
        print_error_msg(response.status_code)
        print response
    print(response.json())

def parse_cmdline():
    parser = argparse.ArgumentParser(description="KernelCI Database token manager",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", action="version", version="%(prog)s 0.1")
    parser.add_argument("--list-tokens", "-l", help="list tokens",
                        action="store_true")
    parser.add_argument("--list-labs", help="list labs",
                        action="store_true")
    parser.add_argument("--add-lab", help="add lab token",
                        action="store_true")
    parser.add_argument('--url', action='store', dest='BACKEND_URL',
                        help="The backend url to manage the tokens from.",
                        required=True)
    parser.add_argument('--token', action='store', dest='TOKEN',
                        help="The token associated to the backend (must be an admin token).",
                        required=True)
    parser.add_argument('--add-token', action='store_true',
                        help="Create a new token. The information needed will be asked interactively.")
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_cmdline()

    headers = {
        "Authorization": args.TOKEN
    }
    BACKEND_URL = args.BACKEND_URL

    if args.list_tokens:
        kci_show_all_tokens()
    if args.list_labs:
        kci_show_labs()
    if args.add_lab:
        kci_add_lab_token()
    if args.add_token:
        kci_create_new_token()
sys.exit(0)
