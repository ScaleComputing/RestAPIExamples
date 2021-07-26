#!/usr/bin/env python3

"""
Purpose: to demonstrate how to login to a cluster via REST API.

Input: URL, cluster username, and password

Returns: sessiondID cookie

Note: 
"""

import requests
import json
import base64

#prompt for url and provide example
print("Please provide the URL..")
url = input("Example: https://cluster.domain.internal/rest/v1/login \n")

#prompt for username and password
username = input("Username: ")
password = input("Password: ")

#base64 encode and format for header
encoded = str(base64.b64encode(bytes('{0}:{1}'.format(username, password), 'utf-8')), 'utf-8')
auth = str.format('Basic ' + encoded)

# request body and headers
payload = json.dumps({
  "username": username,
  "password": password,
  "useOIDC": False
})
headers = {
  'content': 'application/json',
  'Authorization': auth,
  'Content-Type': 'application/json'
}

#login request
response = requests.request("POST", url, headers=headers, data=payload, verify='cert-bundle.crt')

print(response.text)

