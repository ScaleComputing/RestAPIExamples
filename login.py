#!/usr/bin/env python3

"""
Purpose: to serve as an example on how to query the login endpoint for session
resuse

Input: URL, cluster username, and password

Returns: sessiondID cookie

Note: Before running, provide the path to your certificate chain or set the
request argument to verify=False. However, with this setting you maybe subject
to a man-in-the-middle attack. Please only use for local
development or testing
"""

import requests
import json
import base64

#prompt for url and provide example
print("Please provide the URL..")
url = input("Example: https://cluster.domain.internal/ \n")

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
  'Authorization': auth,
  'Content-Type': 'application/json'
}

#login request
response = requests.request("POST", url + 'rest/v1/login', headers=headers, data=payload,
        verify=False)

print('Response: ', response.text)
print('Cookies: ', response.cookies)

# Create session object
s = requests.Session()

#login request but now using session object
s.request("POST", url + 'rest/v1/login', headers=headers, data=payload, verify=False)
print('New cookie: ', s.cookies)

# reusing cookie
s.request("GET", url + 'rest/v1/ping', headers=headers)
print('Reusing cookie: ', s.cookies)

# log out and destory current session cookie
s.request("POST", url + 'rest/v1/logout', headers=headers)
