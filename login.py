#!/usr/bin/env python3

"""
Purpose: to serve as an example on how to query the login endpoint for session
resuse

Input: URL, cluster username, and password

Returns: sessionID cookie

Dependency: Requests library. See: https://docs.python-requests.org/en/latest/user/install/#install

Note: Before running, provide the path to your certificate chain or set the
request argument to verify=False. However, with this setting you maybe subject
to a man-in-the-middle attack. Please only use for local
development or testing.
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
print('Logging in...')
response = requests.request("POST", url + 'rest/v1/login', headers=headers, data=payload,
        verify='path/to/cert')
print('Response: ', response.text)
print('Cookies: ', response.cookies)

#logout request header reusing cookie
headers_cookie = {
        'Cookie': 'sessionID={0}'.format(response.cookies.get('sessionID'))
}

print('Logging out...')
logout = requests.request("POST", url + 'rest/v1/logout', headers=headers_cookie, verify='path/to/cert')
print('Status code: ', logout.status_code)

print('Clearing Cookie Jar...\n')
requests.cookies.RequestsCookieJar.clear(response.cookies)
requests.cookies.RequestsCookieJar.clear(logout.cookies)

# Create session object
print('Create Requests session this time...')
s = requests.Session()
s.verify = 'path/to/cert'

#login request but now using session object
r = s.request("POST", url + 'rest/v1/login', headers=headers, data=payload)
print('Response: ', r.text)
print('New cookie: ', r.cookies)

# reusing cookie without authorization header
s.request("GET", url + 'rest/v1/ping')
print('Reusing cookie: ', s.cookies)

# log out and destory current session cookie
print('Logging out once more...')
s.request("POST", url + 'rest/v1/logout')

