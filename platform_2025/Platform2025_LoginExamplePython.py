import requests
import json
import urllib3

# Suppress only the single warning from urllib3.
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

api_login = 'https://172.16.0.246/rest/v1/login'

api_headers = {
    'Content-Type': 'application/json'
    }

login_payload = json.dumps({
    "username": "demo",
    "password": "apidemo",
    "useOIDC": False
    })

login_response = requests.request("POST",
                                  api_login,
                                  headers=api_headers,
                                  data=login_payload,
                                  verify=False
                                  )

api_headers['Cookie'] = 'sessionID={0}'.format(
    login_response.cookies.get('sessionID'))

print(api_headers)

logout_response = requests.request("POST",
                                   "https://172.16.0.246/rest/v1/logout",
                                   headers=api_headers,
                                   verify=False
)
print(logout_response)
