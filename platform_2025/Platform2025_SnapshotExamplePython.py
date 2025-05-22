import requests
import json
import urllib3
import time

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

api_snapshot = 'https://172.16.0.246/rest/v1/VirDomainSnapshot/'
vm_to_snap = "cb2c84c3-b5fd-4612-b903-65073f108bce"

snapshot_payload = json.dumps({
    "domainUUID": vm_to_snap,
    "label": "SC Platform 2025"
})
snapshot_response = json.loads(requests.request("POST",
                                                api_snapshot,
                                                headers=api_headers,
                                                data=snapshot_payload,
                                                verify=False)
                                                .text)

print(snapshot_response)

logout_response = requests.request("POST",
                                   "https://172.16.0.246/rest/v1/logout",
                                   headers=api_headers,
                                   verify=False
)

print(logout_response)
