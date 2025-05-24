import requests
import json
import urllib3
import time

# Use this to supppress certificate warnings. In production environments makes sure to create a DNS reccord and uppload a certificate that matches to the cluster.
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# all requests below have 'verify=False' added to it. If your system has proper certificates installed remove False and replace it with
# your certificate path.


api_login = 'https://172.16.0.246/rest/v1/login'

# creating the bodies and headers we need
api_headers = {
    'Content-Type': 'application/json'
    }

login_payload = json.dumps({
    "username": "demo",
    "password": "apidemo",
    "useOIDC": False
    })

# logging in
login_response = requests.request("POST",
                                  api_login,
                                  headers=api_headers,
                                  data=login_payload,
                                  verify=False
                                  )

# update api_headers to include the cookie with the sessionID in it
api_headers['Cookie'] = 'sessionID={0}'.format(
    login_response.cookies.get('sessionID'))

# Show the updated api headers
print(api_headers)

# set the endpoint for taking a snapshot and the vm that we want to snap
# the script 
api_snapshot = 'https://172.16.0.246/rest/v1/VirDomainSnapshot/'
vm_to_snap = "01234567-89ab-cdef-0123-456789abcdef"               # This should match the UUID you want to make a snapshot of

# create the snapshot payload. read the above vm_to_snap variable into a JSON string, including a label to apply.
# This body can include more info, such as when to delete the snapshot. Refer to the API documentation for this.
snapshot_payload = json.dumps({
    "domainUUID": vm_to_snap,
    "label": "SC Platform 2025"
})

# perform the snapshot and store the response in a varable
snapshot_response = json.loads(requests.request("POST",
                                                api_snapshot,
                                                headers=api_headers,
                                                data=snapshot_payload,
                                                verify=False)
                                                .text)

# write the response to the console
print(snapshot_response)

# do not forget to logout. this is very important
logout_response = requests.request("POST",
                                   "https://172.16.0.246/rest/v1/logout",
                                   headers=api_headers,
                                   verify=False
)

print(logout_response)
