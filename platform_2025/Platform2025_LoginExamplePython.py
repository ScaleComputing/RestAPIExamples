import requests
import json
import urllib3

# Use the below to suppress certificate warnings. This requires urllib3 to be imported
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# the api endpoint we want to log in to.
api_login = 'https://IP_OR_FQDN_OF_CLUSTER/rest/v1/login' # can also have the IP of the cluster as a variable of course

# make sure the API knows it can expect JSON information
api_headers = {
    'Content-Type': 'application/json'
    }

# Create the payload for the login in JSON format. This requires the json libraties to be imported
login_payload = json.dumps({
    "username": "YOUR_USERNAME",
    "password": "YOUR_PASSWORD",
    "useOIDC": False
    })

# Store the login response in a variable login_response
login_response = requests.request("POST",
                                  api_login,
                                  headers=api_headers,
                                  data=login_payload,
                                  verify=False
                                  )

# Extract the sessionID from login_response and add this to the headers
api_headers['Cookie'] = 'sessionID={0}'.format(
    login_response.cookies.get('sessionID'))

# For this example we will print out the headers to show that the cookie has been added to it
print(api_headers)

# Logging out is important to make sure the session wont linger on the cluster
logout_response = requests.request("POST",
                                   "https://172.16.0.246/rest/v1/logout",
                                   headers=api_headers,
                                   verify=False
)

# Print the logout response. This should print the HTTP code <200> when successfull.
print(logout_response)
