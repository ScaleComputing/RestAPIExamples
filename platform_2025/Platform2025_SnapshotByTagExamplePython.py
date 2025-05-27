#!/usr/bin/env python3

"""

Script to demonstrate login, setting cookie and using cookies sessionID to retrieve a list of vm's, making a snapshot when a tag matches, and finally logging out.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risc.

Usage: Fill out the variables below starting at line 31 and run the script.

William David van Collenburg
Scale Computing

dependencies: requests, json, time, sleep, sys

"""

# import required modules
import requests
import json
import time
import sys

# the below module suppresses SSL warnings. It comes without saying that you should not use this. It is in here for educational reasons
import urllib3

# Use this to supppress certificate warnings. In production environments makes sure to create a DNS reccord and uppload a certificate that matches to the cluster.
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# all requests below have 'verify=False' added to it. If your system has proper certificates installed remove False and replace it with
# your certificate path.

# set required variables
username = "YOUR_USERNAME"               # Scale Computing Hypercore Username with at minimal Backup permissions
password = "YOUR_PASSWORD"               # Scale Computing Hypercore Password
url = "https://IP_OR_FQDN_OF_ONE_NODE/"  # Scale Computing Hypercore Node URL or IP address
task_timeout = 300                       # time in secconds, How long can tasks run before assuming they failed. Exports take long, shutdowns relatively short.
search_tag = "SnapMeScript"              # All vm's with this tag will be snapped when running this script

# You should not have to change anything below this point for the script to work as designed.

# vars for quickly using the endpoints we want to access
prefix = 'rest/v1/'
api_login = url + prefix + 'login'
api_logout = url + prefix + 'logout'
api_virdomain = url + prefix + 'VirDomain'
api_snapshot = url + prefix + 'VirDomainSnapshot'

# creating the bodies and headers we need
login_payload = json.dumps({
    "username": username,
    "password": password,
    "useOIDC": False
    })

api_headers = {
    'Content-Type': 'application/json'
}

# Many actions are asynchronous, often we need a way to wait for a returned taskTag to complete before taking further action
# the below function shows one of the possible ways to use the taskTag that is created with almost every API request or
# change you make in the GUI, to monitor the status of a task. When this returns COMPLETE the script will return true and
# can continue. If this returns ERROR or times out (task_timeout variable) the script will force a logoff and exit the script

def Scale_WaitForTask(sctag):
    api_tasktag = url + prefix + "TaskTag/" + str(sctag)
    task_check = ''
    wait_timeout = time.time() + task_timeout # tasks needs to be completed within this time in secconds

    while time.time() < wait_timeout:
        task_check = requests.request("GET",
                                      api_tasktag,
                                      headers=api_headers,
                                      verify=False)
        
        task_check_json = json.loads(task_check.text)

        if task_check_json[0]["state"] == "COMPLETE":
            print("task " + str(sctag) + " completed")
            return True
        
        elif task_check_json[0]["state"] == "ERROR":
            print("and error ocurred while exectuing the last task. Please consult the cluster log for more information.")
            sc_logout()
            sys.exit()

        else:
            time.sleep(2) # wait for 2 seconds before re-testing to prevent ddos-ing the api
    
    print("Timeout for task reached! The task might still be running on the cluster, please inspect cluster logs")
    sc_logout()
    sys.exit()

# when errors are detected call this function to log out of the cluster and terminate the script.
def sc_logout():
    logout_response = requests.request("POST",
                                   api_logout,
                                   headers=api_headers,
                                   verify=False
    )
    if logout_response.status_code == 200:
        print("Signed out of the cluster API")

# logging in (as we do this only once i have not build a function)
login_response = requests.request("POST", 
                                  api_login,
                                  headers=api_headers,
                                  data=login_payload,
                                  verify=False
)

# update api_headers to include the cookie with the sessionID in it
api_headers['Cookie'] = 'sessionID={0}'.format(login_response.cookies.get('sessionID'))

# Below this point, all the way up to the logout response you can perform actions on the cluster.
# For this example script we are going to snapshot all vm's with the configured search_tag.

# First we will retrieve the list of vm's via the VirDomain API endpoint.
virdomain_response = json.loads(requests.request("GET",
                                      api_virdomain,
                                      headers=api_headers,
                                      verify=False
).text)

# Iterate over all vm's to check if they have the configured searchtag, and if so make the snapshot
for vm in virdomain_response:
    vm_tags = vm["tags"]
    vm_tags_list = vm_tags.split(",")
    if search_tag in vm_tags_list:
        snapshot_payload = json.dumps({
            "domainUUID": vm["uuid"],
            "label": "scripted snapshot by vm tag " + search_tag
        })
        snapshot_response = json.loads(requests.request("POST",
                                                        api_snapshot,
                                                        headers=api_headers,
                                                        data=snapshot_payload,
                                                        verify=False
                                                        ).text)
        print(snapshot_response)
        
        # we actually do not have to wait for a snapshot to finish to queue the next one but
        # to demonstrate what the function does we do wait for one snapshot to finish before
        # starting the next.

        Scale_WaitForTask(snapshot_response["taskTag"])


# logging out
sc_logout()
