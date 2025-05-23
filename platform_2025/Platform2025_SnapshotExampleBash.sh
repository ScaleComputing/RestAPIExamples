#!/bin/bash

SCUSERNAME="YOUR_USERNAME"                     # User on a Scale Compuintg cluster with the backup right assigned
SCPASSWD="YOUR_PASSWORD"                       # Password for that user
SCNODE="IP_OR_FQDN_OF_ONE_NODE"                # IP or FQDN for the cluster
VMUUID="01234567-89ab-cdef-0123-456789abcdef"  # UUID of the VM we want to make a snapshot of

# A simpeler version (without error handling) for waiting untill a task is done. See the Python example for a more complete version.
Wait-ScaleTask () {
    echo "Waiting for task $1 to complete"
    taskCheckResult=""
    taskTime=0
    while [ $taskTime -le 150 ] # in increments of 2 seconds (sleep 2 just below this) 150 means a time-out for the task of 300 seconds / 5 minutes.
    do
        sleep 2
        taskCheck=$(curl -s -k --cookie ./cookie -X 'GET' 'https://'$SCNODE'/rest/v1/TaskTag/'$1)
        taskCheckResult=$( echo $taskCheck | jq -r .[].state)
        if [[ "$taskCheckResult" == "COMPLETE" ]]
	then
		break
	fi
		taskTime=$(( $taskTime + 1 ))
	done
}

# login and write a cookie file in the same directory as the script
# This script does not cover deleting the cookie file afterwards
curl -s -k -X POST https://$SCNODE/rest/v1/login \
           -H 'Content-Type: application/json' \
           -d '{"username":"'"${SCUSERNAME}"'","password":"'"${SCPASSWD}"'"}' \
           -c ./cookie >/dev/null

# Create a snapshot of the vm (vaniable VMUUID)
RESULT1="$(curl -s -k --cookie ./cookie -X 'POST' \
        'https://'$SCNODE'/rest/v1/VirDomainSnapshot' \
        -H 'accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{"domainUUID":"'"${VMUUID}"'","label":"scripted snapshot"}')"

# read the taskTag from the snapshot request
# read the UUID of the snapshot that was created
taskID=$( echo ${RESULT1} | jq -r .taskTag )
newSnapUUID=$( echo ${RESULT1} | jq -r .createdUUID )

# If you wish to do something smart with the snapshot you have just created, you need to wait for the process to finish before
# continuing the script. The Wait_ScaleTask function helps this process based on the taskTag
Wait-ScaleTask $taskID

# logout
curl -s -k --cookie ./cookie -X 'POST' \
        'https://'$SCNODE'/rest/v1/logout' \
        -H 'accept: application/json'

