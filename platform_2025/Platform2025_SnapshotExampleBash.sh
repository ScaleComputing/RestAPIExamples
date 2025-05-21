#!/bin/bash

SCUSERNAME="demo"
SCPASSWD="apidemo"
SCNODE="172.16.0.246"

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

# login
curl -s -k -X POST https://$SCNODE/rest/v1/login \
           -H 'Content-Type: application/json' \
           -d '{"username":"'"${SCUSERNAME}"'","password":"'"${SCPASSWD}"'"}' \
           -c ./cookie >/dev/null


VMUUID="8485f751-3e02-458a-89c9-0ccc2f38d681"

RESULT1="$(curl -s -k --cookie ./cookie -X 'POST' \
        'https://'$SCNODE'/rest/v1/VirDomainSnapshot' \
        -H 'accept: application/json' \
        -H 'Content-Type: application/json' \
        -d '{"domainUUID":"'"${VMUUID}"'","label":"scripted snapshot"}')"


taskID=$( echo ${RESULT1} | jq -r .taskTag )
newSnapUUID=$( echo ${RESULT1} | jq -r .createdUUID )

Wait-ScaleTask $taskID

# logout
curl -s -k --cookie ./cookie -X 'POST' \
        'https://'$SCNODE'/rest/v1/logout' \
        -H 'accept: application/json'

