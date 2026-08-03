#!/usr/bin/python3
import requests
import urllib3
import json
import time
import asyncio
import time
import os
import subprocess
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CLUSTER_0_IP = os.environ["SOURCECLUSTER"]
CLUSTER_1_IP = os.environ["TARGETCLUSTER"]
CLUSTER_0_PATH = f"https://{CLUSTER_0_IP}/rest/v2"
CLUSTER_1_PATH = f"https://{CLUSTER_1_IP}/rest/v2"


acceptJSONHeader = {"accept": "application/json"}
contentTypeJSONHeader = {"Content-Type": "application/json"}
authString = f"{os.environ["USERNAME"]}:{os.environ["PASSWORD"]}"
basicAuthHeader = {
    "Authorization": f"Basic {base64.b64encode(authString.encode("utf-8")).decode("utf-8")}"
}
nonAuthHeaders = acceptJSONHeader | contentTypeJSONHeader

defaultHeaders = nonAuthHeaders | basicAuthHeader


class WaitTimeoutError(Exception):
    pass


class TaskFailedError(Exception):
    def __init__(self, taskState):
        self.taskState = taskState
        super().__init__(f"Task {taskState['taskTag']} is in state Error")


async def waitUntilTaskComplete(basePath, taskTag, timeout=600, period=1):
    if taskTag == "":
        return
    start = time.monotonic()
    end = start + timeout
    while time.monotonic() < end:
        print("task wait: " + basePath + "/TaskTag")
        tasks = requests.get(
            basePath + "/TaskTag",
            params={"taskTag": str(taskTag), "limitSize": 1},
            headers=defaultHeaders,
            verify=False,
        )

        if not tasks.ok:
            raise Exception(f"Failed to fetch task: {tasks.status_code} - {tasks.text}")

        tasks = tasks.json()
        for task in tasks:
            if task["state"] == "ERROR":
                raise TaskFailedError(task)
            elif task["state"] == "COMPLETE":
                return
            await asyncio.sleep(period)
    raise WaitTimeoutError(f"Timed out waiting for task {taskTag} to complete")


async def create_remote_cluster_connection():
    print("Performing Host Key Exhange")
    CLUSTER_1_HOSTKEYS = requests.get(
        f"{CLUSTER_1_PATH}/AuthenticationServerHostKey",
        headers=defaultHeaders,
        verify=False,
    ).json()

    CLUSTER_1_HOSTKEYS = {"keys": CLUSTER_1_HOSTKEYS}

    response = requests.post(
        f"{CLUSTER_0_PATH}/AuthenticationHostKey/Accept",
        headers=defaultHeaders,
        data=json.dumps(CLUSTER_1_HOSTKEYS),
        verify=False,
    )

    print("generating authentication key on source and accepting on target")
    response = requests.post(
        f"{CLUSTER_0_PATH}/AuthenticationKey",
        headers=defaultHeaders,
        verify=False,
    )

    remote_cluster_connection_create_body = {
        "authInfo": {
            "connectionTimeoutSeconds": 300,
            "receiveTimeoutSeconds": 300,
            "ipAddress": CLUSTER_1_IP,
            "secureConnection": True,
        },
        "compression": True,
        "createOptions": {"cleanupOnFailure": True},
    }

    print("Creating remote cluster connection")
    response = requests.post(
        f"{CLUSTER_0_PATH}/RemoteClusterConnection",
        headers=defaultHeaders,
        data=json.dumps(remote_cluster_connection_create_body),
        verify=False,
    )

    remoteConnectionUUID = response.json()["createdUUID"]
    remoteConnectionCreateTaskTag = response.json()["taskTag"]

    response = requests.get(
        f"{CLUSTER_0_PATH}/AuthenticationKey",
        headers=defaultHeaders,
        verify=False,
    )

    CLUSTER_0_AUTHENTICATION_KEYS = {"keys": response.json()}

    response = requests.post(
        f"{CLUSTER_1_PATH}/AuthenticationKey/Accept",
        headers=defaultHeaders,
        data=json.dumps(CLUSTER_0_AUTHENTICATION_KEYS),
        verify=False,
    )

    await waitUntilTaskComplete(
        CLUSTER_0_PATH, remoteConnectionCreateTaskTag, timeout=600
    )

    print("Remote Cluster Connection initialization Complete")

    blockDevs = [
        {"type": "IDE_CDROM", "capacity": 10**9},
        {"type": "VIRTIO_DISK", "capacity": 10**9},
    ]
    vmDesc = {
        "name": "Grey Goo",
        "description": "I exist to replicate",
        "numVCPU": 2,
        "mem": 8675309000,
        "blockDevs": blockDevs,
    }
    vm_json = {"dom": vmDesc, "options": {"attachGuestToolsISO": True}}

    print("creating vm for replication")

    response = requests.post(
        f"{CLUSTER_0_PATH}/VirDomain",
        headers=defaultHeaders,
        verify=False,
        data=json.dumps(vm_json),
    )

    vmUUID = response.json().get("createdUUID")
    vmCreateTaskTag = response.json().get("taskTag")

    await waitUntilTaskComplete(CLUSTER_0_PATH, vmCreateTaskTag)

    print("Setting up replication for VM")
    replicationSetupJSON = {
        "connectionUUID": remoteConnectionUUID,
        "enable": True,
        "label": "Grey Goo Replication",
        "sourceDomainUUID": vmUUID,
    }

    replicationSetupResponse = requests.post(
        f"{CLUSTER_0_PATH}/VirDomainReplication",
        headers=defaultHeaders,
        verify=False,
        data=json.dumps(replicationSetupJSON),
    )

    await waitUntilTaskComplete(
        CLUSTER_0_PATH, replicationSetupResponse.json()["taskTag"]
    )

    print("taking snapshot with replication enabled")

    snapInfo = {"domainUUID": vmUUID, "label": "Track the spread of the grey goo"}
    snapResp = requests.post(
        f"{CLUSTER_0_PATH}/VirDomainSnapshot",
        headers=defaultHeaders,
        verify=False,
        data=json.dumps(snapInfo),
    )
    snapResp.raise_for_status()
    await waitUntilTaskComplete(CLUSTER_0_PATH, snapResp.json()["taskTag"])

    cleanup = False
    if cleanup:
        print("Deleting remote cluster connection")
        response = requests.delete(
            f"{CLUSTER_0_PATH}/RemoteClusterConnection/{remoteConnectionUUID}",
            headers=defaultHeaders,
            verify=False,
        )

        await waitUntilTaskComplete(CLUSTER_0_PATH, response.json()["taskTag"])

        print("deleting vm")

        response = requests.delete(
            f"{CLUSTER_0_PATH}/VirDomain/{vmUUID}",
            headers=defaultHeaders,
            verify=False,
        )
        response.raise_for_status()

        await waitUntilTaskComplete(CLUSTER_0_PATH, response.json()["taskTag"])


async def main():
    try:
        print("Running create_remote_cluster_connection")
        await asyncio.wait_for(create_remote_cluster_connection(), timeout=600)
    except asyncio.TimeoutError:
        print("create_remote_cluster_connection timed out!")


if __name__ == "__main__":
    asyncio.run(main())
