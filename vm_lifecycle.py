#!/usr/bin/env python3

# vm_lifecycle.py
#
# Purpose: Demonstrate basic VM examples and waiting for task completion using the Scale Computing REST API
#
# Usage: python3 ./vm_lifecycle.py
#

import base64
import getpass
import http.client as http
import json
import ssl


class InternalException(Exception):
    pass


class TaskException(InternalException):
    def __init__(self, tag, message, parameters):
        self.tag = tag
        self.message = message
        self.parameters = parameters

    def __str__(self):
        return '%s "%s" %s' % (self.tag, self.message, self.parameters)


class HTTPResponseException(InternalException):
    def __init__(self, response):
        self.response = response
        self.body = response.read()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.response.status) + ": " + str(self.body)


def get_host():
    host = input("Cluster node hostname or IP: ")
    if not host:
        print('Failed to get host or IP')
        exit(2)
    return host


def get_credentials():
    username = input("Username: ")
    if not username:
        print('Failed to get username')
        exit(2)
    password = getpass.getpass("Password: ")
    if not password:
        print('Failed to get password')
        exit(2)
    return str(base64.b64encode(bytes('{0}:{1}'.format(username, password), 'utf-8')), 'utf-8')


def get_connection(host):
    timeout = 120
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE

    return http.HTTPSConnection(host, timeout=timeout, context=context)


def get_response(connection):
    response = connection.getresponse()
    if response.status != http.OK:
        raise HTTPResponseException(response)

    return json.loads(response.read().decode("utf-8"))


def wait_for_task_completion(connection, task_id):
    inprogress = True
    while inprogress:
        connection.request(
            'GET', '{0}/{1}'.format(url, 'TaskTag/{0}'.format(task_id)), None, rest_opts)
        task_status = get_response(connection)[0]
        if task_status['state'] == 'ERROR':
            raise TaskException(
                task_id, task_status['formattedMessage'], task_status['messageParameters'])
        if task_status['state'] == 'COMPLETE':
            inprogress = False


host = get_host()
url = 'https://{0}/rest/v1'.format(host)
credentials = 'Basic {0}'.format(get_credentials())
rest_opts = {
    'Content-Type': 'application/json',
    'Authorization': credentials,
    'Connection': 'keep-alive'
}


def main():
    connection = get_connection(host)
    default_vm = {
        'dom': {
            'name': 'python-vmLifeCycle',
            'description': 'An example VM created using the rest API',
            'mem': 4294967296,  # 4GiB
            'numVCPU': 2,
            'blockDevs': [{
                'capacity': 10000000000,  # 10GB
                'type': 'VIRTIO_DISK',
                'cacheMode': 'WRITETHROUGH'
            }],
            'netDevs': [{
                'type': 'VIRTIO'
            }]
        },
        'options': {
            #  'attachGuestToolsISO': true
            }
    }

    print("Create VM")
    connection.request(
        'POST', '{0}/VirDomain'.format(url), json.dumps(default_vm), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])
    vmUUID = result['createdUUID']

    print("Create a block device for the VM")
    block_device_attrs = {
        'virDomainUUID': vmUUID,
        'capacity': 10000000000,  # 10GB
        'type': 'VIRTIO_DISK',
        'cacheMode': 'WRITETHROUGH'
    }
    connection.request('POST', '{0}/VirDomainBlockDevice'.format(url), json.dumps(
        block_device_attrs), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    print("Start VM")
    start_vm = [{
        'actionType': 'START',
        'virDomainUUID': vmUUID
    }]
    connection.request(
        'POST', '{0}/VirDomain/action'.format(url), json.dumps(start_vm), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    # Create a list of cluster nodes without the one the VM is running on
    connection.request('GET', '{0}/Node'.format(url), None, rest_opts)
    nodes = get_response(connection)
    if len(nodes) > 1:
        print("Live migrate VM to another node")
        # Get VM Info to determine which node the VM is currently running on
        connection.request(
            'GET', '{0}/VirDomain/{1}'.format(url, vmUUID), None, rest_opts)
        result = get_response(connection)
        vm = result[0]

        nodeUUIDs = [node['uuid']
                     for node in nodes if node['uuid'] != vm['nodeUUID']]
        migrate_vm_to_node = [{
            'actionType': 'LIVEMIGRATE',
            'nodeUUID': nodeUUIDs[0],  # just use the first node in the list
            'virDomainUUID': vmUUID
        }]
        connection.request('POST', '{0}/VirDomain/action'.format(url), json.dumps(
            migrate_vm_to_node), rest_opts)
        result = get_response(connection)
        wait_for_task_completion(connection, result['taskTag'])

    print("Stop VM")
    stop_vm = [{
        'actionType': 'STOP',
        'virDomainUUID': vmUUID
    }]
    connection.request(
        'POST', '{0}/VirDomain/action'.format(url), json.dumps(stop_vm), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    print("Update VM properties")
    edit_vm_attrs = {
        'name': default_vm['dom']['name'] + 'Updated',
        'numVCPU': 4,
        'mem': 8589934592,  # 8GiB
        'tags': ",".join(['burger', 'tastes', 'good'])
    }
    connection.request(
        'PATCH', '{0}/VirDomain/{1}'.format(url, vmUUID), json.dumps(edit_vm_attrs), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    print("Clone VM")
    vm_clone_attrs = {
        'template': {
            'name': 'python-vmLifeCycle-Clone',
            'description': 'An example VM cloned using the rest API'
        }
    }
    connection.request('POST', '{0}/VirDomain/{1}/clone'.format(
        url, vmUUID), json.dumps(vm_clone_attrs), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])
    cloneUUID = result['createdUUID']

    print("Create VM snapshot")
    snapshotUUID = ''
    snapshot_attrs = {
        'domainUUID': vmUUID,
        'label': 'Created by Python Script'
    }
    connection.request(
        'POST', '{0}/VirDomainSnapshot'.format(url), json.dumps(snapshot_attrs), rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])
    snapshotUUID = result['createdUUID']

    print("Delete VM snapshot")
    connection.request(
        'DELETE', '{0}/VirDomainSnapshot/{1}'.format(url, snapshotUUID), None, rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    print("Delete original VM")
    connection.request(
        'DELETE', '{0}/VirDomain/{1}'.format(url, vmUUID), None, rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    print("Delete cloned VM")
    connection.request(
        'DELETE', '{0}/VirDomain/{1}'.format(url, cloneUUID), None, rest_opts)
    result = get_response(connection)
    wait_for_task_completion(connection, result['taskTag'])

    return 0

if __name__ == '__main__':
    exit(main())
