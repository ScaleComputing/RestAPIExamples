#!/usr/bin/env python3

# NodeCPUUsage.py
#
# Purpose: Example script to get the highest node CPU utilaztion in the cluster
#
# Usage: python3 ./NodeCPUUsage.py -n 192.168.1.1 -u admin -p s3cr3t
#

import base64
import getpass
import http.client as http
import json
import ssl
import argparse

class InternalException(Exception):
    pass

class HTTPResponseException(InternalException):
    def __init__(self, response):
        self.response = response
        self.body = response.read()

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.response.status) + ": " + str(self.body)

def main():
    parser = argparse.ArgumentParser(description="Obtain individual node CPU information from a Hypercore cluster")
    parser.add_argument("-n", "--node")
    parser.add_argument("-u", "--user")
    parser.add_argument("-p", "--passwd")
    args = vars(parser.parse_args())
    if args["node"] is None:
        host = input("Cluster node hostname or IP: ")
        if not host:
            print('Failed to get host or IP')
            exit(2)
    else:
        host = args["node"]

    if args["user"] is None:
        username = input("Username: ")
        if not username:
            print('Failed to get username')
            exit(2)
    else:
        username = args["user"]

    if args["passwd"] is None:
        password = getpass.getpass("Password: ")
        if not password:
            print('Failed to get password')
            exit(2)
    else:
        password = args["passwd"]

    url = 'https://{0}/rest/v1'.format(host)
    credentials = 'Basic {0}'.format(str(base64.b64encode(bytes('{0}:{1}'.format(username, password), 'utf-8')), 'utf-8'))
    rest_opts = {
        'Content-Type': 'application/json',
        'Authorization': credentials,
        'Connection': 'keep-alive'
    }

    timeout = 120
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE

    connection = http.HTTPSConnection(host, timeout=timeout, context=context)

    connection.request('GET', '{0}/Node'.format(url), None, rest_opts)
    response = connection.getresponse()
    if response.status != http.OK:
        raise HTTPResponseException(response)

    result = json.loads(response.read().decode("utf-8"))

    # Example: See the documentation for other possible values to print out/sort
    # at https://{node-ip}/rest/v1/Node on the Hypercore cluster
    for node in sorted(result, key=lambda result: result.get('cpuUsage'), reverse=True):
        print("\nNode {}: ".format(node.get('lanIP')))
        print("  numCPUs : {}".format(node.get('numCPUs')))
        print("  numCores : {}".format(node.get('numCores')))
        print("  numThreads : {}".format(node.get('numThreads')))
        print("  CPUhz : {}".format(node.get('CPUhz')))
        print("  cpuUsage : {}".format(node.get('cpuUsage')))

    return 0

if __name__ == '__main__':
    exit(main())
