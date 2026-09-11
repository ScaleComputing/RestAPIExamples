#!/usr/bin/env python3
"""
hypercore_transfer.py

Shared helpers for the SC//HyperCore(TM) VM export / import examples.

Nothing in here is specific to export or import -- it is the small amount of
plumbing every SC//HyperCore REST client needs:

  * a requests.Session with basic auth and certificate verification disabled
    (SC//HyperCore clusters ship a self-signed certificate)
  * task-tag polling, because every mutating call on the API is asynchronous
  * building an SMB pathURI with the credentials URL-encoded, and a masked
    version of the same URI that is safe to print or log

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

SECURITY NOTE
    Certificate verification is disabled below so the examples work against a
    cluster's self-signed certificate. Only do this on a trusted network. If
    you have uploaded a certificate to the cluster, set verify=True instead.
"""

import json
import sys
import time
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Poll interval and overall budget for task-tag waits. Export/import copy
# disk data, so these tasks can run for a long time on a large VM -- raise
# TASK_TIMEOUT rather than assuming a stall.
POLL_SECONDS = 2
TASK_TIMEOUT = 3600

# A task tag is finished when it leaves these two states.
NON_TERMINAL = ("RUNNING", "QUEUED")
# ERROR and UNINITIALIZED are failures; anything else terminal is a success.
FAILED = ("ERROR", "UNINITIALIZED")


class TaskFailed(RuntimeError):
    """A task tag reached a terminal state that is not a success."""


class ApiError(RuntimeError):
    """The cluster rejected a request outright, with no task tag created."""


def make_session(username, password):
    """Return a requests.Session ready to talk to an SC//HyperCore cluster."""
    session = requests.Session()
    session.auth = (username, password)
    session.verify = False          # self-signed cluster certificate
    session.headers["Content-Type"] = "application/json"
    return session


def api_base(node, api_version="v1"):
    """Build the REST base URL for a node address.

    `node` may be an IP address or FQDN, with or without a scheme.
    """
    node = node.strip().rstrip("/")
    if not node.startswith(("http://", "https://")):
        node = "https://" + node
    return "{0}/rest/{1}".format(node, api_version)


def build_smb_uri(server, share, path, username, password, domain=None):
    """Build an SMB pathURI for an export target or an import source.

    The credentials travel inside the URI, which is how the SC//HyperCore API
    takes them -- there is no separate credential field. Both are URL-encoded
    so that a password containing '@', ':', '/' or '#' does not corrupt the
    URI. An Active Directory domain, when supplied, is prefixed with a
    semicolon, which is the libsmbclient syntax the cluster expects:

        smb://DOMAIN;user:password@server/share/path

    Returns (uri, masked_uri). Print the masked one.
    """
    user_part = quote(username, safe="")
    if domain:
        user_part = "{0};{1}".format(quote(domain, safe=""), user_part)
    path = path.strip("/")
    tail = "{0}@{1}/{2}/{3}".format("{0}", server, share.strip("/"), path)
    uri = "smb://" + tail.format("{0}:{1}".format(user_part, quote(password, safe="")))
    masked = "smb://" + tail.format("{0}:{1}".format(user_part, "****"))
    return uri, masked


def mask_uri(uri):
    """Replace the password in a user-supplied pathURI so it is safe to print."""
    if "://" not in uri or "@" not in uri:
        return uri
    scheme, rest = uri.split("://", 1)
    creds, host = rest.rsplit("@", 1)
    if ":" in creds:
        creds = creds.rsplit(":", 1)[0] + ":****"
    return "{0}://{1}@{2}".format(scheme, creds, host)


def wait_for_task(session, base, task_tag, label="task", timeout=TASK_TIMEOUT):
    """Poll GET /TaskTag/<tag> until the task leaves RUNNING/QUEUED.

    Every POST, PATCH and DELETE on the SC//HyperCore API may return a
    taskTag, and the work is not finished when the HTTP call returns -- it is
    finished when the task tag reaches a terminal state. Issuing the next call
    without waiting is the single most common mistake made against this API.

    Returns the final task record. Raises TaskFailed on ERROR.
    """
    deadline = time.time() + timeout
    last_reported = None
    while time.time() < deadline:
        response = session.get("{0}/TaskTag/{1}".format(base, task_tag), timeout=(10, 30))
        response.raise_for_status()
        body = response.json()
        # Every GET on this API returns a single-element list, even for a
        # lookup by id.
        task = body[0] if isinstance(body, list) else body

        state = task.get("state", "")
        percent = task.get("progressPercent", 0)
        if (state, percent) != last_reported:
            print("  {0} {1}: {2} {3}%".format(label, task_tag, state, percent))
            last_reported = (state, percent)

        if state not in NON_TERMINAL:
            if state in FAILED:
                raise TaskFailed(
                    "{0} {1} failed: state={2} {3}".format(
                        label, task_tag, state, task.get("formattedMessage") or ""
                    )
                )
            return task
        time.sleep(POLL_SECONDS)

    raise TaskFailed("{0} {1} did not finish within {2}s".format(label, task_tag, timeout))


def post_and_wait(session, base, path, payload, label):
    """POST a payload, then wait on the returned task tag.

    Prints the API's error body on a non-2xx response -- for export and import
    a 400 tells you exactly which field the cluster rejected, and it is much
    more useful than the status code alone.
    """
    url = "{0}{1}".format(base, path)
    response = session.post(url, data=json.dumps(payload), timeout=(10, 60))
    if not response.ok:
        # A share the cluster cannot reach, and a body the cluster will not
        # accept, both come back as a synchronous 400 -- no task tag is ever
        # created. The body says which, so surface it verbatim.
        detail = response.text.strip()
        try:
            detail = json.loads(detail).get("error", detail)
        except ValueError:
            pass          # schema errors come back as plain text, not JSON
        raise ApiError("HTTP {0} from {1}: {2}".format(
            response.status_code, url, detail))

    body = response.json()
    result = body[0] if isinstance(body, list) else body
    task_tag = result.get("taskTag")
    if not task_tag:
        raise TaskFailed("{0}: no taskTag in response: {1}".format(label, result))

    print("{0} accepted, taskTag={1}".format(label, task_tag))
    task = wait_for_task(session, base, task_tag, label=label)
    return result, task


def find_vm(session, base, name=None, uuid=None):
    """Look a VM up by name or UUID and return its record."""
    if uuid:
        response = session.get("{0}/VirDomain/{1}".format(base, uuid), timeout=(10, 60))
        response.raise_for_status()
        body = response.json()
        if not body:
            raise LookupError("no VM with UUID {0}".format(uuid))
        return body[0] if isinstance(body, list) else body

    response = session.get("{0}/VirDomain".format(base), timeout=(10, 120))
    response.raise_for_status()
    matches = [vm for vm in response.json() if vm.get("name") == name]
    if not matches:
        raise LookupError("no VM named {0!r}".format(name))
    if len(matches) > 1:
        raise LookupError(
            "{0} VMs are named {1!r} -- use --uuid to disambiguate".format(len(matches), name)
        )
    return matches[0]
