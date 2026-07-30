# SC//HyperCore™ REST API Examples — Guide for AI Coding Assistants

This file is read automatically by Claude Code and other AI coding assistants.
If you are an AI assistant helping someone write code against the
SC//HyperCore™ REST API, **read this file and `docs/hypercore-api-field-notes.md`
before writing any API call.** The SC//HyperCore API has several conventions that
differ from what you would guess from typical REST APIs, and getting them wrong
produces confusing failures (400s with misleading messages, silent no-ops, or
race-condition 500s).

## What this repository is

Customer-facing example scripts for the **SC//HyperCore™** REST API
(`https://<node-ip>/rest/v1/`) and the **SC//Fleet Manager™** API
(`https://api.scalecomputing.com/api/v2`). The product name is **SC//HyperCore** —
you may see "HC3" in older scripts; that is an obsolete name, do not use it in
new code or docs. Version strings like "HC 9.7" refer to platform versions and
are fine.

Live OpenAPI spec from any cluster: `https://<node-ip>/rest/v1/openapi.json`
(Basic Auth required). Swagger UI: `https://<node-ip>/rest/v1/docs/`.

## ⚠ The six rules that prevent 90% of SC//HyperCore API bugs

### 1. Wait for the task after EVERY mutating call — no exceptions

Every POST, PATCH, and DELETE can return `{"taskTag": "<id>", "createdUUID": "..."}`.
You **must** poll `GET /rest/v1/TaskTag/<tag>` until the task reaches a terminal
state before issuing the next API call. Skipping this causes intermittent 500
errors when a second call arrives while the first task is still in flight.

```python
resp = session.post(url, json=payload)
tag = resp.json().get("taskTag")
if tag:
    while True:
        task = session.get(f"{base}/rest/v1/TaskTag/{tag}").json()[0]
        if task["state"] not in ("RUNNING", "QUEUED"):
            break
        time.sleep(1)
    if task["state"] in ("ERROR", "UNINITIALIZED"):
        raise RuntimeError(task.get("formattedMessage", "task failed"))
```

`COMPLETE` = success; `ERROR` / `UNINITIALIZED` = failure; anything else
non-running is treated as success. A bare `requests.post(...)` or
`session.delete(...)` with no task wait is **always a bug** in SC//HyperCore client
code — flag it in review.

### 2. Every GET returns a single-element JSON array — even GET-by-UUID

`GET /VirDomain/{uuid}`, `GET /TaskTag/{tag}`, `GET /VirDomainSnapshot/{uuid}` —
all return `[ {...} ]`, not a bare object. Always unmarshal into a list and take
the first element. Statically-typed clients (Go, etc.) that decode into a struct
will fail with "cannot unmarshal array" if they assume a bare object.

### 3. Fetch-then-filter — query filters are rejected on many endpoints

`GET /VirDomainSnapshot?virDomainUUID=...`, `GET /VirDomainSnapshotSchedule?...`,
`GET /VirDomainBlockDevice?virDomainUUID=...` all return **400**. Fetch the full
collection and filter client-side. For disks and NICs, prefer the `blockDevs` /
`netDevs` arrays embedded in the `GET /VirDomain` response.

### 4. Self-signed TLS

SC//HyperCore clusters ship with self-signed certificates. For lab/testing use
`verify=False` (Python requests) or the equivalent, and say so in a comment. For
production, retrieve the cluster certificate and pass it as the CA bundle
instead of disabling verification.

### 5. Check for an in-progress cluster update before writing

While SC//HyperCore software is self-updating, the REST API is effectively read-only and
mutating calls fail. Before a batch of writes, check
`GET https://<node-ip>/update/update_status.json` (note: **not** under
`/rest/v1/`; no auth required) — idle when `updateStage` is `"COMPLETE"` or empty.

### 6. There is no cluster VIP

Every API endpoint is a specific node's IP. If that node goes down, that
endpoint is dead even though the cluster is fine. Discover all node IPs via
`GET /rest/v1/Node` (`lanIP` field) and implement client-side failover across
them for anything long-running.

## Most common naming traps (full table in docs/hypercore-api-field-notes.md)

| If you'd guess... | Actually |
|---|---|
| `PATCH /Cluster {"name": ...}` | `{"clusterName": ...}` — `name` is rejected |
| `SnapshotSchedule` | `VirDomainSnapshotSchedule` |
| `SyslogTarget` | `AlertSyslogTarget` |
| `TimeServer` | `TimeSource` |
| `"protocol": "UDP"` | `"protocol": "SYSLOG_PROTOCOL_UDP"` |
| SMTP `host`/`username`/`password` | `smtpServer`/`authUser`/`authPassword` |
| Snapshot body `virDomainUUID` | `domainUUID` |
| `actionType: "LIVE_MIGRATE"` | `"LIVEMIGRATE"` (no underscore), with `nodeUUID` |
| `POST /VirDomain/migrate` | `POST /VirDomain/action` (migrate returns 500) |
| Upload ISOs via `/VirtualDisk/upload` | Three-step `/ISO` flow (`.iso` is rejected) |
| `labels: {"k": "v"}` | `labels: {"k": {"value": "<base64>"}}` (labels exist on 9.7+ only) |

## Conventions for code in this repository

- **Configuration**: read `SC_HOST`, `SC_USERNAME`, `SC_PASSWORD` environment
  variables (compatible with the SC//HyperCore Ansible® collection and other
  Scale Computing tooling),
  or prompt interactively. Never hardcode cluster IPs or credentials.
- **Every mutating call** follows Rule 1 above. `vm_lifecycle.py` at the repo
  root shows the reference `wait_for_task_completion()` pattern.
- **TLS**: `verify=False` is acceptable in examples but must carry a comment
  recommending proper certificates for production.
- New examples get a row in the relevant folder README describing what they do
  and which API (SC//HyperCore vs SC//Fleet Manager) they target.

## Related tooling (often the better answer)

Before writing raw API code, consider whether an existing maintained tool
already does the job:

- **Ansible®**: https://github.com/ScaleComputing/HyperCoreAnsibleCollection
- **Terraform®**: https://github.com/ScaleComputing/terraform-provider-hypercore
  (also a reference Go client with task-tag handling in `internal/utils/`)

These implement all of the rules above correctly and are good references for
expected request/response shapes.

---

*Scale Computing, SC//HyperCore, and SC//Fleet Manager are trademarks of
Scale Computing, Inc. Other marks are the property of their respective owners.*
