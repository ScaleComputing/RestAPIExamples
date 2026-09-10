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

While SC//HyperCore software is self-updating the REST API does not just go
read-only — it stops answering entirely, **by hanging**. Measured on a real
9.8.3 → 9.8.4 update: every `/rest/v1/` endpoint returned a read timeout for
minutes (connection accepted, no response — not a refusal, not a `503`), while
`GET https://<node-ip>/update/update_status.json` kept returning 200 the whole
time. So **always set an explicit read timeout**, and use that file — not any
REST endpoint — to decide whether it is safe to write. It is not under
`/rest/v1/` and needs no auth.

The cluster is idle only when **both** `prepareStatus.state` and
`updateStatus.masterState` are `"COMPLETE"`. There is no top-level
`updateStage`. You must check both, because each one alone reports "idle"
through a whole phase of a real update:

| phase | `prepareStatus.state` | `updateStatus.masterState` |
|---|---|---|
| never updated | *(HTTP 404, HTML body)* | *(404)* |
| prepare | `DOWNLOAD BUNDLE` → `DOWNLOAD RPMS` → `UPDATE RPM` | **absent** |
| apply | `COMPLETE` | `EXECUTING` ⇄ `IN PROGRESS` |
| settled | `COMPLETE` | `COMPLETE` |

**Fail closed.** Treat any other value, a missing field, a 404, a 502, an
unparseable body, a timeout, a TLS failure, or an unreachable node as **busy**.

⚠ **"Unreachable" is at least four different things.** One update produced all
of these, and none was a refused connection: **404 + HTML** (never updated),
**read timeout** (apply phase — connection accepted, backend silent), **TLS
error** then **read timeout** (node tearing down, then fully down — ~2m20s
total), and **502 + HTML** (back up, backend still starting). So: catching only
`Timeout` is a bug — `requests.exceptions.SSLError` subclasses
`ConnectionError`, not `Timeout`, so the reboot escapes it (in `curl` that
moment is exit 35, not 7). And check the status code *before* parsing, because
the 404 and the 502 both return HTML — `r.json()` raises rather than failing
closed. `masterState` also has *two* in-progress values, so test
`!= "COMPLETE"` rather than matching a name.

`/rest/v1/Condition` has a tempting `condition.updateInProgress` flag, but it
fails at both ends: the endpoint dies with the rest of the API mid-update, and
the flag also *lags* on the way out (measured still `true` ~17 s after
`masterState` went `COMPLETE`). Don't rely on it.
`POST /rest/v1/Update/{uuid}/apply` returns 200 with an **empty** `taskTag`, so
there is no task to wait on (see Rule 1).

Reference implementation: `specific_task/HyperCoreDynamicBalancer/HyperCore_balancer.py`
— correct across the sequence above and does node failover, but its
`if state and state != "COMPLETE"` guards read an absent field as idle, so
don't lift that pattern on its own. Full detail:
`docs/hypercore-api-field-notes.md`.

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
