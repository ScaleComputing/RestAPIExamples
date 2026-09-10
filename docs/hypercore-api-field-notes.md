# SC//HyperCore™ REST API — Field Notes

Practical, empirically-verified notes for anyone writing code against the
SC//HyperCore™ REST API. Collected from real integration work
(CLI tooling, Ansible®, Terraform®, Kubernetes® drivers) against SC//HyperCore
**9.6.x and 9.7.x** clusters. Unless a note carries a version stamp, the
behavior was observed on both; where versions differ, the difference is
called out explicitly.

- Base URL: `https://<node-ip>/rest/v1/`
- Auth: HTTP Basic (a session-cookie login endpoint also exists — see "Auth")
- TLS: clusters ship with self-signed certificates (see "TLS")
- Live OpenAPI spec: `https://<node-ip>/rest/v1/openapi.json` (Basic Auth)
- Swagger UI: `https://<node-ip>/rest/v1/docs/` — also linked from the
  Support tab of the SC//HyperCore web UI Control Panel
- API v2 (`/rest/v2/`) exists on SC//HyperCore **9.7.1+ only** (on 9.6 every
  `/rest/v2/` path returns 404). Live v2 spec:
  `https://<node-ip>/rest/v2/openAPI.json` (note the capital "A"). These
  notes target v1 unless stated otherwise.

> These notes describe observed behavior, including a few quirks the official
> spec does not capture. When the spec and these notes disagree, the notes
> reflect what the server actually enforces on the versions listed.

## Detecting versions and capabilities

- **Platform version**: `GET /rest/v1/Cluster` → `icosVersion` (e.g.
  `"9.6.27.225000"`, `"9.7.4.225310"`). This is the value to gate features on.
- **v2 API presence**: any `/rest/v2/` GET returns 404 on 9.6, normal
  responses on 9.7.1+.
- **Do not capability-detect from the v1 spec's version string.** SC//HyperCore
  9.6.27 and 9.7.4 both serve `/rest/v1/openapi.json` reporting version
  `1.3.2`, but the content differs (e.g. the `labels` schema exists only in
  the 9.7 spec). If you need to know whether an endpoint or field exists,
  check `icosVersion`, or fetch the spec and look for the specific path or
  schema — never the spec version number.

Features that genuinely require 9.7.1+ (because they're v2-API-only or were
introduced alongside it): `useUEFISecureBoot` (create-time, v2 only),
`labels` and `runnable` on VirDomain/VirDomainBlockDevice, `/SNMPConfig`,
`/VirDomainReplication`, `attemptQuiesce` on snapshot create, and
`/VirtualDisk/upload` returning a `taskTag` that covers conversion (v2 —
the v1 upload also returns a `taskTag`, but it does not cover the
conversion phase; see "Virtual disks"). Notably **not** in that
list: `snapDiff` (CBT) — it's a v1 endpoint available on 9.6 too (see
"Changed Block Tracking").

---

## Universal rules — never skip these

### 1. Task-tag waits after every mutating call

Every POST, PATCH, DELETE **can** return a `taskTag` (string) and
`createdUUID` in the response body. You **must** poll until the task reaches
a terminal state before issuing the next API call. Skipping this causes
intermittent 500 errors when a second call hits while the first task is
in flight.

```python
resp = session.post(url, json=payload)
data = resp.json()
task_tag = data.get("taskTag")
if task_tag:
    wait_for_task(task_tag)   # poll GET /rest/v1/TaskTag/<tag> until terminal
```

The polling endpoint is **`/rest/v1/TaskTag/{tag}`** (not `/Task/{n}`; the
tag is a string). Terminal states: `COMPLETE` (success), `ERROR` /
`UNINITIALIZED` (failure). `RUNNING` / `QUEUED` are non-terminal — keep
polling. Treat any other non-running state as success.

Reference implementations:
- Python: `vm_lifecycle.py` in this repository (`wait_for_task_completion`)
- Python (Ansible): `plugins/module_utils/task_tag.py` in the
  [SC//HyperCore Ansible® collection](https://github.com/ScaleComputing/HyperCoreAnsibleCollection)
- Go: `internal/utils/` in the
  [Terraform provider](https://github.com/ScaleComputing/terraform-provider-hypercore)

### 2. Every GET returns a single-element JSON array — even GET-by-UUID

Even when fetching a specific resource (`GET /VirDomain/{uuid}`,
`GET /VirDomainSnapshot/{uuid}`, `GET /TaskTag/{tag}`), SC//HyperCore software returns a
**single-element JSON array**, not a bare object. Always unmarshal into a
list and take the first element.

```python
records = session.get(f"{base}/rest/v1/VirDomain/{uuid}").json()  # [ {...} ]
vm = records[0] if records else None
```

Statically-typed clients (Go and similar) hit a
`cannot unmarshal array into Go value of type Foo` error if they assume a
bare object.

### 3. Fetch-then-filter, not query-filter

Several endpoints **reject** query parameters like `?virDomainUUID=...` with
a 400. Fetch the full list and filter client-side. Known affected endpoints:

- `GET /VirDomainSnapshot?virDomainUUID=...` → 400
- `GET /VirDomainSnapshotSchedule?virDomainUUID=...` → 400
- `GET /VirDomainBlockDevice?virDomainUUID=...` → 400
- `GET /VirDomainNetDevice?virDomainUUID=...` → 400

For disks and NICs, prefer the `blockDevs` / `netDevs` arrays embedded in
the `GET /VirDomain` response — they're already filtered for you.

### 4. Self-signed TLS

All SC//HyperCore clusters ship with self-signed certificates, so default
certificate verification fails. For lab and development work, disable
verification (`verify=False` in Python requests, `-k` in curl) — and note
in your code that this is a lab convenience. For production automation,
either install a proper certificate on each node (see "TLS Certificate"
below) or retrieve the node's certificate once and pass it as the CA
bundle, which gets you real verification without a CA-signed cert.

### 5. Cluster update awareness

While SC//HyperCore software is self-updating, **the REST API on the node
being updated is not merely read-only — it becomes entirely unavailable, and it
fails by hanging.**

Measured end to end across two real updates, sampling every ~5 seconds from
before each update started until it settled: a **single-node** cluster going
9.8.3 → 9.8.4 (30 minutes), and a **4-node** cluster with running VMs going
9.6.30 → 9.6.32 (3.5 hours).

⚠ **On a multi-node cluster the outage is per node, and peers keep serving** —
see "Multi-node: it's a rolling outage" below. That distinction is the
difference between an unusable API and a usable one, so read both parts before
designing a client.

#### Use `update_status.json`, not `/rest/v1/`

(Everything in this subsection was measured on the single-node cluster, where
there is no peer to answer. The multi-node scoping follows further down.)

```
GET https://<node-ip>/update/update_status.json
```

Not under `/rest/v1/`, and needs no auth. During the apply phase this file kept
returning 200 continuously while **every** `/rest/v1/` endpoint tried
(`Cluster`, `Node`, `Drive`, `Condition`, `VirDomain`, `Update`) returned a
**read timeout** for minutes at a stretch. The file is served as a static file
by the front-end web server, independently of the REST backend — which is why it
is the progress channel and no REST endpoint is.

⚠ **Set an explicit read timeout on every call.** The observed failure was a
*hang*, not a refusal and not a `503`: the TCP connection is accepted and the
backend never answers. A client with no read timeout blocks indefinitely instead
of getting an error it can handle. In `requests` that means
`timeout=(connect, read)` — a bare number sets only the connect timeout in some
client libraries, and no timeout at all is never correct here.

#### The state machine, and why you must check *both* fields

| phase | `prepareStatus.state` | `updateStatus.masterState` |
|---|---|---|
| never updated | *(HTTP 404 — an HTML error page, not JSON)* | *(404)* |
| prepare | `DOWNLOAD BUNDLE` → `DOWNLOAD RPMS` → `UPDATE RPM` | **key absent entirely** |
| apply | `COMPLETE` | `EXECUTING` ⇄ `IN PROGRESS`, `percent` climbing |
| settled | `COMPLETE` | `COMPLETE` |

The cluster is idle only when **both** `prepareStatus.state` and
`updateStatus.masterState` are `"COMPLETE"`. There is no top-level
`updateStage` field in any phase.

**Checking only one of the two fields fails open for an entire phase of the
update:**

- During **prepare**, `updateStatus` contains only `percent` and `status`.
  `masterState` does not exist, so `.get("masterState")` returns `None` — which
  is falsy, and a `masterState`-only check reports the cluster *idle* while it
  is downloading and installing packages.
- During **apply**, `prepareStatus.state` has already returned to `"COMPLETE"`.
  A `prepareStatus`-only check reports the cluster *idle* while the update is
  halfway through.
- `masterState` alternates between **two** in-progress values, `"EXECUTING"` and
  `"IN PROGRESS"`. Test `!= "COMPLETE"`; never match against a specific
  in-progress name.

A settled response looks like this — note that `masterState`, `toVersion` and
`fromBuild` appear only once the apply phase has begun:

```json
{
  "prepareStatus": { "state": "COMPLETE" },
  "updateStatus": {
    "masterState": "COMPLETE",
    "fromBuild": "227336",
    "toBuild": "227597",
    "toVersion": "9.8.4.227597",
    "percent": "100",
    "status": { "statusdetails": "Update Complete. Press 'Reload' to reconnect" }
  }
}
```

#### A cluster that has never updated returns 404, not empty JSON

The file does not exist until the cluster's first update, and the web server
answers with **HTTP 404 and an HTML error body**. So `response.json()` raises a
JSON decode error — there is no "empty JSON" case to handle, and code that
parses before checking the status code will throw. This was observed on three
never-updated clusters running three different builds (9.6.32, 9.7.8 and
9.8.3), so it tracks *never having updated*, not the software version.

Once an update is triggered the file appears within a few seconds, so the
window in which a genuinely updating cluster still returns 404 is short — but a
correct check must still treat 404 as *unknown*, not as *idle*.

#### "Unreachable" is at least four different things

This is the single most important practical finding, and the reason the rule
below is written the way it is. Across one update the same client hitting the
same cluster saw **four distinct failure shapes**, and *none of them was a
refused connection*:

| when | `/update/update_status.json` | `/rest/v1/*` |
|---|---|---|
| never updated | **HTTP 404**, HTML body | 404 |
| apply, backend busy | 200 throughout | **read timeout** (accepted, never answered) |
| node tearing down to reboot | **TLS error** (~100 s) | TLS error |
| node fully down | **read timeout** (~35 s) | read timeout |
| just back, backend still starting | 200 | **HTTP 502**, HTML body |

The reboot alone moved through *two* shapes in sequence — TLS error, then read
timeout — and took roughly 2m20s end to end before the file answered again.

Three consequences for real client code:

- **Catching only timeouts is not enough.** In `requests`, the reboot raises
  `SSLError`, which subclasses `ConnectionError` and **not** `Timeout` — so
  `except requests.exceptions.Timeout` lets it through and the caller crashes
  during the reboot. Catch `RequestException`, or at minimum both
  `ConnectionError` and `Timeout`. With `curl`, the same moment is exit code
  **35** (SSL connect error), not 7 (couldn't connect); once the host is fully
  down it becomes exit **28** (timeout).
- **Check the status code before parsing.** Both the 404 and the 502 return
  **HTML**, so `response.json()` raises a decode error rather than giving you
  something to inspect. Code shaped like `r.json().get("prepareStatus", {})`
  throws instead of failing closed.
- **A 502 means "ask again later", never "idle".** It appears in the window
  where the front-end web server is up but the REST backend has not finished
  starting — a genuinely mid-update state that a naive check reads as an error
  it can ignore.

#### Multi-node: it's a rolling outage, and failover is most of the answer

On the 4-node cluster, while the node being updated was unreachable, **its
peers served both channels normally**. Measured across the whole upgrade:

- **314 sample rounds** had a healthy peer while another node was down.
- **2 sample rounds** had every node unreachable at once (one ~19-second
  window, during the first VM evacuation, before any node had rebooted; it did
  not recur).
- All four nodes followed the identical pattern, one at a time, with reboot
  outages of **7.5–10 minutes each**.
- Nodes on the new version served happily alongside nodes still on the old one.

So the guidance is two-part, and neither half substitutes for the other:

1. **Multi-endpoint failover** handles the per-node reboots, which dominate an
   upgrade's wall clock. A client holding every node's address never lost
   access across the entire 3.5-hour upgrade.
2. **Retry with backoff** handles the rest — the brief all-node window, where
   no other endpoint would have helped, and ordinary flakiness: peers not being
   updated still returned scattered timeouts, roughly **97–98% availability**
   rather than 100%. A single failed call to a healthy peer is expected.

⚠ **A single hostname is not a cluster address — it is one node.** The
cluster's DNS name failed and recovered in *exactly* the same sample rounds as
one specific node IP, with identical outage durations, in all three of that
node's outages. **A client configured with one hostname lost the cluster
entirely while three of four nodes were healthy and serving.** Configure the
node addresses, not a name. See Rule 6.

#### Timing, and what `percent` does and doesn't mean

- The 4-node upgrade took **3.5 hours**; the empty single-node one took **30
  minutes**. Most of the difference is VM migration — evacuating and restoring
  a node's VMs took ~15 minutes *per node*, on top of a ~10-minute reboot.
- `totalComponents` scales with cluster size (688 for four nodes, 180 for one).
- ⚠ **`percent` is cluster-wide but NOT proportional to nodes completed** — it
  read 51% with only one of four nodes upgraded, because the shared prepare and
  pre-flight phases account for a large share. Don't scale it into an ETA.
- Multi-node prepare has two extra states: `BEGIN` → `DOWNLOAD BUNDLE` →
  `DOWNLOAD RPMS` → **`SYNC NODES`** → `UPDATE RPM` → `COMPLETE`.

#### Which node is being updated, and which are done

- **`updateStatus.status.node` names the node currently being worked on** — but
  in *backplane* addressing, not the LAN address you connect to. It's the clean
  signal for following the rollout.
- **`update_status.json` is cluster-consistent**: every node reports identical
  `prepareStatus`, `masterState` and `percent`. Nodes do not disagree about
  update progress.
- **But `Cluster.icosVersion` is the ANSWERING node's version, not the
  cluster's.** Mid-upgrade, the same request returns different versions
  depending on which node serves it — a 2/2 split was observed directly. It
  flips at that node's upgrade reboot, so it *is* a reliable per-node "this one
  is done" signal — and simultaneously a trap:

⚠ **Version-gated feature detection is unreliable during an upgrade.** For the
hours an upgrade runs, a client asking "what version is this cluster?" gets an
answer that depends on which node answered, and that can change on retry. If
you gate behaviour on version, pin the answer for the operation rather than
re-reading it per call. (`Node.activeVersion` is `0` and is not a version
source.)

#### Fail closed

Treat every one of these as **busy**, not idle:

- either state present and not `"COMPLETE"`
- either field absent — `.get()` returning `None` must never read as "idle"
- a 404, a 502, a non-JSON body, or any other HTTP error
- the request timing out, failing TLS, or the node otherwise unreachable —
  nodes reboot during an update, so any of these is a likely *symptom* of the
  very thing you are checking for

Because a mid-update node can be down or hanging, check the file on more than
one node before concluding the cluster is idle.

#### Progress: use `percent`, not the status text

`percent` and `currentComponent` advanced monotonically across the whole run
(no decreases in any sample). The human-readable `status.statusdetails` is for
display only — it is not a progress indicator, and at least one placeholder
value (`"No-op"`) recurs at several different percentages. Don't drive logic
off it.

#### Don't use `/rest/v1/Condition` to detect an update

It looks like the right answer — there is a first-class
`condition.updateInProgress` flag, and it was `true` throughout the prepare
phase. It fails you at both ends:

- **It stops answering during apply**, along with the rest of the API, exactly
  when you need it.
- **It lags on the way out.** The flag was still `true` about 17 seconds after
  `masterState` had already gone `COMPLETE`, and cleared roughly half a minute
  after that. So a client gating writes on it would keep refusing to write after
  the update was already finished.

`update_status.json` is the channel that tracks the update accurately at both
edges. ⚠ It is **not** guaranteed, though: it disappears when its own node
reboots, and on the 4-node run one ~19-second window had it timing out on
every node at once. Treat it as *more available* than any `/rest/v1/`
endpoint, never as always-up.

If you read `Condition` for other reasons, note that it returns the **full
catalogue of every possible condition on every call** — over 250 entries — each
with a boolean `value`. Presence in the list carries no information; filter on
`value` being true. Only a handful are typically active.

#### Applying an update returns no task tag

`POST /rest/v1/Update/{uuid}/apply` returns **HTTP 200 with an empty task
tag**: `{"taskTag": "", "createdUUID": ""}`. There is no task to poll, so the
usual "wait for the task tag" rule does not apply — `update_status.json` is the
only way to follow progress. The standard `if task_tag:` guard handles this
correctly because `""` is falsy, but don't block waiting for a tag that will
never arrive. `{uuid}` is the version string exactly as `GET /rest/v1/Update`
returns it, e.g. `9.8.4.227597`.

#### Reference implementation, with one caveat

`specific_task/HyperCoreDynamicBalancer/HyperCore_balancer.py` implements this
check with node failover, and reads the correct two fields. Two things in it are
worth understanding before you copy it:

- Its guards are written as `if state and state != "COMPLETE"`, so an **absent**
  field is falsy and reads as idle. It is nonetheless correct across the
  sequence above, because at every point at least one of the two fields is
  present and not `"COMPLETE"` — but the pattern is not safe on its own.
- When *every* node fails the check it concludes no update is running, which is
  right for a never-updated cluster but cannot distinguish that from every node
  being unreachable mid-update. If you need that distinction, treat
  all-nodes-unreachable as busy.

### 6. No cluster VIP — plan for node failover

SC//HyperCore clusters do not provide a floating/virtual IP for the REST API.
Every endpoint is a specific node's address; the same API is served from
every node, but if the node you configured goes down, that endpoint is dead
even though the cluster is healthy. The only VIP-shaped field in the API is
`Node.vips`, which is empty and marked deprecated in the spec.

**This and Rule 5 are the same problem.** A rolling software update takes each
node down in turn for several minutes, so an update is the most likely time a
single-endpoint client will fail — measured directly: a client configured with
the cluster's hostname lost access completely during an upgrade while three of
four nodes were serving, and a client holding all four node addresses never
lost access at all.

For anything long-running:

- Discover all node addresses via `GET /rest/v1/Node` (the `lanIP` field)
- Implement client-side failover across the node list, **with retry** — healthy
  peers were ~97–98% available during an upgrade, not 100%
- **A hostname is one node, not the cluster.** Don't treat a DNS name as an
  address for "the cluster"; it resolves to a single node and dies with it
- Don't rely on DNS round-robin alone — most HTTP stacks pick one resolved
  IP per connection and won't automatically retry siblings

⚠ **Do not use `networkStatus` to decide whether a node's API is usable.**
`GET /rest/v1/Node` filtered on `networkStatus == "ONLINE"` is the obvious way
to build an endpoint list, and it is wrong: during an update, all peers
reported the node being updated as `ONLINE` with `currentDisposition: IN`
while that node's API was completely unreachable. It answered ICMP too. Those
fields describe **cluster membership** — backplane and storage health — not API
reachability, and they are correct to do so. **The only test of an endpoint is
a request to it.**

---

## Auth

Two mechanisms:

1. **HTTP Basic** on every request — simplest for scripts and what most
   examples in this repository use.
2. **Session cookie** — `POST /rest/v1/login` with
   `{"username": "...", "password": "...", "useOIDC": false}` returns a
   `sessionID` (as JSON and as a cookie). Pass it as `Cookie: sessionID=<id>`
   on subsequent requests, and `POST /rest/v1/logout` when done so sessions
   don't linger on the cluster.

Quick connectivity test:

```bash
curl -sk -u <user>:<pass> https://<node-ip>/rest/v1/Cluster | python3 -m json.tool
```

---

## Endpoint corrections (wrong → right)

| If you'd guess... | Actual |
|---|---|
| `SyslogTarget` | `AlertSyslogTarget` |
| `TimeServer` | `TimeSource` |
| `GET /Task/{n}` | `GET /TaskTag/{tag}` (tag is a string) |
| `GET /Version` | `GET /Cluster` → read `icosVersion` from the first element |
| `cluster.name` field | `cluster.clusterName` (read AND write) |
| `SnapshotSchedule` | `VirDomainSnapshotSchedule` |
| `POST /VirDomain/migrate` | `POST /VirDomain/action` with `actionType: "LIVEMIGRATE"` (the migrate endpoint returns 500 on SC//HyperCore 9.7.x) |
| Upload ISOs via `PUT /VirtualDisk/upload` | Three-step `/ISO` flow — `/VirtualDisk/upload` rejects `.iso` ("File type is invalid") |
| `labels: {"k": "v"}` | `labels: {"k": {"value": "<base64-string>"}}` — 9.7+ only; see "Labels" |
| Snapshot body field `virDomainUUID` | `domainUUID` |
| `description` on `POST /VirDomainBlockDevice` | Rejected ("Property not allowed") |
| `labels` on `VirDomainSnapshot` | Rejected on POST and PATCH (PATCH returns 405). GET shows `labels: {}` but it is read-only — use the single-string `label` field |

---

## Cluster

`GET /Cluster` — returns a list (usually one item). Fields of note:
`clusterName` (the cluster name — **not** `name`), `icosVersion` (software
version string), `uuid`.

```
PATCH /Cluster/{uuid}   {"clusterName": "new-name"}   # correct
PATCH /Cluster/{uuid}   {"name": "new-name"}          # WRONG — 400 "Property not allowed"
```

## Nodes

`GET /Node` — read-only. No POST/PATCH/DELETE. The `disposition` field
cannot be set via the REST API. `lanIP` is the per-node API address (see
universal rule 6).

---

## Virtual machines

`GET /VirDomain` — full VM list with embedded `blockDevs` (disks) and
`netDevs` (NICs). Use those embedded arrays rather than separately querying
the BlockDevice/NetDevice endpoints with a filter (rejected — rule 3).

### Power actions

`POST /VirDomain/action` with a **list** body:

```json
[{"virDomainUUID": "<uuid>", "actionType": "START"}]
```

Valid `actionType`: `START`, `SHUTDOWN`, `STOP`, `PAUSE`, `REBOOT`, `RESET`,
`LIVEMIGRATE`, `NMI`.

- `SHUTDOWN` sends an ACPI signal; the guest may ignore it. Poll the VM
  `state` until `SHUTOFF`/`SHUTDOWN`, with a hard-`STOP` fallback on timeout.
- `STOP` is an immediate hard power-off (the web UI's "Power Off").
  `FORCE_STOP` is **not** a valid value.

### Live migration

```json
POST /VirDomain/action
[{"virDomainUUID": "<uuid>", "actionType": "LIVEMIGRATE", "nodeUUID": "<target-node-uuid>"}]
```

- `"LIVEMIGRATE"` has no underscore — `"LIVE_MIGRATE"` returns 400.
- The target field is `nodeUUID`, not `targetNodeUUID`.
- `POST /VirDomain/migrate` exists in the spec but returns 500 on SC//HyperCore 9.7.x —
  do not use it.

### Clone

```json
POST /VirDomain/{uuid}/clone
{"template": {"name": "clone-name", "description": "..."}}
```

What a clone carries and what it resets (verified on SC//HyperCore 9.6/9.7):

- **Carried from source** (unless overridden in `template.*`): description,
  tags, machine type, vCPU/memory, disks (with new disk UUIDs), NICs, SMBIOS.
- **Always reset, by design** (9.7.x, where these fields exist): `labels` →
  `{}` and `runnable` → `true` on every clone path (plain clone and
  clone-from-snapshot). This supports the VM-template workflow
  (`runnable=false` marks a gold-master; its clones must come out
  startable). Re-apply labels — and `runnable=false` if the clone is itself
  a template — with a post-clone PATCH. The same stripping applies to SMB
  export → import round-trips.
- **MAC addresses are regenerated by default.** To keep the source's MACs
  (the web UI's "Clone Existing MAC Addresses" option), GET the source's
  `netDevs` and pass them — including `macAddress` — in `template.netDevs`.
  Only do this when the source VM is retired or powered off; duplicate live
  MACs break the network.
- **Do not pass `template.smbios`** — on current versions it silently drops
  both the override and the source's SMBIOS data. Clone without it (the
  source SMBIOS is inherited), then PATCH the clone if you need changes.
- `bootDevices` on clones of cloud-image-derived VMs can come out empty —
  set it explicitly post-clone (see "Cloud-image VM gotchas" below).

### `useUEFISecureBoot` — v2 API only (9.7.1+), and effectively create-only

The field does not exist in the v1 API at all: it appears in neither the v1
spec nor v1 `GET /VirDomain` responses on any version (verified on 9.6.27
and 9.7.4). On SC//HyperCore 9.6 there is no way to read or set it via REST.

On 9.7.1+ via the v2 API (`/rest/v2/VirDomain`):

- It is readable on GET and settable **at create time only**, via
  `options.useUEFISecureBoot` in `VirDomainCreateOptions` on
  `POST /rest/v2/VirDomain`.
- PATCHing it, or passing it as a clone `template` override, is a **silent
  no-op** (HTTP 200, task COMPLETE, stored value unchanged) — verified on
  9.7.x. The v2 spec does not mark the field read-only; don't trust the
  spec's writability here.
- It defaults to `true` — even on BIOS VMs, where it's meaningless but still
  stored as `true`.

Practical consequence: if a VM needs Secure Boot off (e.g. a migrated
Windows VM that wasn't Secure Boot enrolled, or a Linux guest with an
unsigned kernel), set it in the v2 create call — you cannot flip it to
`false` afterwards through the API.

### Disk create

```json
POST /VirDomainBlockDevice
{"virDomainUUID": "<uuid>", "type": "VIRTIO_DISK", "capacity": 10737418240, "cacheMode": "NONE"}
```

- `type`: `IDE_DISK`, `SCSI_DISK`, `VIRTIO_DISK`, `IDE_CDROM`, `IDE_FLOPPY`,
  `NVRAM`, `VTPM`
- `cacheMode`: `NONE`, `WRITEBACK`, `WRITETHROUGH`
- `description` is rejected on POST ("Property not allowed").
- Hot-add and hot-remove of block devices against **running** VMs works.

**`tieringPriorityFactor`** (integer, default 8): SSD-tiering priority,
mapping to the UI "Priority" setting. `0` = bypass SSD tiering entirely —
useful for temporary/scratch disks (e.g. migration staging) so bulk writes
don't saturate the SSD tier. On tiered (SSD + HDD) clusters, SC//HyperCore software
requires all SSD tiers below 90% full to allow snapshots, clones, and VM
creation — a CRITICAL condition fires when exceeded. On all-flash clusters
the field is accepted but has no effect, so it's safe to set
unconditionally. Restore the default (8) on any disk that becomes a
production VM's disk.

### NIC create

```json
POST /VirDomainNetDevice
{"virDomainUUID": "<uuid>", "type": "VIRTIO", "vlan": 0, "connected": true}
```

`type`: `RTL8139`, `INTEL_E1000`, `VIRTIO`, `PCNET`.

---

## Labels (on `VirDomain` and `VirDomainBlockDevice`) — SC//HyperCore 9.7+ only

Labels do not exist on 9.6: the field is absent from both the 9.6 v1 spec
and 9.6 `GET /VirDomain` responses (verified on 9.6.27). On 9.7.x the field
is readable and writable through both `/rest/v1/` and `/rest/v2/` — though
note that some 9.7 builds' v1 spec omits the labels schema even while the
server enforces it (another reason not to trust spec contents for
capability detection).

**`labels` is not a flat string map.** It's a map of objects with a single
`value` field, and the value must be **base64-encoded**:

```json
"labels": {
  "env":   {"value": "cHJvZHVjdGlvbg=="},
  "owner": {"value": "b3BzLXRlYW0="}
}
```

The schema is enforced by the server even where the spec is vague.
Empirically verified rules (SC//HyperCore 9.7.x):

| Aspect | Rule |
|---|---|
| Key charset | Alphanumeric + `-` + `_` only. No `/`, `.`, `:`, spaces, or unicode. |
| Key length | 1–64 characters. |
| Value charset | Standard base64 (`A–Z a–z 0–9 + / =`). **Not** base64url — `-` and `_` in values are rejected. |
| Value length | 0–256 characters (after encoding). |
| Entry count | Max 64 entries per object. |
| PATCH semantics | **REPLACE, not MERGE.** PATCH `{"labels": {...}}` overwrites the whole map. To merge: GET → modify client-side → PATCH the full map. |
| Shape errors | `null` values, bare string values, missing `"value"`, numeric values, and extra fields are all rejected. |
| Clones | Labels are **not inherited** by clones (any path) — by design. Re-apply via post-clone PATCH. |
| Export/import | Labels are stripped on SMB export round-trips — by design. Back them up out-of-band if they matter. |
| Snapshots | `VirDomainSnapshot` rejects labels entirely (see "Snapshots"). |

Tip: if you need to carry an identifier containing `/` or other forbidden
key characters (e.g. `namespace/name`), put it in the **value** (base64
accepts anything) and keep the key simple.

---

## Snapshots

### Listing

`GET /VirDomainSnapshot` — rejects `?virDomainUUID=` (rule 3). Fetch all and
filter client-side on `snap["domainUUID"]` (the field is `domainUUID`,
**not** `virDomainUUID`).

### Create

```json
POST /VirDomainSnapshot
{
  "domainUUID": "<vm-uuid>",
  "label": "my-snapshot",
  "type": "USER",
  "replication": false
}
```

- The field is `domainUUID` — `virDomainUUID` returns 400.
- `type: "USER"` is the right type for caller-initiated snapshots.
- SC//HyperCore software defaults `replication` to **true** — override to `false` for
  transient snapshots (clone/move intermediates), otherwise the snapshot is
  pushed to any configured replication target, wasting bandwidth and
  potentially delaying local deletion until the remote acknowledges.
- `labels` is rejected on POST and PATCH (PATCH on the resource returns 405
  entirely). Use the single-string `label` field for snapshot identity.

### Response shape gotchas

The `GET /VirDomainSnapshot` response shape is non-obvious:

```json
{
  "uuid": "<snap-uuid>",
  "domainUUID": "<vm-uuid>",
  "label": "...",
  "timestamp": 1700000000,
  "labels": {},
  "deviceSnapshots": [
    {"uuid": "<disk-uuid>", "serialNumber": 2, ...}
  ],
  "domain": {
    "uuid": "<vm-uuid>",
    "blockDevs": [ {"uuid": "...", "type": "VIRTIO_DISK", "capacity": 0, ...} ]
  },
  "type": "USER",
  "replication": false
}
```

- **There is no top-level `blockDevices` field.** Per-disk metadata captured
  at snapshot time (type, capacity, cacheMode...) lives under
  `domain.blockDevs` — the embedded copy of the VM as it was at snapshot
  time. A decoder that looks for a top-level disk array will silently get
  nothing.
- `deviceSnapshots` is storage-level only — disk UUIDs, serial numbers,
  checksums. No type/capacity/cacheMode. Don't use it as the source of disk
  metadata for restores.
- `labels` appears in the response but is always empty (write-rejected).

### Clone a disk from a snapshot

The accepted body shape for
`POST /VirDomainBlockDevice/{live-disk-uuid}/clone` **varies between
builds** — a different shape (`snapshotUUID` + `preserveDiskSignature`) has
been observed accepted on earlier builds, and on SC//HyperCore 9.7.3 that shape is
rejected ("Property not allowed"). Verify against your target version. On
SC//HyperCore 9.7.3 the server enforces this shape:

```json
{
  "options":  {"regenerateDiskID": false},
  "snapUUID": "<vm-snapshot-uuid>",
  "template": {
    "virDomainUUID": "<target-vm-uuid>",
    "type": "VIRTIO_DISK",
    "capacity": 10737418240,
    "cacheMode": "NONE"
  }
}
```

- The UUID **in the path** is the (live) disk's UUID (matches
  `deviceSnapshots[].uuid`); `snapUUID` **in the body** is the VM snapshot's
  own UUID — not a per-device snapshot UUID.
- `template.type` and `template.capacity` are required.
- The clone **auto-attaches** to `template.virDomainUUID` (at
  `template.slot` if given, else the next free slot).
- `template.name` is **silently dropped** (same as on VM clone; verified on
  9.6 and 9.7) — the cloned disk arrives with `name: ""`. Set it via
  post-clone PATCH if needed; the PATCH works on 9.7+ but is **silently
  ignored on 9.6**.
- Snapshot data is independent of the live disk: deleting the live
  VirDomainBlockDevice does not invalidate the snapshot's `deviceSnapshots`;
  you can still clone from the snapshot afterwards.
- `DELETE /VirDomainBlockDevice` also strips that disk's UUID from
  `VirDomain.bootDevices` — capture the boot order before detaching anything
  you intend to reattach.

### `regenerateDiskID` should almost always be `false`

On disk attach/clone operations the API default is `true`, which regenerates
the GPT UUID / MBR signature — and **breaks bootable disk images**: GRUB
stores the disk UUID in `grub.cfg`, Windows stores the MBR signature in the
BCD store. Always send `"regenerateDiskID": false` unless you specifically
need a new disk identity (e.g. attaching a clone alongside its source in the
same VM).

---

## Snapshot schedules

Endpoint: `VirDomainSnapshotSchedule` (not `SnapshotSchedule`). Rejects
`?virDomainUUID=` — fetch all, filter client-side.

---

## Cluster settings endpoints

### DNS — `GET/POST/PATCH /DNSConfig`
Fields: `serverIPs` (list of strings), `searchDomains` (list of strings).

### Time
- NTP servers: `GET/POST/DELETE /TimeSource`, field `host`. To replace the
  set: DELETE each existing entry (each returns a task tag — wait!), then
  POST new ones.
- Timezone: `GET/POST/PATCH /TimeZone`, field `timeZone` (e.g.
  `"America/Chicago"`). PATCH returns a task tag — wait before further
  time-related calls.

### SMTP — `AlertSMTPConfig`
Field names are non-standard:

| Intuitive | Actual |
|---|---|
| `host` | `smtpServer` |
| `username` | `authUser` |
| `password` | `authPassword` |
| `ssl` | `useSSL` |
| `auth` | `useAuth` |
| `from` | `fromAddress` |

### Email alert targets — `GET/POST/DELETE /AlertEmailTarget`
Fields: `emailAddress`, `resendDelay` (seconds), `silentPeriod` (seconds).

### Syslog alert targets — `GET/POST/DELETE /AlertSyslogTarget`
The `protocol` enum requires the full prefixed value:
`"SYSLOG_PROTOCOL_UDP"` / `"SYSLOG_PROTOCOL_TCP"`. Bare `"UDP"` returns 400.

### OIDC — `OIDCConfig`
Fields: `clientID`, `configurationURL`, `scopes`, `sharedSecret`,
`certificate`. **`sharedSecret` is write-only** — GET always returns `""`,
but POST/PATCH requires at least one of `sharedSecret` or `certificate` to
be non-empty. Implication for backup/restore tooling: you cannot round-trip
the secret through the API; store a placeholder and warn on restore.

### Users & roles
`GET/POST/PATCH/DELETE /User` — fields: `username`, `password`, `fullName`,
`roleUUIDs` (list), `sessionLimit`, `sessionExpiration`.
`GET /Role` — read-only list of available roles.

Consider creating a dedicated, least-privilege API user per integration
rather than using a shared admin account: you get a clean audit trail in the
cluster log, and revoking one integration doesn't disturb the others.

### Registration — `GET /Registration` (read-only)

---

## TLS certificate management

`POST /Certificate` with `{"certificate": "<PEM>", "privateKey": "<PEM>"}`
(field is `privateKey`, camelCase).

- **Per-node, not cluster-wide.** A single POST updates only the node you
  connected to. To re-certificate a whole cluster, POST to every node's IP
  individually (`GET /Node` → `lanIP`).
- **The upload restarts that node's API server** — the HTTPS connection
  drops mid-call. Wrap the task-tag wait in a retry loop that tolerates
  connection-reset / SSL-EOF errors for several attempts; the upload usually
  succeeded.
- **Validate before uploading** — a mismatched key or expired cert can leave
  the API unreachable (console-only recovery). Check key↔cert match, expiry,
  and that the SAN actually covers the names/IPs clients connect with.
- SAN tips: include every node FQDN **and** every node IP; IPs must be
  `IP:` SAN entries (a `DNS:10.0.0.1` entry never matches).
- There is no GET on `/Certificate` and no factory reset. To inspect what a
  node serves, open a TLS connection and read the presented certificate. To
  return to a self-signed baseline, generate and upload a fresh self-signed
  cert (ideally with a correct SAN — better than the generic factory one).

---

## ISO images

ISOs use the `/ISO` endpoint — `/VirtualDisk/upload` **rejects** `.iso`
files ("File type is invalid").

### Upload (three steps, each task-tag-waited)

```
1. POST /ISO                {"name": "file.iso", "size": <bytes>, "readyForInsert": false}
   → {"taskTag": ..., "createdUUID": "<uuid>"}
2. PUT /ISO/{uuid}/data     Content-Type: application/octet-stream, Content-Length: <bytes>, raw body
3. PATCH /ISO/{uuid}        {"readyForInsert": true}
```

`name` must end in `.iso`; `size` is create-only; the read-only `path` field
is what you mount.

### Mounting / inserting / ejecting

Create a CDROM device using the ISO's `path` (from `GET /ISO/{uuid}`):

```json
POST /VirDomainBlockDevice
{"virDomainUUID": "<vm-uuid>", "type": "IDE_CDROM", "capacity": 0, "cacheMode": "NONE", "path": "<iso.path>"}
```

To swap media on a **running** VM, PATCH the existing CDROM device with
**both** `path` and `name`: `{"path": "<iso.path>", "name": "<iso-name>"}`
to insert, `{"path": "", "name": ""}` to eject. Sending only `path` fails
the task. There is no ISO download endpoint (`GET /ISO/{uuid}/data` → 405).

---

## Virtual disks (non-ISO images)

`.vmdk`, `.qcow2`, `.vhd`/`.vhdx`, `.img` use the VirtualDisk endpoint.

```
PUT /rest/v1/VirtualDisk/upload?filename=name.ext&filesize=N
Content-Type: application/octet-stream
Content-Length: N
<raw bytes>
```

- The `filename` extension determines the format and is required.
- `Content-Length` is **required** — chunked transfer encoding is rejected.
  When streaming from a URL, get the size from a HEAD request first.
- Returns `{"taskTag": ..., "createdUUID": ...}` — wait for the task.

**Conversion tracking:** SC//HyperCore software renames the disk during processing:
`uploading-<name>` → `converting-<name>` → `<name>`. The VirtualDisk record
has **no `state` field** — poll the `name` field until it equals the final
name. (ISO uploads have no converting phase. On the v2 API, upload returns
a taskTag that covers conversion, which is simpler.)

Streaming a disk image from a URL to the cluster without a temp file:

```bash
URL="https://example.com/disk.img"
FILESIZE=$(curl -sI "$URL" | awk 'tolower($1) ~ /content-length/ {print $2}' | tr -d '\r')
curl -L "$URL" | curl -u <user>:<pass> -k \
  -H "Content-Type: application/octet-stream" \
  -H "Content-Length: $FILESIZE" \
  -T - "https://<node-ip>/rest/v1/VirtualDisk/upload?filename=disk.img&filesize=$FILESIZE"
```

---

## Conditions (health alerts)

`GET /Condition` — the `value` field is a JSON boolean. A useful pattern on
API errors during heavy operations (imports, clones): fetch `/Condition` and
surface any SET CRITICAL/ERROR conditions alongside the HTTP error — "SSD
tier full" explains a 400 far better than "Bad Request".

---

## Cloud-image VM gotchas (Ubuntu cloud images and similar)

VMs provisioned from cloud images (e.g. via clone + cloud-init `cloudInitData`)
have two independent failure modes that both surface when a **second disk is
attached and the VM reboots**:

1. **Empty `bootDevices`** → BIOS reports "No bootable device". Always set
   `bootDevices` explicitly (PATCH the VM with the OS disk's UUID) after
   cloning/creating.
2. **Grub uses `root=/dev/vda1`** because Ubuntu cloud images set
   `GRUB_DISABLE_LINUX_UUID=true` — after a second disk shifts device
   ordering, the initramfs hangs. Fix inside the guest (re-enable UUID-based
   root) or keep disk ordering stable.

Practical cloud-init baseline for debuggability on SC//HyperCore: install
`qemu-guest-agent` (without it, `GET /VirDomain/{uuid}` shows
`guestAgentState: UNAVAILABLE` and `ipv4Addresses: []`, so you can't find
the VM's IP via the API).

Cloud-init data is passed at clone/create time as base64:

```json
"cloudInitData": {"userData": "<base64>", "metaData": "<base64>"}
```

---

## Changed Block Tracking (snapDiff)

`POST /rest/v1/VirDomainBlockDevice/{disk-uuid}/snapDiff` with
`{"snapshotSerialFrom": N, "snapshotSerialTo": M}` returns an array of
changed block intervals (`[{"lower": ..., "upper": ...}, ...]`) between two
snapshot serials — the native CBT API used by backup integrations.

**Available in the v1 API on both 9.6 and 9.7** (verified live on 9.6.27 and
9.7.x; present in both versions' v1 specs, and in the v2 spec as well).

- Serial numbers come from `VirDomainSnapshot.deviceSnapshots[].serialNumber`
  (different from snapshot UUIDs).
- `snapshotSerialFrom: 0` means HEAD (the live device state).
- Although it's a POST, the operation is read-only — no taskTag is returned
  and no task wait is needed.

---

## SC//Fleet Manager™ API

SC//Fleet Manager™ has its own API, separate from that of SC//HyperCore software:
`https://api.scalecomputing.com/api/v2` with an
`api-key` header (generate keys at fleet.scalecomputing.com). Standard
public TLS — no self-signed concerns. Collection endpoints are paginated
(`offset`/`limit`, max 200 per page) — iterate if you have more clusters
than one page. See the `Fleet Manager/` folder for examples.

---

*Scale Computing, SC//HyperCore, and SC//Fleet Manager are trademarks of
Scale Computing, Inc. Other marks are the property of their respective owners.*
