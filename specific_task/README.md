# SC//HyperCore™ Cluster REST API Examples — Task Specific

This directory contains scripts for running task-specific API queries against an
SC//HyperCore™ virtualization suite cluster.

These scripts are only examples and demonstrate common use cases with the API.
Refer to the API docs on an SC//HyperCore™ virtualization suite cluster for a
detailed guide on available calls.

Everything here is provided "as is", without warranty of any kind. Test against
a lab cluster before running anything against production.

## Contents

### Single-file examples

| Script | Language | What it does |
|---|---|---|
| [`SnapshotReport.ps1`](SnapshotReport.ps1) | PowerShell | Reports replication snapshots that fall outside a defined RPO / age timeframe. Optional arguments retrieve additional detail about snapshots, schedules and remote cluster connections. |
| [`checkAffinity.ps1`](checkAffinity.ps1) | PowerShell | Lists each node's LAN IP and UUID, then each VM with its current node and its preferred and backup affinity assignments. |
| [`SetTag.ps1`](SetTag.ps1) | PowerShell | Sets a VM tag on every VM whose name matches a string, optionally restarting the VM. Useful for any tag, and especially for applying a GPU tag and restarting the VM to enable the vGPU. |
| [`iso-upload.ps1`](iso-upload.ps1) | PowerShell | Demonstrates uploading an ISO to a cluster, including the two-step create-then-`PUT`-payload pattern. |
| [`NodeCPUUsage.py`](NodeCPUUsage.py) | Python 3 | Reports the highest node CPU utilization in the cluster. Uses only the standard library. |

### Multi-file examples

| Directory | Language | What it does |
|---|---|---|
| [`vm-export-import/`](vm-export-import/) | PowerShell + Python | Export a VM to an SMB share and import one back, in both languages. Covers the `pathURI` credential format, task-tag polling, how export and import failures are reported, and what changes across a round trip. Resolves issues [#1](https://github.com/ScaleComputing/RestAPIExamples/issues/1) and [#2](https://github.com/ScaleComputing/RestAPIExamples/issues/2). |
| [`upload_iso/`](upload_iso/) | Python 3 | Downloads an ISO, verifies its checksum, and uploads it to a cluster. The Python counterpart to `iso-upload.ps1` above — the same task, so pick whichever language suits you rather than treating them as different examples. |
| [`HyperCoreDynamicBalancer/`](HyperCoreDynamicBalancer/) | Python 3 | Single-file automated VM load balancer: watches node CPU and RAM and live-migrates VMs to even out load. Has a `DRY_RUN` mode, which is where to start. |
| [`HyperCoreBalancerv2/`](HyperCoreBalancerv2/) | Python 3 (containerized) | A much larger successor to the above: reactive balancing, optional Prophet-based predictive balancing, and tag-driven affinity enforcement, shipped as a `docker-compose` stack with InfluxDB and a dashboard. |
| [`superaudit/`](superaudit/) | Python 3 | VM inventory, compliance reporting, capacity planning and historical monitoring for a cluster, with continuous collection, a web dashboard and trend analysis. |
| [`ZabbixPlugin/`](ZabbixPlugin/) | Zabbix templates | Zabbix monitoring templates that use the REST API to auto-discover and monitor nodes, VMs and physical drives, creating one Zabbix host per discovered object. |

Each directory has its own README with setup and usage detail.

## Things that apply to everything here

A few API behaviours bite every one of these examples, so they are worth knowing
before you read any single script.

**Poll the task tag after every mutating call.** Any `POST`, `PATCH` or `DELETE`
may return `{"taskTag": "<id>"}`, and the work is not finished when the HTTP
call returns. Poll `GET /rest/v1/TaskTag/<id>` until `state` leaves
`RUNNING`/`QUEUED`; `ERROR` and `UNINITIALIZED` are failures. Issuing the next
call without waiting is the most common mistake made against this API.

**Every GET returns an array**, even a lookup by UUID — take the first element.

**Clusters use a self-signed certificate**, so these examples disable
certificate validation. That is only safe on a trusted network.

**Clusters negotiate TLS 1.3 only** — every one we checked, across 9.6 and
9.7 and 9.8, refuses a TLS 1.2 handshake. The client's TLS library has to
support it, and this is where PowerShell and Python part company: PowerShell
is .NET, and .NET uses a different TLS backend on each platform.

| Client | TLS 1.3 | Reaches a cluster |
|---|---|---|
| Windows PowerShell 5.1 on Windows Server 2016 | no (Schannel has none) | ❌ `Could not create SSL/TLS secure channel` |
| PowerShell 7+ on macOS | no (.NET's macOS TLS stops at 1.2) | ❌ `bad protocol version` |
| PowerShell 7+ on Linux | yes (OpenSSL) | ✅ |
| Python, Ansible, curl — any OS | yes (OpenSSL) | ✅ |
| PowerShell 5.1 or 7+ on Windows 10 | no (Schannel has none) | ❌ same as Server 2016 |
| PowerShell 7+ on Windows 11 / Server 2022+ | yes | ✅ expected; not verified here |

So the same machine can run the Python examples fine and fail every PowerShell
one. Windows gained TLS 1.3 in Windows 11 / Server 2022, so Server 2019,
Server 2016 and **Windows 10 in every build** are all in the same position as
the 2016 host measured above — a Windows 10 workstation cannot run the
PowerShell examples at all. On a capable Windows build, prefer PowerShell 7
over Windows PowerShell 5.1: 5.1 runs on .NET Framework 4.8, whose TLS 1.3
support Microsoft does not officially claim. A script that pins
`SecurityProtocol` to `Tls12` fails the same way even on a Windows build that
does support 1.3 — the pin is then the blocker, not the OS.

The failure arrives as a TLS error before any credential is sent, which makes
it easy to mistake for an authentication or certificate problem. If a
PowerShell example cannot connect at all, check the client platform first.

See [`vm-export-import/README.md`](vm-export-import/README.md) for the full
measurement behind that table.
