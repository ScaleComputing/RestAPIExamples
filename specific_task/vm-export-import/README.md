# VM Export and Import

Examples for exporting a VM out of an SC//HyperCore™ cluster to an SMB share,
and importing one back in, in both PowerShell and Python.

| File | Language | What it does |
|---|---|---|
| `VMExport.ps1` | PowerShell | Export a VM (or one of its snapshots) to an SMB share |
| `VMImport.ps1` | PowerShell | Import a VM from a previously exported directory |
| `HyperCoreTransfer.ps1` | PowerShell | Shared helpers, dot-sourced by both `.ps1` scripts |
| `vm_export.py` | Python 3 | Export a VM (or one of its snapshots) to an SMB share |
| `vm_import.py` | Python 3 | Import a VM from a previously exported directory |
| `hypercore_transfer.py` | Python 3 | Shared helpers, imported by both `.py` scripts |

The two implementations send identical request bodies; pick whichever suits
your environment. The Python scripts need `requests`
(`pip install requests`). The PowerShell scripts run on Windows PowerShell 5.1
and PowerShell 7+ — but see **Client TLS requirement** below, which is the
first thing to check if a script cannot connect at all.

## The endpoints

```
POST /rest/v1/VirDomain/{uuid}/export     body: {"target": {...}, "snapUUID": "..."}
POST /rest/v1/VirDomain/import            body: {"source": {...}, "template": {...}}
```

`target` and `source` take the same core fields; only `pathURI` is required:

| Field | Export | Import | Notes |
|---|---|---|---|
| `pathURI` | ✅ required | ✅ required | destination or source, credentials included |
| `definitionFileName` | ✅ | ✅ | the VM definition XML written / read |
| `format` | ✅ | ✅ | empty string means qcow2 |
| `allowNonSequentialWrites` | ✅ | ✅ | defaults to `true` |
| `parallelCountPerTransfer` | ✅ | ✅ | streams per disk transfer |
| `compress` | ✅ | — | compress the disk images |
| `compat` | ✅ | — | qcow2 compatibility level, e.g. `0.10` |

Two fields sit outside that object:

- `snapUUID` (export) exports a `VirDomainSnapshot` instead of the VM's
  current state.
- `template` (import) overrides fields of the VM being created. `name` is the
  common one; `cloudInitData` and `operatingSystem` also work. Leave it `{}`
  to take everything from the definition file.

## Building the pathURI

Credentials travel **inside** the URI — the API has no separate credential
field:

```
smb://user:password@server/share/path
smb://DOMAIN;user:password@server/share/path      # Active Directory account
```

The domain form uses a semicolon, which is libsmbclient syntax, not a typo.

Both sets of scripts URL-encode the user and password for you, so a password
containing `@`, `:`, `/` or `#` does not corrupt the URI. The cluster
percent-decodes the userinfo before using it: re-sending a known-good password
with its first character percent-escaped (`%53` for `S`, and so on) exported
just as successfully as the literal form. So the encoding is the correct thing
to do rather than a hopeful one. If you pass a complete `-PathURI` /
`--path-uri` yourself, you must encode it yourself.

Because the password is in the URI, **neither script ever prints the URI
as given** — they print a masked copy. Keep that habit in anything you build
from these: a PowerShell transcript or a CI log will otherwise capture it.

`http://` works as a `pathURI` too, but only on the **v2** API
(`--api-version v2` / `-ApiVersion v2`). SMB and HTTP are mutually exclusive
for a given transfer, and NFS is not supported.

## Waiting for the task

Both endpoints return a task tag, and the transfer is *not* finished when the
HTTP call returns:

```json
{"taskTag": "906", "createdUUID": ""}
```

Poll `GET /rest/v1/TaskTag/906` until `state` leaves `RUNNING`/`QUEUED`.
`ERROR` and `UNINITIALIZED` are failures; anything else terminal is success.
`progressPercent` rose steadily in every transfer we watched, so both scripts
print it as a progress indicator — treat that as an observation rather than a
guarantee. Both scripts poll for you, with a `-TimeoutSec` / `TASK_TIMEOUT`
you should raise for a large VM rather than assuming a stall.

## Reading a failure

A misconfigured share does **not** come back as a failed task. It comes back
as a synchronous **HTTP 400**, before any task tag exists, with a JSON body:

```json
{"error":"smb://10.0.0.50/share/path export failed no access or invalid URI "}
```

The API does not distinguish causes. All four of these produced that same
message, character for character, apart from the URI:

- an unreachable server
- a share or directory that does not exist
- a valid share with the wrong password
- a valid share and a `definitionFileName` that is not in it

So the message tells you the transfer did not start, and nothing more — check
all four. Note the cluster strips the credentials out of the URI it echoes
back, so this body is safe to log.

A **schema** mistake also returns 400, but with a plain-text body rather than
JSON:

```
Request has one or more errors
  In body
    For Content-Type application/json
      Invalid value
        at: target
          One or more required properties missing: pathURI
```

Both `target` and `source` reject unknown fields outright
(`at: target > bogusField / Property not allowed`), so a typo in a field name
fails loudly rather than being ignored. Sending `target` to the import
endpoint gives `One or more required properties missing: source`.

## What changes across a round trip

Measured on a 9.7.8 cluster, exporting a stopped VM and importing it back:

- **An import always attaches an empty `IDE_CDROM`** that the source VM did
  not have.
- **If the imported VM's `operatingSystem` is a Windows value, the import also
  attaches `scale-guest-tools.iso`** as a second `IDE_CDROM`. Importing the
  same export with `template.operatingSystem = "os_other"` produces only the
  empty CDROM, so this is driven by the OS field rather than being
  unconditional. Its `capacity` read as 0 immediately after one import and
  ~28 MiB after another, so do not treat that figure as settled.
- `bootDevices` therefore does not match the source either — it grew from 2
  entries to 3 in that run.
- `tags`, `description`, `mem`, `numVCPU`, `machineType` and the VIRTIO disk's
  capacity all came across unchanged.
- The imported VM is created **stopped**, with a new UUID and new disk UUIDs.

So check `blockDevs` and `bootDevices` after an import rather than assuming
the device list matches the source.

## Client TLS requirement

Every cluster we checked — four of them, spanning 9.6.32 through 9.8.4 —
negotiates **TLS 1.3 only**, refusing a TLS 1.2 handshake with
`tlsv1 alert protocol version` (alert 70). The client's TLS stack therefore has to support TLS 1.3, and
several common ones do not. PowerShell is .NET, and .NET uses a different TLS
backend on each platform, so the answer depends on where you run it:

| Client | TLS 1.3 | Reaches a cluster | |
|---|---|---|---|
| Windows PowerShell 5.1 on Windows Server 2016 | no (Schannel) | ❌ `Could not create SSL/TLS secure channel` | measured |
| PowerShell 7+ on macOS | no (.NET's macOS TLS caps at 1.2) | ❌ `bad protocol version` | measured |
| PowerShell 7+ on Linux | yes (OpenSSL) | ✅ | measured |
| Python `requests`, any OS | yes (OpenSSL) | ✅ | measured |
| Windows PowerShell 5.1 on Windows 10 | no (Schannel) | ❌ same as 2016 | not measured here |
| PowerShell 7+ on Windows 11 / Server 2022+ | yes | ✅ expected | not measured here |
| Windows PowerShell 5.1 on Windows 11 / Server 2022+ | OS yes, .NET Framework unclear | ⚠ see below | not measured here |

Windows gained TLS 1.3 in **Windows 11 and Server 2022**. Everything older is
in the same position as the Server 2016 host we measured: Server 2019, Server
2016, and **Windows 10 in every build, including 22H2**. Windows 10 is the one
that catches people out — Schannel carried draft TLS 1.3 code from 1903 behind
a registry flag, off by default and never supported for production use, so a
Windows 10 workstation cannot run these PowerShell examples at all.

On a TLS 1.3-capable Windows build, prefer **PowerShell 7** over Windows
PowerShell 5.1. PowerShell 7 runs on modern .NET, where TLS 1.3 support on
Windows is unambiguous. Windows PowerShell 5.1 runs on .NET Framework 4.8,
which added the `Tls13` enum value but which Microsoft documents as not
officially supporting TLS 1.3, steering callers to `SystemDefault` instead. We
have not measured that combination, so treat 5.1-on-Windows-11 as untested
rather than working.

Two things follow. First, this is not specific to these examples — it applies
to every PowerShell script in this directory. Second, the failure arrives as a
TLS error *before any credential is sent*, which makes it easy to mistake for
an authentication or certificate problem. If a PowerShell example cannot
connect at all, check the client platform before you check anything else.

One related trap worth naming, because plenty of older examples do it: a
script that pins `[Net.ServicePointManager]::SecurityProtocol` to `Tls12` will
fail this way **even on a Windows build whose Schannel supports TLS 1.3** — the
pin, not the OS, is the blocker. `HyperCoreTransfer.ps1` deliberately leaves
the protocol at `SystemDefault`.

Certificate validation is disabled in both implementations, because clusters
ship a self-signed certificate. That is safe only on a trusted network; if you
have uploaded a certificate to the cluster, remove the bypass.

## Examples

Export a VM, then import it back under a new name:

```bash
# Python
export SC_USERNAME=admin SC_PASSWORD=admin

./vm_export.py --node 10.0.0.1 --vm-name my-vm \
    --smb-server 10.0.0.50 --smb-share exports --smb-path hcexports/my-vm \
    --smb-user administrator --smb-domain example.local

./vm_import.py --node 10.0.0.1 --name my-vm-restored \
    --smb-server 10.0.0.50 --smb-share exports --smb-path hcexports/my-vm \
    --smb-user administrator --smb-domain example.local
```

```powershell
# PowerShell
.\VMExport.ps1 -Node 10.0.0.1 -VMName my-vm `
    -SmbServer 10.0.0.50 -SmbShare exports -SmbPath hcexports/my-vm `
    -SmbDomain example.local

.\VMImport.ps1 -Node 10.0.0.1 -Name my-vm-restored `
    -SmbServer 10.0.0.50 -SmbShare exports -SmbPath hcexports/my-vm `
    -SmbDomain example.local
```

Both prompt for the cluster and share credentials when they are not supplied.
The definition file name defaults to the last element of the path plus `.xml`
(`hcexports/my-vm` → `my-vm.xml`), so the export and the import agree without
you naming it twice.

Pass `-DefinitionFileName` / `--definition-file` if you want something else.
The name really is independent of the directory — exporting to
`hcexports/apiexample-mismatch` with `definitionFileName: custom-name.xml` and
importing that same pair both succeeded — so the default is a convention (it
matches what the cluster UI writes), not a constraint. But the two sides must
agree: pointing the import at the right directory with the wrong definition
file name fails with the same generic `no access or invalid URI` 400 as a
missing share, which is why these scripts derive one from the other.

Export a snapshot rather than the VM's current state:

```bash
./vm_export.py --node 10.0.0.1 --vm-name my-vm --snapshot-uuid 1b0e... \
    --smb-server 10.0.0.50 --smb-share exports --smb-path hcexports/my-vm-snap \
    --smb-user administrator
```

Seed an imported VM with cloud-init:

```bash
./vm_import.py --node 10.0.0.1 --name my-vm-seeded \
    --path-uri 'smb://administrator:secret@10.0.0.50/exports/hcexports/my-vm' \
    --user-data-file user-data.yaml --meta-data-file meta-data.yaml
```

## What was exercised

Against a single-node 9.7.8 cluster, exporting a stopped 10 GiB VM to a
Windows SMB share with an Active Directory account:

- full export → import round trips in **both** languages, with byte-identical
  request bodies
- `snapUUID` (exporting a snapshot rather than the VM's current state) and
  `compress: true`, both successful
- the four failure causes above, plus the schema-rejection shapes
- `template.name` and `template.operatingSystem` overrides

Not exercised, and therefore not claimed to work: exporting a **running** VM,
the `cloudInitData` seed on import, `parallelCountPerTransfer`, `compat`, and
the `http://` (v2) transport.

## Resolves

These examples were written to close
[#1](https://github.com/ScaleComputing/RestAPIExamples/issues/1) (export) and
[#2](https://github.com/ScaleComputing/RestAPIExamples/issues/2) (import).
