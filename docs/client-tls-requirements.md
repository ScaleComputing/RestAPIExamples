# SC//HyperCore™ — Client TLS Requirements

**SC//HyperCore™ clusters negotiate TLS 1.3 only.** A client that cannot do
TLS 1.3 cannot reach the REST API at all, and the failure arrives as a TLS
error *before any credential is sent* — which makes it read like an
authentication problem, a certificate problem, or a firewall problem. It is
none of those.

This is the most common reason a working API example fails on one machine and
succeeds on another, so it is worth ruling out first.

> Measured 2026-09-10 against four clusters spanning **9.6.32 through 9.8.4**,
> from a macOS client. Rows below marked *measured* were observed directly;
> *inferred* means it shares its TLS stack with something that was measured;
> *documented* comes from that runtime's own vendor support matrix and was not
> reproduced here. The OpenSSL rows were measured on one platform only — the
> library, not the OS, is what decides, so the same OpenSSL elsewhere is
> expected to behave identically.

---

## The 10-second check

Run this against the cluster from the machine that is failing:

```bash
openssl s_client -tls1_2 -connect <node-ip>:443 </dev/null 2>&1 | grep -i alert
```

If you get:

```
tlsv1 alert protocol version ... SSL alert number 70
```

…the cluster is refusing TLS 1.2, which is expected and correct. Now confirm
the client itself can do 1.3:

```bash
openssl s_client -connect <node-ip>:443 </dev/null 2>&1 | grep -E "^New,|^ *Protocol"
```

```
Protocol: TLSv1.3                                      # OpenSSL 3.x
    Protocol  : TLSv1.3                                # LibreSSL (macOS)
```

Read the `Protocol` line, not the `New,` line above it. LibreSSL reports
`New, TLSv1/SSLv3, Cipher is AEAD-CHACHA20-POLY1305-SHA256` for a session it
then correctly describes as `Protocol : TLSv1.3`, which looks alarming and
means nothing. The two libraries also indent differently, hence the loose
pattern above.

`openssl` is not the tool that matters, though — it links its own TLS library.
If `openssl` succeeds and your script still fails, the script's runtime uses a
different TLS stack. That is the whole problem, and the next section is why.

---

## It is not a client bug — the cluster requires 1.3

Worth stating plainly, because the failure usually shows up first in
PowerShell and gets blamed on PowerShell. Python, which works fine by default,
fails in exactly the same way the moment it is capped at TLS 1.2:

```python
ctx = ssl.create_default_context()
ctx.maximum_version = ssl.TLSVersion.TLSv1_2      # mimic a client with no 1.3
# -> ssl.SSLError: [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version
```

Same script with the cap removed connects and reports
`TLSv1.3 / TLS_AES_256_GCM_SHA384`. So the constraint lives on the cluster and
applies to every client equally. What differs between clients is only whether
their TLS library *has* TLS 1.3.

Clusters measured, all four identical — default `TLSv1.3`, and
`tlsv1 alert protocol version` on a TLS 1.2 ClientHello:

| `icosVersion` | default protocol | TLS 1.2 ClientHello |
|---|---|---|
| 9.6.32 | TLS 1.3 | refused, alert 70 |
| 9.7.8 | TLS 1.3 | refused, alert 70 |
| 9.8.3 | TLS 1.3 | refused, alert 70 |
| 9.8.4 | TLS 1.3 | refused, alert 70 |

No cluster in that range accepted TLS 1.2. Treat TLS 1.3 as a requirement, not
a preference.

---

## Which clients can reach a cluster

TLS 1.3 support is a property of the **TLS library**, not of the language or
the tool. There are three libraries in practice:

- **OpenSSL** — TLS 1.3 from **1.1.1** onward. Used by Python, Ansible®,
  curl, Ruby, PHP, and .NET *on Linux*.
- **Schannel** (Windows) — TLS 1.3 from **Windows 11 / Server 2022** onward.
  Used by .NET on Windows, WinHTTP, and anything built on the Windows stack.
- **Apple SecureTransport / Network.framework** — as consumed by .NET on
  macOS, **TLS 1.2 is the ceiling**.
- **LibreSSL** — TLS 1.3 from **3.3** onward. This is what macOS's bundled
  `curl` links, so `curl` on macOS works even though PowerShell on the same
  machine does not. A good illustration that the OS is not the thing that
  decides.

.NET is the awkward one, because it uses a *different* library on each
platform. That is why PowerShell's answer depends on where you run it:

| Client | TLS library | 1.3 | Reaches a cluster | |
|---|---|---|---|---|
| Python (`requests`, `urllib3`) | OpenSSL ≥ 1.1.1 | yes | ✅ | measured on macOS |
| curl | LibreSSL 3.3.6 | yes | ✅ | measured on macOS |
| Ansible® | OpenSSL, via Python | yes | ✅ expected | inferred — same stack as Python |
| PowerShell 7+ on Linux | OpenSSL | yes | ✅ | measured |
| PowerShell 7+ on macOS | SecureTransport | **no** | ❌ `bad protocol version` | measured |
| Windows PowerShell 5.1 on Server 2016 | Schannel | **no** | ❌ `Could not create SSL/TLS secure channel` | measured |
| Windows PowerShell 5.1 on Server 2019 | Schannel | **no** | ❌ same as 2016 | documented |
| PowerShell 5.1 or 7 on Windows 10 (any build, incl. 22H2) | Schannel | **no** | ❌ same as 2016 | documented |
| PowerShell 7+ on Windows 11 / Server 2022+ | Schannel | yes | ✅ expected | documented |
| Windows PowerShell 5.1 on Windows 11 / Server 2022+ | Schannel + .NET Framework 4.8 | OS yes, runtime unclear | ⚠ see below | not tested |
| Python on RHEL®/CentOS® 7 | OpenSSL 1.0.2 | **no** | ❌ expected | documented |
| Java™ 8 before 8u261 | JSSE | **no** | ❌ expected | documented |
| Java™ 11+ | JSSE | yes | ✅ expected | documented |
| Go 1.13+ | `crypto/tls` | yes | ✅ expected | documented |

### Two Windows notes worth calling out

**Windows 10 is the one that catches people.** It is a desktop OS, so it is
where people run examples by hand, and it has **no usable TLS 1.3** in any
build including 22H2. Schannel carried draft TLS 1.3 code from build 1903
behind a registry flag, off by default and never supported for production, so
"Windows 10 supports TLS 1.3" turns up in search results and is wrong in
practice. Windows 10 also passed end of support in October 2025.

**On a capable Windows build, prefer PowerShell 7 over Windows PowerShell
5.1.** PowerShell 7 runs on modern .NET, where TLS 1.3 on Windows is
unambiguous. Windows PowerShell 5.1 runs on .NET Framework 4.8, which added a
`Tls13` enum value but which Microsoft does not officially document as
supporting TLS 1.3 — it steers callers to `SystemDefault` instead. We have not
tested that combination, so treat it as unknown rather than working.

---

## Self-inflicted failures

Two ways to produce this failure on a machine that is perfectly capable.

### Pinning `SecurityProtocol` to TLS 1.2

Very common in older PowerShell examples, and it was standard advice back when
the problem was servers that only spoke TLS 1.0:

```powershell
# DON'T: this caps the client at 1.2 and guarantees the handshake fails,
# even on Windows 11 / Server 2022 where Schannel does support 1.3.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

Leave it alone. The default, `SystemDefault`, lets the OS offer the best
protocol it has. If you must be explicit, include `Tls13` — but note the enum
value does not exist at all on Server 2016, so referencing it there is itself
an error.

The same applies to any client that pins a maximum version: `curl --tlsv1.2`
with `--tls-max 1.2`, a Python `ssl` context with
`maximum_version = TLSv1_2`, a Java `-Dhttps.protocols=TLSv1.2`.

### An old TLS library under a current-looking tool

A modern Python on an old distribution still links that distribution's
OpenSSL. `python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"` tells you what
you actually have; anything below 1.1.1 has no TLS 1.3 regardless of the
Python version. The same applies to `curl -V`.

---

## Diagnosing from the error message alone

These all mean "no TLS 1.3", and none of them mentions TLS:

| Client | Message |
|---|---|
| Windows PowerShell 5.1 | `The request was aborted: Could not create SSL/TLS secure channel.` |
| PowerShell 7 / .NET | `The SSL connection could not be established` → inner: `Authentication failed` → inner: `bad protocol version` |
| Python `requests` | `SSLError(... [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version)` |
| curl | exit code **35**, `... SSL routines ... tlsv1 alert protocol version` (the numeric error code varies by TLS library) |
| openssl s_client | `SSL alert number 70` |

Two traps in how these surface in code:

- In Python, `SSLError` subclasses **`ConnectionError`, not `Timeout`** — code
  that catches only timeouts will let this through.
- In .NET the useful text is two `InnerException` levels down; the top-level
  message says only that the SSL connection could not be established. Walk the
  chain before reporting the error.

---

## Recommendations

- **Writing a client?** Python or any OpenSSL-based runtime works everywhere
  and needs nothing special. This is the default choice.
- **Writing PowerShell?** Say in the script header which platforms can run it.
  PowerShell 7 on Linux and on Windows 11 / Server 2022+ are the safe targets;
  macOS cannot work at any version.
- **Never pin the TLS version.** See above.
- **Do not conflate this with certificate handling.** Clusters ship
  self-signed certificates, so clients also need to trust or bypass the
  certificate — that is a *separate* problem, and bypassing certificate
  validation does nothing for a protocol-version failure. See the
  "TLS certificate management" section of
  [`hypercore-api-field-notes.md`](hypercore-api-field-notes.md).

---

*Scale Computing and SC//HyperCore are trademarks of Scale Computing, Inc.
Windows, PowerShell, and .NET are trademarks of Microsoft Corporation. Other
marks are the property of their respective owners.*
