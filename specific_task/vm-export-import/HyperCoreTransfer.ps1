<#
HyperCoreTransfer.ps1

Shared helpers for the SC//HyperCore(TM) VM export / import examples. Dot-source
it from a script in the same directory:

    . "$PSScriptRoot/HyperCoreTransfer.ps1"

What lives here is the plumbing every SC//HyperCore REST client needs, and
nothing specific to export or import:

  * Invoke-ScaleRest      -- one REST call with self-signed TLS handled on both
                             Windows PowerShell 5.1 and PowerShell 7+
  * Wait-ScaleTask        -- poll a task tag until it reaches a terminal state
  * Invoke-ScaleTaskCall  -- POST a body and then wait on the returned task tag
  * New-ScaleSmbPathUri   -- build an SMB pathURI with the credentials
                             URL-encoded, plus a masked copy safe to print

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

SECURITY NOTE
    Certificate validation is bypassed so the examples work against a
    cluster's self-signed certificate. Only do this on a trusted network. If
    you have uploaded a certificate to the cluster, remove the bypass.

PLATFORM NOTE
    SC//HyperCore clusters negotiate TLS 1.3 only. .NET on macOS tops out at
    TLS 1.2, so PowerShell on macOS cannot reach a cluster at all -- the
    handshake fails with "bad protocol version" before any credential is sent.
    Confirmed working: PowerShell 7+ on Linux, and on Windows 11 / Server
    2022+, where .NET's TLS stack supports 1.3. Windows PowerShell 5.1 has
    not been confirmed against a cluster on any Windows version we tested --
    its TLS stack there has no TLS 1.3 regardless of the OS build. See
    README.md for the full measured table. The Python examples alongside
    these use OpenSSL and work everywhere, including macOS.
#>

# PowerShell 7+ takes -SkipCertificateCheck per call. Windows PowerShell 5.1
# has no such parameter, so it needs the older process-wide policy shim.
$script:SupportsSkipCertCheck =
    (Get-Command Invoke-RestMethod).Parameters.ContainsKey('SkipCertificateCheck')

if (-not $script:SupportsSkipCertCheck) {
    if (-not ('TrustAllCertsPolicy' -as [type])) {
        Add-Type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # Deliberately NOT pinning SecurityProtocol here. Clusters negotiate TLS
    # 1.3 only, and pinning Tls12 -- which plenty of older examples do -- is
    # itself enough to cause the handshake to fail, even on a Windows build
    # whose Schannel does support 1.3. Leaving it at SystemDefault lets the OS
    # offer the best protocol it has.
}


function Get-ScaleApiBase {
    <#  Build the REST base URL for a node address, which may be an IP, an
        FQDN, or either of those with a scheme already attached. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Node,
        [string] $ApiVersion = 'v1'
    )
    $n = $Node.Trim().TrimEnd('/')
    if ($n -notmatch '^https?://') { $n = "https://$n" }
    return "$n/rest/$ApiVersion"
}


function Invoke-ScaleRest {
    <#  One REST call against the cluster. Returns the deserialised body.

        On a non-2xx the cluster's response body is written to the host before
        the error is rethrown -- for export and import a 400 names the exact
        field or share problem, which the status code alone does not. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Uri,
        [string] $Method = 'GET',
        [Parameter(Mandatory = $true)] [PSCredential] $Credential,
        $Body,
        [int] $TimeoutSec = 60
    )

    # Send basic auth preemptively rather than relying on -Credential. Windows
    # PowerShell 5.1 and PowerShell 7 differ over when they will answer a 401
    # challenge, and PowerShell 7's -Authentication Basic refuses a plain-http
    # URL without an extra switch. An explicit header behaves the same on both.
    $pair = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))

    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = @{ Authorization = "Basic $encoded" }
        ContentType = 'application/json'
        TimeoutSec  = $TimeoutSec
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) { $params['Body'] = $Body }
    if ($script:SupportsSkipCertCheck) { $params['SkipCertificateCheck'] = $true }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        # Set-StrictMode makes a bare $_.Exception.Response throw when the
        # exception type has no such property, so probe for it first.
        $status = $null
        $response = $_.Exception.PSObject.Properties['Response']
        if ($response -and $response.Value) { $status = [int]$response.Value.StatusCode }

        $detail = $null
        if ($_.PSObject.Properties['ErrorDetails'] -and $_.ErrorDetails) {
            $detail = $_.ErrorDetails.Message
        }

        $where = if ($null -ne $status) { "returned HTTP $status" } else { 'failed' }
        Write-Host "ERROR: $Method $Uri $where" -ForegroundColor Red
        if ($detail) { Write-Host $detail -ForegroundColor Red }
        throw
    }
}


function Get-ScaleRecords {
    <#  Normalise a response into a flat array of records.

        Two things combine badly here. Every GET on the SC//HyperCore API
        returns a JSON array, even a lookup by UUID. And Invoke-RestMethod
        hands a top-level JSON array back as a single Object[] rather than as
        a stream of records -- so @(Invoke-ScaleRest ...) gives a ONE-element
        array wrapping the list, not the list.

        That is worth more than a shrug, because PowerShell's -eq against an
        array returns the matching elements rather than $true/$false. A
        Where-Object filter over the unflattened value is therefore truthy and
        passes the entire list through instead of selecting from it, and the
        caller ends up holding every VM on the cluster while believing it holds
        one. Flattening in one place is what stops that.

        Returns the flat array as a single value (note the leading comma), so
        assign it rather than wrapping the call in @(). #>
    param($Response)

    $flat = New-Object System.Collections.ArrayList
    foreach ($item in , $Response) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Array]) {
            foreach ($record in $item) { [void]$flat.Add($record) }
        }
        else {
            [void]$flat.Add($item)
        }
    }
    return , $flat.ToArray()
}


function Wait-ScaleTask {
    <#  Poll GET /TaskTag/<tag> until the task leaves RUNNING / QUEUED.

        Every POST, PATCH and DELETE on the SC//HyperCore API may return a
        taskTag, and the work is not finished when the HTTP call returns -- it
        is finished when that task reaches a terminal state. Export and import
        copy disk data, so raise -TimeoutSec for a large VM rather than
        assuming a stall.

        Returns the final task record. Throws on ERROR or UNINITIALIZED. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $TaskTag,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential,
        [string] $Label = 'task',
        [int] $TimeoutSec = 3600,
        [int] $PollSeconds = 2
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastState = $null
    $lastPercent = -1

    while ((Get-Date) -lt $deadline) {
        # Every GET on this API returns a single-element array, even a lookup
        # by id -- hence Get-ScaleRecords and the [0].
        $records = Get-ScaleRecords (Invoke-ScaleRest -Uri "$Base/TaskTag/$TaskTag" `
                                                      -Credential $Credential)
        if ($records.Count -eq 0) { throw "$Label ${TaskTag}: task tag not found" }
        $task = $records[0]
        $state = [string]$task.state
        $percent = if ($null -ne $task.progressPercent) { [int]$task.progressPercent } else { 0 }

        if ($state -ne $lastState -or $percent -ne $lastPercent) {
            Write-Host "  $Label ${TaskTag}: $state $percent%"
            $lastState = $state
            $lastPercent = $percent
        }

        if ($state -notin @('RUNNING', 'QUEUED')) {
            if ($state -in @('ERROR', 'UNINITIALIZED')) {
                # Under Set-StrictMode a missing property throws, which would
                # replace the failure reason with a PowerShell error. Probe.
                $why = ''
                foreach ($field in @('formattedMessage', 'messageDetails', 'description')) {
                    if ($task.PSObject.Properties[$field] -and $task.$field) {
                        $why = $task.$field; break
                    }
                }
                throw "$Label $TaskTag failed: state=$state $why"
            }
            return $task
        }
        Start-Sleep -Seconds $PollSeconds
    }
    throw [TimeoutException] "$Label $TaskTag did not finish within $TimeoutSec seconds"
}


function Invoke-ScaleTaskCall {
    <#  POST a JSON body, then wait on the task tag it returns.

        Returns a hashtable with the POST Result and the final task record. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $JsonBody,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential,
        [string] $Label = 'task',
        [int] $TimeoutSec = 3600
    )

    $records = Get-ScaleRecords (Invoke-ScaleRest -Uri "$Base$Path" -Method POST `
                                                 -Credential $Credential -Body $JsonBody)
    if ($records.Count -eq 0) { throw "${Label}: empty response" }
    $result = $records[0]
    if (-not $result.taskTag) {
        throw "${Label}: no taskTag in response: $($result | ConvertTo-Json -Compress)"
    }

    Write-Host "$Label accepted, taskTag=$($result.taskTag)"
    $task = Wait-ScaleTask -Base $Base -TaskTag $result.taskTag `
                           -Credential $Credential -Label $Label -TimeoutSec $TimeoutSec
    return @{ Result = $result; Task = $task }
}


function New-ScaleSmbPathUri {
    <#  Build an SMB pathURI for an export target or an import source.

        The credentials travel inside the URI, which is how the SC//HyperCore
        API takes them -- there is no separate credential field. Both halves
        are URL-encoded so a password containing '@', ':', '/' or '#' does not
        corrupt the URI. An Active Directory domain, when supplied, is
        prefixed with a semicolon, which is the libsmbclient syntax the
        cluster expects:

            smb://DOMAIN;user:password@server/share/path

        The share name and each path segment are URL-encoded too (a share or
        directory name containing a space or '#' would otherwise corrupt the
        URI the same way an unencoded password does) -- '/' is kept literal
        in the path so multi-level directories still work.

        Returns an object with Uri and MaskedUri. Print the masked one -- a
        PowerShell transcript log will otherwise capture the password. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Server,
        [Parameter(Mandatory = $true)] [string] $Share,
        [string] $Path = '',
        [Parameter(Mandatory = $true)] [PSCredential] $SmbCredential,
        [string] $Domain
    )

    $user = [System.Uri]::EscapeDataString($SmbCredential.UserName)
    if ($Domain) {
        $user = "$([System.Uri]::EscapeDataString($Domain));$user"
    }
    $password = [System.Uri]::EscapeDataString(
        $SmbCredential.GetNetworkCredential().Password)

    $shareEncoded = [System.Uri]::EscapeDataString($Share.Trim('/'))
    $tail = "$Server/$shareEncoded"
    if ($Path) {
        $pathEncoded = ($Path.Trim('/') -split '/' |
            ForEach-Object { [System.Uri]::EscapeDataString($_) }) -join '/'
        $tail = "$tail/$pathEncoded"
    }

    return [PSCustomObject]@{
        Uri       = "smb://${user}:${password}@$tail"
        MaskedUri = "smb://${user}:****@$tail"
    }
}


function Get-ScaleMaskedUri {
    <#  Blank out the password in a caller-supplied pathURI so it can be printed. #>
    param([Parameter(Mandatory = $true)] [string] $Uri)

    if ($Uri -notmatch '://' -or $Uri -notmatch '@') { return $Uri }
    $scheme, $rest = $Uri -split '://', 2
    $at = $rest.LastIndexOf('@')
    $creds = $rest.Substring(0, $at)
    $host_ = $rest.Substring($at + 1)
    $colon = $creds.LastIndexOf(':')
    if ($colon -ge 0) { $creds = $creds.Substring(0, $colon) + ':****' }
    return "${scheme}://${creds}@${host_}"
}


function Get-ScaleVm {
    <#  Look a VM up by name or UUID and return its record. #>
    param(
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential,
        [string] $Name,
        [string] $Uuid
    )

    if ($Uuid) {
        $vm = Get-ScaleRecords (Invoke-ScaleRest -Uri "$Base/VirDomain/$Uuid" `
                                                -Credential $Credential)
        if ($vm.Count -eq 0) { throw "no VM with UUID $Uuid" }
        return $vm[0]
    }

    $all = Get-ScaleRecords (Invoke-ScaleRest -Uri "$Base/VirDomain" `
                                             -Credential $Credential -TimeoutSec 120)
    $found = @($all | Where-Object { $_.name -eq $Name })
    if ($found.Count -eq 0) { throw "no VM named '$Name'" }
    if ($found.Count -gt 1) {
        throw "$($found.Count) VMs are named '$Name' -- use -VMUUID to disambiguate"
    }
    return $found[0]
}


function Get-ScaleDefinitionFileName {
    <#  Derive a definition file name from the last element of the target path.

        Naming the definition file after its directory means the import side
        can be pointed at the directory alone, and it matches what the
        cluster's own UI writes. #>
    param([Parameter(Mandatory = $true)] [string] $PathUri)

    $tail = ($PathUri.TrimEnd('/') -split '/')[-1]
    if ($tail) { return "$tail.xml" }
    return 'vm.xml'
}
