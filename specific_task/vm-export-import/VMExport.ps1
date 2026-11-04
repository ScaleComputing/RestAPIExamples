<#
VMExport.ps1

Export a VM from an SC//HyperCore(TM) cluster to an SMB share, using
POST /rest/v1/VirDomain/{uuid}/export.

An export writes two things into the target directory: a definition file (XML)
describing the VM, and one qcow2 file per disk. That directory is what
VMImport.ps1 reads back.

Usage
    # export a VM to an SMB share (prompts for both sets of credentials)
    .\VMExport.ps1 -Node 10.0.0.1 -VMName my-vm `
        -SmbServer 10.0.0.50 -SmbShare exports -SmbPath hcexports/my-vm

    # Active Directory domain account for the share
    .\VMExport.ps1 ... -SmbDomain example.local

    # export a point-in-time snapshot instead of the VM's current state
    .\VMExport.ps1 ... -SnapshotUUID 1b0e...

    # supply a complete pathURI yourself instead of the -Smb* parameters
    .\VMExport.ps1 -Node 10.0.0.1 -VMName my-vm `
        -PathURI 'smb://administrator:secret@10.0.0.50/exports/hcexports/my-vm'

Clusters negotiate TLS 1.3 only (see README.md). Confirmed working: PowerShell
7+ on Linux, and on Windows 11 / Server 2022+. Windows PowerShell 5.1 has not
been confirmed to work against a cluster on any Windows version we tested
(Server 2016, Server 2019, Windows 10) -- its TLS stack there has no TLS 1.3.
Does not work on macOS at any PowerShell version.

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risk.
#>

[CmdletBinding(DefaultParameterSetName = 'Smb')]
param(
    [Parameter(Mandatory = $true)]
    [string] $Node,

    [string] $VMName,
    [string] $VMUUID,

    # Export this VirDomainSnapshot rather than the VM's current state.
    [string] $SnapshotUUID,

    [Parameter(ParameterSetName = 'Uri', Mandatory = $true)]
    [string] $PathURI,

    [Parameter(ParameterSetName = 'Smb', Mandatory = $true)]
    [string] $SmbServer,
    [Parameter(ParameterSetName = 'Smb', Mandatory = $true)]
    [string] $SmbShare,
    [Parameter(ParameterSetName = 'Smb')]
    [string] $SmbPath = '',
    [Parameter(ParameterSetName = 'Smb')]
    [string] $SmbDomain,
    [Parameter(ParameterSetName = 'Smb')]
    [PSCredential] $SmbCredential,

    # Defaults to the last element of the target path plus .xml.
    [string] $DefinitionFileName,

    # Compress the exported disk images: smaller on the share, slower to write.
    [switch] $Compress,

    # Disk image format. Empty means qcow2.
    [string] $Format = '',

    # Non-sequential writes are on by default and usually faster, but some SMB
    # servers do not handle them well.
    [switch] $NoNonSequentialWrites,

    [int] $ParallelCountPerTransfer,

    # REST API version. An http:// pathURI requires v2.
    [ValidateSet('v1', 'v2')]
    [string] $ApiVersion = 'v1',

    [int] $TimeoutSec = 3600,

    [PSCredential] $Credential = (Get-Credential -Message 'Enter SC//HyperCore cluster credentials')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/HyperCoreTransfer.ps1"

if (-not $VMName -and -not $VMUUID) {
    throw 'Give -VMName or -VMUUID.'
}

$base = Get-ScaleApiBase -Node $Node -ApiVersion $ApiVersion

# Resolve the export target into a pathURI plus a copy safe to print.
if ($PSCmdlet.ParameterSetName -eq 'Uri') {
    $uri = $PathURI
    $masked = Get-ScaleMaskedUri -Uri $PathURI
}
else {
    if (-not $SmbCredential) {
        $SmbCredential = Get-Credential -Message "Enter credentials for the SMB share on $SmbServer"
    }
    $built = New-ScaleSmbPathUri -Server $SmbServer -Share $SmbShare -Path $SmbPath `
                                 -SmbCredential $SmbCredential -Domain $SmbDomain
    $uri = $built.Uri
    $masked = $built.MaskedUri
}

if (-not $DefinitionFileName) {
    $DefinitionFileName = Get-ScaleDefinitionFileName -PathUri $uri
}

$vm = Get-ScaleVm -Base $base -Credential $Credential -Name $VMName -Uuid $VMUUID

Write-Host "Exporting VM '$($vm.name)' ($($vm.uuid)) from $Node"
Write-Host "  target:          $masked"
Write-Host "  definition file: $DefinitionFileName"

# Only pathURI is required. Everything else is sent only when asked for, so
# the cluster's own defaults apply otherwise.
$target = [ordered]@{
    pathURI            = $uri
    definitionFileName = $DefinitionFileName
    compress           = [bool]$Compress
    format             = $Format
}
if ($NoNonSequentialWrites) { $target['allowNonSequentialWrites'] = $false }
if ($ParallelCountPerTransfer) { $target['parallelCountPerTransfer'] = $ParallelCountPerTransfer }

$payload = [ordered]@{ target = $target }
if ($SnapshotUUID) { $payload['snapUUID'] = $SnapshotUUID }

$body = $payload | ConvertTo-Json -Depth 5

$outcome = Invoke-ScaleTaskCall -Base $base -Path "/VirDomain/$($vm.uuid)/export" `
                                -JsonBody $body -Credential $Credential `
                                -Label 'export' -TimeoutSec $TimeoutSec

Write-Host "Export complete ($($outcome.Task.state))."
Write-Host 'Import it back with:'
$hint = "  .\VMImport.ps1 -Node $Node -PathURI '<same pathURI>'" +
        " -DefinitionFileName $DefinitionFileName -Name <new-vm-name>"
Write-Host $hint
