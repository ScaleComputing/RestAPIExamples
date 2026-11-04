<#
VMImport.ps1

Import a VM into an SC//HyperCore(TM) cluster from a previously exported
directory on an SMB share, using POST /rest/v1/VirDomain/import.

The source directory is one produced by VMExport.ps1 (or by the cluster UI's
export): a definition file plus one qcow2 per disk.

Usage
    .\VMImport.ps1 -Node 10.0.0.1 -Name my-vm-restored `
        -SmbServer 10.0.0.50 -SmbShare exports -SmbPath hcexports/my-vm

    # complete pathURI instead of the -Smb* parameters
    .\VMImport.ps1 -Node 10.0.0.1 -Name my-vm-restored `
        -PathURI 'smb://administrator:secret@10.0.0.50/exports/hcexports/my-vm' `
        -DefinitionFileName my-vm.xml

    # seed the imported VM with cloud-init user-data / meta-data
    .\VMImport.ps1 ... -UserDataFile .\user-data.yaml -MetaDataFile .\meta-data.yaml

Note that the imported VM is created stopped.

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

    # Name for the imported VM. Omit to keep the name in the definition file.
    [string] $Name,

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

    # Defaults to the last element of the source path plus .xml.
    [string] $DefinitionFileName,

    # Disk image format. Empty means qcow2.
    [string] $Format = '',

    [switch] $NoNonSequentialWrites,

    [int] $ParallelCountPerTransfer,

    # Cloud-init seed for the imported VM.
    [string] $UserDataFile,
    [string] $MetaDataFile,

    # REST API version. An http:// pathURI requires v2.
    [ValidateSet('v1', 'v2')]
    [string] $ApiVersion = 'v1',

    [int] $TimeoutSec = 3600,

    [PSCredential] $Credential = (Get-Credential -Message 'Enter SC//HyperCore cluster credentials')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/HyperCoreTransfer.ps1"

$base = Get-ScaleApiBase -Node $Node -ApiVersion $ApiVersion

# Resolve the import source into a pathURI plus a copy safe to print.
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

Write-Host "Importing a VM into $Node"
Write-Host "  source:          $masked"
Write-Host "  definition file: $DefinitionFileName"
if ($Name) { Write-Host "  new VM name:     $Name" }

$source = [ordered]@{
    pathURI            = $uri
    definitionFileName = $DefinitionFileName
    format             = $Format
}
if ($NoNonSequentialWrites) { $source['allowNonSequentialWrites'] = $false }
if ($ParallelCountPerTransfer) { $source['parallelCountPerTransfer'] = $ParallelCountPerTransfer }

# 'template' overrides fields of the VM being created. Leave it empty to take
# everything from the definition file.
$template = [ordered]@{}
if ($Name) { $template['name'] = $Name }

$cloudInit = [ordered]@{}
if ($UserDataFile) {
    $cloudInit['userData'] = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes((Resolve-Path $UserDataFile)))
}
if ($MetaDataFile) {
    $cloudInit['metaData'] = [Convert]::ToBase64String(
        [IO.File]::ReadAllBytes((Resolve-Path $MetaDataFile)))
}
if ($cloudInit.Count -gt 0) { $template['cloudInitData'] = $cloudInit }

$body = [ordered]@{ source = $source; template = $template } | ConvertTo-Json -Depth 5

$outcome = Invoke-ScaleTaskCall -Base $base -Path '/VirDomain/import' `
                                -JsonBody $body -Credential $Credential `
                                -Label 'import' -TimeoutSec $TimeoutSec

Write-Host "Import complete ($($outcome.Task.state))."

$newUuid = $outcome.Result.createdUUID
if (-not $newUuid) { $newUuid = $outcome.Task.createdUUID }
if ($newUuid) {
    Write-Host "  new VM UUID: $newUuid"
    Write-Host '  The imported VM is stopped. Check its blockDevs before starting it --'
    Write-Host '  an import attaches an empty IDE_CDROM, and for a Windows operatingSystem'
    Write-Host '  it also attaches scale-guest-tools.iso.'
}
