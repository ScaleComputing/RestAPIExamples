#!/usr/bin/env pwsh

<#
.SYNOPSIS
Demonstrate ISO upload using the Scale Computing REST API
.PARAMETER Server
Cluster/System to test the API against
.PARAMETER Credential
User credentials used to authenticate with the server
.PARAMETER SkipCertificateCheck
Ignore Invalid/self-signed certificate errors
.EXAMPLE
./iso-upload.ps1 -Server server-name -Credential (Get-Credential)
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $true,Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Server,
    [PSCredential] $Credential = (Get-Credential -Message "Enter Scale HC3 Credentials"),
    [switch] $SkipCertificateCheck
)

$ErrorActionPreference = 'Stop';

# Set the cluster address
$url = "https://$Server/rest/v1"

# In general, json is used in API requests
$restOpts = @{
    Credential = $Credential
    ContentType = 'application/json'
}

# Manage certificate handling or bypass
if ($PSVersionTable.PSEdition -eq 'Core') {
    $restOpts.SkipCertificateCheck = $SkipCertificateCheck
}
elseif ($SkipCertificateCheck) {
    try
    {
        add-type -ErrorAction stop @"
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
    } catch { write-error "Failed to create TrustAllCertsPolicy: $_" }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

Write-Host " "
Write-Host "Waiting for file selection"

# Create the file browser instance limited to .iso files only
$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop') 
    Filter = 'Standard ISO Images (*.iso)|*.iso'
}
$null = $FileBrowser.ShowDialog()

# Assign the requisite values needed for the rest of the process using the selected ISO file
$SelectedISO = $FileBrowser.FileName
$ISOName = $FileBrowser.SafeFileName
$ISOSize = (Get-Item $SelectedISO).Length


# Create the file placeholder in the media pool
$json = @{
    name = "$ISOName"
    size = $ISOSize
    readyForInsert = $false
} | ConvertTo-Json -Depth 100
$result = Invoke-RestMethod @restOpts "$url/ISO"  -Method POST -Body $json
$ISOUUID = $($result.createdUUID)

# Upload the ISO file payload
$ISOUpload = Get-ChildItem -Path $SelectedISO
$allFileBytes = [System.IO.File]::ReadAllBytes($ISOUpload.FullName)
$ISOpayload = $allFileBytes
$restOptsUpload = @{
    Credential = $Credential
    ContentType = 'application/octet-stream'
}
Write-Host "Uploading $ISOName - Please wait"
$result = Invoke-RestMethod @restOptsUpload "$url/ISO/$ISOUUID/data"  -Method PUT -Body $ISOpayload

# Confirm upload completes and mark ISO as ready for use in UI
Do {
    Start-Sleep 2
    $completionCheck = Invoke-RestMethod @restOpts "$url/ISO/$ISOUUID" -Method GET
    $remaining = $ISOSize - $completionCheck.size
} While ($completionCheck.size -lt $ISOSize)

Write-Host "Upload complete - ISO is ready for use"
# Update ISO status to ready
$json = @{
    name = "$ISOName"
    readyForInsert = $true
} | ConvertTo-Json -Depth 100
$result = Invoke-RestMethod @restOpts "$url/ISO/$ISOUUID"  -Method POST -Body $json

