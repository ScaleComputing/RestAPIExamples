#!/usr/bin/env pwsh

<#
.SYNOPSIS
Demonstrate basic VM examples and waiting for task completion using the Scale Computing REST API

.PARAMETER Server
Cluster/System to test the API against

.PARAMETER Credential
User credentials used to authenticate with the server

.PARAMETER SkipCertificateCheck
Ignore Invalid/self-signed certificate errors

.EXAMPLE
./vm-lifecycle.ps1 -Server server-name -Credential (Get-Credential)
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

$url = "https://$Server/rest/v1"


$restOpts = @{
    Credential = $Credential
    ContentType = 'application/json'
}

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


# Many actions are asynchronous, often we need a way to wait for a returned taskTag to complete before taking further action
function Wait-ScaleTask {
    Param(
        [Parameter(Mandatory = $true,Position  = 1, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $TaskTag
    )

    $retryDelay = [TimeSpan]::FromSeconds(1)
    $timeout = [TimeSpan]::FromSeconds(300)

    $timer = [Diagnostics.Stopwatch]::new()
    $timer.Start()

    while ($timer.Elapsed -lt $timeout)
    {
        Start-Sleep -Seconds $retryDelay.TotalSeconds
        $taskStatus = Invoke-RestMethod @restOpts "$url/TaskTag/$TaskTag" -Method GET

        if ($taskStatus.state -eq 'ERROR') {
            throw "Task '$TaskTag' failed!"
        }
        elseif ($taskStatus.state -eq 'COMPLETE') {
            Write-Verbose "Task '$TaskTag' completed!"
            return
        }
    }
    throw [TimeoutException] "Task '$TaskTag' failed to complete in $($timeout.Seconds) seconds"
}



Write-Host "Create VM"
$json = @{
    dom = @{
        name = "VMLifeycleTest"
        description = "An example created for testing the rest API"
        mem = 4GB
        numVCPU = 4;
        blockDevs = @(
            @{
                capacity = 1GB
                type = "VIRTIO_DISK"
                cacheMode = "WRITETHROUGH"
            }
        )
        netDevs = @(
            @{
                type = "VIRTIO"
            }
        )
    }
    options = @{
        #  attachGuestToolsISO = true
    }
} | ConvertTo-Json -Depth 100
$result = Invoke-RestMethod @restOpts "$url/VirDomain/"  -Method POST -Body $json
$vmUUID = $($result.createdUUID)
Wait-ScaleTask -TaskTag $($result.taskTag)

Write-Host "Create a block device for the VM"
$json = @{
    virDomainUUID = $vmUUID
    capacity = 10GB
    type = 'VIRTIO_DISK'
    cacheMode = 'WRITETHROUGH'
} | ConvertTo-Json
$result = Invoke-RestMethod @restOpts "$url/VirDomainBlockDevice" -Method POST -Body $json
Wait-ScaleTask -TaskTag $($result.taskTag)



Write-Host "Start VM"
$json = ConvertTo-Json @(@{
    actionType = 'START'
    virDomainUUID = $vmUUID
})
$result = Invoke-RestMethod @restOpts "$url/VirDomain/action" -Method POST -Body $json
Wait-ScaleTask -TaskTag $($result.taskTag)



# Get VM Info to determine which node the VM is currently running on
$nodes = Invoke-RestMethod @restOpts "$url/Node" -Method GET
if ($nodes.Count -gt 1) {
    Write-Host "Live migrate VM to another node"

    $vm = Invoke-RestMethod @restOpts "$url/VirDomain/$vmUUID" -Method GET
    # Get Node UUID where VM is not running currently
    $migrateTargetNode = ($nodes | ? { $_ -ne $vm.nodeUUID })[0]
    $json = ConvertTo-Json @(@{
        actionType = 'LIVEMIGRATE'
        nodeUUID = $migrateTargetNode.uuid
        virDomainUUID = $vmUUID
    })
    $result = Invoke-RestMethod @restOpts "$url/VirDomain/action" -Method POST  -Body $json
    Wait-ScaleTask -TaskTag $($result.taskTag)
}



Write-Host "Stop VM"
$json = ConvertTo-Json @(@{
    actionType = 'STOP'
    virDomainUUID = $vmUUID
})
$result = Invoke-RestMethod @restOpts "$url/VirDomain/action" -Method POST -Body $json
Wait-ScaleTask -TaskTag $($result.taskTag)



Write-Host "Update VM properties"
$json = @{
    name = "VMLifecycleUpdated";
    description = "An updated example using the rest API";
    mem = 8GB
    numVCPU = 2
} | ConvertTo-Json

$result = Invoke-RestMethod @restOpts "$url/VirDomain/$vmUUID" -Method PATCH  -Body $json
Wait-ScaleTask -TaskTag $($result.taskTag)

# The following (available in v9.1) is an example cloud-init customization that would be recognized
# on first boot by a cloud-image VM configured to run cloud-init. (Note: the VM
# cloned in this example script is not a cloud-image configured to run cloud-init)
# More example cloud-config and documentation can be found here:
# https://cloudinit.readthedocs.io/en/latest/topics/examples.html
#
# yaml for cloud-init meta-data
$metaData = @"
dsmode: local
local-hostname:"VMLifeycleTest"
"@

# yaml for cloud-init user-data
$userData = @'
#cloud-config
#apt_update: true
#apt_upgrade: true
password: my_secret_password
chpasswd: { expire: false }
ssh_pwauth: true
#ssh_authorized_keys:
#  - ssh-rsa my_secret_ssh_key
apt: {sources: {docker.list: {source: 'deb [arch=amd64] https://download.docker.com/linux/ubuntu $RELEASE stable', keyid: 9DC858229FC7DD38854AE2D88D81803C0EBFCD88}}}
packages: [qemu-guest-agent, docker-ce, docker-ce-cli]
bootcmd:
  - [ sh, -c, 'sudo echo GRUB_CMDLINE_LINUX="nomodeset" >> /etc/default/grub' ]
  - [ sh, -c, 'sudo echo GRUB_GFXPAYLOAD_LINUX="1024x768" >> /etc/default/grub' ]
  - [ sh, -c, 'sudo echo GRUB_DISABLE_LINUX_UUID=true >> /etc/default/grub' ]
  - [ sh, -c, 'sudo update-grub' ]
runcmd:
  - [docker, pull, hello-world]
  - [docker, run, hello-world]
  - [docker, images, hello-world]
'@

# base64 encode the cloud-init data
$metaData64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($metaData))
$userData64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userData))
$cloudInitData64 = @{
    userData = $userData64
    metaData = $metaData64
}

Write-Host "Clone VM with example cloud-init customization payload"
$json = @{
    template = @{
        name = "VMLifecycle-Clone-CloudInit"
        description = "An example VM cloned using the rest API with cloud-init data"
        cloudInitData = $cloudInitData64
    }
} | ConvertTo-Json

$result = Invoke-RestMethod @restOpts "$url/VirDomain/$vmUUID/clone" -Method POST  -Body $json
$cloneUUID = $($result.createdUUID)
Wait-ScaleTask -TaskTag $($result.taskTag)



Write-Host "Create VM snapshot"
$json = @{
    domainUUID = $vmUUID;
    label = "This is a test snapshot created via rest API"
} | ConvertTo-Json
$result = Invoke-RestMethod @restOpts "$url/VirDomainSnapshot" -Method POST -Body $json
Wait-ScaleTask -TaskTag $($result.taskTag)
$snapUUID = $($result.createdUUID)



Write-Host "Delete VM snapshot"
$result = Invoke-RestMethod @restOpts "$url/VirDomainSnapshot/$snapUUID" -Method DELETE
Wait-ScaleTask -TaskTag $($result.taskTag)



Write-Host "Delete original VM"
$result = Invoke-RestMethod @restOpts "$url/VirDomain/$vmUUID" -Method DELETE
Wait-ScaleTask -TaskTag $($result.taskTag)

Write-Host "Delete cloned VM"
$result = Invoke-RestMethod @restOpts "$url/VirDomain/$cloneUUID" -Method DELETE
Wait-ScaleTask -TaskTag $($result.taskTag)
