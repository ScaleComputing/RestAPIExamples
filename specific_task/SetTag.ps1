<#
SetTag.ps1

William David van Collenburg
Scale Computing

Script to demonstrate assigning a tag to a VM based on part of the VM name

THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND
feel free to use without attribution in any way as seen fit, at your own risc.

Usage: SetTag.ps1 [IP or FQDN] [Reboot (yes/no)] [String to look for] [desired tag] [Credential Object] (if no Credential Object is given a login prompt will appear.)
#>

# Define the input options for the script
[CmdletBinding()]
param(
	[Parameter(mandatory=$true)]
	[string]$node,
	[Parameter(mandatory=$true)]
	[string]$rebootQ,
	[Parameter(mandatory=$true)]
	[string]$vmString,
	[Parameter(mandatory=$true)]
	[string]$setTag,
	[PSCredential] $Cred = (Get-Credential -Message "Enter Scale HC3 Credentials")
	)


# set all of the variables needed.

$readURL = "https://$node/rest/v1/VirDomain"
$checkURL = "https://$node/rest/v1/TaskTag"
$actionURL= "https://$node/rest/v1/VirDomain/action"
$checkVmURL= "https://$node/rest/v1/VirDomain"
$counter = 0
$VMbootList = New-Object System.Collections.Generic.List[System.Object]

# The below is to ignore certificates. comment out or delete section if cerificates are handled properly (e.g. certificate has been uploaded to cluster)

add-type @"
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

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


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
        $taskStatus = Invoke-RestMethod @restOpts "$checkURL/$TaskTag" -Method GET -Credential $Cred

        if ($taskStatus.state -eq 'ERROR') {
            throw "Task '$TaskTag' failed!"
        }
        elseif ($taskStatus.state -eq 'COMPLETE') {
            Write-Host "Task '$TaskTag' completed!"
            return
        }
    }
    throw [TimeoutException] "Task '$TaskTag' failed to complete in $($timeout.Seconds) seconds"
}

# Add the rest api options

$restOpts = @{
    ContentType = 'application/json'
}

$Body1 = @{
   tags = $setTag
} | ConvertTo-Json

# Read vm info in var

$readinfo = Invoke-RestMethod -Method 'Get' -Uri $readURL -ContentType 'application/json' -Credential $Cred


# Set the tag to the configured tag in $setTag and shut the VM down
ForEach ($VM in $readinfo.name) {
	If ($readinfo.name[$counter] -Match $vmString) {
		Write-Host $readinfo.name[$counter] " : " $readinfo.UUID[$counter]
		If ($readinfo.tags[$counter] -notmatch $setTag) {
			$writeURL = "https://$node/rest/v1/VirDomain/" + $readinfo.UUID[$counter]
			$result = Invoke-RestMethod -Method 'PATCH' -Uri $writeURL -Credential $Cred @restOpts -Body $Body1
			Wait-ScaleTask -TaskTag $($result.taskTag)
			If ($rebootQ -eq "yes") {
				$Body2 = ConvertTo-Json @(@{
					virDomainUUID = $readinfo.UUID[$counter]
					actionType = "SHUTDOWN"
				})
				Invoke-RestMethod -Method 'POST' -Uri $actionURL -Credential $Cred @restOpts -Body $Body2 | out-null
				$VMbootList.Add($readinfo.UUID[$counter]) #Add the UUID of the VM to a list with all of the VM's that have been shutdown so that in the next section we can start them again
				}	
		}
		
	}
	$counter++
}


While ($VMbootList) {
	Start-Sleep -Seconds 5 # inserted a pause to make sure we are not overloading the API
	ForEach ($VMUUID in $VMbootList) {
		# Get the VM status information
		$vmInfo = Invoke-RestMethod -Method 'GET' -Uri "$checkVmURL/$VMUUID" -Credential $Cred @restOpts
		# Check if the VM is finished shutting down
		If ($vmInfo.state -eq "SHUTOFF") { 
			
			$Body3 = ConvertTo-Json @(@{
				actionType = "START"
				virDomainUUID = $VMUUID
			})
		
			$result = Invoke-RestMethod -Method 'POST' -Uri $actionURL -Credential $Cred @restOpts -Body $body3
			Wait-ScaleTask -TaskTag $($result.taskTag)
			
			$ToRemove = $VMUUID
			break
		}
	
	}
	# Remove the UUID that we have just started from the list so it will not be checked again.
	If ($VMbootList.remove($ToRemove) -eq "True") {
		Write-Host "$ToRemove was given the start command succesfully"
	}
}
