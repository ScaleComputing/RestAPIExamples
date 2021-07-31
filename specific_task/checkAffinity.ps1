<# .SYNOPSIS #>
[ValidateCount(3,3)]
param(
    [Parameter(Position = 0, Mandatory=$true, 
               HelpMessage="        
               Usage: .\checkAffinity.ps1 <ip> <user> <pw> 

                 Display VM node affinity preference")]
    [ValidateLength(7,15)]
    [string]$clusterip,
    [Parameter(Position = 1, Mandatory=$true)]
    [string]$user,
    [Parameter(Position = 2, Mandatory=$true)]
    [string]$pass
)


#region -- CommonStuff used in all script

Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            ServicePointManager.ServerCertificateValidationCallback += 
                delegate
                (
                    Object obj, 
                    X509Certificate certificate, 
                    X509Chain chain, 
                    SslPolicyErrors errors
                )
                {
                    return true;
                };
        }
    }
"@

[ServerCertificateValidationCallback]::Ignore();

#This section formats credentials
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($user):$($pass)"))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
    ContentType = 'application/json'
}

#endregion


#region -- Data sources

function apiQuery {
    param( [string]$target )
    return Invoke-RestMethod https://$clusterip/rest/v1/$target -Headers $Headers
}

# REST API calls
$VirDomain = apiQuery VirDomain
$NodeGet = apiQuery Node

# Convert to local hashtables to minimize traffic
$Domain = Write-Output -NoEnumerate $VirDomain
$Node = Write-Output -NoEnumerate $NodeGet


# Collect the information and display it
Write-Output ""; Write-Output ""; "NODE MAPPING:" | Write-Output; 
$Node | Select-Object lanIP, uuid | Out-Host

Write-Output ""; "VM LOCATION AND AFFINITY:" | Write-Output
$Domain | Select-Object name, @{n="Current Location"; e={$_.lastSeenRunningOnNodeUUID}},
                              @{n="Preferred Node"; e={$_.affinityStrategy.preferredNodeUUID}},
                              @{n="Backup Node"; e={$_.affinityStrategy.backupNodeUUID}}
