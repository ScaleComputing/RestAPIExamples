<# 
.SYNOPSIS 
Determine replication snapshots that fall outside of RPO

.PARAMETER clusterip
IPv4 address to desired cluster

.PARAMETER user
Cluster login username

.PARAMETER pass
Cluster login password

.PARAMETER RPO
Time using hours (int/float) and/or minutes (int)

.PARAMETER showall
Return additional information; default returns only the latest
out of RPO value [optional: allsnap, all, remote]

.EXAMPLE
./SnapshotReport.ps1 admin admin 192.168.100.15 1h15m
./SnapshotReport.ps1 admin admin 10.125.14.5 3.5h all
#>

[ValidateCount(3,5)]
param(
    [Parameter(Position = 0, Mandatory=$true)]
    [ValidateLength(7,15)]
    [string]$clusterip,
    [Parameter(Position = 1, Mandatory=$true)]
    [string]$user,
    [Parameter(Position = 2, Mandatory=$true)]
    [string]$pass,
    [Parameter(Position = 3, Mandatory=$false)]
    [string]$RPO = "default",
    [Parameter(Position = 4, Mandatory=$false)]
    [string]$showall = 'sparse'
)

if($RPO -in "all","allsnap","remote") {
    $showall = $RPO
    $RPO = "default"
}

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
$url = "https://$clusterip/rest/v1"
#endregion


#region -- Data sources

function apiQuery {
    param( [string]$target )
    return Invoke-RestMethod $url/$target -Headers $Headers
}

# REST API calls (Convert to local hashtables to minimize traffic)
$Snapshot = Write-Output -NoEnumerate (apiQuery VirDomainSnapshot)
$SnapSchedule = Write-Output -NoEnumerate (apiQuery VirDomainSnapshotSchedule)
$RemoteCluster = Write-Output -NoEnumerate (apiQuery RemoteClusterConnection)
$Cluster = Write-Output -NoEnumerate (apiQuery Cluster)

$EnumSnapshots = $Snapshot.count - 1
$EnumSchedules = $SnapSchedule.count

$TimeNow = [DateTimeOffset]::Now.ToUnixTimeSeconds()

# Init data collectors
$storedResults = @{}
[System.Collections.ArrayList]$targetUUIDs = @()
[System.Collections.ArrayList]$exportUUIDs = @()
[System.Collections.ArrayList]$allReplications = @()

#endregion


#region -- Transforms

# Select specific schedule based on UUID
function ReturnSchedule {
    param( [string]$UUID )
    $SnapSchedule | Where-Object {$_.uuid -contains $UUID}
}

# Hashtable for relevant snapshot entries
function StoreResults {
    param(
        [string]$snapuuid, 
        [string]$name,
        [string]$time, 
        [string]$avail,
        [string]$type,
        [string]$domUUID,
        [string]$diff,
        [string]$serial
    )
    $storedResults.Add($snapuuid,@{"uuid"=$snapuuid;"name"=$name;
            "timestamp"=$time;"available"=$avail;"type"=$type;
            "last_snap"=$diff;"domUUID"=$domUUID;"serial"=$serial})
}

# Convert Unix time to readable
function ConvertTime {
    param( [int]$time )
    [DateTimeOffset]::FromUnixTimeSeconds($time)
}

# Convert RPO time to Unix
function RPO2Unix {
    param( [string]$rpoIn )
    if($rpoIn -match 'h') {
        if ($rpoIn -match 'm') {
            $unpack = $rpoIn -split "h"
            $minutes = $unpack[1] -replace '[m]'
            $hours = $unpack[0]
            [int]$minutes = [int]$minutes + ([float]$hours * 60)
        } 
        else 
        {
            $hours = $rpoIn -replace '[h]'
            [int]$minutes = [float]$hours * 60 
        }
    } 
    else 
    {
        if($rpoIn -match 'm') { 
            $minutes = $rpoIn -replace '[m]'
        } 
        else 
        {
            [int]$minutes = [float]$rpoIn * 60
        }
    }
    [int]$seconds = [int]$minutes * 60
    return $seconds
}

# Parse and display filtered snapshots
function SnapShow {
    if($exportUUIDs.count -eq 0) {
        Write-Host "All snapshots current"; Write-Host ""
    }
    foreach($id in $exportUUIDs) {
        $storedResults[$id] | Select-Object @{n="name";e={$_.name}}, 
        @{n="last_snap";e={$_.last_snap+" hours"}},@{n="available";e={$_.available}},
        @{n="serial";e={$_.serial}},@{n="uuid";e={$_.uuid}}
    }
}

# Filter only the latest replications
function SnapFilter {
    [System.Collections.ArrayList]$tally = @()
    [System.Collections.ArrayList]$times = @()
    $names = @{}
    foreach($id in $storedResults.Keys) {
        $tally += ($storedResults.$id.timestamp)
    }
    $times += $tally | Sort -Descending
    foreach($item in $times) {      
        $stored = $storedResults[$storedResults.Keys.where{$storedResults[$_].timestamp -eq $item}]
        $names.Add($item,@{"uuid"=$stored.uuid;"domain"=$stored.name;
                           "timestamp"=$item;"serial"=$stored.serial})
    }
    [System.Collections.ArrayList]$serials = @()
    $filtered = @{}
    $names.GetEnumerator() | Sort-Object { $_.Value.serial } -Descending | `
                    ForEach-Object { [void]$serials.Add($_.Value.serial) }
    foreach($sid in $serials) {
        $stored = $storedResults[$storedResults.Keys.where{$storedResults[$_].serial -eq $sid}]
        if($filtered.count -eq 0) {
            $filtered.Add($stored.uuid,@{"name"=$stored.name;"serial"=$stored.serial})
        } 
        else 
        {
            if($stored.serial -ne 1) {
                if($filtered.Values.name -contains $stored.name) {
                    $filterchoice = $filtered[$filtered.Keys.where{$filtered[$_].name -eq $stored.name}]
                    if($stored.serial -ge $filterchoice.name) {
                        $filtered.Add($stored.uuid,@{"name"=$stored.name;"serial"=$stored.serial})
                        $filtered.Remove($filterchoice)
                    }
                } 
                else 
                {
                    $filtered.Add($stored.uuid,@{"name"=$stored.name;"serial"=$stored.serial})
                }
            }
        }
    } 
    if($showall -eq 'allsnap') {
        foreach($uids in $storedResults.values.uuid) { 
            [void]$targetUUIDs.Add($uids) 
        }
    } 
    else 
    {
        foreach($uids in $filtered.Keys) {
            [void]$targetUUIDs.Add($uids) 
        }
    }
}

# Display remote cluster connections when remote flag is called
function RemoteInfo {
    $RemoteSummary = @{}
    $RemoteCluster | foreach -Process {
        $RemoteSummary.Add($_.uuid, @{"ip"=$_.remoteNodeIPs; "connection"=$_.connectionStatus; 
            "state"=$_.remoteNodeConnectionStates; "remoteUUIDs"=$_.remoteNodeUUIDs})
    }
    Write-Host "Remote cluster connections"
    foreach($uid in $RemoteCluster.uuid) {
        $RemoteSummary.$uid | Select-Object @{n="ip"; e={$_.ip}}, @{n="connection";
        e={$_.connection}}, @{n="state";e={$_.state}}, @{n="remoteUUID"; e={$_.remoteUUIDs}}
    }
}

#endregion


# Cluster summary in alt modes
if($showall -inotmatch "sparse") {
    Write-Host ""
    Write-Host $Snapshot.count "total snapshots found on" `
        $Cluster.clusterName"running HCOS version" $Cluster.icosVersion
}

# Detail number of backup schedules and rules in alt modes
if($showall -inotmatch "sparse") {
    if ($EnumSchedules -eq 0) { 
        Write-Host "No backup schedules found" 
    } 
    else 
    { 
        if ($EnumSchedules -gt 0) {
            Write-Host $SnapSchedule.count "backup schedule(s) found with" `
                $SnapSchedule.rrules.count "rules total";
            foreach($entry in $SnapSchedule) {
                if(!$entry.rrules) {
                    Write-Host ""; Write-Host "No rules set for $($entry.name)"
                } 
                else 
                {
                    $EnumRules = $entry.rrules.count - 1;
                    Write-Host ""; Write-Host $entry.name "rules: ";
                    if($EnumRules -eq 0) {
                        Write-Host "  " ($_+1)">>" $entry.rrules.name
                    } 
                    else 
                    {
                        0..$EnumRules | foreach -Process {
                            Write-Host "  " ($_+1)">>" $entry.rrules.name[$_] 
                        }
                    }        
                }
            }
        }
    }
}

# Supply most recent task completed
if($showall -eq "all") {
    Write-Output ""; Write-Output "Most recent task:"
    $Cluster.latestTaskTag | Select-Object taskTag, state, @{Name="progress";
        e={$_.progressPercent}}, @{Name="created"; e={ConvertTime $_.created}},
        @{Name="completed"; e={ConvertTime $_.completed}} | Out-Host
}


# Prepare snapshot list in alt modes
if($showall -notcontains "sparse") { 
    Start-Sleep -Seconds 1; Write-Host "VM status for $($Cluster.clusterName):";Write-Host "" 
}

# Inform if no RPO provided
if($RPO -eq "default") { 
    Write-Host "No RPO provided - using local retention policy" 
}

# Build initial store for non-negative snaps
$Snapshot.where{$_.domain.sourceVirDomainUUID -ne ""} | ForEach -Process {
    if ($_.unavailable -match "False") { 
        $available = "Yes" 
    } 
    else 
    { 
        $available = "No" 
    }
    $timeDiff = $TimeNow - $_.timestamp
    $roundedDiff = [math]::Round(($timeDiff / 60)/60,1)
    if([double]$roundedDiff -lt 0 ) { 
        $discard = "negative" 
    }
    # UUID - UUID - TIMESTAMP - AVAILABILITY - TYPE - SCHEDULE UUID - TIME DIFFERENCE
    if($discard -ne 'negative') {
        StoreResults $_.uuid $_.domain.name $_.timestamp $available $_.type `
        $_.domain.sourceVirDomainUUID $roundedDiff $_.domain.snapshotSerialNumber
    }
    [void]$allReplications.Add($_.uuid)
}


# Confirm snapshots beyond RPO definitions
if($showall -ne 'sparse') { 
    Write-Host "$($allReplications.count) total replication snapshots" 
}
SnapFilter
foreach($id in $targetUUIDs) {
    $snapLabel = $Snapshot[$id].label -split " - "
    if ($RPO -eq "default") {
        $iterSchedule = ReturnSchedule $Snapshot[$id].domain.snapshotScheduleUUID;
        $targetrrules = $iterSchedule.rrules | where {$_.name -eq $snapLabel[-1]};
        if(!$targetrrules.localRetentionDurationSeconds) { 
            $localRention = 0 
        } 
        else 
        { 
            $localRention = $targetrrules.localRetentionDurationSeconds 
        }
    } 
    else 
    { 
        $localRention = RPO2Unix $RPO 
    }
    $timeDiff = $TimeNow - $storedResults[$id].timestamp
    if($timeDiff -gt $localRention) {
        [void]$exportUUIDs.Add($id)
    } 
    else 
    { 
        continue 
    }
}

# Display results, if any        
SnapShow | Format-Table -AutoSize

# Display remote connections (when 'all' or 'remote' option present)
if(($showall -match 'remote') -or ($showall -eq 'all')) 
    { RemoteInfo | Out-Host }
