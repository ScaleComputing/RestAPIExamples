$scaleuser = "YOUR_USERNAME"
$scalepassword = "YOUR_PASSWORD"
$node = "IP_OR_FQDN_OF_CLUSTER"

# the below section is an example on how to ignore certificate failures
# Whenever possible, make sure a DNS entry is made and a matching certificate is uploaded to the cluster
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
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Create the login JSON body
$login = ConvertTo-Json @{
    username = $scaleuser
    password = $scalepassword
}

# Perform the login and store session details in a SessionVariable called mywebSession
Invoke-RestMethod -Method POST -Uri https://$node/rest/v1/login -Body $login -ContentType 'application/json' -SessionVariable mywebSession | Out-Null
Write-Host "logged in"

# Get info for all VM's on the cluster using the mywebSession variable to confirm identity
$readURL = "https://$node/rest/v1/VirDomain"
$readInfo = Invoke-RestMethod -Method 'Get' -Uri "$readURL" -ContentType 'application/json' -WebSession $mywebsession

# Iterate over the vm's in the readInfo variable and extract / print their names and UUID's
# This can be usefull as all actions performed on a VM are targeted at its UUID
foreach ($vm in $readInfo) {
    Write-Host $vm.name "  ---  " $vm.uuid
}

# Logout - Logging out at the end of a script is important and makes sure no sessions are lingering on the cluster.
Invoke-RestMethod -Method Post -Uri https://$node/rest/v1/logout -WebSession $mywebsession
Write-Host "logged out"
