$scaleuser = "demo"
$scalepassword = "apidemo"
$node = "172.16.0.246"

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

$login = ConvertTo-Json @{
    username = $scaleuser
    password = $scalepassword
}

Invoke-RestMethod -Method POST -Uri https://$node/rest/v1/login -Body $login -ContentType 'application/json' -SessionVariable mywebSession | Out-Null
Write-Host "logged in"

$readURL = "https://$node/rest/v1/VirDomain"
$readInfo = Invoke-RestMethod -Method 'Get' -Uri "$readURL" -ContentType 'application/json' -WebSession $mywebsession

foreach ($vm in $readInfo) {
    Write-Host $vm.name "  ---  " $vm.uuid
}

Invoke-RestMethod -Method Post -Uri https://$node/rest/v1/logout -WebSession $mywebsession
Write-Host "logged out"