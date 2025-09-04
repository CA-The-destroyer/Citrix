$CustomerId   = "<your_customer_id>"
$ClientId     = "<your_client_id>"
$ClientSecret = "<your_client_secret>"
$Base         = "https://api-us.cloud.com"   # change to api-eu.cloud.com / api-ap-s.cloud.com / api.citrixcloud.jp

$TokenUri = "$Base/cctrustoauth2/$CustomerId/tokens/clients"
$Body = @{ clientId = $ClientId; clientSecret = $ClientSecret } | ConvertTo-Json

$tokResp = Invoke-RestMethod -Method Post -Uri $TokenUri -ContentType "application/json" -Body $Body
$TokenType   = $tokResp.token_type   # usually "CwsAuth"
$AccessToken = $tokResp.access_token

# Example API call: Monitor OData Machines
$Headers = @{
  "Authorization" = "$TokenType bearer $AccessToken"
  "Citrix-CustomerId" = $CustomerId       # some docs show Citrix-Cloud-CustomerId; Citrix accepts this header name
  "Accept" = "application/json"
}
$odata = "$Base/monitorodata/$CustomerId/v4/data/Machines`?$top=1000"
$r = Invoke-RestMethod -Uri $odata -Headers $Headers -Method Get
$r.value.Count
