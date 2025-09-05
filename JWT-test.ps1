# ==== Inputs you DO have ====
$base = "https://api-us.cloud.com"   # match the region you used for the token
$cid  = "<ClientId>"
$sec  = "<ClientSecret>"
$org  = "zzzInc"                     # the org key you used successfully for the token

# 1) Get a token using the org key (since that works for you)
$tok = Invoke-RestMethod -Method Post -Uri "$base/cctrustoauth2/$org/tokens/clients" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "grant_type=client_credentials&client_id=$cid&client_secret=$sec"
$auth = if ($tok.token_type) { "$($tok.token_type) $($tok.access_token)" } else { "Bearer $($tok.access_token)" }

# 2) Decode token payload and collect GUIDs
$mid = ($tok.access_token -split '\.')[1]
$pad = 4 - ($mid.Length % 4); if ($pad -lt 4) { $mid += ('=' * $pad) }
$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($mid.Replace('-','+').Replace('_','/')))
$guids = [regex]::Matches($payloadJson,'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}') | ForEach-Object { $_.Value } | Select-Object -Unique
if (-not $guids) { throw "No GUIDs found in token payload. You’ll need an admin to give you the Customer ID." }

# 3) Probe OData root with each GUID until one works
$headers1 = @{ Authorization = $auth; "Citrix-CustomerId" = ""; Accept = "application/json" }
$headers2 = @{ Authorization = $auth; "Citrix-Cloud-CustomerId" = ""; Accept = "application/json" }

$found = $null
foreach ($g in $guids) {
  foreach ($h in @($headers1, $headers2)) {
    $key = ($h.Keys | Where-Object { $_ -like 'Citrix*' })[0]
    $h[$key] = $g
    $root = "$base/monitorodata/$g/v4/data"
    try {
      # Quick lightweight probe
      Invoke-RestMethod -Method Get -Uri $root -Headers $h -TimeoutSec 15 | Out-Null
      $found = @{ cust = $g; header = $key }
      break
    } catch {}
  }
  if ($found) { break }
}

if (-not $found) {
  Write-Host "Could not reach OData with any GUID from the token. Likely OData is not enabled for this tenant." -ForegroundColor Yellow
  Write-Host "Try DaaS REST instead:" -ForegroundColor Yellow
  Invoke-RestMethod -Method Get -Uri "$base/cvad/manage/Machines?`$top=1000" -Headers $headers1 | ConvertTo-Json -Depth 6 | Out-File .\machines_admin.json -Encoding utf8
  return
}

Write-Host "OData OK with CustomerId=$($found.cust) using header '$($found.header)'. Pulling Machines..." -ForegroundColor Green
Invoke-RestMethod -Method Get -Uri "$base/monitorodata/$($found.cust)/v4/data/Machines?`$top=1000" `
  -Headers (@{ Authorization = $auth; Accept = "application/json"; $found.header = $found.cust }) `
  | ConvertTo-Json -Depth 6 | Out-File .\machines.json -Encoding utf8
