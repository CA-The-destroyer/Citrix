function Get-CitrixCustomerIdFromToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        [Parameter(Mandatory=$true)]
        [string]$Base,  # e.g. https://api-us.cloud.com (or api-eu / api-ap-s / api.citrixcloud.jp)
        [int]$TimeoutSec = 10
    )

    # --- Decode JWT payload (base64url) ---
    $parts = $AccessToken -split '\.'
    if ($parts.Count -lt 2) { throw "AccessToken is not a JWT." }
    $mid = $parts[1]
    $pad = 4 - ($mid.Length % 4); if ($pad -lt 4) { $mid += ('=' * $pad) }
    $mid = $mid.Replace('-', '+').Replace('_', '/')
    $payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($mid))

    # --- Collect GUIDs from payload ---
    $matches = [regex]::Matches($payloadJson,'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
    $guids = $matches | ForEach-Object { $_.Value } | Select-Object -Unique
    if (-not $guids) { throw "No GUIDs found in token payload." }

    $auth = "Bearer $AccessToken"

    foreach ($g in $guids) {
        foreach ($headerName in @("Citrix-CustomerId","Citrix-Cloud-CustomerId")) {
            $h = @{ Authorization = $auth; Accept = "application/json" }
            $h[$headerName] = $g
            try {
                Invoke-RestMethod -Method Get -Uri "$Base/monitorodata/$g/v4/data" -Headers $h -TimeoutSec $TimeoutSec | Out-Null
                return [pscustomobject]@{
                    CustomerId = $g
                    HeaderName = $headerName
                    ODataWorks = $true
                }
            } catch {}
        }
    }

    # fallback DaaS
    foreach ($g in $guids) {
        foreach ($headerName in @("Citrix-CustomerId","Citrix-Cloud-CustomerId")) {
            $h = @{ Authorization = $auth; Accept = "application/json" }
            $h[$headerName] = $g
            try {
                Invoke-RestMethod -Method Get -Uri "$Base/cvad/manage/Machines?`$top=1" -Headers $h -TimeoutSec $TimeoutSec | Out-Null
                return [pscustomobject]@{
                    CustomerId = $g
                    HeaderName = $headerName
                    ODataWorks = $false
                }
            } catch {}
        }
    }
    throw "No working CustomerId GUID found."
}
