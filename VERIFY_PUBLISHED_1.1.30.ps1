$ErrorActionPreference = "Stop"

$expectedVersion = "1.1.30-beta"
$expectedSize = 317143
$expectedHash = "cf985e98ec9582b6ba3e9a90ee6c93bc5f0995d83db25f97095cea39498d8473"
$expectedAppUrl = "https://stockticker-ota.pages.dev/Beta/app.py?v=1130-secure-pairing-v1-1"
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$manifestUrl = "https://stockticker-ota.pages.dev/manifest.json?cb=$timestamp"
$tempManifest = Join-Path $env:TEMP "stockticker-manifest-1.1.30.json"
$tempApp = Join-Path $env:TEMP "stockticker-app-1.1.30.py"

Write-Host "Downloading live manifest..."
Invoke-WebRequest -Uri $manifestUrl -OutFile $tempManifest -UseBasicParsing
$manifest = Get-Content $tempManifest -Raw | ConvertFrom-Json
$beta = $manifest.beta
if (-not $beta) { throw "Manifest does not contain a beta release." }

if ($beta.app_url -ne $expectedAppUrl) {
    throw "Manifest app URL mismatch. Expected $expectedAppUrl but found $($beta.app_url)."
}

$joiner = if ($beta.app_url.Contains("?")) { "&" } else { "?" }
$liveAppUrl = "$($beta.app_url)$($joiner)cb=$timestamp"
Write-Host "Downloading live firmware..."
Invoke-WebRequest -Uri $liveAppUrl -OutFile $tempApp -UseBasicParsing

$actualSize = (Get-Item $tempApp).Length
$actualHash = (Get-FileHash -Path $tempApp -Algorithm SHA256).Hash.ToLower()
$appText = Get-Content $tempApp -Raw
$versionPattern = 'APP_VERSION\s*=\s*["'']([^"'']+)["'']'
$versionMatch = [regex]::Match($appText, $versionPattern)
$embeddedVersion = if ($versionMatch.Success) { $versionMatch.Groups[1].Value } else { "not-found" }

Write-Host ""
Write-Host "Manifest version: $($beta.version)"
Write-Host "Manifest size: $($beta.size)"
Write-Host "Manifest SHA256: $($beta.sha256)"
Write-Host "Manifest app URL: $($beta.app_url)"
Write-Host "Embedded app version: $embeddedVersion"
Write-Host "Downloaded size: $actualSize"
Write-Host "Downloaded SHA256: $actualHash"
Write-Host ""

if ($beta.version -ne $expectedVersion) { throw "Manifest version mismatch." }
if ([int64]$beta.size -ne $expectedSize) { throw "Manifest size mismatch." }
if ($beta.sha256.ToLower() -ne $expectedHash) { throw "Manifest SHA256 mismatch." }
if ($embeddedVersion -ne $expectedVersion) { throw "Downloaded app.py contains the wrong APP_VERSION." }
if ($actualSize -ne $expectedSize) { throw "Published app.py size mismatch." }
if ($actualHash -ne $expectedHash) { throw "Published app.py SHA256 mismatch." }

Write-Host "PASS: live 1.1.30 firmware and manifest match exactly." -ForegroundColor Green
