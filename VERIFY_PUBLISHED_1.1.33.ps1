$ErrorActionPreference = "Stop"

$expectedVersion = "1.1.33-beta"
$expectedSize = 350325
$expectedHash = "dece48e81988567bebb8bef2552e7f27a64b5df8184bcdb7a04361c02d4f36d3"
$expectedAppUrl = "https://stockticker-ota.pages.dev/Beta/app.py?v=1133-onboarding-audit-1"

$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$manifestUrl = "https://stockticker-ota.pages.dev/manifest.json?cb=$timestamp"
$tempManifest = Join-Path $env:TEMP "stockticker-manifest-1.1.33.json"
$tempApp = Join-Path $env:TEMP "stockticker-app-1.1.33.py"

Write-Host "Downloading live manifest..."
Invoke-WebRequest -Uri $manifestUrl -OutFile $tempManifest -UseBasicParsing
$manifest = Get-Content $tempManifest -Raw | ConvertFrom-Json
$beta = $manifest.beta

if (-not $beta) { throw "Manifest does not contain a beta release." }
if ($beta.version -ne $expectedVersion) {
    throw "Version mismatch. Expected $expectedVersion but found $($beta.version)."
}
if ([int64]$beta.size -ne $expectedSize) {
    throw "Manifest size mismatch. Expected $expectedSize but found $($beta.size)."
}
if ($beta.sha256.ToLower() -ne $expectedHash) {
    throw "Manifest SHA256 mismatch."
}
if ($beta.app_url -ne $expectedAppUrl) {
    throw "Manifest app_url mismatch. Expected $expectedAppUrl but found $($beta.app_url)."
}

$joiner = if ($beta.app_url.Contains("?")) { "&" } else { "?" }
$appUrl = "$($beta.app_url)$($joiner)cb=$timestamp"
Write-Host "Downloading live firmware..."
Invoke-WebRequest -Uri $appUrl -OutFile $tempApp -UseBasicParsing

$actualSize = (Get-Item $tempApp).Length
$actualHash = (Get-FileHash -Path $tempApp -Algorithm SHA256).Hash.ToLower()
$appText = Get-Content $tempApp -Raw
$versionNeedle = 'APP_VERSION = "1.1.33-beta"'
$embeddedVersionOk = $appText.Contains($versionNeedle)

Write-Host ""
Write-Host "Manifest version: $($beta.version)"
Write-Host "Manifest size: $($beta.size)"
Write-Host "Manifest SHA256: $($beta.sha256)"
Write-Host "Manifest app URL: $($beta.app_url)"
Write-Host "Embedded app version: $embeddedVersionOk"
Write-Host "Downloaded size: $actualSize"
Write-Host "Downloaded SHA256: $actualHash"
Write-Host ""

if (-not $embeddedVersionOk) {
    throw "Downloaded app.py does not contain the expected 1.1.33-beta APP_VERSION line."
}
if ($actualSize -ne $expectedSize) {
    throw "Published app.py size mismatch. Expected $expectedSize but found $actualSize."
}
if ($actualHash -ne $expectedHash) {
    throw "Published app.py SHA256 mismatch."
}

Write-Host "PASS: live 1.1.33 firmware and manifest match exactly." -ForegroundColor Green
