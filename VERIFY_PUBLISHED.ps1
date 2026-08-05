$ErrorActionPreference = "Stop"

$appUrl = "https://stockticker-ota.pages.dev/Beta/app.py?v=1129-customer-polish-1&cb=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
$manifestUrl = "https://stockticker-ota.pages.dev/manifest.json?cb=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"

$temp = Join-Path $env:TEMP "StockTicker-1.1.29-live.py"

Invoke-WebRequest -Uri $appUrl -OutFile $temp -UseBasicParsing

$actualSize = (Get-Item $temp).Length
$actualHash = (Get-FileHash -Path $temp -Algorithm SHA256).Hash.ToLower()

$manifest = (
    (Invoke-WebRequest -Uri $manifestUrl -UseBasicParsing).Content |
    ConvertFrom-Json
).beta

Write-Host "Downloaded size:" $actualSize
Write-Host "Downloaded SHA256:" $actualHash
Write-Host "Manifest version:" $manifest.version
Write-Host "Manifest size:" $manifest.size
Write-Host "Manifest SHA256:" $manifest.sha256

if ($actualSize -ne 285382) {
    throw "Live app.py size does not match the 1.1.29 release."
}

if ($actualHash -ne "56508bb07c8cc938417da7bdfda7b6ccc12ab9c56721387617c798ab56b7334d") {
    throw "Live app.py SHA256 does not match the 1.1.29 release."
}

if ([int64]$manifest.size -ne 285382) {
    throw "Manifest size does not match the 1.1.29 release."
}

if ($manifest.sha256.ToLower() -ne "56508bb07c8cc938417da7bdfda7b6ccc12ab9c56721387617c798ab56b7334d") {
    throw "Manifest SHA256 does not match the 1.1.29 release."
}

if ($manifest.version -ne "1.1.29-beta") {
    throw "Manifest version is not 1.1.29-beta."
}

Write-Host "PASS: live 1.1.29 firmware and manifest match exactly." -ForegroundColor Green
