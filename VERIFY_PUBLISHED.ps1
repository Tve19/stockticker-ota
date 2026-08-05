$ErrorActionPreference = "Stop"
$appUrl = "https://stockticker-ota.pages.dev/Beta/app.py?v=1128-auto-pairing-stable-links-1&cb=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
$manifestUrl = "https://stockticker-ota.pages.dev/manifest.json?cb=$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
$temp = Join-Path $env:TEMP "StockTicker-1.1.28-live.py"
Invoke-WebRequest -Uri $appUrl -OutFile $temp -UseBasicParsing
$actualSize = (Get-Item $temp).Length
$actualHash = (Get-FileHash -Path $temp -Algorithm SHA256).Hash.ToLower()
$manifest = ((Invoke-WebRequest -Uri $manifestUrl -UseBasicParsing).Content | ConvertFrom-Json).beta
Write-Host "Downloaded size:" $actualSize
Write-Host "Downloaded SHA256:" $actualHash
Write-Host "Manifest version:" $manifest.version
Write-Host "Manifest size:" $manifest.size
Write-Host "Manifest SHA256:" $manifest.sha256
if ($actualSize -ne 281687) { throw "Live app.py size does not match the release." }
if ($actualHash -ne "b53c4632a6f70795e85ef2cdfb7bd408752bfd4acb2dfce5710ab11a906c186a") { throw "Live app.py SHA256 does not match the release." }
if ([int64]$manifest.size -ne 281687) { throw "Manifest size does not match the release." }
if ($manifest.sha256.ToLower() -ne "b53c4632a6f70795e85ef2cdfb7bd408752bfd4acb2dfce5710ab11a906c186a") { throw "Manifest SHA256 does not match the release." }
if ($manifest.version -ne "1.1.28-beta") { throw "Manifest version is not 1.1.28-beta." }
Write-Host "PASS: live firmware and manifest match exactly." -ForegroundColor Green
