Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

$distDir = Join-Path $projectRoot "dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$zipPath = Join-Path $distDir ("wechat-filehelper-listener-" + $stamp + ".zip")

$sources = @(
    ".\app",
    ".\config",
    ".\scripts",
    ".\requirements.txt",
    ".\README.md"
)

Compress-Archive -Path $sources -DestinationPath $zipPath -CompressionLevel Optimal -Force
Write-Host "Package created: $zipPath"
