Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "[1/4] Checking Python..."
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    throw "python command not found. Install Python 3.11+ and add it to PATH."
}

$pyVersionText = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ([version]$pyVersionText -lt [version]"3.11") {
    throw "Python version is too low: $pyVersionText. Python 3.11+ is required."
}

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[2/4] Creating virtual environment..."
    & python -m venv .venv
} else {
    Write-Host "[2/4] Virtual environment already exists. Skipping."
}

Write-Host "[3/4] Installing dependencies..."
& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install -r .\requirements.txt

Write-Host "[4/4] Preparing runtime folders..."
New-Item -ItemType Directory -Path ".\runtime\logs" -Force | Out-Null

Write-Host ""
Write-Host "Install complete. Run:"
Write-Host "  .\scripts\run.cmd"
