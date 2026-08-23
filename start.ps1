# Entry point for a fresh clone on Windows: creates the virtualenv if
# needed, installs the webscan package, checks (and offers to install)
# every external tool a scan can use, then drops straight into the
# `webscan` interactive shell.
#
# Usage:  .\start.ps1
# Safe to re-run any time -- every step is idempotent.

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RepoRoot "backend"
$VenvDir = Join-Path $BackendDir "venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvActivate = Join-Path $VenvDir "Scripts\Activate.ps1"

function Log($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }

if (-not (Test-Path $VenvPython)) {
    Log "No virtualenv found -- creating one at backend\venv ..."
    Push-Location $BackendDir
    try {
        python -m venv venv
    } finally {
        Pop-Location
    }
}

# Everything from here on (venv activation, pip install, and every
# `webscan` invocation) runs from backend\ on purpose: the app's sqlite
# database path is relative to the current directory
# (DATABASE_URL defaults to sqlite:///./dev.db), so running `webscan`
# from anywhere else creates a second, empty database there instead of
# using the one the rest of the tutorial/docs assume.
Set-Location $BackendDir

Log "Activating the virtualenv..."
. $VenvActivate

$webscanInstalled = $null -ne (Get-Command webscan -ErrorAction SilentlyContinue)
if (-not $webscanInstalled) {
    Log "Installing the webscan package (first run)..."
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -e .
}

Log "Checking external tools (subfinder, httpx, nuclei, nmap, msfconsole, testssl.sh)..."
webscan doctor
$doctorFailed = ($LASTEXITCODE -ne 0)

if ($doctorFailed) {
    Write-Host ""
    $answer = Read-Host "Some tools are missing or misdetected. Run the installer now? [Y/n]"
    if ($answer -eq "" -or $answer -match "^[Yy]") {
        & (Join-Path $BackendDir "scripts\install_all_windows.ps1")
        Write-Host ""
        Log "Re-checking tools after install..."
        webscan doctor
    } else {
        Write-Host "Skipping. You can run scripts\install_all_windows.ps1 later, or 'webscan doctor' to re-check." -ForegroundColor Yellow
    }
}

Write-Host ""
Log "Starting the webscan interactive shell..."
webscan
