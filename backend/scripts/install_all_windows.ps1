# One-shot installer for everything this tool can use on native Windows:
# Go (if missing), subfinder, httpx, nuclei (via 'go install'), this
# project's Python package (editable, inside the active venv), the
# Playwright Chromium browser, and nmap (via winget, if available).
#
# Every tool here is OPTIONAL at the module level -- a missing one just
# means that specific module reports a module_error and the rest of the
# scan continues (see README.md > Limitacoes conhecidas). Run
# `webscan doctor` after this to confirm what actually got detected.
#
# Metasploit and testssl.sh have no good native-Windows install path
# (Metasploit's Windows installer is unmaintained/deprecated upstream;
# testssl.sh is a bash script). Both are covered by
# scripts/install_all_linux.sh instead -- run that inside WSL if you
# want those two validators too.
#
# Idempotent: already-installed tools are detected and skipped, so
# re-running this after a partial run is safe.

$ErrorActionPreference = "Stop"

function Log($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "!! $msg" -ForegroundColor Yellow }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Split-Path -Parent $ScriptDir

Write-Host "This will install, for everything not already present:"
Write-Host "  - subfinder, httpx, nuclei (via 'go install', user-level)"
Write-Host "  - this project's Python package + dependencies (pip install -e ., in the active venv)"
Write-Host "  - Playwright's Chromium browser (playwright install chromium)"
Write-Host "  - nmap (via winget, if available)"
Write-Host ""
Write-Host "Metasploit and testssl.sh are NOT installed by this script -- see"
Write-Host "scripts/install_all_linux.sh (run inside WSL) for those two."
Write-Host ""

# --- Go-based tools (subfinder, httpx, nuclei) -------------------------

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Warn "Go is not installed. Install it from https://go.dev/dl/ first, then re-run this script."
    Warn "Skipping subfinder/httpx/nuclei."
} else {
    $goTools = @{
        "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "httpx"     = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "nuclei"    = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    }
    $gopathBin = (go env GOPATH) + "\bin"
    foreach ($tool in $goTools.Keys) {
        $existing = Get-Command $tool -ErrorAction SilentlyContinue
        if ($existing -and (Test-Path (Join-Path $gopathBin "$tool.exe"))) {
            Log "$tool already installed, skipping."
            continue
        }
        Log "Installing $tool..."
        go install $goTools[$tool]
    }

    $pathDirs = $env:PATH -split ";"
    if ($pathDirs -notcontains $gopathBin) {
        Warn "$gopathBin is not on PATH -- add it so subfinder/httpx/nuclei are found:"
        Warn '  [Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";' + $gopathBin + '", "User")'
    }
}

# --- Python package + Playwright ---------------------------------------

Log "Installing the webscan Python package (editable) and its dependencies..."
Push-Location $BackendDir
try {
    python -m pip install --quiet --upgrade pip
    python -m pip install --quiet -e .
} finally {
    Pop-Location
}

Log "Installing Playwright's Chromium browser..."
python -m playwright install chromium

# --- nmap ----------------------------------------------------------------

if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Log "nmap already installed, skipping."
} elseif (Get-Command winget -ErrorAction SilentlyContinue) {
    Log "Installing nmap via winget..."
    winget install --id Insecure.Nmap -e --accept-source-agreements --accept-package-agreements
} else {
    Warn "nmap not found and winget isn't available. Install it manually from https://nmap.org/download.html#windows"
}

Write-Host ""
Write-Host "Done. Run 'webscan doctor' to see what was actually detected on PATH." -ForegroundColor Green
Write-Host "For Metasploit + testssl.sh, run scripts/install_all_linux.sh inside WSL." -ForegroundColor Green
