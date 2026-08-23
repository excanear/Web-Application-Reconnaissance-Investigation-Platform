#!/usr/bin/env bash
# One-shot installer for everything this tool can use on Linux:
# Go (if missing), subfinder, httpx, nuclei, the Python package itself
# (editable, inside whatever venv is active), the Playwright Chromium
# browser + its OS libraries, and the Metasploit Framework.
#
# Every tool here is OPTIONAL at the module level -- a missing one just
# means that specific module reports a module_error and the rest of the
# scan continues (see README.md > Limitações conhecidas). This script
# exists so a fresh Linux machine doesn't have to hunt down each one by
# hand across five different READMEs.
#
# Idempotent: already-installed tools are detected and skipped, so
# re-running this after a partial run (or to pick up a new tool added
# later) is safe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"

log() { echo ">> $*"; }
warn() { echo "!! $*" >&2; }

if [ "$(uname -s)" != "Linux" ]; then
  warn "This script is Linux-only (Metasploit's installer and --with-deps both assume apt/dpkg)."
  warn "On Windows/macOS, follow the per-tool install steps in README.md instead."
  exit 1
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    warn "Not running as root and 'sudo' isn't available -- Metasploit and 'playwright install --with-deps' both need root to install OS packages."
    exit 1
  fi
  SUDO="sudo"
fi

echo "This will install, for everything not already present:"
echo "  - Go (via apt), if missing"
echo "  - subfinder, httpx, nuclei (via 'go install', user-level, no root)"
echo "  - this project's Python package + dependencies (pip install -e ., in the active venv)"
echo "  - Playwright's Chromium + required OS libraries (playwright install --with-deps chromium)"
echo "  - the Metasploit Framework (Rapid7's official apt-repo installer)"
echo
echo "Go/Playwright/Metasploit steps need sudo (apt); you'll be prompted if needed."
echo

# --- Go + Go-based tools ----------------------------------------------

if ! command -v go >/dev/null 2>&1; then
  log "Go not found -- installing via apt..."
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq golang-go
else
  log "Go already installed, skipping."
fi

# nuclei pulls in cgo dependencies (e.g. mattn/go-sqlite3, zmap/zgrab2)
# that need a real C toolchain + libpcap headers to build -- a bare
# `apt-get install golang-go` doesn't include either, and `go install`
# fails deep in a cgo compile with no indication build-essential was the
# problem. Installed unconditionally since apt already no-ops on
# packages that are present.
log "Ensuring a C toolchain is available for nuclei's cgo dependencies..."
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq build-essential libpcap-dev

GOBIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOBIN"

declare -A go_tools=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for tool in "${!go_tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    log "$tool already installed, skipping."
    continue
  fi
  log "Installing $tool..."
  go install "${go_tools[$tool]}"
done

if command -v nuclei >/dev/null 2>&1; then
  log "Updating nuclei's community template library..."
  nuclei -update-templates -silent || warn "nuclei -update-templates failed -- nuclei_validation will still run once you retry this manually."
fi

# --- This project's Python package -------------------------------------

log "Installing the webscan Python package (pip install -e .)..."
cd "$BACKEND_DIR"
python3 -m pip install -q -r requirements.txt
python3 -m pip install -q -e .

# --- Playwright Chromium (for browser_fingerprint) ----------------------

if python3 -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch()
    b.close()
" >/dev/null 2>&1; then
  log "Playwright Chromium already installed and launches cleanly, skipping."
else
  log "Installing Playwright's Chromium + OS libraries (playwright install --with-deps chromium)..."
  # Run as the invoking user, not wrapped in $SUDO: Playwright downloads
  # the browser into that user's own $HOME/.cache/ms-playwright and only
  # shells out to sudo itself for the OS-package half of --with-deps.
  # Wrapping the whole command in sudo would download the browser into
  # root's home instead, and the tool (run later as a normal user) would
  # never find it.
  python3 -m playwright install --with-deps chromium
fi

# --- Metasploit Framework (for msf_validation) --------------------------

if command -v msfconsole >/dev/null 2>&1; then
  log "msfconsole already installed, skipping."
else
  log "Installing the Metasploit Framework (this downloads ~400MB, takes a few minutes)..."
  MSF_INSTALLER="$(mktemp)"
  curl -sS https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o "$MSF_INSTALLER"
  chmod 755 "$MSF_INSTALLER"
  $SUDO "$MSF_INSTALLER"
  rm -f "$MSF_INSTALLER"
fi

echo
log "Done. Summary:"
for tool in subfinder httpx nuclei msfconsole; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  [ok] $tool"
  else
    echo "  [missing] $tool"
  fi
done
if python3 -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    p.chromium.launch().close()
" >/dev/null 2>&1; then
  echo "  [ok] Playwright Chromium"
else
  echo "  [missing] Playwright Chromium"
fi

echo
echo "If this is a new shell, make sure \$(go env GOPATH)/bin is on your PATH"
echo "before running 'webscan' (add 'export PATH=\"\$PATH:\$(go env GOPATH)/bin\"' to your shell profile)."
