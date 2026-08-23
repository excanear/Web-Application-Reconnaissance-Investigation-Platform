#!/usr/bin/env bash
# Entry point for a fresh clone on Linux/macOS/WSL: creates the
# virtualenv if needed, installs the webscan package, checks (and
# offers to install) every external tool a scan can use, then drops
# straight into the `webscan` interactive shell.
#
# Usage:  ./start.sh
# Safe to re-run any time -- every step is idempotent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
VENV_DIR="$BACKEND_DIR/venv"

log() { echo ">> $*"; }

if [ ! -x "$VENV_DIR/bin/python" ]; then
  log "No virtualenv found -- creating one at backend/venv ..."
  (cd "$BACKEND_DIR" && python3 -m venv venv)
fi

# Everything from here on (venv activation, pip install, and every
# `webscan` invocation) runs from backend/ on purpose: the app's sqlite
# database path is relative to the current directory (DATABASE_URL
# defaults to sqlite:///./dev.db), so running `webscan` from anywhere
# else creates a second, empty database there instead of using the one
# the rest of the tutorial/docs assume.
cd "$BACKEND_DIR"

log "Activating the virtualenv..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if ! command -v webscan >/dev/null 2>&1; then
  log "Installing the webscan package (first run)..."
  python -m pip install --quiet --upgrade pip
  python -m pip install --quiet -e .
fi

log "Checking external tools (subfinder, httpx, nuclei, msfconsole, nmap, testssl.sh)..."
if ! webscan doctor; then
  echo
  read -r -p "Some tools are missing or misdetected. Run the installer now? [Y/n] " answer
  answer="${answer:-Y}"
  if [[ "$answer" =~ ^[Yy] ]]; then
    "$BACKEND_DIR/scripts/install_all_linux.sh"
    echo
    log "Re-checking tools after install..."
    webscan doctor || true
  else
    echo "Skipping. You can run backend/scripts/install_all_linux.sh later, or 'webscan doctor' to re-check."
  fi
fi

echo
log "Starting the webscan interactive shell..."
exec webscan
