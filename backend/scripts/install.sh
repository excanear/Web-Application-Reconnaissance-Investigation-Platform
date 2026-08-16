#!/usr/bin/env bash
set -euo pipefail

declare -A tools=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
)

if ! command -v go >/dev/null 2>&1; then
  echo "Go is not installed. Install Go from https://go.dev/dl/ before running this script." >&2
  exit 1
fi

for tool in "${!tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "$tool already installed, skipping."
    continue
  fi
  echo "Installing $tool..."
  go install "${tools[$tool]}"
done

echo "Done. Ensure \$(go env GOPATH)/bin is on your PATH."
