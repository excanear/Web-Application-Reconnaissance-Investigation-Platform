$tools = @{
    "subfinder" = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx"     = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Go is not installed. Install Go from https://go.dev/dl/ before running this script." -ForegroundColor Red
    exit 1
}

foreach ($tool in $tools.Keys) {
    if (Get-Command $tool -ErrorAction SilentlyContinue) {
        Write-Host "$tool already installed, skipping."
        continue
    }
    Write-Host "Installing $tool..."
    go install $tools[$tool]
}

Write-Host "Done. Ensure `$(go env GOPATH)\bin` is on your PATH."
