$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required. Install Node 24.16 or newer from https://nodejs.org/"
}
& node "scripts/install-from-source.mjs" @args
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
