#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required. Install Node 24.16 or newer from https://nodejs.org/" >&2
  exit 1
fi
exec node scripts/install-from-source.mjs "$@"
