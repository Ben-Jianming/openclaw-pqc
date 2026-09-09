#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if [[ ! -f dist/entry.js && ! -f dist/entry.mjs ]]; then
  echo "OpenClaw PQC is not built. Run ./install.sh first." >&2
  exit 1
fi
exec node openclaw.mjs gateway run "$@"
