#!/usr/bin/env bash
# ============================================================================
# openclaw-pqc stop script (bash / sh) — kills gateway + dashboard processes
# ============================================================================
set -euo pipefail

echo "Stopping gateway + dashboard..."

# Match OpenClaw gateway by command line (node openclaw.mjs gateway)
PIDS=$(pgrep -f "node openclaw.mjs gateway" 2>/>/dev/null || true)
if [ -n "$PIDS" ]; then
    echo "  killing gateway pids: $PIDS"
    kill -TERM $PIDS 2>/>/dev/null || true
    sleep 1
    kill -KILL $PIDS 2>/>/dev/null || true
fi

# Match dashboard (python3 app.py) — heuristic only, since the dashboard does
# not set a marker process title.
PIDS=$(pgrep -f "python3? .*app\.py" 2>/>/dev/null || true)
if [ -n "$PIDS" ]; then
    echo "  killing dashboard pids: $PIDS"
    kill -TERM $PIDS 2>/>/dev/null || true
    sleep 1
    kill -KILL $PIDS 2>/>/dev/null || true
fi

echo "Done. Verify with:"
echo "  ss -tlnp 2>/dev/null | grep -E '18789|18800' || netstat -an | grep -E '18789|18800'"