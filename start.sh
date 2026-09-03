#!/usr/bin/env bash
# ============================================================================
# openclaw-pqc production gateway + PQC dashboard starter (bash / sh)
# Runs on Linux, macOS, and WSL. Detects dashboard at ../pqc-dashboard
# relative to FORK_DIR (default: this script's directory).
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORK_DIR="${FORK_DIR:-$SCRIPT_DIR}"

# MiniMax LLM token. Replace by setting MINIMAX_API_KEY in your shell before
# running this script in production.
export MINIMAX_API_KEY="${MINIMAX_API_KEY:-sk-api-rUyClb7esCB2XTZ3L9aD1QOZt_fdm0T5ZtxFVflXeGy2hrSMujA0DeEhBZgSZyU5hVFxmmQDDjLl8TEiIGSs0f66xnGVdgZmuYunPrtglkGjItC0nFF4UVQ}"

# Detect dashboard location: look in ../pqc-dashboard relative to fork
DASHBOARD_DIR="${DASHBOARD_DIR:-$(cd "$FORK_DIR/.." 2>/dev/null && pwd)/pqc-dashboard}"
if [ ! -f "$DASHBOARD_DIR/app.py" ]; then
    DASHBOARD_DIR=""
fi

GATEWAY_PORT="${GATEWAY_PORT:-18789}"
DASHBOARD_PORT="${DASHBOARD_PORT:-18800}"

mkdir -p "$FORK_DIR"

# Start PQC dashboard (Python Flask) if present
if [ -n "$DASHBOARD_DIR" ] && [ -f "$DASHBOARD_DIR/app.py" ]; then
    echo "Starting PQC dashboard (port $DASHBOARD_PORT)..."
    (cd "$DASHBOARD_DIR" && nohup python3 app.py >"$FORK_DIR/dashboard-autostart.log" 2>&1 &)
else
    echo "PQC dashboard skipped (no app.py at $DASHBOARD_DIR)"
fi

# Give dashboard 2 s to bind its port
sleep 2

# Start OpenClaw gateway
echo "Starting OpenClaw gateway (port $GATEWAY_PORT)..."
cd "$FORK_DIR"
nohup node openclaw.mjs gateway run --port "$GATEWAY_PORT" --allow-unconfigured \
    >"$FORK_DIR/fork-autostart.log" 2>&1 &

echo
echo "Both services started:"
[ -n "$DASHBOARD_DIR" ] && echo "  - PQC dashboard: http://127.0.0.1:$DASHBOARD_PORT/"
echo "  - Gateway:       ws://127.0.0.1:$GATEWAY_PORT (internal only)"
echo
echo "To stop: run ./stop.sh"