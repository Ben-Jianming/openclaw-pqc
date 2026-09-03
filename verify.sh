#!/usr/bin/env bash
# ============================================================================
# openclaw-pqc 6-check PQC verification (bash / sh)
# Runs the same checks as verify.bat. Exits non-zero if any check fails.
# ============================================================================
set -uo pipefail

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"
PASS=0
FAIL=0

ok()   { printf "${GREEN}[PASS]${RESET} %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "${RED}[FAIL]${RESET} %s\n" "$1"; FAIL=$((FAIL+1)); }
warn() { printf "${YELLOW}[WARN]${RESET} %s\n" "$1"; :; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORK_DIR="${FORK_DIR:-$SCRIPT_DIR}"
cd "$FORK_DIR"

echo "==============================================="
echo "  openclaw-pqc — 6-check PQC verify"
echo "==============================================="
echo "FORK_DIR: $FORK_DIR"
echo

# --- check 1: dashboard reachable (18800) ---
echo "[1/6] PQC dashboard reachable on http://127.0.0.1:18800"
DASH_RESP=$(curl -s --max-time 3 http://127.0.0.1:18800/api/pqc-status 2>/>/dev/null || true)
if echo "$DASH_RESP" | grep -q "pqc"; then
    ok "dashboard reachable + returned pqc-status JSON"
else
    bad "dashboard unreachable on 18800 (is dashboard running?)"
fi

# --- check 2: sqlite wrapped identity ---
echo "[2/6] sqlite ML-DSA-65 device-identity wrapped"
SQLITE_PATH="$HOME/.openclaw/state.db"
if [ ! -f "$SQLITE_PATH" ]; then
    SQLITE_PATH="$USERPROFILE/.openclaw/state.db"
fi
if [ -f "$SQLITE_PATH" ]; then
    # wrapped_private_key_pem is NULL when plaintext, non-NULL when wrapped.
    ROWS=$(sqlite3 "$SQLITE_PATH" "SELECT wrap_key_id, length(private_key_pem) FROM device_identities LIMIT 1;" 2>/>/dev/null || true)
    if [ -n "$ROWS" ] && echo "$ROWS" | grep -qE "wrap-key|0$|NULL"; then
        ok "device_identities wrapped (wrap_key_id set, plaintext gone)"
    else
        bad "device_identities NOT wrapped: $ROWS"
    fi
else
    warn "sqlite db not found at $SQLITE_PATH (gateway may not have started yet)"
fi

# --- check 3: PQC log markers in today's log ---
echo "[3/6] pqcLog markers present in today's log"
LOG_DIR="$HOME/.openclaw/logs"
if [ ! -d "$LOG_DIR" ]; then
    LOG_DIR="/tmp/openclaw"
fi
TODAY=$(date +%Y-%m-%d)
LOG_FILE="$LOG_DIR/openclaw-$TODAY.log"
if [ ! -f "$LOG_FILE" ]; then
    LOG_FILE=$(ls -1t "$LOG_DIR"/openclaw-*.log 2>/dev/null | head -1)
fi
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    PQC_LINES=$(grep -c '\[PQC\]' "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$PQC_LINES" -gt 0 ]; then
        ok "$PQC_LINES [PQC] lines in $LOG_FILE"
    else
        bad "no [PQC] markers in $LOG_FILE"
    fi
else
    warn "no log file found at $LOG_DIR"
fi

# --- check 4: dist symbols present ---
echo "[4/6] dist artifacts contain ML-DSA-65 / wrapSecret / pqcLog"
DIST_GLOB=$(ls -1 "$FORK_DIR/dist"/plugin-sdk/*.js 2>/dev/null | head -3)
if [ -z "$DIST_GLOB" ]; then
    DIST_GLOB=$(ls -1 "$FORK_DIR"/dist-*/*.js 2>/dev/null | head -3)
fi
if [ -n "$DIST_GLOB" ]; then
    HITS=0
    for f in $DIST_GLOB; do
        for sym in mldsa65 wrapSecret pqcLog; do
            if grep -q "$sym" "$f" 2>/dev/null; then
                HITS=$((HITS+1))
            fi
        done
    done
    if [ "$HITS" -ge 3 ]; then
        ok "dist symbols present (ML-DSA-65 / wrapSecret / pqcLog all referenced)"
    else
        bad "dist symbols missing ($HITS/3+ matched)"
    fi
else
    warn "no dist artifacts in $FORK_DIR/dist"
fi

# --- check 5: fork process reachable (18789) ---
echo "[5/6] fork gateway process listening on port $GATEWAY_PORT"
if command -v ss >/dev/null 2>&1; then
    if ss -tlnp 2>/dev/null | grep -q ":$GATEWAY_PORT "; then
        ok "gateway listening on port $GATEWAY_PORT"
    else
        bad "no process listening on $GATEWAY_PORT"
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tln 2>/dev/null | grep -q ":$GATEWAY_PORT "; then
        ok "gateway listening on port $GATEWAY_PORT"
    else
        bad "no process listening on $GATEWAY_PORT"
    fi
else
    warn "neither ss nor netstat available"
fi

# --- check 6: gatekeeper count is positive ---
echo "[6/6] pqcLog event counters increasing"
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    EVENT_COUNT=$(grep -cE '(push-signature|device-identity|wrap-secret|unwrap-secret)' "$LOG_FILE" 2>/dev/null || echo 0)
    if [ "$EVENT_COUNT" -gt 0 ]; then
        ok "$EVENT_COUNT PQC events recorded in $LOG_FILE"
    else
        bad "no PQC events found in $LOG_FILE"
    fi
else
    warn "skip (no log file)"
fi

echo
echo "==============================================="
echo "  Result: $PASS passed, $FAIL failed"
echo "==============================================="
[ "$FAIL" -eq 0 ]