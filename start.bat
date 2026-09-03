@echo off
REM ============================================================================
REM openclaw-pqc production gateway + PQC dashboard starter
REM Run this from a normal cmd window (not from a background task!)
REM ============================================================================

set GATEWAY_DIR=D:\openclaw-pqc-fresh\openclaw-pqc-pqc-ws
set DASHBOARD_DIR=D:\minimax\pqc-dashboard

REM MiniMax LLM token (replace if regenerating)
set MINIMAX_API_KEY=sk-api-rUyClb7esCB2XTZ3L9aD1QOZt_fdm0T5ZtxFVflXeGy2hrSMujA0DeEhBZgSZyU5hVFxmmQDDjLl8TEiIGSs0f66xnGVdgZmuYunPrtglkGjItC0nFF4UVQ

REM Open PQC dashboard in new window
echo Starting PQC dashboard (port 18800)...
start "PQC Dashboard (18800)" /MIN cmd /k "cd /d %DASHBOARD_DIR% && python app.py"

REM Wait for dashboard to be ready
timeout /t 2 /nobreak > NUL

REM Open gateway in new window
echo Starting OpenClaw gateway (port 18789)...
cd /d %GATEWAY_DIR%
start "OpenClaw Gateway (18789)" /MIN cmd /k "set MINIMAX_API_KEY=%MINIMAX_API_KEY% && node openclaw.mjs gateway run"

echo.
echo Both services started:
echo   - PQC dashboard: http://127.0.0.1:18800/
echo   - Gateway:       ws://127.0.0.1:18789 (internal only)
echo.
echo To stop: close the two cmd windows, or run STOP.bat
pause
