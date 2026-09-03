@echo off
REM ============================================================================
REM openclaw-pqc 6-check PQC verification (Windows cmd / bat)
REM Runs the same checks as verify.sh.
REM ============================================================================
setlocal EnableDelayedExpansion

set GREEN=[92m
set RED=[91m
set YELLOW=[93m
set RESET=[0m
set PASS=0
set FAIL=0
set FORK_DIR=%~dp0

echo ===============================================
echo   openclaw-pqc — 6-check PQC verify (Windows)
echo ===============================================
echo FORK_DIR: %FORK_DIR%
echo.

REM --- check 1: dashboard reachable ---
echo [1/6] PQC dashboard reachable on http://127.0.0.1:18800
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Uri 'http://127.0.0.1:18800/api/pqc-status').Content } catch { '' }" > "%TEMP%\dash.txt" 2>nul
findstr /i "pqc" "%TEMP%\dash.txt" >nul
if errorlevel 1 (
    echo %RED%[FAIL]%RESET% dashboard unreachable on 18800
    set /a FAIL+=1
) else (
    echo %GREEN%[PASS]%RESET% dashboard reachable + returned pqc-status JSON
    set /a PASS+=1
)

REM --- check 2: sqlite wrapped identity ---
echo [2/6] sqlite ML-DSA-65 device-identity wrapped
set SQLITE_PATH=%USERPROFILE%\.openclaw\state.db
if exist "%SQLITE_PATH%" (
    for /f "delims=" %%R in ('powershell -NoProfile -Command "try { (Get-Content -Raw '%SQLITE_PATH%' -ErrorAction Stop | Select-String -Pattern 'wrap-key').Matches.Count } catch { 0 }"') do set WRAPPED=%%R
    if !WRAPPED! GTR 0 (
        echo %GREEN%[PASS]%RESET% device_identities wrapped (wrap_key_id set)
        set /a PASS+=1
    ) else (
        echo %RED%[FAIL]%RESET% device_identities NOT wrapped
        set /a FAIL+=1
    )
) else (
    echo %YELLOW%[WARN]%RESET% sqlite db not found at %SQLITE_PATH%
)

REM --- check 3: PQC log markers ---
echo [3/6] pqcLog markers present in today's log
set LOG_FILE=
for /f "delims=" %%L in ('powershell -NoProfile -Command "Get-ChildItem -Path '%USERPROFILE%\.openclaw\logs','%TEMP%\openclaw' -ErrorAction SilentlyContinue -Filter 'openclaw-*.log' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName"') do set LOG_FILE=%%L
if defined LOG_FILE (
    powershell -NoProfile -Command "(Get-Content '%LOG_FILE%' | Select-String -Pattern '\[PQC\]').Count" > "%TEMP%\pqc_count.txt" 2>nul
    set /p PQC_LINES=<"%TEMP%\pqc_count.txt"
    if !PQC_LINES! GTR 0 (
        echo %GREEN%[PASS]%RESET% !PQC_LINES! [PQC] lines in %LOG_FILE%
        set /a PASS+=1
    ) else (
        echo %RED%[FAIL]%RESET% no [PQC] markers in %LOG_FILE%
        set /a FAIL+=1
    )
) else (
    echo %YELLOW%[WARN]%RESET% no log file found
)

REM --- check 4: dist symbols ---
echo [4/6] dist artifacts contain ML-DSA-65 / wrapSecret / pqcLog
set HITS=0
if exist "%FORK_DIR%dist" (
    for %%F in ("%FORK_DIR%dist\plugin-sdk\*.js") do (
        findstr /m "mldsa65" "%%F" >nul 2>&1 && set /a HITS+=1
        findstr /m "wrapSecret" "%%F" >nul 2>&1 && set /a HITS+=1
        findstr /m "pqcLog" "%%F" >nul 2>&1 && set /a HITS+=1
    )
)
if !HITS! GEQ 3 (
    echo %GREEN%[PASS]%RESET% dist symbols present
    set /a PASS+=1
) else (
    echo %RED%[FAIL]%RESET% dist symbols missing
    set /a FAIL+=1
)

REM --- check 5: gateway listening ---
echo [5/6] fork gateway process listening on port 18789
netstat -ano | findstr ":18789" >nul
if errorlevel 1 (
    echo %RED%[FAIL]%RESET% no process listening on 18789
    set /a FAIL+=1
) else (
    echo %GREEN%[PASS]%RESET% gateway listening on 18789
    set /a PASS+=1
)

REM --- check 6: PQC events ---
echo [6/6] pqcLog event counters increasing
if defined LOG_FILE (
    powershell -NoProfile -Command "(Get-Content '%LOG_FILE%' | Select-String -Pattern 'push-signature|device-identity|wrap-secret|unwrap-secret').Count" > "%TEMP%\ev_count.txt" 2>nul
    set /p EV_COUNT=<"%TEMP%\ev_count.txt"
    if !EV_COUNT! GTR 0 (
        echo %GREEN%[PASS]%RESET% !EV_COUNT! PQC events recorded in %LOG_FILE%
        set /a PASS+=1
    ) else (
        echo %RED%[FAIL]%RESET% no PQC events found
        set /a FAIL+=1
    )
) else (
    echo %YELLOW%[WARN]%RESET% skip (no log file)
)

echo.
echo ===============================================
echo   Result: !PASS! passed, !FAIL! failed
echo ===============================================
if !FAIL! NEQ 0 exit /b 1