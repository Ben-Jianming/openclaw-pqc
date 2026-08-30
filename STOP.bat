@echo off
REM Stop all openclaw-pqc related processes
echo Stopping gateway + dashboard...

taskkill /F /IM node.exe /FI "WINDOWTITLE eq OpenClaw Gateway*" 2>NUL
taskkill /F /IM python.exe /FI "WINDOWTITLE eq PQC Dashboard*" 2>NUL

echo Done. Check:
echo   netstat -ano | findstr "18789 18800"
pause
