@echo off
setlocal
cd /d "%~dp0"
if not exist "dist\entry.js" if not exist "dist\entry.mjs" (
  echo OpenClaw PQC is not built. Run install.bat first.
  exit /b 1
)
node openclaw.mjs gateway run %*
exit /b %errorlevel%
