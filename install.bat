@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node 24.16 or newer from https://nodejs.org/
  exit /b 1
)
node scripts\install-from-source.mjs %*
exit /b %errorlevel%
