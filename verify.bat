@echo off
setlocal
cd /d "%~dp0"
node scripts\verify-source-install.mjs
exit /b %errorlevel%
