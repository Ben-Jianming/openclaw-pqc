@echo off
setlocal
cd /d "%~dp0"
node openclaw.mjs gateway stop %*
exit /b %errorlevel%
