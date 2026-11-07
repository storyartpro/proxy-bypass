@echo off
setlocal
set "ROOT=%~dp0"
set "PROXY_APP_DATA=%ROOT%data"
if not exist "%PROXY_APP_DATA%" mkdir "%PROXY_APP_DATA%"
cd /d "%ROOT%app"
set PROXY_APP_PORT=8077
node server.mjs
