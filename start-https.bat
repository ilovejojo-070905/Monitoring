@echo off
cd /d "%~dp0"
echo InfraSight (HTTPS via Caddy) starting...

rem Backend: same as start.bat, but no browser tab opens for it directly --
rem Caddy is the thing you actually browse to now.
rem Both resolved via PATH rather than this machine's exact install paths
rem (portability pass) so this script also works on another PC.
start "InfraSight backend" /min python server.py

rem Give the backend a moment to bind :5057 before Caddy starts proxying to it.
ping -n 3 127.0.0.1 >nul

start "" "https://localhost:8443"
caddy run --config Caddyfile
pause
