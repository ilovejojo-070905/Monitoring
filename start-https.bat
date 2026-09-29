@echo off
cd /d "%~dp0"
echo InfraSight (HTTPS via Caddy) starting...

rem Backend: same as start.bat, but no browser tab opens for it directly --
rem Caddy is the thing you actually browse to now.
start "InfraSight backend" /min "C:\Users\ilove\AppData\Local\Programs\Python\Python314\python.exe" server.py

rem Give the backend a moment to bind :5057 before Caddy starts proxying to it.
ping -n 3 127.0.0.1 >nul

start "" "https://localhost:8443"
"C:\Users\ilove\AppData\Local\Microsoft\WinGet\Packages\CaddyServer.Caddy_Microsoft.Winget.Source_8wekyb3d8bbwe\caddy.exe" run --config Caddyfile
pause
