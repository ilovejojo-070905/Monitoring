@echo off
cd /d "%~dp0"
echo InfraSight starting...
rem Security review pass: the login session cookie now requires HTTPS
rem (SESSION_COOKIE_SECURE) -- http://localhost:5057 will load the page but
rem never actually keep you logged in. Opens the HTTPS address via Caddy
rem instead; see ops\supervisor.ps1 for the normal (auto-start, auto-restart)
rem way to run both the backend and Caddy together.
start "" "https://localhost:8443"
rem Resolved via PATH rather than this machine's exact Python install path
rem (portability pass) so this script also works on another PC.
python server.py
pause
