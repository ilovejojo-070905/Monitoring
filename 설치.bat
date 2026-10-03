@echo off
rem InfraSight installer launcher -- double-click this file to start.
rem Just runs install.ps1 (in this same folder) with the flags needed to
rem bypass PowerShell's default "scripts are disabled" policy for this one
rem run only (does not change the system-wide execution policy).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
