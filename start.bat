@echo off
cd /d "%~dp0"
echo InfraSight starting...
start "" "http://localhost:5057"
"C:\Users\ilove\AppData\Local\Programs\Python\Python314\python.exe" server.py
pause
