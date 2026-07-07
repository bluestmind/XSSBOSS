@echo off
setlocal
title XSS Boss - Defender Lab Target
color 0A

echo =====================================================================
echo                 XSS Boss - Defender Lab Target Server
echo =====================================================================
echo.

set "ROOT=%~dp0"
set "PYTHONPATH=%ROOT%"

set "PYTHON_CMD=python"
if exist "%ROOT%.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%.venv\Scripts\python.exe"
) else if exist "%ROOT%venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%venv\Scripts\python.exe"
)

echo [+] Launching Defender Lab on http://127.0.0.1:8085 ...
echo [*] CTRL+C in this window to stop.
echo.

cd /d "%ROOT%defender_lab"
%PYTHON_CMD% backend.py

pause
endlocal
