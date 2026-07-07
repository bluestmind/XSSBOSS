@echo off
setlocal
title XSS Boss Backend Setup

cd /d "%~dp0"

set PYTHON_CMD=
where py >nul 2>nul
if not errorlevel 1 (
    set PYTHON_CMD=py -3
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        set PYTHON_CMD=python
    )
)

if "%PYTHON_CMD%"=="" (
    echo [!] Python 3 was not found.
    echo [!] Install Python 3.10+ from https://www.python.org/downloads/ and enable "Add python.exe to PATH".
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [+] Creating backend virtual environment...
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 exit /b 1
)

echo [+] Upgrading pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b 1

echo [+] Installing backend dependencies...
".venv\Scripts\python.exe" -m pip install -r backend_api\requirements.txt
if errorlevel 1 exit /b 1

echo [+] Installing Chromium for browser execution...
".venv\Scripts\python.exe" -m playwright install chromium
if errorlevel 1 exit /b 1

echo.
echo [+] Backend setup complete. You can now run run_all.bat.
pause

