@echo off
setlocal Enabledelayedexpansion
title XSS Boss - Complete System Installer
color 0B

echo =====================================================================
echo                 XSS Boss - Full Environment Installer
echo =====================================================================
echo.
echo  This script will prepare your system to run XSS Boss by installing
echo  both backend and frontend dependencies.
echo.
echo ---------------------------------------------------------------------
echo  STEP 1: Backend Setup (Python Virtual Environment ^& Playwright)
echo ---------------------------------------------------------------------
echo.

cd /d "%~dp0"

:: Detect Python
set "PYTHON_CMD="
where py >nul 2>nul
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_CMD=python"
    )
)

if "%PYTHON_CMD%"=="" (
    echo [!] ERROR: Python 3 was not found on your system PATH.
    echo [!] Please install Python 3.10+ from https://www.python.org/downloads/
    echo [!] Make sure to check the box "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Using Python command: %PYTHON_CMD%

:: Validate and Create Virtual Environment
set "RECREATE_VENV=false"
if exist ".venv\Scripts\python.exe" (
    echo [*] Verifying existing virtual environment integrity...
    ".venv\Scripts\python.exe" -c "import os" >nul 2>nul
    if errorlevel 1 (
        echo [!] Virtual environment path mismatch or invalid (e.g. copied from another laptop). Rebuilding...
        set "RECREATE_VENV=true"
    ) else (
        echo [+] Virtual environment is valid.
    )
) else (
    set "RECREATE_VENV=true"
)

if "%RECREATE_VENV%"=="true" (
    echo [+] Creating Python virtual environment in .venv...
    if exist ".venv" rd /s /q ".venv"
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: Force Playwright to download and run browser binaries strictly inside the project root
set "PLAYWRIGHT_BROWSERS_PATH=%~dp0.playwright-browsers"
echo [+] Setting Playwright browser path to: %PLAYWRIGHT_BROWSERS_PATH%

echo [+] Upgrading package manager (pip)...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo [!] Failed to upgrade pip.
    pause
    exit /b 1
)

echo [+] Installing Python dependencies...
".venv\Scripts\python.exe" -m pip install -r backend_api\requirements.txt
if errorlevel 1 (
    echo [!] Failed to install python packages.
    pause
    exit /b 1
)

echo [+] Installing headless Playwright Chromium driver into project root...
".venv\Scripts\python.exe" -m playwright install chromium
if errorlevel 1 (
    echo [!] Warning: Playwright browser installation encountered a problem.
    echo [!] You might need to manually run: set PLAYWRIGHT_BROWSERS_PATH=%~dp0.playwright-browsers && .venv\Scripts\python -m playwright install chromium
)

echo.
echo ---------------------------------------------------------------------
echo  STEP 2: Frontend Setup (NodeJS ^& UI Dependencies)
echo ---------------------------------------------------------------------
echo.

:: Detect Node / NPM
set "NPM_CMD="
where npm >nul 2>nul
if not errorlevel 1 (
    set "NPM_CMD=npm"
)

if "%NPM_CMD%"=="" (
    echo [!] WARNING: Node.js/NPM was not found on your system PATH.
    echo [!] You must install Node.js (LTS version recommended) from:
    echo [!] https://nodejs.org/
    echo [!] After installing Node.js, reopen this installer or run:
    echo [!]   cd ui ^&^& npm install
    echo.
) else (
    echo [+] Node.js/NPM detected. Installing UI dependencies...
    cd ui
    call npm install
    if errorlevel 1 (
        echo [!] ERROR: npm install failed. Check npm-debug.log or your connection.
    ) else (
        echo [+] Frontend dependencies installed successfully.
    )
    cd ..
)

echo.
echo =====================================================================
echo                 INSTALLATION PROCESS COMPLETE
echo =====================================================================
echo.
echo  To run the full hackathon presentation target lab + UI:
echo     ==^> Run: run_hackathon_demo.bat
echo.
echo  To run the production interface normally:
echo     ==^> Run: run_all.bat
echo.
echo =====================================================================
pause
endlocal
