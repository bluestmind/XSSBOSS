@echo off
setlocal
title Medium XSS Writeup Scraper
color 0E

echo =====================================================================
echo                 Medium XSS Writeup Scraper Launcher
echo =====================================================================
echo.

set "ROOT=%~dp0"
set "PYTHONPATH=%ROOT%"

set "PYTHON_CMD=python"
if exist "%ROOT%xss-lab\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%xss-lab\.venv\Scripts\python.exe"
) else if exist "%ROOT%.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%.venv\Scripts\python.exe"
) else if exist "%ROOT%venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%venv\Scripts\python.exe"
)

echo [*] Running medium_scraper.py using %PYTHON_CMD%...
echo.

%PYTHON_CMD% "%ROOT%medium_scraper.py"

echo.
echo =====================================================================
echo [*] Done. Press any key to exit.
echo =====================================================================
pause >nul
endlocal
