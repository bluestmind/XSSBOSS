@echo off
setlocal
title XSS Boss - Fast LLM Evasion Test
color 0E

echo =====================================================================
echo                 XSS Boss - Fast LLM Evasion Test Launcher
echo =====================================================================
echo.

set "ROOT=%~dp0"
set "PLAYWRIGHT_BROWSERS_PATH=%ROOT%.playwright-browsers"
set "PYTHONPATH=%ROOT%"

set "PYTHON_CMD=python"
if exist "%ROOT%.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%.venv\Scripts\python.exe"
) else if exist "%ROOT%venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%venv\Scripts\python.exe"
) else if exist "%ROOT%backend_api\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%backend_api\.venv\Scripts\python.exe"
) else if exist "%ROOT%backend_api\venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%backend_api\venv\Scripts\python.exe"
)

echo [*] Running fast_test_llm.py using %PYTHON_CMD%...
echo.

%PYTHON_CMD% "%ROOT%fast_test_llm.py"

echo.
echo =====================================================================
echo [*] Done. Press any key to exit.
echo =====================================================================
pause >nul
endlocal
