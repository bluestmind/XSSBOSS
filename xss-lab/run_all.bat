@echo off
setlocal
title XSS Boss Launcher
color 0B

echo =====================================================================
echo                 XSS Boss - Simplified Launcher
echo =====================================================================
echo.
echo [+] Starting Simplified SQLite + Eager mode.
echo [*] No menu, no Redis, no Celery. This is the default XSS Boss flow.
echo.

set "ROOT=%~dp0"
set "PLAYWRIGHT_BROWSERS_PATH=%ROOT%.playwright-browsers"
set "DATABASE_URL=sqlite:///%ROOT%xssboss.db"
set "CELERY_TASK_ALWAYS_EAGER=True"
set "REDIS_URL="
set "BROWSER_WORKER_CONCURRENCY=1"
set "MAX_QUEUE_ACTIVE=1"
set "MAX_PAYLOADS_PER_CONTEXT=8"
set "MAX_TEST_CASES_PER_EXPERIMENT=300"
set "BROWSER_RESTART_EVERY_TESTS=15"
set "CAPTURE_SCREENSHOTS=hits"
set "CAPTURE_DOM_SNAPSHOT=hits"
set "API_HOST=127.0.0.1"
set "API_PORT=8000"
set "API_RELOAD=False"
set "BURP_API_URL=http://127.0.0.1:13337"
set "PYTHONPATH=%ROOT%"

if not defined BURP_API_KEY (
    echo [*] BURP_API_KEY is not set in this shell. The backend will use its configured default or .env value.
)

echo [+] Cleaning stale API listeners on port %API_PORT%...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%API_PORT%" ^| findstr "LISTENING"') do (
    echo     Stopping stale process %%p
    taskkill /F /PID %%p >nul 2>nul
)

set "PYTHON_CMD=python"
if exist "%ROOT%.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%.venv\Scripts\python.exe"
) else if exist "%ROOT%venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%venv\Scripts\python.exe"
) else if exist "%ROOT%backend_api\.venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%backend_api\.venv\Scripts\python.exe"
) else if exist "%ROOT%backend_api\venv\Scripts\python.exe" (
    set "PYTHON_CMD=%ROOT%backend_api\venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if errorlevel 1 (
        where py >nul 2>nul
        if errorlevel 1 (
            echo [!] Python was not found on PATH and no virtual environment was found.
            echo [!] Run setup_backend.bat after installing Python 3.10+.
            pause
            exit /b 1
        ) else (
            set "PYTHON_CMD=py -3"
        )
    )
)

echo [+] Launching Oracle Callback Server...
start "XSS Boss - Oracle Server" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT%oracle_server && %PYTHON_CMD% main.py"

echo [+] Launching FastAPI API Server...
start "XSS Boss - API Server" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set CELERY_TASK_ALWAYS_EAGER=%CELERY_TASK_ALWAYS_EAGER%&& set REDIS_URL=%REDIS_URL%&& set BROWSER_WORKER_CONCURRENCY=%BROWSER_WORKER_CONCURRENCY%&& set MAX_QUEUE_ACTIVE=%MAX_QUEUE_ACTIVE%&& set MAX_PAYLOADS_PER_CONTEXT=%MAX_PAYLOADS_PER_CONTEXT%&& set MAX_TEST_CASES_PER_EXPERIMENT=%MAX_TEST_CASES_PER_EXPERIMENT%&& set BROWSER_RESTART_EVERY_TESTS=%BROWSER_RESTART_EVERY_TESTS%&& set CAPTURE_SCREENSHOTS=%CAPTURE_SCREENSHOTS%&& set CAPTURE_DOM_SNAPSHOT=%CAPTURE_DOM_SNAPSHOT%&& set API_HOST=%API_HOST%&& set API_PORT=%API_PORT%&& set API_RELOAD=%API_RELOAD%&& set BURP_API_URL=%BURP_API_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT%backend_api && %PYTHON_CMD% main.py"

echo [+] Launching Vite React UI...
start "XSS Boss - Web UI" cmd /k "cd /d %ROOT%ui && npm run dev"

echo [+] Launching Hard Mock Target Lab...
start "XSS Boss - Hard Lab" cmd /k "set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& %PYTHON_CMD% hard_mock_target.py"

echo.
echo =====================================================================
echo [+] XSS Boss launched.
echo [*] API: http://127.0.0.1:%API_PORT%
echo [*] UI:  http://localhost:3000
echo [*] Lab Target: http://127.0.0.1:8099
echo [*] Burp REST: %BURP_API_URL%
echo [*] Close the opened service windows to stop XSS Boss.
echo =====================================================================
pause
endlocal
