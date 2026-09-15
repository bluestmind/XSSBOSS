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
set "ORACLE_SERVER_URL=http://127.0.0.1:8001"
set "BROWSER_WORKER_CONCURRENCY=1"
set "MAX_QUEUE_ACTIVE=1"
set "MAX_PROFILING_WORKERS=1"
set "MAX_PAYLOADS_PER_CONTEXT=32"
set "MAX_TEST_CASES_PER_EXPERIMENT=1500"
set "BROWSER_RESTART_EVERY_TESTS=20"
set "CAPTURE_SCREENSHOTS=hits"
set "CAPTURE_DOM_SNAPSHOT=hits"
set "CAPTURE_RUNTIME_COVERAGE=all"
set "CAPTURE_RUNTIME_LINEAGE=all"
set "CAPTURE_DOM_DIFFERENTIAL=all"
set "RUNTIME_LINEAGE_AAB_PROBES=False"
set "USE_UNDETECTED_CHROME=False"
set "BROWSER_NAVIGATION_TIMEOUT=25"
set "ORACLE_WAIT_TIMEOUT=2.0"
set "REQUEST_DELAY_MS=1200"
set "MAX_REQUESTS_PER_MINUTE=40"
set "RATE_LIMIT_REDIS_ENABLED=False"
set "RATE_LIMIT_REDIS_REQUIRED=False"
set "RATE_LIMIT_FALLBACK_WORKER_ESTIMATE=1"
set "ADAPTIVE_THROTTLE=True"
set "THROTTLE_BACKOFF_MULTIPLIER=2.5"
set "THROTTLE_MAX_DELAY_MS=60000"
set "JITTER_FACTOR=0.15"
set "CIRCUIT_BREAKER_ENABLED=True"
set "CIRCUIT_BREAKER_THRESHOLD=3"
set "CIRCUIT_BREAKER_RECOVERY_SECS=120"
set "PROXY_ENABLED=False"
set "UPSTREAM_ROTATING_PROXY_ENABLED=False"
set "BURP_ENABLED=False"
set "BURP_AUTO_START=False"
set "BURP_PROXY_WORKERS=False"
set "WAF_BYPASS_HEADERS=False"
set "ALLOW_INSECURE_TLS=False"
set "ROTATE_USER_AGENT=False"
set "LLM_ENABLED=False"
set "API_HOST=127.0.0.1"
set "API_PORT=8000"
set "API_RELOAD=False"
set "BURP_API_URL=http://127.0.0.1:13337"
set "BURP_SCAN_STARTUP_TIMEOUT_SECONDS=3"
set "PYTHONPATH=%ROOT%"

if not defined BURP_API_KEY (
    echo [*] BURP_API_KEY is not set in this shell. The backend will use its configured default or .env value.
)

echo [+] Cleaning stale listeners on ports %API_PORT%, 8085, 8099, 8899...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%API_PORT%" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>nul
)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8085" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>nul
)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8099" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>nul
)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8899" ^| findstr "LISTENING"') do (
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
start "XSS Boss - API Server" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set CELERY_TASK_ALWAYS_EAGER=%CELERY_TASK_ALWAYS_EAGER%&& set REDIS_URL=%REDIS_URL%&& set BROWSER_WORKER_CONCURRENCY=%BROWSER_WORKER_CONCURRENCY%&& set MAX_QUEUE_ACTIVE=%MAX_QUEUE_ACTIVE%&& set MAX_PAYLOADS_PER_CONTEXT=%MAX_PAYLOADS_PER_CONTEXT%&& set MAX_TEST_CASES_PER_EXPERIMENT=%MAX_TEST_CASES_PER_EXPERIMENT%&& set BROWSER_RESTART_EVERY_TESTS=%BROWSER_RESTART_EVERY_TESTS%&& set CAPTURE_SCREENSHOTS=%CAPTURE_SCREENSHOTS%&& set CAPTURE_DOM_SNAPSHOT=%CAPTURE_DOM_SNAPSHOT%&& set API_HOST=%API_HOST%&& set API_PORT=%API_PORT%&& set API_RELOAD=%API_RELOAD%&& set BURP_API_URL=%BURP_API_URL%&& set BURP_API_KEY=%BURP_API_KEY%&& set BURP_SCAN_STARTUP_TIMEOUT_SECONDS=%BURP_SCAN_STARTUP_TIMEOUT_SECONDS%&& set BURP_PROXY_WORKERS=%BURP_PROXY_WORKERS%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT% && %PYTHON_CMD% -m uvicorn backend_api.main:app --host %API_HOST% --port %API_PORT%"

echo [+] Launching Vite React UI...
start "XSS Boss - Web UI" cmd /k "cd /d %ROOT%ui && npm run dev"

echo [+] Launching Hard Mock Target Lab...
start "XSS Boss - Hard Lab" cmd /k "set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT% && %PYTHON_CMD% hard_mock_target.py"

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
