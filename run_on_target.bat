@echo off
setlocal
title XSS Boss - Live Target Demo
color 0A

echo =====================================================================
echo                  XSS Boss - Live Target Demo
echo =====================================================================
echo.
echo  Target : http://127.0.0.1:8088/target.html?q=test
echo  UI     : http://localhost:3000
echo.

set "ROOT=%~dp0"
set "PRESENTATION=%ROOT%..\presentation"
set "PYTHONPATH=%ROOT%"
set "PLAYWRIGHT_BROWSERS_PATH=%ROOT%.playwright-browsers"

:: Env overrides
set "DATABASE_URL=sqlite:///%ROOT%xssboss.db"
set "CELERY_TASK_ALWAYS_EAGER=True"
set "REDIS_URL="
set "API_HOST=127.0.0.1"
set "API_PORT=8000"
set "API_RELOAD=False"
set "BROWSER_WORKER_CONCURRENCY=1"
set "MAX_QUEUE_ACTIVE=2"
set "MAX_PAYLOADS_PER_CONTEXT=12"
set "MAX_TEST_CASES_PER_EXPERIMENT=300"
set "BROWSER_RESTART_EVERY_TESTS=20"
set "CAPTURE_SCREENSHOTS=hits"
set "CAPTURE_DOM_SNAPSHOT=hits"
set "USE_UNDETECTED_CHROME=True"
set "LLM_ENABLED=True"
set "LLM_MODEL=qwen3.5-9b"
set "LLM_API_URL=https://api.regolo.ai/v1/chat/completions"
:: OPENAI_API_KEY is read from .env by the backend — do not hardcode here
set "OPENAI_MODEL=qwen3.5-9b"
set "USE_BROWSER_CHATGPT=False"
set "BURP_ENABLED=False"
set "ORACLE_SERVER_URL=http://localhost:8001"

:: Find python
set "PYTHON_CMD=python"
if exist "%ROOT%.venv\Scripts\python.exe" set "PYTHON_CMD=%ROOT%.venv\Scripts\python.exe"

echo [*] Python: %PYTHON_CMD%
echo.

:: Kill stale listeners
echo [*] Clearing stale processes on ports 8000, 8001, 8088...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000 " ^| findstr "LISTENING" 2^>nul') do taskkill /F /PID %%p >nul 2>nul
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8001 " ^| findstr "LISTENING" 2^>nul') do taskkill /F /PID %%p >nul 2>nul
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8088 " ^| findstr "LISTENING" 2^>nul') do taskkill /F /PID %%p >nul 2>nul
timeout /t 1 >nul

:: 1. Serve the presentation target
echo [+] Starting Target Server (http://127.0.0.1:8088)...
start "XSS Boss - Target (8088)" cmd /k "cd /d "%PRESENTATION%" && python -m http.server 8088 --bind 127.0.0.1"

:: 2. Oracle callback server
echo [+] Starting Oracle Callback Server (port 8001)...
start "XSS Boss - Oracle (8001)" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d "%ROOT%oracle_server" && %PYTHON_CMD% main.py"

:: 3. FastAPI backend
echo [+] Starting FastAPI Backend (port 8000)...
start "XSS Boss - API (8000)" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set CELERY_TASK_ALWAYS_EAGER=%CELERY_TASK_ALWAYS_EAGER%&& set REDIS_URL=%REDIS_URL%&& set API_HOST=%API_HOST%&& set API_PORT=%API_PORT%&& set API_RELOAD=%API_RELOAD%&& set BROWSER_WORKER_CONCURRENCY=%BROWSER_WORKER_CONCURRENCY%&& set MAX_QUEUE_ACTIVE=%MAX_QUEUE_ACTIVE%&& set MAX_PAYLOADS_PER_CONTEXT=%MAX_PAYLOADS_PER_CONTEXT%&& set MAX_TEST_CASES_PER_EXPERIMENT=%MAX_TEST_CASES_PER_EXPERIMENT%&& set BROWSER_RESTART_EVERY_TESTS=%BROWSER_RESTART_EVERY_TESTS%&& set CAPTURE_SCREENSHOTS=%CAPTURE_SCREENSHOTS%&& set CAPTURE_DOM_SNAPSHOT=%CAPTURE_DOM_SNAPSHOT%&& set USE_UNDETECTED_CHROME=%USE_UNDETECTED_CHROME%&& set LLM_ENABLED=%LLM_ENABLED%&& set LLM_MODEL=%LLM_MODEL%&& set LLM_API_URL=%LLM_API_URL%&& set OPENAI_MODEL=%OPENAI_MODEL%&& set USE_BROWSER_CHATGPT=%USE_BROWSER_CHATGPT%&& set BURP_ENABLED=%BURP_ENABLED%&& set ORACLE_SERVER_URL=%ORACLE_SERVER_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d "%ROOT%backend_api" && %PYTHON_CMD% main.py"

:: 4. React UI
echo [+] Starting React UI (port 3000)...
start "XSS Boss - UI (3000)" cmd /k "cd /d "%ROOT%ui" && npm run dev"

echo.
echo =====================================================================
echo                         DEMO INSTRUCTIONS
echo =====================================================================
echo.
echo  STEP 1  Open http://localhost:3000 in your browser.
echo.
echo  STEP 2  Go to "Recon and Vuln Scan" in the sidebar.
echo          Enter target URL:
echo.
echo            http://127.0.0.1:8088/target.html?q=test
echo.
echo          Tick "I confirm I am authorized to test this target".
echo.
echo  STEP 3  Click "Run recon + vuln scan".
echo          The scanner will discover 4 XSS sinks:
echo            - Reflected XSS  (search ?q= parameter)
echo            - Reflected XSS  (profile ?user= parameter)
echo            - DOM XSS        (#hash fragment)
echo            - Stored XSS     (comment form -> localStorage)
echo.
echo  STEP 4  Watch findings appear live, then show PoC screenshots
echo          and the generated bug bounty report.
echo.
echo =====================================================================
echo  [+] All services launched. Press any key to close this window.
echo =====================================================================
echo.
pause >nul
endlocal
