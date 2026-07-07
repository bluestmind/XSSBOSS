@echo off
setlocal
title XSS Boss - Hackathon Presentation Launcher
color 0C

echo =====================================================================
echo                 XSS Boss - Hackathon Demo Launcher
echo =====================================================================
echo.
echo [+] Preparing the system for a flawless hackathon demonstration...
echo.

set "ROOT=%~dp0"
set "PLAYWRIGHT_BROWSERS_PATH=%ROOT%.playwright-browsers"
set "DATABASE_URL=sqlite:///%ROOT%xssboss.db"
set "CELERY_TASK_ALWAYS_EAGER=True"
set "REDIS_URL="
set "BROWSER_WORKER_CONCURRENCY=1"
set "MAX_QUEUE_ACTIVE=1"
set "MAX_PAYLOADS_PER_CONTEXT=8"
set "MAX_TEST_CASES_PER_EXPERIMENT=150"
set "BROWSER_RESTART_EVERY_TESTS=15"
set "CAPTURE_SCREENSHOTS=hits"
set "CAPTURE_DOM_SNAPSHOT=hits"
set "API_HOST=127.0.0.1"
set "API_PORT=8000"
set "API_RELOAD=False"
set "BURP_API_URL=http://127.0.0.1:13337"
set "PYTHONPATH=%ROOT%"

:: Clean stale API listeners on port 8000
echo [*] Checking for stale processes on port %API_PORT%...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":%API_PORT%" ^| findstr "LISTENING"') do (
    echo     Stopping stale process %%p
    taskkill /F /PID %%p >nul 2>nul
)

:: Find python command
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

echo [*] Using python: %PYTHON_CMD%

:: Seed mock target and reset DB state
echo [*] Resetting and seeding database with vulnerable Mock Lab...
%PYTHON_CMD% "%ROOT%tools\seed_hard_lab.py" --reset
if errorlevel 1 (
    echo.
    echo [!] Database seeding failed. Make sure you ran setup_backend.bat first.
    pause
    exit /b 1
)

echo.
echo =====================================================================
echo                 LAUNCHING SERVICE ORCHESTRATION
echo =====================================================================
echo.

:: 1. Launch Oracle callback server
echo [+] Starting Oracle Callback Server (Port 8001)...
start "XSS Boss - Oracle Server" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT%oracle_server && %PYTHON_CMD% main.py"

:: 2. Launch API Server
echo [+] Starting FastAPI Backend (Port 8000)...
start "XSS Boss - API Server" cmd /k "set DATABASE_URL=%DATABASE_URL%&& set CELERY_TASK_ALWAYS_EAGER=%CELERY_TASK_ALWAYS_EAGER%&& set REDIS_URL=%REDIS_URL%&& set BROWSER_WORKER_CONCURRENCY=%BROWSER_WORKER_CONCURRENCY%&& set MAX_QUEUE_ACTIVE=%MAX_QUEUE_ACTIVE%&& set MAX_PAYLOADS_PER_CONTEXT=%MAX_PAYLOADS_PER_CONTEXT%&& set MAX_TEST_CASES_PER_EXPERIMENT=%MAX_TEST_CASES_PER_EXPERIMENT%&& set BROWSER_RESTART_EVERY_TESTS=%BROWSER_RESTART_EVERY_TESTS%&& set CAPTURE_SCREENSHOTS=%CAPTURE_SCREENSHOTS%&& set CAPTURE_DOM_SNAPSHOT=%CAPTURE_DOM_SNAPSHOT%&& set API_HOST=%API_HOST%&& set API_PORT=%API_PORT%&& set API_RELOAD=%API_RELOAD%&& set BURP_API_URL=%BURP_API_URL%&& set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& cd /d %ROOT%backend_api && %PYTHON_CMD% main.py"

:: 3. Launch Hard Mock Target Lab
echo [+] Starting Hard Mock Target Lab (Port 8099)...
start "XSS Boss - Hard Lab" cmd /k "set PYTHONPATH=%PYTHONPATH%&& set PLAYWRIGHT_BROWSERS_PATH=%PLAYWRIGHT_BROWSERS_PATH%&& %PYTHON_CMD% hard_mock_target.py"

:: 4. Launch React UI
echo [+] Starting React Frontend UI (Port 3000)...
start "XSS Boss - Web UI" cmd /k "cd /d %ROOT%ui && npm run dev"

echo.
echo =====================================================================
echo                HACKATHON DEMO INSTRUCTIONS
echo =====================================================================
echo.
echo  Your local environment is fully configured for a 3-minute pitch!
echo.
echo  STEP 1: Open http://localhost:3000 in your browser.
echo.
echo  STEP 2: Select 'Recon & Vuln Scan' from the sidebar. 
echo        - Click on the seed run in the 'Previous runs' panel to load 
echo          the pre-configured 'XSS Boss Hard Local Lab' target.
echo.
echo  STEP 3: Click 'Run recon + vuln scan' to start.
echo        - Watch the Live Fuzzing monitor execute payloads in headless
echo          Chrome using Selenium/Playwright in the background.
echo        - Within 15 seconds, findings will begin popping up in red!
echo.
echo  STEP 4: Showcase the Features:
echo        - Click the 'Findings Database' tab to show the triaged PoCs.
echo        - Show a generated Proof of Concept (e.g. SVG onload alert).
echo        - Click 'Hunting Checklist' to walk the judges through the
echo          comprehensive scanning methodology.
echo.
echo =====================================================================
echo [+] Launch sequence completed. Press any key to terminate this window.
echo =====================================================================
pause >nul
endlocal
