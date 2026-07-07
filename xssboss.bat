@echo off
setlocal
set ROOT=%~dp0
set PLAYWRIGHT_BROWSERS_PATH=%ROOT%.playwright-browsers
"%ROOT%.venv\Scripts\python.exe" "%ROOT%xssboss.py" %*
