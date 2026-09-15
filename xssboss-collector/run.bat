@echo off
setlocal
set "PROJECT_DIR=%~dp0"
set "PYTHONPATH=%PROJECT_DIR%src;%PYTHONPATH%"
if exist "%PROJECT_DIR%.venv\Scripts\python.exe" (
  if "%~1"=="" (
    "%PROJECT_DIR%.venv\Scripts\python.exe" -m xsscollector ui
  ) else (
    "%PROJECT_DIR%.venv\Scripts\python.exe" -m xsscollector %*
  )
) else (
  if "%~1"=="" (
    python -m xsscollector ui
  ) else (
    python -m xsscollector %*
  )
)
exit /b %errorlevel%
