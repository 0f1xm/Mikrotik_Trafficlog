@echo off
setlocal
cd /d "%~dp0"
if exist "python\python.exe" (
  "python\python.exe" run.py %*
  goto done
)
if exist ".python-path" (
  set /p TRAFFICLOG_PYTHON=<.python-path
  goto custom
)
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 run.py %*
) else (
  python run.py %*
)
goto done
:custom
"%TRAFFICLOG_PYTHON%" run.py %*
:done
if errorlevel 1 pause
