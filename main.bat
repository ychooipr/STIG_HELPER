@echo off
REM ================================================================
REM  STIG Helper - Unified STIG Compliance Utilities Launcher
REM  Double-click this file to open STIG Helper.
REM ================================================================

cd /d "%~dp0"

where py >nul 2>nul
if errorlevel 1 (
    echo.
    echo ERROR: The Python launcher 'py' was not found.
    echo.
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo During installation check:  [x] Install launcher for all users
    echo.
    pause
    exit /b 1
)

if not exist "stig_helper.py" (
    echo.
    echo ERROR: stig_helper.py was not found in:
    echo    %~dp0
    echo.
    echo Make sure main.bat, stig_helper.py, stig_diff.py,
    echo and combine_stig.py are all in the same folder.
    echo.
    pause
    exit /b 1
)

if not exist "stig_diff.py" (
    echo ERROR: stig_diff.py is missing from %~dp0
    pause
    exit /b 1
)

if not exist "combine_stig.py" (
    echo ERROR: combine_stig.py is missing from %~dp0
    pause
    exit /b 1
)

start "" pyw "%~dp0stig_helper.py"
exit /b 0
