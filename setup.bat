@echo off
REM ================================================================
REM  STIG Helper - First-Time Setup
REM  Creates the default working folders for this toolkit.
REM ================================================================

cd /d "%~dp0"

echo.
echo STIG Helper setup
echo =================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo WARNING: The Python launcher 'py' was not found.
    echo.
    echo Install Python 3.8+ from https://www.python.org/downloads/
    echo and enable: [x] Install launcher for all users
    echo.
) else (
    echo [OK] Python launcher detected.
    echo.
)

for %%D in ("CKLs" "Reports" "Snapshots" "Merged" "Exports") do (
    if not exist "%%~D" (
        mkdir "%%~D"
        echo [CREATED] %%~D
    ) else (
        echo [EXISTS]  %%~D
    )
)

echo.
echo Setup complete.
echo Start the app with: main.bat
echo.
pause
