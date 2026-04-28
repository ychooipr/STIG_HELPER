@echo off
setlocal
REM ================================================================
REM  STIG Helper - Unpack Helper
REM  Extracts the packaged zip into %USERPROFILE%\Documents\STIG_Helper
REM ================================================================

cd /d "%~dp0"

set "ZIP_NAME="
for /f "usebackq delims=" %%F in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -LiteralPath '%~dp0' -Filter 'STIG_Helper_package_v*.zip' -File | Where-Object { $_.BaseName -match '_v(\d+(?:\.\d+)*)$' } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Version = [version]$matches[1] } }; if ($files) { ($files | Sort-Object Version -Descending | Select-Object -First 1).Name }"`) do (
    set "ZIP_NAME=%%F"
)
if "%ZIP_NAME%"=="" (
    for /f "usebackq delims=" %%F in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$fallback = Get-ChildItem -LiteralPath '%~dp0' -Filter 'STIG_Helper*.zip' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($fallback) { $fallback.Name }"`) do (
        set "ZIP_NAME=%%F"
    )
)

set "DEFAULT_TARGET_ROOT=%USERPROFILE%\Documents"
set "TARGET_ROOT=%DEFAULT_TARGET_ROOT%"
set "TARGET_DIR=%TARGET_ROOT%\STIG_Helper"

echo.
echo STIG Helper unpack
echo ==================
echo.
if not "%ZIP_NAME%"=="" (
    echo Package found:
    echo   %ZIP_NAME%
    echo.
)

if "%ZIP_NAME%"=="" (
    echo ERROR: No STIG Helper package zip was found next to unpack.bat
    echo.
    echo Make sure unpack.bat is next to a versioned package zip such as:
    echo   - unpack.bat
    echo   - STIG_Helper_package_v1.1.1.zip
    echo.
    pause
    exit /b 1
)

if not exist "%DEFAULT_TARGET_ROOT%" (
    echo ERROR: Could not find the Documents folder:
    echo   %DEFAULT_TARGET_ROOT%
    echo.
    pause
    exit /b 1
)

echo Default install location:
echo   %TARGET_DIR%
echo.
set /p "CUSTOM_TARGET=Press Enter to use this folder, or type a different parent folder: "
if not "%CUSTOM_TARGET%"=="" (
    set "TARGET_ROOT=%CUSTOM_TARGET%"
)
set "TARGET_INPUT=%TARGET_ROOT:"=%"
set "TARGET_ROOT="
set "TARGET_DIR="
for /f "usebackq delims=" %%F in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "$raw = [Environment]::ExpandEnvironmentVariables('%TARGET_INPUT%').Trim('\"'); $full = [System.IO.Path]::GetFullPath($raw); if ([System.IO.Path]::GetFileName($full).TrimEnd() -ieq 'STIG_Helper') { 'ROOT=' + [System.IO.Path]::GetDirectoryName($full); 'DIR=' + $full } else { 'ROOT=' + $full; 'DIR=' + (Join-Path $full 'STIG_Helper') }"`) do (
    set "%%F"
)

if "%TARGET_ROOT%"=="" (
    echo.
    echo ERROR: Could not resolve the install folder.
    echo.
    pause
    exit /b 1
)

if not exist "%TARGET_ROOT%" (
    echo.
    echo The folder does not exist:
    echo   %TARGET_ROOT%
    echo.
    choice /C YN /M "Do you want to create it"
    if errorlevel 2 (
        echo.
        echo Cancelled.
        echo.
        pause
        exit /b 0
    )
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "New-Item -ItemType Directory -Path '%TARGET_ROOT%' -Force | Out-Null"
    if errorlevel 1 (
        echo.
        echo ERROR: Could not create:
        echo   %TARGET_ROOT%
        echo.
        pause
        exit /b 1
    )
)

echo Install location:
echo   %TARGET_DIR%
echo.

if exist "%TARGET_DIR%" (
    echo The STIG_Helper folder already exists here:
    echo   %TARGET_DIR%
    choice /C YN /M "Do you want to replace it with the packaged copy"
    if errorlevel 2 (
        echo.
        echo Cancelled.
        echo.
        pause
        exit /b 0
    )
    rmdir /S /Q "%TARGET_DIR%"
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Expand-Archive -LiteralPath '%~dp0%ZIP_NAME%' -DestinationPath '%TARGET_ROOT%' -Force"

if errorlevel 1 (
    echo.
    echo ERROR: Extraction failed.
    echo.
    pause
    exit /b 1
)

echo.
echo [OK] STIG Helper was extracted to:
echo   %TARGET_DIR%
echo.
if exist "%TARGET_DIR%\setup.bat" (
    echo Running setup.bat...
    echo.
    call "%TARGET_DIR%\setup.bat"
) else (
    echo WARNING: setup.bat was not found in:
    echo   %TARGET_DIR%
    echo.
)

echo.
echo Next step:
echo   Run main.bat from:
echo   %TARGET_DIR%
echo.
pause
exit /b 0
