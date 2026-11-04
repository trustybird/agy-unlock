@echo off
REM agy-unlock-analog installer (Windows CMD)
REM One-line install:
REM   curl -fsSL https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.cmd -o install.cmd && install.cmd && del install.cmd
REM Local:  install.cmd
setlocal EnableDelayedExpansion

set "DEFAULT_BASE=https://raw.githubusercontent.com/trustybird/agy-unlock/main"
if "%AGY_ANALOG_BASE_URL%"=="" (set "BASE=%DEFAULT_BASE%") else (set "BASE=%AGY_ANALOG_BASE_URL%")
set "SCRIPTDIR=%~dp0"
set "LOCALPATCHER=%SCRIPTDIR%patcher.py"
if not exist "%LOCALPATCHER%" set "LOCALPATCHER=%CD%\patcher.py"

set "DIR=%LOCALAPPDATA%\Programs\agy-unlock-analog"
if not exist "%DIR%" mkdir "%DIR%"
set "DESTPY=%DIR%\agy-unlock-analog.py"
set "DESTCMD=%DIR%\agy-unlock-analog.cmd"

if exist "%LOCALPATCHER%" (
  echo Installing from local file: %LOCALPATCHER%
  copy /Y "%LOCALPATCHER%" "%DESTPY%" >nul
) else (
  if "%BASE%"=="" (
    echo patcher.py not found; set AGY_ANALOG_BASE_URL=https://host/dir or run from repo dir
    exit /b 1
  )
  echo Downloading patcher.py from %BASE%/...
  curl -fsSL "%BASE%/patcher.py" -o "%DESTPY%"
  if errorlevel 1 (echo download failed & exit /b 1)
)

echo @echo off> "%DESTCMD%"
echo python "%%~dp0agy-unlock-analog.py" %%*>> "%DESTCMD%"

REM setx обрезает PATH до 1024 знаков - пишем через PowerShell без лимита.
powershell -NoProfile -Command "$d=$env:DIR; $p=[Environment]::GetEnvironmentVariable('Path','User'); if(-not $p){$p=''}; if(($p -split ';') -notcontains $d){[Environment]::SetEnvironmentVariable('Path', ($p+';'+$d), 'User'); 'Added to PATH (restart the terminal to pick it up).'}"

echo.
echo Installed: %DESTPY%
echo Wrapper:   %DESTCMD%

where python >nul 2>&1
if errorlevel 1 (
  echo Need Python 3.8+ in PATH: https://www.python.org/downloads/ ^(tick "Add to PATH"^), then re-run.
  exit /b 1
)

REM Запущенный Antigravity держит language_server.exe и иногда app.asar.
REM Окно закрывают, а бэкенд language_server остаётся висеть - глушим сами.
tasklist /FI "IMAGENAME eq Antigravity.exe" 2>nul | find /I "Antigravity.exe" >nul
if errorlevel 1 goto checkls
echo Stopping Antigravity.exe so the patcher can write its files...
taskkill /F /T /IM Antigravity.exe >nul 2>&1
:checkls
tasklist /FI "IMAGENAME eq language_server.exe" 2>nul | find /I "language_server.exe" >nul
if errorlevel 1 goto killdone
echo Stopping language_server.exe so the patcher can write its files...
taskkill /F /T /IM language_server.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul
:killdone
tasklist /FI "IMAGENAME eq Antigravity.exe" 2>nul | find /I "Antigravity.exe" >nul
if errorlevel 1 goto verifyls
echo   WARN: Antigravity.exe still running; locked files will be skipped.
:verifyls
tasklist /FI "IMAGENAME eq language_server.exe" 2>nul | find /I "language_server.exe" >nul
if errorlevel 1 goto runpatch
echo   WARN: language_server.exe still running; locked files will be skipped.

:runpatch
python "%DESTPY%" unlock all
echo.
echo Next steps:
echo   agy-unlock-analog status           - check state
endlocal
