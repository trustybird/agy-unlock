@echo off
REM agy-unlock-analog installer (Windows CMD)
REM Локально:  install.cmd
REM Удалённо:  curl -fsSL https://YOUR_HOST/agy-unlock-analog/install.cmd -o install.cmd && install.cmd && del install.cmd
setlocal EnableDelayedExpansion

if "%AGY_ANALOG_BASE_URL%"=="" (set "BASE=") else (set "BASE=%AGY_ANALOG_BASE_URL%")
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

set "UPATH="
for /f "skip=2 tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul') do set "UPATH=%%B"
echo !UPATH! | find /I "%DIR%" >nul
if errorlevel 1 (
  if defined UPATH (setx PATH "!UPATH!;%DIR%" >nul) else (setx PATH "%DIR%" >nul)
  echo Added to PATH ^(restart the terminal to pick it up^).
)

echo.
echo Installed: %DESTPY%
echo Wrapper:   %DESTCMD%

python "%DESTPY%" daemon refresh >nul 2>&1
python "%DESTPY%" status
echo.
echo For interactive: agy-unlock-analog
echo Autopatch: agy-unlock-analog daemon install
endlocal
