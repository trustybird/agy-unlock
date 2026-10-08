# agy-unlock-analog exe builder (Windows PowerShell)
# Run from repo dir:  .\build.ps1
# Output: dist\agy-unlock-analog.exe (upload it to GitHub Release manually)
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dist = Join-Path $Root 'dist\agy-unlock-analog.exe'

function Step($n, $total, $msg) {
  Write-Host ""
  Write-Host "[$n/$total] $msg" -ForegroundColor Cyan
}

Step 1 4 "Checking Python..."
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { throw 'Python 3.8+ not found in PATH - https://www.python.org/downloads/' }
$ver = & python --version 2>&1
Write-Host "  Found: $ver" -ForegroundColor Green

Step 2 4 "Ensuring PyInstaller..."
& python -m pip install --quiet pyinstaller
Write-Host "  OK" -ForegroundColor Green

Step 3 4 "Building exe (onefile, this takes a minute)..."
Push-Location $Root
try {
  & python -m PyInstaller --noconfirm --onefile --console --name agy-unlock-analog --noupx patcher.py
} finally {
  Pop-Location
}
if (-not (Test-Path $Dist)) { throw 'Build failed - dist\agy-unlock-analog.exe not found' }
Write-Host "  OK" -ForegroundColor Green

Step 4 4 "Verifying..."
$size = (Get-Item $Dist).Length
$hash = (Get-FileHash $Dist -Algorithm SHA256).Hash
$verOut = & $Dist version
Write-Host "  File:    $Dist" -ForegroundColor Green
Write-Host ("  Size:    {0:N1} MB" -f ($size / 1MB)) -ForegroundColor Green
Write-Host "  SHA256:  $hash" -ForegroundColor Green
Write-Host "  Version: $verOut" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Upload dist\agy-unlock-analog.exe to GitHub Release manually." -ForegroundColor Yellow
