# agy-unlock-analog installer (Windows PowerShell)
# One-line install:
#   irm https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.ps1 | iex
# Local:  .\install.ps1
# Override:  $env:AGY_ANALOG_BASE_URL='https://host/dir'; irm ... | iex
$ErrorActionPreference = 'Stop'

$DefaultBase = 'https://raw.githubusercontent.com/trustybird/agy-unlock/main'
$Base = if ($env:AGY_ANALOG_BASE_URL) { $env:AGY_ANALOG_BASE_URL } else { $DefaultBase }
$InvPath = $MyInvocation.MyCommand.Path
$ScriptDir = if ($InvPath) { Split-Path -Parent $InvPath } else { '' }
$LocalPatcher = if ($ScriptDir) { Join-Path $ScriptDir 'patcher.py' } else { '' }
if ($LocalPatcher -and (Test-Path $LocalPatcher)) {
  # local patcher.py next to the script - use it
} else {
  $LocalPatcher = Join-Path (Get-Location) 'patcher.py'
}

$dir = Join-Path $env:LOCALAPPDATA 'Programs\agy-unlock-analog'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$destPy = Join-Path $dir 'agy-unlock-analog.py'
$destCmd = Join-Path $dir 'agy-unlock-analog.cmd'

if (Test-Path $LocalPatcher) {
  Write-Host "Installing from local file: $LocalPatcher"
  Copy-Item -Path $LocalPatcher -Destination $destPy -Force
} elseif ($Base) {
  Write-Host "Downloading patcher.py from $Base/..."
  Invoke-WebRequest -Uri "$Base/patcher.py" -OutFile $destPy -UseBasicParsing
} else {
  throw "patcher.py not found nearby; set `$env:AGY_ANALOG_BASE_URL='https://host/dir' or run from repo dir"
}

# .cmd wrapper so it works without typing python
$cmdContent = "@echo off`r`npython `"%~dp0agy-unlock-analog.py`" %*`r`n"
Set-Content -Path $destCmd -Value $cmdContent -Encoding Ascii

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($userPath -notlike "*$dir*") {
  $new = if ($userPath) { "$userPath;$dir" } else { $dir }
  [Environment]::SetEnvironmentVariable('Path', $new, 'User')
  Write-Host "Added to PATH (restart the terminal to pick it up)."
}

Write-Host ""
Write-Host "Installed: $destPy"
Write-Host "Wrapper:   $destCmd"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw 'Python 3.8+ not found in PATH - install from https://www.python.org/downloads/ (tick "Add to PATH"), then re-run.'
}

# Запущенный Antigravity держит language_server.exe и иногда app.asar.
# Ждём закрытия, иначе патч молча пропустит занятые файлы.
function Wait-AntigravityClosed([int]$TimeoutSec = 120) {
  $names = @('Antigravity', 'language_server')
  if (-not (Get-Process -Name $names -ErrorAction SilentlyContinue)) { return $true }
  Write-Host ""
  Write-Host "Antigravity is running - close it so the patcher can write its files."
  for ($i = 1; $i -le $TimeoutSec; $i++) {
    Start-Sleep -Seconds 1
    if (-not (Get-Process -Name $names -ErrorAction SilentlyContinue)) {
      Write-Host "Antigravity closed."
      return $true
    }
    if ($i % 15 -eq 0) {
      Write-Host "  still running ($($TimeoutSec - $i)s left)..."
    }
  }
  return $false
}

$closed = Wait-AntigravityClosed
try { & python $destPy unlock all } catch {}
if (-not $closed) {
  Write-Host ""
  Write-Host "Antigravity was still running, so locked files were skipped." -ForegroundColor Yellow
  Write-Host "Close it and run: python `"$destPy`" unlock all" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  agy-unlock-analog status           # check state"
Write-Host "  agy-unlock-analog daemon install   # re-patch automatically after updates"
