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
try { & python $destPy unlock all } catch {}
Write-Host ""
Write-Host "Next steps:"
Write-Host "  agy-unlock-analog status           # check state"
Write-Host "  agy-unlock-analog daemon install   # re-patch automatically after updates"
