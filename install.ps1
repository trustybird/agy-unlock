# agy-unlock-analog installer (Windows PowerShell)
# Локально:  .\install.ps1
# Удалённо:  irm https://YOUR_HOST/agy-unlock-analog/install.ps1 | iex
# Override:  $env:AGY_ANALOG_BASE_URL='https://host/dir'; irm ... | iex
$ErrorActionPreference = 'Stop'

$Base = if ($env:AGY_ANALOG_BASE_URL) { $env:AGY_ANALOG_BASE_URL } else { '' }
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LocalPatcher = Join-Path $ScriptDir 'patcher.py'
if (-not $LocalPatcher -or -not (Test-Path $LocalPatcher)) {
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

# wrapper .cmd чтобы работало без указания python
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

try { & python $destPy daemon refresh 2>$null } catch {}
try { & python $destPy status } catch {}
Write-Host ""
Write-Host "Для интерактива: agy-unlock-analog"
Write-Host "Автопатч: agy-unlock-analog daemon install"
