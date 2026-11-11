#!/bin/sh
# agy-unlock-analog installer (Linux/macOS)
# One-line install:
#   curl -fsSL https://raw.githubusercontent.com/trustybird/agy-unlock/main/install.sh | bash
# Local:  sh install.sh
# Override:  AGY_ANALOG_BASE_URL=https://host/dir sh install.sh
set -eu
DEFAULT_BASE_URL="https://raw.githubusercontent.com/trustybird/agy-unlock/main"
BASE_URL="${AGY_ANALOG_BASE_URL:-$DEFAULT_BASE_URL}"
BIN_NAME="agy-unlock-analog"
SRC_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || pwd)"

err() { printf 'error: %s\n' "$*" >&2; exit 1; }

os=$(uname -s 2>/dev/null || echo unknown)
case "$os" in
  Linux|Darwin) ;;
  *) err "unsupported OS: $os (on Windows use install.ps1 / install.cmd)" ;;
esac

bindir="$HOME/.local/bin"
mkdir -p "$bindir"
dest="$bindir/$BIN_NAME"

FOUND_SRC=""
if [ -f "$SRC_DIR/patcher.py" ]; then
  FOUND_SRC="$SRC_DIR/patcher.py"
elif [ -f "./patcher.py" ]; then
  FOUND_SRC="./patcher.py"
fi

tmp=""
if [ -n "$FOUND_SRC" ]; then
  printf 'Installing from local file: %s\n' "$FOUND_SRC"
  cp "$FOUND_SRC" "$dest"
elif [ -n "$BASE_URL" ]; then
  tmp=$(mktemp) || err "mktemp failed"
  trap 'rm -f "$tmp"' EXIT
  printf 'Downloading patcher.py from %s...\n' "$BASE_URL"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$BASE_URL/patcher.py" -o "$tmp" || err "download failed"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp" "$BASE_URL/patcher.py" || err "download failed"
  else
    err "need curl or wget"
  fi
  cp "$tmp" "$dest"
  trap - EXIT
else
  err "patcher.py not found nearby; set AGY_ANALOG_BASE_URL=https://host/dir or run from repo dir"
fi

chmod +x "$dest"
# shebang is enough; check python3 (macOS 12.3+ ships without it)
if ! command -v python3 >/dev/null 2>&1; then
  err "need python3: macOS - https://www.python.org/downloads/ ; Linux - apt install python3"
fi

printf '\nInstalled: %s\n' "$dest"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) printf 'Add to PATH:  export PATH="%s:$PATH"\n' "$bindir" ;;
esac

# Запущенное приложение и бэкенд держат бинари открытыми и продолжают отдавать
# старый код, пока не перезапущены: патч записан, а «не срабатывает».
# Windows-установщики глушат эти процессы; на POSIX делаем это здесь.
stop_backend() {
  command -v pkill >/dev/null 2>&1 || return 0
  found=""
  for pat in 'Antigravity' 'antigravity' 'language_server' '/agy( |$)'; do
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    for p in $pids; do
      [ "$p" = "$$" ] && continue
      cmdline=$(ps -p "$p" -o command= 2>/dev/null || true)
      case "$cmdline" in
        *install.sh*|*agy-unlock*|*patcher.py*) continue ;;
      esac
      found="$found $p"
      kill "$p" 2>/dev/null || true
    done
  done
  if [ -n "$found" ]; then
    printf 'Stopped running processes (PID%s) - restart Antigravity after patching.\n' "$found"
    sleep 1
  fi
}
stop_backend

if ! "$dest" unlock all; then
  if [ "$os" = "Darwin" ] && [ "$(id -u)" -ne 0 ]; then
    printf '\n[!] Permissions required for /Applications. Retrying with sudo:\n'
    sudo "$dest" unlock all || printf '\nPatch failed. If on macOS 13+, grant App Management in System Settings -> Privacy & Security.\n'
  else
    printf '\npatch reported errors; close the app and retry (macOS: with sudo)\n'
  fi
fi

printf '\nNext steps:\n'
printf '  agy-unlock-analog status           # check state\n'
printf '  agy-unlock-analog doctor           # diagnose "patched but ineligible"\n'
printf '  agy-unlock-analog daemon install   # re-patch automatically after updates\n'
