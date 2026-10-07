#!/bin/bash
# monitor.sh <GAMEDIR> <FIREJAIL_PID> <ALERTLOG>
#
# Watches the sandboxed process tree and the prefix for suspicious activity.
# On the first ALERT it kills the sandbox and opens a terminal with the log.
# All events are appended to ALERTLOG.

set -u

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
if ! source "$SCRIPT_DIR/config.sh"; then
  echo "monitor.sh: cannot load config.sh from $SCRIPT_DIR" >&2
  exit 1
fi

GAMEDIR="${1:?usage: monitor.sh <GAMEDIR> <FIREJAIL_PID> <ALERTLOG>}"
FIREJAIL_PID="${2:?usage: monitor.sh <GAMEDIR> <FIREJAIL_PID> <ALERTLOG>}"
ALERTLOG="${3:?usage: monitor.sh <GAMEDIR> <FIREJAIL_PID> <ALERTLOG>}"

PREFIX="$GAMEDIR/prefix"
GAMEBIN="$GAMEDIR/game"

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'

KILL_FIRED=0

# events are queued in a file and flushed every LOG_FLUSH_INTERVAL seconds
mkdir -p "$GAMEDIR/logs"
LOG_BUFFER_LOCK="$GAMEDIR/logs/.monitor-log.lock"
: > "$LOG_BUFFER_LOCK"

buffer_event() {
  local level="$1" msg="$2"
  printf '%s\t%s\n' "$level" "$msg" >> "$LOG_BUFFER_LOCK"
}

flush_log() {
  [ -s "$LOG_BUFFER_LOCK" ] || return 0
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  local tmp; tmp="$(mktemp)"
  mv "$LOG_BUFFER_LOCK" "$tmp" 2>/dev/null || return 0
  : > "$LOG_BUFFER_LOCK"
  while IFS=$'\t' read -r level msg; do
    [ -z "$level" ] && continue
    echo "[$ts] [$level] $msg" >> "$ALERTLOG"
  done < "$tmp"
  rm -f "$tmp"
}

log() {
  local level="$1" msg="$2"
  buffer_event "$level" "$msg"

  case "$level" in
    ALERT) echo -e "${RED}[ALERT] $msg${NC}" ;;
    WARN)  echo -e "${YEL}[WARN]  $msg${NC}" ;;
    INFO)  echo -e "${GRN}[INFO]  $msg${NC}" ;;
  esac

  if [ "$level" = "ALERT" ] && [ "$KILL_FIRED" -eq 0 ]; then
    KILL_FIRED=1
    flush_log

    echo "[ALERT] Kill switch triggered - terminating sandbox." >> "$ALERTLOG"

    kill -TERM -"$FIREJAIL_PID" 2>/dev/null || kill -TERM "$FIREJAIL_PID" 2>/dev/null

    local term
    if term="$(detect_terminal 2>/dev/null)"; then
      "$term" \
        --title "Malware Alert: $(basename "$GAMEDIR")" \
        --class malware-alert \
        bash -c 'cat "$1"; echo; echo "--- press enter to close ---"; read -r' _ "$ALERTLOG" \
        >/dev/null 2>&1 &
    else
      echo "[ALERT] No terminal emulator found; see $ALERTLOG" >> "$ALERTLOG"
    fi
  fi
}

# background log flusher
(
  while kill -0 "$FIREJAIL_PID" 2>/dev/null; do
    sleep "${LOG_FLUSH_INTERVAL:-2}"
    if [ -s "$LOG_BUFFER_LOCK" ]; then
      ts=$(date '+%Y-%m-%d %H:%M:%S')
      tmp="$(mktemp)"
      mv "$LOG_BUFFER_LOCK" "$tmp" 2>/dev/null || continue
      : > "$LOG_BUFFER_LOCK"
      while IFS=$'\t' read -r level msg; do
        [ -z "$level" ] && continue
        echo "[$ts] [$level] $msg" >> "$ALERTLOG"
      done < "$tmp"
      rm -f "$tmp"
    fi
  done
) &
FLUSHER_PID=$!

SUSPICIOUS_PROCS='powershell|powershell\.exe|cmd\.exe|cscript|wscript|certutil|regsvr32|rundll32|mshta|bitsadmin|schtasks|reg\.exe|netsh|vssadmin|wmic|msiexec\.exe|installutil\.exe|regasm\.exe|regsvcs\.exe|csc\.exe|vbc\.exe|hh\.exe|curl|wget|ftp|tftp|ssh|scp|socat|ncat|nc\.exe|telnet|chisel|ngrok|python\.exe|perl\.exe|ruby\.exe|node\.exe'

SUSPICIOUS_EXT='\.ps1$|\.psm1$|\.ps1xml$|\.bat$|\.cmd$|\.vbs$|\.vbe$|\.js$|\.jse$|\.wsf$|\.wsh$|\.ws$|\.scr$|\.hta$|\.lnk$|\.url$|\.scf$|\.inf$|\.job$|\.msc$'

EXEC_EXT='\.exe$|\.dll$|\.scr$|\.com$|\.pif$|\.sys$'

KNOWN_RUNTIME='d3d(8|9|10core|11|12|12core)\.dll$|dxgi\.dll$|icu(in|uc|dt)68\.dll$|nvapi(64)?\.dll$|nvcuda\.dll$|nvngx\.dll$|nvofapi64\.dll$|vrclient(_x64)?\.dll$|openvr_api_dxvk\.dll$|discord.*bridge\.exe$|dxvk_config\.dll$|d3dcompiler_47\.dll$|xalia\.exe$|UnityCrashHandler(64)?\.exe$|crashpad_handler\.exe$|msvcp.*\.dll$|vcruntime.*\.dll$|ucrtbase.*\.dll$|d3dx9_.*\.dll$|x3daudio.*\.dll$|xapofx.*\.dll$|xinput.*\.dll$|windows\.networking\.dll$|windows\.devices\..*\.dll$|kernelbase\.dll$|oleaut32\.dll$|winsta\.dll$|cabinet\.dll$|advpack\.dll$|cryptext\.dll$|pstorec\.dll$|sspicli\.dll$|wineopenxr\.dll$|ntdll\.dll$|kernel32\.dll$|user32\.dll$|gdi32\.dll$|shell32\.dll$|combase\.dll$|comctl32\.dll$|rpcrt4\.dll$|sechost\.dll$|setupapi\.dll$|shlwapi\.dll$|winmm\.dll$|ws2_32\.dll$|imm32\.dll$|hid\.dll$|dinput.*\.dll$|dsound\.dll$|dwmapi\.dll$|uxtheme\.dll$|version\.dll$|winspool\.dll$|wldap32\.dll$|crypt32\.dll$|bcrypt\.dll$|ncrypt\.dll$|dbghelp\.dll$|wintrust\.dll$|mpr\.dll$|netapi32\.dll$|userenv\.dll$|propsys\.dll$|dwrite\.dll$|d2d1\.dll$|windowscodecs\.dll$|wtsapi32\.dll$|cfgmgr32\.dll$|powrprof\.dll$|psapi\.dll$|iphlpapi\.dll$|dnsapi\.dll$|wininet\.dll$|urlmon\.dll$|msimg32\.dll$|opengl32\.dll$|glu32\.dll$|secur32\.dll$|authz\.dll$|sxs\.dll$|msvcrt\.dll$|msvcr.*\.dll$'

PERSIST_KEYS='Run|RunOnce|RunServices|RunServicesOnce|Image File Execution Options|AppInit_DLLs|Winlogon|ShellServiceObjectDelayLoad|SharedTaskScheduler|Userinit|AppCertDlls|SilentProcessExit|KnownDLLs|BootExecute|Browser Helper Objects'

PREFIX_FRESH=0
[ ! -f "$PREFIX/system.reg" ] && PREFIX_FRESH=1
if [ "$PREFIX_FRESH" -eq 1 ]; then
  log INFO "Wine INIT (fresh prefix - system32/registry writes will be INFO, not ALERT)"
fi

log INFO "Monitor started for $GAMEDIR (firejail pid $FIREJAIL_PID)"
sleep 2

# filesystem watcher
WATCH_PATHS=()

[ -d "$PREFIX/drive_c/windows/system32" ] && \
  WATCH_PATHS+=("$PREFIX/drive_c/windows/system32")

[ -d "$PREFIX/drive_c/windows/syswow64" ] && \
  WATCH_PATHS+=("$PREFIX/drive_c/windows/syswow64")

[ -d "$PREFIX/drive_c/windows" ] && \
  WATCH_PATHS+=("$PREFIX/drive_c/windows")

for u in "$PREFIX"/drive_c/users/*/; do
  [ -d "${u}Start Menu/Programs/Startup" ] && \
    WATCH_PATHS+=("${u}Start Menu/Programs/Startup")
  [ -d "${u}Startup" ] && \
    WATCH_PATHS+=("${u}Startup")
done

[ -d "$GAMEBIN" ] && WATCH_PATHS+=("$GAMEBIN")

if [ "${#WATCH_PATHS[@]}" -eq 0 ]; then
  log WARN "no watch paths exist under $PREFIX - filesystem monitoring disabled"
fi

INOTIFY_PID=""
if [ "${#WATCH_PATHS[@]}" -gt 0 ]; then
  (
    inotifywait -m \
      -e create -e moved_to -e moved_from -e delete \
      --format '%w%f|%e' \
      "${WATCH_PATHS[@]}" 2>/dev/null |
    while IFS='|' read -r file event; do
      base="$(basename "$file")"

      if echo "$file" | grep -qi 'Startup'; then
        if echo "$base" | grep -qiE "$EXEC_EXT"; then
          log ALERT "Executable dropped into Startup: $file ($event)"
        else
          log ALERT "Write to Startup folder: $file ($event)"
        fi
        continue
      fi

      if echo "$file" | grep -qiE '/drive_c/windows/(system32|syswow64)/'; then
        if echo "$base" | grep -qiE "$KNOWN_RUNTIME"; then
          echo "$base" >> "$GAMEDIR/logs/.runtime-writes"
          continue
        fi
        if [ "$PREFIX_FRESH" -eq 1 ]; then
          log INFO "system32 write during fresh-prefix init: $base ($event)"
        else
          log ALERT "Unexpected write to system32: $file ($event)"
        fi
        continue
      fi

      if echo "$file" | grep -qiE '/(system|user|userdef)\.reg$'; then
        if [ "$PREFIX_FRESH" -eq 1 ]; then
          log INFO "Registry hive written during init: $base ($event)"
        else
          log ALERT "Registry hive modified at runtime: $base ($event)"
        fi
        continue
      fi

      if echo "$file" | grep -qiE '/drive_c/windows/[^/]+$'; then
        log WARN "New file in windows/: $file ($event)"
        continue
      fi

      if echo "$file" | grep -qF "$GAMEBIN/"; then
        if echo "$base" | grep -qiE "$SUSPICIOUS_EXT"; then
          log ALERT "Suspicious file in game dir: $file ($event)"
        elif echo "$base" | grep -qiE "$EXEC_EXT" && echo "$event" | grep -qE 'CREATE|MOVED_TO'; then
          log WARN "New executable in game dir: $file ($event)"
        fi
        continue
      fi

      if echo "$base" | grep -qiE "$SUSPICIOUS_EXT"; then
        log ALERT "Suspicious file dropped: $file ($event)"
        continue
      fi
    done
  ) &
  INOTIFY_PID=$!
fi

# process-tree watcher
declare -A PPID_OF
declare -A SEEN_PIDS
declare -A PENDING_PIDS

refresh_tree() {
  PPID_OF=()
  local d pid ppid
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    [ -r "$d/stat" ] || continue
    ppid=$(awk '{ sub(/^[^)]*\) /,""); print $2 }' "$d/stat" 2>/dev/null)
    [ -n "$ppid" ] && PPID_OF[$pid]=$ppid
  done
}

walk() {
  local target=$1 pid
  for pid in "${!PPID_OF[@]}"; do
    if [ "${PPID_OF[$pid]}" = "$target" ]; then
      echo "$pid"
      walk "$pid"
    fi
  done
}

read_cmdline() {
  local pid=$1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | tr -d '\r\n' | tr -s ' '
}

INJECTION_PARENTS='services\.exe|winlogon\.exe|lsass\.exe|csrss\.exe|smss\.exe'

while kill -0 "$FIREJAIL_PID" 2>/dev/null; do
  refresh_tree

  for pid in $(walk "$FIREJAIL_PID"); do
    [ -d "/proc/$pid" ] || continue
    [ -n "${SEEN_PIDS[$pid]:-}" ] && continue

    # only inspect a pid once it has been seen on two consecutive polls
    if [ -z "${PENDING_PIDS[$pid]:-}" ]; then
      PENDING_PIDS[$pid]=1
      continue
    fi
    SEEN_PIDS[$pid]=1
    unset PENDING_PIDS[$pid]

    cmd="$(read_cmdline "$pid")"
    [ -z "$cmd" ] && continue
    exe="${cmd%% *}"
    exe_base="$(basename "$exe")"

    log INFO "New process: pid=$pid cmd=$cmd"

    if echo "$exe_base" | grep -qiE "$SUSPICIOUS_PROCS"; then
      log ALERT "Suspicious process running: pid=$pid cmd=$cmd"
      continue
    fi

    parent="${PPID_OF[$pid]:-}"
    if [ -n "$parent" ] && [ -r "/proc/$parent/comm" ]; then
      pcomm="$(cat "/proc/$parent/comm" 2>/dev/null)"
      if echo "$pcomm" | grep -qiE "$INJECTION_PARENTS"; then
        log ALERT "System process '$pcomm' spawned child: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if echo "$exe_base" | grep -qiE '^cmd(\.exe)?$'; then
      if echo "$cmd" | grep -qE '(/c|/C).*[><|]'; then
        log ALERT "cmd.exe with redirection/pipe: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if echo "$exe_base" | grep -qiE '^rundll32(\.exe)?$'; then
      if echo "$cmd" | grep -qiE 'javascript:|http://|https://|vbscript:'; then
        log ALERT "rundll32 with script/URL argument: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if echo "$exe_base" | grep -qiE '^reg(\.exe)?$'; then
      if echo "$cmd" | grep -qiE "(add|import).*($PERSIST_KEYS)"; then
        log ALERT "reg.exe modifying persistence key: pid=$pid cmd=$cmd"
        continue
      fi
    fi
  done

  sleep "${POLL_INTERVAL:-5}"
done

# shutdown
[ -n "$INOTIFY_PID" ] && {
  kill "$INOTIFY_PID" 2>/dev/null
  pkill -P "$INOTIFY_PID" 2>/dev/null
}

sleep 1
if [ -s "$LOG_BUFFER_LOCK" ]; then
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  while IFS=$'\t' read -r level msg; do
    [ -z "$level" ] && continue
    echo "[$ts] [$level] $msg" >> "$ALERTLOG"
  done < "$LOG_BUFFER_LOCK"
  : > "$LOG_BUFFER_LOCK"
fi

RUNTIME_COUNT=0
if [ -f "$GAMEDIR/logs/.runtime-writes" ]; then
  RUNTIME_COUNT=$(wc -l < "$GAMEDIR/logs/.runtime-writes")
  rm -f "$GAMEDIR/logs/.runtime-writes"
fi
if [ "$RUNTIME_COUNT" -gt 0 ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $RUNTIME_COUNT known-runtime component(s) written to system32 (suppressed)" >> "$ALERTLOG"
fi

log INFO "Game process ended. Full log: $ALERTLOG"

kill "$FLUSHER_PID" 2>/dev/null
wait "$FLUSHER_PID" 2>/dev/null || true
exit 0
