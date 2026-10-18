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

# native Linux games get their own rules (lib-monitor-native.sh); everything else is the
# original Windows/Wine monitor below, unchanged
MODE=wine
[ "$(read_game_conf "$GAMEDIR" RUNNER 2>/dev/null || true)" = "native" ] && MODE=native
if [ "$MODE" = native ]; then
  # shellcheck source=lib-monitor-native.sh
  source "$SCRIPT_DIR/lib-monitor-native.sh" || { echo "monitor.sh: cannot load lib-monitor-native.sh" >&2; exit 1; }
  # where the game thinks $HOME is (the launcher exports it; private home is the default)
  NHOME="${WQ_MONITOR_HOME:-$GAMEDIR/home}"
  NHOME="${NHOME%/}"
fi

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
# colour only on a terminal (or WQ_FORCE_COLOR=1); monitor.out and pipes stay plain text
USE_COLOR=0
if [ -z "${NO_COLOR:-}" ] && { [ -t 1 ] || [ -n "${WQ_FORCE_COLOR:-}" ]; }; then USE_COLOR=1; fi

# Stop signals the whole process group. Survive it (handlers reset in the watcher subshells, which
# is what we want) so the loop below sees the sandbox gone and writes the final events.
trap ':' TERM INT HUP

# mkdir is atomic, so only one of the watcher subshells fires the kill switch
KILL_FLAG="$GAMEDIR/logs/.monitor-killed"
rm -rf "$KILL_FLAG"

# MONITOR_KILL=0 (game.conf or the default profile): alerts are logged but do not stop the sandbox
KILL_ON_ALERT=1
if declare -F _wq_get >/dev/null 2>&1; then
  [ "$(_wq_get "$GAMEDIR" MONITOR_KILL 1)" = 0 ] && KILL_ON_ALERT=0
else
  [ "$(read_game_conf "$GAMEDIR" MONITOR_KILL 2>/dev/null || true)" = 0 ] && KILL_ON_ALERT=0
fi

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
  while IFS=$'\t' read -r level msg; do
    [ -z "$level" ] && continue
    echo "[$ts] [$level] $msg" >> "$ALERTLOG"
  done < "$tmp"
  rm -f "$tmp"
}

log() {
  local level="$1" msg="$2"
  msg="${msg//[[:cntrl:]]/}"   # file/process names can carry escape sequences
  buffer_event "$level" "$msg"

  if [ "$USE_COLOR" = 1 ]; then
    case "$level" in
      ALERT) printf '%b[ALERT] %s%b\n' "$RED" "$msg" "$NC" ;;
      WARN)  printf '%b[WARN]  %s%b\n' "$YEL" "$msg" "$NC" ;;
      INFO)  printf '%b[INFO]  %s%b\n' "$GRN" "$msg" "$NC" ;;
    esac
  else
    printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg"
  fi

  if [ "$level" = "ALERT" ] && [ "$KILL_ON_ALERT" = 1 ] && mkdir "$KILL_FLAG" 2>/dev/null; then
    flush_log

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ALERT] Kill switch triggered - terminating sandbox." >> "$ALERTLOG"

    kill -TERM -"$FIREJAIL_PID" 2>/dev/null || kill -TERM "$FIREJAIL_PID" 2>/dev/null

    local term
    if term="$(detect_terminal 2>/dev/null)"; then
      term_run "$term" "Malware Alert: $(basename "$GAMEDIR")" malware-alert \
        bash -c 'if [ -x "$2" ]; then WQ_FORCE_COLOR=1 "$2" < "$1"; else cat "$1"; fi; echo; echo "--- press enter to close ---"; read -r' _ "$ALERTLOG" "$SCRIPT_DIR/wq-colorize" \
        >/dev/null 2>&1 &
    else
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ALERT] No terminal emulator found; see $ALERTLOG" >> "$ALERTLOG"
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

KNOWN_RUNTIME='d3d(8|9|10core|11|12|12core)\.dll$|dxgi\.dll$|icu(in|uc|dt)68\.dll$|_?nvapi(64)?\.dll$|nvcuda\.dll$|_?nvngx\.dll$|_?nvofapi64\.dll$|vrclient(_x64)?\.dll$|openvr_api_dxvk\.dll$|discord.*bridge\.exe$|dxvk_config\.dll$|d3dcompiler_47\.dll$|xalia\.exe$|UnityCrashHandler(64)?\.exe$|crashpad_handler\.exe$|msvcp.*\.dll$|vcruntime.*\.dll$|ucrtbase\.dll$|d3dx9_.*\.dll$|x3daudio.*\.dll$|xapofx.*\.dll$|xinput.*\.dll$|windows\.networking\.dll$|windows\.devices\..*\.dll$|kernelbase\.dll$|oleaut32\.dll$|winsta\.dll$|cabinet\.dll$|advpack\.dll$|cryptext\.dll$|pstorec\.dll$|sspicli\.dll$|wineopenxr\.dll$|ntdll\.dll$|kernel32\.dll$|user32\.dll$|gdi32\.dll$|shell32\.dll$|combase\.dll$|comctl32\.dll$|rpcrt4\.dll$|sechost\.dll$|setupapi\.dll$|shlwapi\.dll$|winmm\.dll$|ws2_32\.dll$|imm32\.dll$|hid\.dll$|dinput.*\.dll$|dsound\.dll$|dwmapi\.dll$|uxtheme\.dll$|version\.dll$|winspool\.dll$|wldap32\.dll$|crypt32\.dll$|bcrypt\.dll$|ncrypt\.dll$|dbghelp\.dll$|wintrust\.dll$|mpr\.dll$|netapi32\.dll$|userenv\.dll$|propsys\.dll$|dwrite\.dll$|d2d1\.dll$|windowscodecs\.dll$|wtsapi32\.dll$|cfgmgr32\.dll$|powrprof\.dll$|psapi\.dll$|iphlpapi\.dll$|dnsapi\.dll$|wininet\.dll$|urlmon\.dll$|msimg32\.dll$|opengl32\.dll$|glu32\.dll$|secur32\.dll$|authz\.dll$|sxs\.dll$|msvcrt\.dll$|msvcr.*\.dll$'

# anchored: unanchored, "sync.exe" matched nc\.exe and "x-kernel32.dll" counted as known runtime
KNOWN_RUNTIME="^(${KNOWN_RUNTIME})"
SUSPICIOUS_PROCS="^(${SUSPICIOUS_PROCS})(\.exe)?$"

PERSIST_KEYS='Run|RunOnce|RunServices|RunServicesOnce|Image File Execution Options|AppInit_DLLs|Winlogon|ShellServiceObjectDelayLoad|SharedTaskScheduler|Userinit|AppCertDlls|SilentProcessExit|KnownDLLs|BootExecute|Browser Helper Objects'

PREFIX_FRESH=0
if [ "$MODE" = wine ]; then
  [ ! -f "$PREFIX/system.reg" ] && PREFIX_FRESH=1
  if [ "$PREFIX_FRESH" -eq 1 ]; then
    log INFO "Wine INIT (fresh prefix - system32/registry writes will be INFO, not ALERT)"
  fi
fi

log INFO "Monitor started for $GAMEDIR (firejail pid $FIREJAIL_PID, mode: $MODE)"
[ "$KILL_ON_ALERT" = 1 ] || log WARN "Kill switch is OFF for this game (MONITOR_KILL=0): alerts are logged, the sandbox keeps running"
# Wine needs a moment to set up. A native game does not, so watching starts at once for those.
if [ "$MODE" = wine ]; then sleep 2; fi

# filesystem watcher
NATIVE_PIDS=()
NATIVE_WARN_CAP=25
NATIVE_SUPPRESSED="$GAMEDIR/logs/.native-suppressed"
: > "$NATIVE_SUPPRESSED"
rm -f "$NATIVE_SUPPRESSED.n"
declare -A RC_BASE=()

# one event from either native inotify pipeline: classify, then log
native_fs_event() {
  local event="$1" file="$2" res level kind msg
  res="$(native_classify_path "$file" "$event" "$NHOME" "$GAMEBIN")" || return 0
  [ -n "$res" ] || return 0
  IFS=$'\t' read -r level kind msg <<< "$res"
  if [ "$kind" = rc ]; then
    # only a real content change counts (a skeleton .bashrc copied in at jail start is fine)
    local rel="${file#"$NHOME"/}" now
    now="$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)"
    [ "$now" = "${RC_BASE[$rel]:-}" ] && return 0
    native_is_skeleton "$file" "$rel" && return 0   # firejail's own skeleton file
  fi
  if [ "$level" = WARN ]; then
    # a first-run unpack can write thousands of files: log the first few, count the rest
    local n=0
    [ -f "$NATIVE_SUPPRESSED.n" ] && n=$(wc -l < "$NATIVE_SUPPRESSED.n")
    echo x >> "$NATIVE_SUPPRESSED.n"
    if [ "$n" -ge "$NATIVE_WARN_CAP" ]; then echo x >> "$NATIVE_SUPPRESSED"; return 0; fi
  fi
  log "$level" "$msg"
}

if [ "$MODE" = native ]; then
  for f in .bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .zshenv .zprofile .zlogin \
           .xprofile .xinitrc .xsession .xsessionrc .pam_environment .config/fish/config.fish; do
    [ -f "$NHOME/$f" ] && RC_BASE[$f]="$(sha256sum "$NHOME/$f" 2>/dev/null | cut -d' ' -f1)"
  done

  R_PATHS=(); NR_PATHS=()
  [ -d "$GAMEBIN" ] && R_PATHS+=("$GAMEBIN")
  case "${WQ_MONITOR_PRIVATE:-1}" in
    1)
      # private home: the whole thing is the game's own, watch all of it
      mkdir -p "$NHOME"
      R_PATHS+=("$NHOME")
      log INFO "Native mode: watching private home $NHOME and the game folder" ;;
    *)
      # the real $HOME is exposed (Hide home directory is off): best effort. Watching it
      # recursively is not practical, so watch the persistence spots that exist, plus their
      # parents (non-recursive) to catch the spots being created
      log WARN "Home directory is NOT hidden for this game: monitoring $NHOME is best-effort"
      for d in .config/autostart .config/systemd/user .config/environment.d .local/bin \
               .local/share/applications .local/share/systemd/user .ssh; do
        [ -d "$NHOME/$d" ] && R_PATHS+=("$NHOME/$d")
      done
      for d in "" .config .config/systemd .local .local/share .local/share/systemd; do
        [ -d "$NHOME/$d" ] && NR_PATHS+=("$NHOME${d:+/$d}")
      done ;;
  esac

  NATIVE_EXCLUDE='/(\.cache|mesa_shader_cache[^/]*|shader_cache|GPUCache|Code Cache)(/|$)'
  NATIVE_EVENTS=(-e create -e moved_to -e close_write)
  if [ "${#R_PATHS[@]}" -gt 0 ]; then
    (
      inotifywait -m -r "${NATIVE_EVENTS[@]}" --exclude "$NATIVE_EXCLUDE" --format '%e|%w%f' "${R_PATHS[@]}" 2>/dev/null |
      while IFS='|' read -r event file; do native_fs_event "$event" "$file"; done
    ) &
    NATIVE_PIDS+=($!)
  fi
  if [ "${#NR_PATHS[@]}" -gt 0 ]; then
    (
      inotifywait -m "${NATIVE_EVENTS[@]}" --format '%e|%w%f' "${NR_PATHS[@]}" 2>/dev/null |
      while IFS='|' read -r event file; do native_fs_event "$event" "$file"; done
    ) &
    NATIVE_PIDS+=($!)
  fi
  [ "${#NATIVE_PIDS[@]}" -eq 0 ] && log WARN "nothing to watch - filesystem monitoring disabled"
fi

WATCH_PATHS=()

if [ "$MODE" = wine ]; then
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
fi

if [ "$MODE" = wine ] && [ "${#WATCH_PATHS[@]}" -eq 0 ]; then
  log WARN "no watch paths exist under $PREFIX - filesystem monitoring disabled"
fi

INOTIFY_PID=""
if [ "$MODE" = wine ] && [ "${#WATCH_PATHS[@]}" -gt 0 ]; then
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

# One read per pid and no fork: this runs every poll over every process on the machine, and an
# awk per pid was hundreds of forks each time. /proc/N/stat is "pid (comm) S ppid ...", comm may
# contain spaces and ')', so strip up to the LAST ") ".
refresh_tree() {
  PPID_OF=()
  local d pid line rest
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    read -r line < "$d/stat" 2>/dev/null || continue
    rest="${line##*) }"          # "S ppid pgrp ..."
    rest="${rest#* }"            # "ppid pgrp ..."
    [ -n "${rest%% *}" ] && PPID_OF[$pid]="${rest%% *}"
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
    exe_base="${exe##*[\\/]}"   # handles C:\windows\system32\cmd.exe too

    log INFO "New process: pid=$pid cmd=$cmd"

    if [ "$MODE" = native ]; then
      link="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
      nexe="${link% (deleted)}"; nexe="${nexe##*/}"
      [ -n "$nexe" ] || nexe="$(cat "/proc/$pid/comm" 2>/dev/null || true)"
      res="$(native_classify_proc "$nexe" "${exe##*/}" "$cmd" "$link")"
      if [ -n "$res" ]; then
        IFS=$'\t' read -r nlevel _ nmsg <<< "$res"
        log "$nlevel" "$nmsg: pid=$pid cmd=$cmd"
      fi
      continue
    fi

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
for np in "${NATIVE_PIDS[@]+"${NATIVE_PIDS[@]}"}"; do
  pkill -P "$np" 2>/dev/null
  kill "$np" 2>/dev/null
done
[ -n "$INOTIFY_PID" ] && {
  pkill -P "$INOTIFY_PID" 2>/dev/null   # children first, or they get orphaned
  kill "$INOTIFY_PID" 2>/dev/null
}

# logged before the final flush: afterwards nothing would write it to the alert log any more
log INFO "Game process ended. Full log: $ALERTLOG"

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

if [ -s "$NATIVE_SUPPRESSED" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $(wc -l < "$NATIVE_SUPPRESSED") more executable/script write(s) not listed (first $NATIVE_WARN_CAP were)" >> "$ALERTLOG"
fi
rm -f "$NATIVE_SUPPRESSED" "$NATIVE_SUPPRESSED.n"
rmdir "$KILL_FLAG" 2>/dev/null || true

kill "$FLUSHER_PID" 2>/dev/null
wait "$FLUSHER_PID" 2>/dev/null || true
exit 0
