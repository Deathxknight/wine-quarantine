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

# Proton/umu file list, built by _launch-core.sh before the game starts (see lib-runtime.sh)
source "$SCRIPT_DIR/lib-runtime.sh"
RUNTIME_LIST="$GAMEDIR/logs/.runtime-allowlist"
# points this run adds to the game's score; the next pre-launch scan reads it (wq-prescan.sh).
# Starting a run replaces it, so once you have reviewed a run and let the next one go, it no longer counts.
RUN_SCORE="$GAMEDIR/logs/.run-score"
mkdir -p "$GAMEDIR/logs"; : > "$RUN_SCORE"

# MONITOR_SYS32_SCORE=1: a system32 write that is not Proton's own file is logged as a scored alert
# (it still counts as ALERT in the verdict) but does not stop the sandbox
SYS32_SCORE=0
if declare -F _wq_get >/dev/null 2>&1; then
  [ "$(_wq_get "$GAMEDIR" MONITOR_SYS32_SCORE 0)" = 1 ] && SYS32_SCORE=1
else
  [ "$(read_game_conf "$GAMEDIR" MONITOR_SYS32_SCORE 2>/dev/null || true)" = 1 ] && SYS32_SCORE=1
fi

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
  # the timestamp is taken when the event happens, not when the buffer is flushed (up to
  # LOG_FLUSH_INTERVAL seconds later)
  printf '%s\t%s\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$msg" >> "$LOG_BUFFER_LOCK"
}

flush_log() {
  [ -s "$LOG_BUFFER_LOCK" ] || return 0
  local tmp ts level msg
  tmp="$(mktemp)"
  mv "$LOG_BUFFER_LOCK" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  while IFS=$'\t' read -r ts level msg; do
    [ -z "$level" ] && continue
    echo "[$ts] [$level] $msg" >> "$ALERTLOG"
  done < "$tmp"
  rm -f "$tmp"
}

log() {
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
  local level="$1" msg="$2" nokill="${3:-0}"
  msg="$(wq_clean_text "$msg")"   # file/process names can carry escape sequences and direction overrides
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

  if [ "$level" = "ALERT" ] && [ "$KILL_ON_ALERT" = 1 ] && [ "$nokill" != 1 ] && mkdir "$KILL_FLAG" 2>/dev/null; then
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
    flush_log
  done
) &
FLUSHER_PID=$!

# a file the kernel reports as created may still be being written: wait for its size to settle
settle_file() {
  local f="$1" a b i
  for i in 1 2 3; do
    a="$(stat -c %s "$f" 2>/dev/null)" || return 0
    sleep 0.5
    b="$(stat -c %s "$f" 2>/dev/null)" || return 0
    [ "$a" = "$b" ] && return 0
  done
  return 0
}

# a system32 write that is not known runtime: an alert, or a scored note when MONITOR_SYS32_SCORE=1
sys32_unlisted() {
  if [ "$SYS32_SCORE" = 1 ]; then
    log ALERT "$1 - scored +$PRESCAN_SYS32_POINTS, sandbox kept (MONITOR_SYS32_SCORE=1)" 1
    echo "sys32_unlisted $PRESCAN_SYS32_POINTS" >> "$RUN_SCORE"
  else
    log ALERT "$1"
  fi
}

# msbuild/pwsh/systeminfo/tasklist/whoami/net/net1/nltest: seen in 2025-26 game-lure campaigns, either as the
# LOLBin that runs the payload (MSBuild) or as the "is this a sandbox?" probe (net session, systeminfo, whoami)
# a loader runs before it decides whether to unpack anything. A game has no reason to start any of them.
SUSPICIOUS_PROCS='powershell|powershell\.exe|cmd\.exe|cscript|wscript|certutil|regsvr32|rundll32|mshta|bitsadmin|schtasks|reg\.exe|netsh|vssadmin|wmic|msiexec\.exe|installutil\.exe|regasm\.exe|regsvcs\.exe|csc\.exe|vbc\.exe|hh\.exe|curl|wget|ftp|tftp|ssh|scp|socat|ncat|nc\.exe|telnet|chisel|ngrok|python\.exe|perl\.exe|ruby\.exe|node\.exe|msbuild|pwsh|systeminfo|tasklist|whoami|net|net1|nltest|forfiles|cmstp|wevtutil'

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
      # the real $HOME is exposed (Hide home directory is off), so this is best effort. Watching it
      # recursively isn't practical, so watch the persistence spots that exist, plus their parents
      # (non-recursive) to catch the spots being created
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
      --format '%e|%w%f' \
      "${WATCH_PATHS[@]}" 2>/dev/null |
    while IFS='|' read -r event file; do   # event first: a file name can contain '|', an event name cannot
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
          continue
        fi
        # Proton's or umu's own file (same name and bytes) is quiet; anything else is judged by the rules above
        if runtime_listed "$base" "$RUNTIME_LIST"; then settle_file "$file"; fi
        case "$(runtime_classify "$file" "$RUNTIME_LIST")" in
          MATCH)
            echo "$base" >> "$GAMEDIR/logs/.runtime-writes"
            ;;
          MODIFIED)
            sys32_unlisted "Proton file changed in system32 (content differs from the shipped build): $file ($event)"
            ;;
          *)
            sys32_unlisted "Unexpected write to system32: $file ($event)"
            ;;
        esac
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
declare -A CHILDREN
declare -A SEEN_PIDS
declare -A PENDING_PIDS
declare -A LIVE_KEYS

# One read per pid, no fork. This runs every poll over every process on the machine and an awk
# per pid meant hundreds of forks each time. /proc/N/stat is "pid (comm) S ppid ..." and comm can
# contain spaces and ')', so strip up to the LAST ") ". Also builds the parent -> children map, so
# walking the tree is a lookup rather than a scan of every process for every node.
refresh_tree() {
  PPID_OF=(); CHILDREN=()
  local d pid line rest pp
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    { read -r line < "$d/stat"; } 2>/dev/null || continue   # (braces: the open error of a pid that just exited is silenced too)
    rest="${line##*) }"          # "S ppid pgrp ..."
    rest="${rest#* }"            # "ppid pgrp ..."
    pp="${rest%% *}"
    [ -n "$pp" ] || continue
    PPID_OF[$pid]="$pp"
    CHILDREN[$pp]+="$pid "
  done
}

walk() {
  local pid
  for pid in ${CHILDREN[$1]:-}; do
    echo "$pid"
    walk "$pid"
  done
}

# PID_KEY = "pid:starttime". A pid can be reused by a different process within one run, and a
# plain pid would make the monitor think it had already looked at the newcomer.
PID_KEY=""
PID_CMINFLT=0
pid_key() {
  local line rest
  local -a f
  { read -r line < "/proc/$1/stat"; } 2>/dev/null || return 1
  rest="${line##*) }"
  read -ra f <<< "$rest"
  PID_KEY="$1:${f[19]:-0}"
  PID_CMINFLT="${f[8]:-0}"     # page faults of children this process has already waited for (rises when ANY child is reaped)
}

read_cmdline() {
  local pid=$1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | tr -d '\r\n' | tr -s ' '
}

# ---- native mode only -------------------------------------------------------------------------------------
# A fingerprint of what a process currently IS: kernel name + argv. Read with builtins, no fork, because it runs for
# every process of the sandbox on every poll. When a process execs something else the fingerprint changes and it is
# judged again (a forked child shows its parent's command line until it execs).
NSIG=""
native_sig() {
  local c a
  { read -r c < "/proc/$1/comm"; } 2>/dev/null || return 1
  { mapfile -d '' -t a < "/proc/$1/cmdline"; } 2>/dev/null || return 1
  [ "${#a[@]}" -gt 0 ] || return 1          # no command line yet (or a zombie): look again next poll
  NSIG="$c|${a[*]}"
}

# The script an interpreter was told to run (bash start.sh, python3 -u main.py): NSCRIPT = full path, or empty.
NSCRIPT=""
native_script_of() {
  local a i cwd base
  NSCRIPT=""
  { mapfile -d '' -t a < "/proc/$1/cmdline"; } 2>/dev/null || return 1
  base="${a[0]##*/}"
  [[ "$base" =~ ^(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|php|node|nodejs|lua[0-9.]*)$ ]] || return 1
  for ((i=1; i<${#a[@]}; i++)); do
    case "${a[i]}" in
      -c|-e|-r|-E) return 1 ;;                  # inline code: native_classify_proc looks at that
      -*) continue ;;
      *) NSCRIPT="${a[i]}"; break ;;
    esac
  done
  [ -n "$NSCRIPT" ] || return 1
  if [[ "$NSCRIPT" != /* ]]; then
    cwd="$(readlink "/proc/$1/cwd" 2>/dev/null)" || true
    NSCRIPT="$cwd/$NSCRIPT"
  fi
  [ -f "$NSCRIPT" ] || { NSCRIPT=""; return 1; }
}

# Spawner / fork-storm detection. A short-lived child can come and go between two polls, so what is counted is what
# the polls DO see: children per parent, and new processes in any 10 second window.
NATIVE_SPAWN_WARN="${NATIVE_SPAWN_WARN:-25}"       # children one process has started during this run
NATIVE_SPAWN_ALERT="${NATIVE_SPAWN_ALERT:-100}"
NATIVE_BURST_WARN="${NATIVE_BURST_WARN:-40}"       # new processes in the last 10 seconds
NATIVE_BURST_ALERT="${NATIVE_BURST_ALERT:-150}"
NATIVE_WARNS_ALERT="${NATIVE_WARNS_ALERT:-6}"      # unusual-process warnings in one run before it becomes an alert
NATIVE_UNOBS_SHELL_WARN="${NATIVE_UNOBS_SHELL_WARN:-60}"   # unseen short-lived children of ONE shell script before it is worth a warning
declare -A SIG_BY_PID=() SPAWN_N=() SPAWN_FLAG=() SCRIPT_SCAN=() CMINFLT=() KIDS_PREV=() UNOBS_N=() KNOWN=()
NEW_TS=(); BURST_FLAG=0; PROC_WARNS=0; WARNS_FLAG=0; UNOBS_TOTAL=0

# native_poll_pid <pid> <key>: runs every poll for every process of the sandbox (right after pid_key)
native_poll_pid() {
  local pid="$1" key="$2" parent n cur prev kids k explained=0 now t cnt cmd
  local -a keep
  if [ -z "${KNOWN[$key]:-}" ]; then          # first sight: count it for its parent and for the 10 second window
    KNOWN[$key]=1
    parent="${PPID_OF[$pid]:-}"
    if [ -n "$parent" ]; then
      n=$(( ${SPAWN_N[$parent]:-0} + 1 )); SPAWN_N[$parent]=$n
      if [ "$n" -ge "$NATIVE_SPAWN_ALERT" ] && [ "${SPAWN_FLAG[$parent]:-0}" -lt 2 ]; then
        SPAWN_FLAG[$parent]=2
        log ALERT "Process pid=$parent has started $n child processes so far (spawner or fork storm): $(read_cmdline "$parent")"
      elif [ "$n" -ge "$NATIVE_SPAWN_WARN" ] && [ "${SPAWN_FLAG[$parent]:-0}" -lt 1 ]; then
        SPAWN_FLAG[$parent]=1
        log WARN "Process pid=$parent has started $n child processes so far (a game rarely does this): $(read_cmdline "$parent")"
      fi
    fi
    now=$SECONDS; keep=(); cnt=0
    NEW_TS+=("$now")
    for t in "${NEW_TS[@]}"; do if [ $((now - t)) -le 10 ]; then keep+=("$t"); cnt=$((cnt+1)); fi; done
    NEW_TS=("${keep[@]}")
    if [ "$cnt" -ge "$NATIVE_BURST_ALERT" ] && [ "$BURST_FLAG" -lt 2 ]; then
      BURST_FLAG=2; log ALERT "$cnt new processes in 10 seconds (fork storm)"
    elif [ "$cnt" -ge "$NATIVE_BURST_WARN" ] && [ "$BURST_FLAG" -lt 1 ]; then
      BURST_FLAG=1; log WARN "$cnt new processes in 10 seconds (a game rarely does this)"
    fi
  fi
  # Children too quick for a poll still leave a trace: the parent's counter of waited-for children's page faults
  # rises when one is reaped. If it rose and no child appeared or vanished in view, a child ran and was reaped
  # between two polls. What it was is unknown, but that it happened is not.
  cur="$PID_CMINFLT"; prev="${CMINFLT[$key]:-}"; kids="${CHILDREN[$pid]:-}"
  if [ -n "$prev" ] && [[ "$cur" =~ ^[0-9]+$ ]] && [ "$cur" -gt "$prev" ]; then
    for k in ${KIDS_PREV[$key]:-}; do case " $kids" in *" $k "*) ;; *) explained=1 ;; esac; done
    for k in $kids; do case " ${KIDS_PREV[$key]:-} " in *" $k "*) ;; *) explained=1 ;; esac; done
    if [ "$explained" -eq 0 ]; then
      UNOBS_TOTAL=$((UNOBS_TOTAL+1))
      n=$(( ${UNOBS_N[$key]:-0} + 1 )); UNOBS_N[$key]=$n
      cmd="$(read_cmdline "$pid")"
      if [[ "$({ read -r k < "/proc/$pid/comm"; } 2>/dev/null; echo "$k")" =~ ^(bash|sh|dash|zsh)$ ]]; then
        [ "$n" -eq "$NATIVE_UNOBS_SHELL_WARN" ] && log WARN "pid=$pid (a shell script) ran $n short commands that finished before they could be inspected (what they were is unknown; a game rarely does this): $cmd"
      else
        [ "$n" -eq 1 ] && log WARN "pid=$pid started a child process that finished before it could be inspected (what it ran is unknown; a game rarely does this): $cmd"
      fi
    fi
  fi
  CMINFLT[$key]="$cur"; KIDS_PREV[$key]="$kids"
  return 0
}

# name_is <regex, lower case> <name>...: does any of the names (path stripped) match?
name_is() {
  local re="$1" n; shift
  for n in "$@"; do
    n="${n##*[\\/]}"
    [ -n "$n" ] || continue
    [[ "${n,,}" =~ $re ]] && return 0
  done
  return 1
}

INJECTION_PARENTS='services\.exe|winlogon\.exe|lsass\.exe|csrss\.exe|smss\.exe'

WATCHER_WARNED=0
while kill -0 "$FIREJAIL_PID" 2>/dev/null; do
  # inotifywait's own errors are discarded (2>/dev/null), so a watcher that died (inotify watch limit,
  # a watched folder removed) would otherwise mean no filesystem monitoring and no sign of it
  if [ "$WATCHER_WARNED" -eq 0 ]; then
    lost=""
    [ -n "$INOTIFY_PID" ] && ! kill -0 "$INOTIFY_PID" 2>/dev/null && lost=1
    for np in "${NATIVE_PIDS[@]+"${NATIVE_PIDS[@]}"}"; do
      kill -0 "$np" 2>/dev/null || lost=1
    done
    if [ -n "$lost" ]; then
      WATCHER_WARNED=1
      log WARN "The filesystem watcher stopped while the game was still running (inotify watch limit reached or a watched folder was removed?). File monitoring is OFF for the rest of this run."
    fi
  fi
  refresh_tree
  LIVE_KEYS=()

  for pid in $(walk "$FIREJAIL_PID"); do
    pid_key "$pid" || continue
    key="$PID_KEY"
    LIVE_KEYS[$key]=1
    rejudge=0
    if [ "$MODE" = native ]; then native_poll_pid "$pid" "$key"; fi
    if [ -n "${SEEN_PIDS[$key]:-}" ]; then
      # native: a process that exec()ed something else is judged again as what it is now
      if [ "$MODE" = native ] && native_sig "$pid" && [ "$NSIG" != "${SIG_BY_PID[$key]:-}" ]; then
        rejudge=1
      else
        continue
      fi
    else
      # only inspect a process once it has been seen on two consecutive polls
      if [ -z "${PENDING_PIDS[$key]:-}" ]; then
        PENDING_PIDS[$key]=1
        continue
      fi
      SEEN_PIDS[$key]=1
      unset "PENDING_PIDS[$key]"
    fi

    cmd="$(read_cmdline "$pid")"
    [ -z "$cmd" ] && continue
    exe="${cmd%% *}"
    exe_base="${exe##*[\\/]}"   # handles C:\windows\system32\cmd.exe too

    # A path with a space in it ("C:\Program Files\x\curl.exe") is cut at the space by the line
    # above, which would hide the real name. So the name is also taken from argv[0] as one
    # piece and from the kernel's own process name; a match on any of them counts.
    argv0=""
    { IFS= read -r -d '' argv0 < "/proc/$pid/cmdline"; } 2>/dev/null || true
    argv0="${argv0//[[:cntrl:]]/}"
    comm="$(cat "/proc/$pid/comm" 2>/dev/null || true)"

    if [ "$rejudge" -eq 1 ]; then log INFO "Process now runs a different program: pid=$pid cmd=$cmd"; else log INFO "New process: pid=$pid cmd=$cmd"; fi

    if [ "$MODE" = native ]; then
      link="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
      nexe="${link% (deleted)}"; nexe="${nexe##*/}"
      [ -n "$nexe" ] || nexe="$comm"
      if native_sig "$pid"; then SIG_BY_PID[$key]="$NSIG"; fi
      native_script_of "$pid" || true
      res="$(native_classify_proc "$nexe" "${exe##*/}" "$cmd" "$link" "${NSCRIPT##*/}")"
      if [ -z "$res" ] && [ -n "$NSCRIPT" ]; then
        # the script's own text, judged once per file
        if [ -z "${SCRIPT_SCAN[$NSCRIPT]:-}" ]; then
          SCRIPT_SCAN[$NSCRIPT]="$(native_scan_script "$NSCRIPT")"
          [ -n "${SCRIPT_SCAN[$NSCRIPT]}" ] || SCRIPT_SCAN[$NSCRIPT]="-"
        fi
        if [ "${SCRIPT_SCAN[$NSCRIPT]}" != "-" ]; then
          IFS=$'\t' read -r nlevel _ nmsg <<< "${SCRIPT_SCAN[$NSCRIPT]}"
          log "$nlevel" "Script ${NSCRIPT##*/} (run by $nexe): $nmsg: pid=$pid cmd=$cmd"
        fi
      elif [ -n "$res" ]; then
        IFS=$'\t' read -r nlevel _ nmsg <<< "$res"
        log "$nlevel" "$nmsg: pid=$pid cmd=$cmd"
        if [ "$nlevel" = WARN ]; then
          PROC_WARNS=$((PROC_WARNS+1))
          if [ "$PROC_WARNS" -ge "$NATIVE_WARNS_ALERT" ] && [ "$WARNS_FLAG" -eq 0 ]; then
            WARNS_FLAG=1; log ALERT "$PROC_WARNS unusual-process warnings in one run (a game rarely needs these)"
          fi
        fi
      fi
      continue
    fi

    if name_is "$SUSPICIOUS_PROCS" "$exe_base" "$argv0" "$comm"; then
      log ALERT "Suspicious process running: pid=$pid cmd=$cmd"
      continue
    fi

    parent="${PPID_OF[$pid]:-}"
    if [ -n "$parent" ] && [ -r "/proc/$parent/comm" ]; then
      pcomm="$(cat "/proc/$parent/comm" 2>/dev/null)"
      if [[ "${pcomm,,}" =~ $INJECTION_PARENTS ]]; then
        log ALERT "System process '$pcomm' spawned child: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if name_is '^cmd(\.exe)?$' "$exe_base" "$argv0" "$comm"; then
      if echo "$cmd" | grep -qE '(/c|/C).*[><|]'; then
        log ALERT "cmd.exe with redirection/pipe: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if name_is '^rundll32(\.exe)?$' "$exe_base" "$argv0" "$comm"; then
      if echo "$cmd" | grep -qiE 'javascript:|http://|https://|vbscript:'; then
        log ALERT "rundll32 with script/URL argument: pid=$pid cmd=$cmd"
        continue
      fi
    fi

    if name_is '^reg(\.exe)?$' "$exe_base" "$argv0" "$comm"; then
      if echo "$cmd" | grep -qiE "(add|import).*($PERSIST_KEYS)"; then
        log ALERT "reg.exe modifying persistence key: pid=$pid cmd=$cmd"
        continue
      fi
    fi
  done

  # forget pending entries of processes that are gone (a short-lived one is never inspected)
  for key in "${!PENDING_PIDS[@]}"; do
    [ -n "${LIVE_KEYS[$key]:-}" ] || unset "PENDING_PIDS[$key]"
  done
  # native: forget what was remembered about processes that are gone (keys are pid:starttime, so a reused pid is new)
  if [ "$MODE" = native ]; then
    for key in "${!KNOWN[@]}"; do
      [ -n "${LIVE_KEYS[$key]:-}" ] && continue
      unset "KNOWN[$key]" "SIG_BY_PID[$key]" "CMINFLT[$key]" "KIDS_PREV[$key]" "UNOBS_N[$key]" "SEEN_PIDS[$key]"
    done
    for key in "${!SPAWN_N[@]}"; do
      [ -n "${PPID_OF[$key]:-}" ] || unset "SPAWN_N[$key]" "SPAWN_FLAG[$key]"
    done
  fi

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

if [ "$MODE" = native ] && [ "$UNOBS_TOTAL" -gt 0 ]; then log INFO "$UNOBS_TOTAL time(s) a child process ran and exited between two polls (every ${POLL_INTERVAL:-5}s), so its command line was never seen"; fi
# logged before the final flush: afterwards nothing would write it to the alert log any more
log INFO "Game process ended. Full log: $ALERTLOG"

sleep 1
flush_log

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
