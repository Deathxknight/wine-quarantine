#!/bin/bash
# _launch-core.sh <GameName>  (internal, called by each game's launch-quarantine.sh)
# Runs a quarantined game in the sandbox with the monitor attached.

set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
source "$QROOT/config.sh" || { echo "FATAL: cannot load $QROOT/config.sh" >&2; exit 1; }
# shellcheck source=lib-firejail.sh
source "$QROOT/lib-firejail.sh" || { echo "FATAL: cannot load $QROOT/lib-firejail.sh" >&2; exit 1; }
source "$QROOT/lib-runtime.sh" || { echo "FATAL: cannot load $QROOT/lib-runtime.sh" >&2; exit 1; }
check_deps || exit 1

[ $# -eq 1 ] || { echo "Usage: _launch-core.sh <GameName>" >&2; exit 1; }
GAMENAME="${1%/}"
case "$GAMENAME" in
  ""|*/*|.|..) echo "Error: invalid game name '$1'" >&2; exit 1 ;;
esac

GAMEDIR="$QROOT/$GAMENAME"
[ -d "$GAMEDIR/game" ] || { echo "Error: no such game: $GAMENAME" >&2; exit 1; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
mkdir -p "$UMU_DATA"
UMU_DATA="$(readlink -f "$UMU_DATA")"

# exe comes from game.conf, which is only ever read as data.
# WQ_RUN_EXE (set by wq-ui's "Run setup file") runs one other file from game/ for this launch only, e.g. an
# installer, and leaves game.conf alone. The prefix it installs into is the game's own, so afterwards the
# installed program can be chosen with Set executable (it is listed as @prefix/drive_c/...).
if [ -n "${WQ_RUN_EXE:-}" ]; then
  EXE="$WQ_RUN_EXE"
  echo "wq: one-time run of $EXE (EXE= in game.conf is not changed)"
else
  EXE="$(read_game_conf "$GAMEDIR" EXE)" || { echo "Error: no EXE= line in $GAMEDIR/game.conf" >&2; exit 1; }
  [ "$EXE" != "CHANGE_ME.exe" ] || { echo "Error: set EXE= in $GAMEDIR/game.conf first" >&2; exit 1; }
fi
valid_exe_rel "$EXE" || { echo "Error: bad EXE path in game.conf" >&2; exit 1; }

EXE_ROOT="$(wq_exe_root "$GAMEDIR" "$EXE")"      # game/, or prefix/ for an @prefix/ program
EXE_SUB="$(wq_exe_rel "$EXE")"
[ -n "$EXE_SUB" ] || { echo "Error: bad EXE path in game.conf" >&2; exit 1; }
EXEDIR="$(readlink -f "$EXE_ROOT/$(dirname "$EXE_SUB")")"
case "$EXEDIR/" in
  "$EXE_ROOT/"*) ;;
  *) echo "Error: exe directory resolves outside ${EXE_ROOT#"$GAMEDIR"/}/" >&2; exit 1 ;;
esac
EXE_REL_PATH="./$(basename "$EXE_SUB")"
[ -f "$EXEDIR/${EXE_REL_PATH#./}" ] || { echo "Error: exe not found: $EXEDIR/${EXE_REL_PATH#./}" >&2; exit 1; }
# the file itself may be a symlink the game planted on an earlier run: it has to stay inside that folder too
case "$(readlink -f "$EXEDIR/${EXE_REL_PATH#./}")" in
  "$EXE_ROOT/"*) ;;
  *) echo "Error: the exe is a symlink that points outside ${EXE_ROOT#"$GAMEDIR"/}/" >&2; exit 1 ;;
esac

LOGDIR="$GAMEDIR/logs"
mkdir -p "$LOGDIR"
ALERTLOG="$LOGDIR/alerts-$(date +%Y%m%d-%H%M%S).log"

# everything printed from here on (sandbox verify failures, umu tracebacks...)
# is also saved, so the wq-ui Debug report can include it
LAUNCHLOG="$LOGDIR/launch-$(date +%Y%m%d-%H%M%S).log"
# log stays plain text, wq-colorize only colours what goes to a terminal.
# The logger ignores TERM/INT/HUP: on Stop the whole group gets the signal, and it has to
# outlive the game or the summary below would write into a dead pipe.
if [ -x "$QROOT/wq-colorize" ]; then
  exec > >(trap '' TERM INT HUP; tee -a "$LAUNCHLOG" | "$QROOT/wq-colorize") 2>&1
else
  exec > >(trap '' TERM INT HUP; tee -a "$LAUNCHLOG") 2>&1
fi

# Stop in the app signals this whole process group. The sandbox and the monitor die, but this
# script carries on to the registry diff, the ClamAV scan and the verdict, which is what you
# want after stopping a game you don't trust. (A handler rather than ignore, since children reset handlers.)
STOP_REQUESTED=0
trap 'STOP_REQUESTED=1' TERM INT HUP

# pre-launch scan: refuses the launch on a ClamAV detection, out-of-date signatures or a high static
# risk score (wq-prescan.sh; PRESCAN=0 in game.conf turns it off for this game)
if ! "$QROOT/wq-prescan.sh" "$GAMENAME" --alertlog "$ALERTLOG"; then
  echo "wq: aborting launch"
  sleep 1   # the tee'd launch log has to flush: summarize-run.sh reads the line above from it
  "$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" 97 || true
  exit 97
fi

PROTONPATH="$(find_proton "$GAMEDIR" || true)"
[ -n "$PROTONPATH" ] || { echo "FATAL: no Proton build found. See config.sh." >&2; exit 1; }
WINESERVER="$(find_wineserver "$PROTONPATH" || true)"

# prune old logs
find "$LOGDIR" -maxdepth 1 -type f \
  \( -name 'alerts-*.log' -o -name 'regdiff-*.log' -o -name 'launch-*.log' \) \
  -mtime +"$LOG_RETENTION_DAYS" -delete 2>/dev/null || true

export EXE_REL_PATH
export WINEPREFIX="$GAMEDIR/prefix"
export PROTONPATH
export XDG_DATA_HOME="$UMU_DATA"
export GAMEDIR
export LUTRIS_UMU

# the runtime can't be downloaded from inside the sandbox (no network)
if [ -n "$LUTRIS_UMU" ] && ! ls "$UMU_DATA/umu"/steamrt* >/dev/null 2>&1; then
  echo "[launcher] umu runtime is not downloaded yet. Run ./install.sh once (needs internet), then launch again." >&2
  exit 1
fi

mkdir -p "$GAMEDIR/prefix"
PREFIX_FRESH=0
[ ! -f "$GAMEDIR/prefix/system.reg" ] && PREFIX_FRESH=1

# A different Proton than the one that made the prefix makes Proton rewrite the prefix's builtin
# DLLs on the next start. Do that in the unmonitored bootstrap step below, otherwise the monitor
# sees hundreds of system32 writes and the kill switch fires on Proton itself.
PREFIX_UPGRADE=0
if [ "$PREFIX_FRESH" -eq 0 ]; then
  _pfx_ver="$(prefix_proton_version "$GAMEDIR/prefix" 2>/dev/null || true)"
  _new_ver="$(proton_build_version "$PROTONPATH")"
  if [ "$_pfx_ver" != "$_new_ver" ]; then
    PREFIX_UPGRADE=1
    echo "[launcher] Prefix was made with '${_pfx_ver:-unknown}', running '$_new_ver': upgrading it before monitoring starts."
    echo "[launcher] (Going back to an older Proton than the prefix's is not supported by Proton: pin the right one in proton.path.)"
  fi
fi

wq_scrub_env_args   # sets WQ_ENV_SCRUB: "-u NAME" for every secret-looking variable of this shell
WQ_LIMITS_SUPPORTED=1  # wq-ui integration: both firejail calls below use WQ_LIMIT_PREFIX
apply_game_profile "$GAMEDIR"  # wq-ui integration
mapfile -t WL_ARGS < <(build_whitelist_args "$GAMEDIR" "$UMU_DATA")
mapfile -t BL_ARGS < <(build_blacklist_args)
mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)  # wq-ui integration

# dry-run the exact firejail arguments: if firejail refuses them the game must not be reported as run
if ! wq_firejail_check "${QUARANTINE_FIREJAIL_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}"; then
  sleep 1   # the tee'd launch log has to flush: summarize-run.sh reads the line above from it
  "$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" 97 || true
  exit 97
fi

# verify-sandbox.sh reads these from inside the sandbox
export QVERIFY_GAMEDIR="$GAMEDIR"
export QVERIFY_UMU_DATA="$UMU_DATA"
export QVERIFY_HOST_USER="${USER:-$(id -un)}"
QVERIFY_WL_PATHS="$(printf '%s\n' "${WL_ARGS[@]}" | sed -n 's/^--whitelist=//p')"
export QVERIFY_WL_PATHS

# first run: let wine populate the prefix before monitoring starts
if [ "$PREFIX_FRESH" -eq 1 ] || [ "$PREFIX_UPGRADE" -eq 1 ]; then
  if [ "$PREFIX_FRESH" -eq 1 ]; then
    echo "Fresh prefix detected - bootstrapping before monitored run..."
  else
    echo "Proton version changed - upgrading the prefix before monitored run..."
  fi
  echo "(Wine will populate system32. This phase is not monitored.)"

  cd "$GAMEDIR/game"
  BOOTSTRAP_BAT="$GAMEDIR/game/_bootstrap.bat"
  # game/ is writable by the game: a symlink left here would make the write below land on a host file
  rm -f -- "$BOOTSTRAP_BAT"
  printf '@echo off\r\nexit /b 0\r\n' > "$BOOTSTRAP_BAT"

  ${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK ${WQ_ENV_SCRUB[@]+"${WQ_ENV_SCRUB[@]}"} \
    firejail "${QUARANTINE_FIREJAIL_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}" -- \
      timeout 120 python3 "$LUTRIS_UMU" "./_bootstrap.bat" \
      >"$LOGDIR/bootstrap.log" 2>&1 || true

  rm -f "$BOOTSTRAP_BAT"
  if [ -n "$WINESERVER" ]; then
    WINEPREFIX="$GAMEDIR/prefix" "$WINESERVER" -k 2>/dev/null || true
    WINEPREFIX="$GAMEDIR/prefix" "$WINESERVER" -w 2>/dev/null || true
  fi
  sleep 2
  if [ ! -f "$GAMEDIR/prefix/system.reg" ]; then
    echo "FATAL: bootstrap did not create the prefix. Last lines of $LOGDIR/bootstrap.log:" >&2
    tail -n 20 "$LOGDIR/bootstrap.log" >&2 || true
    exit 1
  fi
  # everything in the prefix right now is Wine's own runtime: wq-scan.sh skips it unless the game touches it later
  # only a fresh prefix is all Wine's own; after an upgrade, anything the game left there earlier
  # must still be scanned
  [ "$PREFIX_FRESH" -eq 1 ] && touch "$GAMEDIR/.clam-baseline"
  # X-Ray baseline, now that Wine has populated the prefix. Taking it any earlier (when the game was added, or
  # just before this launch) records an empty prefix/, so Wine's own files would all show up as new.
  # Overwrites the pre-launch snapshot the UI took. Best effort; WQ_XRAY_BASELINE=0 turns it off.
  if [ "${WQ_XRAY_BASELINE:-1}" != 0 ] && command -v python3 >/dev/null 2>&1; then
    python3 "$QROOT/wq-ui/wq_xray_core.py" --baseline "$QROOT/$GAMENAME" \
      || echo "(X-Ray baseline not saved; use 'Set baseline now' on the X-Ray tab)"
  fi
  echo "Bootstrap complete. Starting monitored run."
fi

[ "$STOP_REQUESTED" -eq 0 ] || { echo "Stopped before the game started."; exit 130; }

cd "$EXEDIR"

"$QROOT/reg-diff.sh" snapshot "$GAMEDIR"

# the Proton build's own DLL/EXE list (lib-runtime.sh): the monitor uses it to recognise Proton's
# system32 writes. Built here, before the game starts, so the monitor never waits on hashing.
mkdir -p "$GAMEDIR/logs"
if ! runtime_build_allowlist "$PROTONPATH" "$GAMEDIR/logs/.runtime-allowlist" 2>/dev/null; then
  rm -f "$GAMEDIR/logs/.runtime-allowlist"
  echo "[launcher] no Proton file list ($PROTONPATH): system32 writes are judged by name only" >&2
fi

${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK ${WQ_ENV_SCRUB[@]+"${WQ_ENV_SCRUB[@]}"} \
  firejail "${QUARANTINE_FIREJAIL_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}" -- \
    bash -c '
      "$0/verify-sandbox.sh" || exit $?
      exec "$0/_umu-run-wrapper" "$EXE_REL_PATH"
    ' "$QROOT" &

GAME_PID=$!
sleep 1

GAME_REAPED=0
if ! kill -0 "$GAME_PID" 2>/dev/null; then
  EARLY_RC=0; wait "$GAME_PID" 2>/dev/null || EARLY_RC=$?
  if [ "$EARLY_RC" -ne 0 ]; then
    echo "FATAL: firejail failed to start (or sandbox verification aborted), exit code $EARLY_RC" >&2
    # a failed preflight gets the proper verdict instead of just an error line
    case "$EARLY_RC" in 90|91|97) "$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" "$EARLY_RC" || true ;; esac
    exit 1
  fi
  # exit code 0 within a second: the program simply finished quickly. Carry on to the post-run
  # checks (registry diff, scans, verdict) instead of reporting a launch failure and skipping them.
  GAME_REAPED=1
fi

# wq-ui: run the monitor in the background; the Qt UI tails logs/alerts-*.log,
# so no visible terminal is needed. Set WQ_MONITOR_TERMINAL=1 to restore the old behaviour.
if [ "${WQ_MONITOR_TERMINAL:-0}" = "1" ]; then
  TERM_BIN="$(detect_terminal 2>/dev/null || true)"
  if [ -n "$TERM_BIN" ]; then
    term_run "$TERM_BIN" "Malware Monitor: $GAMENAME" "" \
      bash -c '"$@"; if [ "${WQ_MONITOR_HOLD:-0}" = 1 ]; then exec bash; fi' _ "$QROOT/monitor.sh" "$GAMEDIR" "$GAME_PID" "$ALERTLOG" &
    MONITOR_PID=$!
  fi
else
  "$QROOT/monitor.sh" "$GAMEDIR" "$GAME_PID" "$ALERTLOG" \
    >>"$GAMEDIR/logs/monitor.out" 2>&1 &
  MONITOR_PID=$!
fi

# wait returns early when Stop's signal is trapped, so keep waiting until the sandbox is really gone.
# GAME_RC is firejail's exit code: 90/91 = sandbox verification failed, 97 = native preflight failed.
GAME_RC=0
while [ "$GAME_REAPED" -eq 0 ]; do
  GAME_RC=0; wait "$GAME_PID" || GAME_RC=$?      # (|| keeps set -e from ending the script)
  kill -0 "$GAME_PID" 2>/dev/null || break
done

if [ -n "${MONITOR_PID:-}" ]; then
  for _ in 1 2 3 4 5; do
    kill -0 "$MONITOR_PID" 2>/dev/null || break
    sleep 1
  done
  wait "$MONITOR_PID" 2>/dev/null || true
fi

if [ -n "$WINESERVER" ]; then
  WINEPREFIX="$GAMEDIR/prefix" "$WINESERVER" -k 2>/dev/null || true
  WINEPREFIX="$GAMEDIR/prefix" "$WINESERVER" -w 2>/dev/null || true
fi
sleep 2

"$QROOT/reg-diff.sh" compare "$GAMEDIR" "$ALERTLOG"
# ClamAV: whatever the run changed in prefix/ and game/ (findings land in $ALERTLOG as ALERT lines)
wq_post_scan wq-scan.sh "$GAMENAME" --when run --alertlog "$ALERTLOG"
# YARA (bundled rules): the same files, so a payload the run dropped is caught by rules too
wq_post_scan wq-yara.sh "$GAMENAME" --when run --alertlog "$ALERTLOG"
"$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" "$GAME_RC" || true
