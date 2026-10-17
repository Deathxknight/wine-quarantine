#!/bin/bash
# _launch-core.sh <GameName>  (internal, called by each game's launch-quarantine.sh)
# Runs a quarantined game in the sandbox with the monitor attached.

set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
source "$QROOT/config.sh" || { echo "FATAL: cannot load $QROOT/config.sh" >&2; exit 1; }
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

# exe comes from game.conf, which is only ever read as data
EXE="$(read_game_conf "$GAMEDIR" EXE)" || { echo "Error: no EXE= line in $GAMEDIR/game.conf" >&2; exit 1; }
[ "$EXE" != "CHANGE_ME.exe" ] || { echo "Error: set EXE= in $GAMEDIR/game.conf first" >&2; exit 1; }
valid_exe_rel "$EXE" || { echo "Error: bad EXE path in game.conf" >&2; exit 1; }

EXEDIR="$(readlink -f "$GAMEDIR/game/$(dirname "$EXE")")"
case "$EXEDIR/" in
  "$GAMEDIR/game/"*) ;;
  *) echo "Error: exe directory resolves outside game/" >&2; exit 1 ;;
esac
EXE_REL_PATH="./$(basename "$EXE")"
[ -f "$EXEDIR/${EXE_REL_PATH#./}" ] || { echo "Error: exe not found: $EXEDIR/${EXE_REL_PATH#./}" >&2; exit 1; }

LOGDIR="$GAMEDIR/logs"
mkdir -p "$LOGDIR"
ALERTLOG="$LOGDIR/alerts-$(date +%Y%m%d-%H%M%S).log"

# everything printed from here on (sandbox verify failures, umu tracebacks...)
# is also saved, so the wq-ui Debug report can include it
LAUNCHLOG="$LOGDIR/launch-$(date +%Y%m%d-%H%M%S).log"
# the log file stays plain; wq-colorize only colours what reaches a terminal
if [ -x "$QROOT/wq-colorize" ]; then
  exec > >(tee -a "$LAUNCHLOG" | "$QROOT/wq-colorize") 2>&1
else
  exec > >(tee -a "$LAUNCHLOG") 2>&1
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

WQ_LIMITS_SUPPORTED=1  # wq-ui integration: both firejail calls below use WQ_LIMIT_PREFIX
apply_game_profile "$GAMEDIR"  # wq-ui integration
mapfile -t WL_ARGS < <(build_whitelist_args "$GAMEDIR" "$UMU_DATA")
mapfile -t BL_ARGS < <(build_blacklist_args)
mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)  # wq-ui integration

# verify-sandbox.sh reads these from inside the sandbox
export QVERIFY_GAMEDIR="$GAMEDIR"
export QVERIFY_UMU_DATA="$UMU_DATA"
export QVERIFY_HOST_USER="${USER:-$(id -un)}"
QVERIFY_WL_PATHS="$(printf '%s\n' "${WL_ARGS[@]}" | sed -n 's/^--whitelist=//p')"
export QVERIFY_WL_PATHS

# first run: let wine populate the prefix before monitoring starts
if [ "$PREFIX_FRESH" -eq 1 ]; then
  echo "Fresh prefix detected - bootstrapping before monitored run..."
  echo "(Wine will populate system32. This phase is not monitored.)"

  cd "$GAMEDIR/game"
  BOOTSTRAP_BAT="$GAMEDIR/game/_bootstrap.bat"
  printf '@echo off\r\nexit /b 0\r\n' > "$BOOTSTRAP_BAT"

  ${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK \
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
  touch "$GAMEDIR/.clam-baseline"
  echo "Bootstrap complete. Starting monitored run."
fi

cd "$EXEDIR"

"$QROOT/reg-diff.sh" snapshot "$GAMEDIR"

${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK \
  firejail "${QUARANTINE_FIREJAIL_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}" -- \
    bash -c '
      "$0/verify-sandbox.sh" || exit $?
      exec "$0/_umu-run-wrapper" "$EXE_REL_PATH"
    ' "$QROOT" &

GAME_PID=$!
sleep 1

if ! kill -0 "$GAME_PID" 2>/dev/null; then
  echo "FATAL: firejail failed to start (or sandbox verification aborted)" >&2
  exit 1
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

wait "$GAME_PID" || true

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
"$QROOT/wq-scan.sh" "$GAMENAME" --when run --alertlog "$ALERTLOG" || true
"$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG"
