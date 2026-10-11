#!/bin/bash
# _launch-native.sh <GameName>  (called by a native game's launch-quarantine.sh)
# Runs a native Linux game (script or binary) with the same firejail profile
# setup and monitor as the Wine games, minus Wine/umu/Proton.
#
# What's different from _launch-core.sh:
#  * only <game>/game/ is writable (plus anything whitelisted in wq-ui)
#  * with "Hide home directory" on, $HOME is <game>/home so saves persist
#  * verify-sandbox.sh isn't run, it was written for the Wine setup
#  * no registry snapshot
set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
# shellcheck source=/dev/null
source "$QROOT/config.sh" || { echo "FATAL: cannot load $QROOT/config.sh" >&2; exit 1; }
for b in firejail inotifywait; do
  command -v "$b" >/dev/null 2>&1 || { echo "FATAL: $b is not installed" >&2; exit 1; }
done
declare -F apply_game_profile >/dev/null 2>&1 || {
  echo "FATAL: wq-ui profile not loaded - run: python3 wq-ui/integrate.py" >&2; exit 1; }

[ $# -eq 1 ] || { echo "Usage: _launch-native.sh <GameName>" >&2; exit 1; }
GAMENAME="${1%/}"
case "$GAMENAME" in ""|*/*|.|..) echo "Error: invalid game name '$1'" >&2; exit 1 ;; esac

GAMEDIR="$QROOT/$GAMENAME"
[ -d "$GAMEDIR/game" ] || { echo "Error: no such game: $GAMENAME" >&2; exit 1; }
GAMEDIR="$(readlink -f "$GAMEDIR")"
export GAMEDIR

[ "$(read_game_conf "$GAMEDIR" RUNNER || true)" = "native" ] || {
  echo "Error: $GAMENAME is not a native game (no RUNNER=native in game.conf)" >&2; exit 1; }
EXE="$(read_game_conf "$GAMEDIR" EXE)" || { echo "Error: no EXE= line in $GAMEDIR/game.conf" >&2; exit 1; }
[ "$EXE" != "CHANGE_ME.sh" ] && [ "$EXE" != "CHANGE_ME.exe" ] || { echo "Error: set EXE= in $GAMEDIR/game.conf first" >&2; exit 1; }
valid_exe_rel "$EXE" || { echo "Error: bad EXE path in game.conf" >&2; exit 1; }

EXEDIR="$(readlink -f "$GAMEDIR/game/$(dirname "$EXE")")"
case "$EXEDIR/" in "$GAMEDIR/game/"*) ;; *) echo "Error: start directory resolves outside game/" >&2; exit 1 ;; esac
EXE_NAME="$(basename "$EXE")"
[ -f "$EXEDIR/$EXE_NAME" ] || { echo "Error: not found: $EXEDIR/$EXE_NAME" >&2; exit 1; }
case "$EXE_NAME" in *.sh) ;; *) chmod u+x "$EXEDIR/$EXE_NAME" ;; esac

LOGDIR="$GAMEDIR/logs"; mkdir -p "$LOGDIR"
ALERTLOG="$LOGDIR/alerts-$(date +%Y%m%d-%H%M%S).log"
LAUNCHLOG="$LOGDIR/launch-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LAUNCHLOG") 2>&1
find "$LOGDIR" -maxdepth 1 -type f \( -name 'alerts-*.log' -o -name 'launch-*.log' \) \
  -mtime +"${LOG_RETENTION_DAYS:-30}" -delete 2>/dev/null || true

echo "wq: native launch of $GAMENAME ($EXE). verify-sandbox.sh is not run for native games."

apply_game_profile "$GAMEDIR"

# private home that persists, instead of firejail's throwaway one
NATIVE_HOME="${WQ_NATIVE_HOME:-$GAMEDIR/home}"
FJ_ARGS=()
for a in "${QUARANTINE_FIREJAIL_ARGS[@]}"; do
  if [ "$a" = "--private" ]; then
    mkdir -p "$NATIVE_HOME"
    FJ_ARGS+=("--private=$NATIVE_HOME")
  else
    FJ_ARGS+=("$a")
  fi
done

WL_ARGS=("--whitelist=$GAMEDIR/game" "--read-write=$GAMEDIR/game")
mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)
mapfile -t BL_ARGS < <(build_blacklist_args)

export WQ_EXE_NAME="$EXE_NAME"
cd "$EXEDIR"

env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK \
  firejail "${FJ_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}" -- \
    bash -c '
      case "$WQ_EXE_NAME" in
        *.sh) exec bash "./$WQ_EXE_NAME" ;;
        *)    exec "./$WQ_EXE_NAME" ;;
      esac
    ' &
GAME_PID=$!
sleep 1
if ! kill -0 "$GAME_PID" 2>/dev/null; then          # already gone, quick script or failed start
  GAME_RC=0
  wait "$GAME_PID" || GAME_RC=$?
  echo "wq: game exited within a second (code $GAME_RC)"
  "$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" || true
  exit "$GAME_RC"
fi

"$QROOT/monitor.sh" "$GAMEDIR" "$GAME_PID" "$ALERTLOG" >>"$LOGDIR/monitor.out" 2>&1 &
MONITOR_PID=$!

GAME_RC=0
wait "$GAME_PID" || GAME_RC=$?
echo "wq: game exited with code $GAME_RC"
for _ in 1 2 3 4 5; do kill -0 "$MONITOR_PID" 2>/dev/null || break; sleep 1; done
wait "$MONITOR_PID" 2>/dev/null || true

"$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" || true
exit "$GAME_RC"
