#!/bin/bash
# _launch-native.sh <GameName>  (called by a native game's launch-quarantine.sh)
# Runs a native Linux game (script or binary) with the same firejail profile
# setup and monitor as the Wine games, minus Wine/umu/Proton.
#
# What's different from _launch-core.sh:
#  * only <game>/game/ is writable (plus anything whitelisted in wq-ui)
#  * with "Hide home directory" on, $HOME is <game>/home so saves persist
#  * verify-sandbox.sh isn't run, it was written for the Wine setup
#  * no registry snapshot: home-diff.sh does the same job for startup files, autostart
#    entries, systemd user units, ~/.local/bin, ~/.ssh and new executables in game/
#  * monitor.sh runs in native mode (lib-monitor-native.sh) because game.conf has RUNNER=native
#  * wq-scan.sh (ClamAV) scans game/ and home/ after the run
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
# (the logger ignores TERM/INT/HUP so it outlives a Stop and the post-run summary can still print)
exec > >(trap '' TERM INT HUP; tee -a "$LAUNCHLOG") 2>&1
# Stop in the app signals this whole process group: the sandbox and monitor die, this script
# carries on to the home diff, the ClamAV scan and the verdict.
STOP_REQUESTED=0
trap 'STOP_REQUESTED=1' TERM INT HUP
find "$LOGDIR" -maxdepth 1 -type f \( -name 'alerts-*.log' -o -name 'launch-*.log' \) \
  -mtime +"${LOG_RETENTION_DAYS:-30}" -delete 2>/dev/null || true

echo "wq: native launch of $GAMENAME ($EXE)."

export WQ_RUNNER=native
WQ_LIMITS_SUPPORTED=1   # the firejail call below uses WQ_LIMIT_PREFIX
apply_game_profile "$GAMEDIR"

# private home that persists, instead of firejail's throwaway one
NATIVE_HOME="${WQ_NATIVE_HOME:-$GAMEDIR/home}"
FJ_ARGS=()
WQ_MONITOR_PRIVATE=0
for a in "${QUARANTINE_FIREJAIL_ARGS[@]}"; do
  if [ "$a" = "--private" ]; then
    mkdir -p "$NATIVE_HOME"
    FJ_ARGS+=("--private=$NATIVE_HOME")
    WQ_MONITOR_PRIVATE=1
  else
    FJ_ARGS+=("$a")
  fi
done
# what the game sees as $HOME, for monitor.sh and home-diff.sh
if [ "$WQ_MONITOR_PRIVATE" = 1 ]; then WQ_MONITOR_HOME="$NATIVE_HOME"; else WQ_MONITOR_HOME="$HOME"; fi
export WQ_MONITOR_HOME WQ_MONITOR_PRIVATE

# after the run: home diff + ClamAV scan + summary
post_run() {   # post_run <game exit code>
  "$QROOT/home-diff.sh" compare "$GAMEDIR" "$ALERTLOG" || true
  "$QROOT/wq-scan.sh" "$GAMENAME" --when run --alertlog "$ALERTLOG" || true
  sleep 1   # let the tee'd launch log flush
  "$QROOT/summarize-run.sh" "$GAMEDIR" "$ALERTLOG" "$1" || true
}

WL_ARGS=("--whitelist=$GAMEDIR/game" "--read-write=$GAMEDIR/game")
# the verifier and its hash go into the jail read-only, as for Windows games
WQ_NATIVE_VERIFY=0
if [ "${NATIVE_VERIFY:-1}" = 1 ] && [ -f "$QROOT/verify-sandbox.sh" ] && [ -f "$QROOT/verify-sandbox.sha256" ]; then
  WQ_NATIVE_VERIFY=1
  _qr="$(readlink -f "$QROOT")"
  for _f in verify-sandbox.sh verify-sandbox.sha256; do
    WL_ARGS+=("--whitelist=$_qr/$_f" "--read-only=$_qr/$_f")
  done
fi
export WQ_NATIVE_VERIFY QVERIFY_MODE=native QVERIFY_GAMEDIR="$GAMEDIR"
mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)
mapfile -t BL_ARGS < <(build_blacklist_args)

export WQ_EXE_NAME="$EXE_NAME"
cd "$EXEDIR"

"$QROOT/home-diff.sh" snapshot "$GAMEDIR"

${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"} env -u DBUS_SESSION_BUS_ADDRESS -u SSH_AUTH_SOCK \
  firejail "${FJ_ARGS[@]}" "${WL_ARGS[@]}" "${BL_ARGS[@]}" -- \
    bash -c '
      # preflight: refuse to start the game if the jail is leaking (honours the
      # profile opt-outs in QVERIFY_SKIP). First the generic verifier (capabilities, seccomp,
      # network, ...), then the extra native checks below.
      if [ "${WQ_NATIVE_VERIFY:-0}" = 1 ]; then
        "$0/verify-sandbox.sh" || exit $?
      fi
      bad=0; sk=",${QVERIFY_SKIP:-},"
      has() { case "$sk" in *",$1,"*) return 1 ;; *) return 0 ;; esac; }
      leak() { echo "wq: SANDBOX LEAK: $*" >&2; bad=1; }
      # group membership is only a note: firejail ignores --nogroups on NVIDIA
      # systems, and what the groups would grant (sockets, /dev/input, sudo) is
      # checked directly below and by --nonewprivs.
      if has groups; then
        for g in docker input libvirt wheel disk kvm; do
          id -nG | tr " " "\n" | grep -qx "$g" && echo "wq: note: still in group $g (resources are blocked separately)" >&2
        done
      fi
      if has sockets; then
        for s in /run/docker.sock /var/run/docker.sock /run/libvirt/libvirt-sock; do
          [ -S "$s" ] && leak "control socket visible: $s"
        done
      fi
      if has sockets && [ "${QVERIFY_NET:-off}" != open ]; then
        # these answer name lookups without any network interface, so --net=none does not cover them
        for s in /run/systemd/resolve/io.systemd.Resolve /run/nscd/socket /var/run/nscd/socket; do
          [ -S "$s" ] && leak "DNS resolver socket visible (bypasses --net=none): $s"
        done
      fi
      if has input; then
        for d in /dev/input/event*; do
          [ -e "$d" ] && { leak "raw input device visible: $d"; break; }
        done
      fi
      if has ns; then
        unshare -U true 2>/dev/null && leak "user namespaces still allowed"
      fi
      [ "$bad" = 0 ] || { echo "wq: aborting launch" >&2; exit 97; }
      case "$WQ_EXE_NAME" in
        *.sh) exec bash "./$WQ_EXE_NAME" ;;
        *)    exec "./$WQ_EXE_NAME" ;;
      esac
    ' "$QROOT" &
GAME_PID=$!

# Start the monitor at once. A native game is running within milliseconds, and whatever it does in
# the first seconds would go unwatched if the monitor waited. If the game is already gone (a quick
# script, a failed start) the monitor simply ends.
"$QROOT/monitor.sh" "$GAMEDIR" "$GAME_PID" "$ALERTLOG" >>"$LOGDIR/monitor.out" 2>&1 &
MONITOR_PID=$!

GAME_RC=0
while :; do
  GAME_RC=0; wait "$GAME_PID" || GAME_RC=$?      # (|| keeps set -e from ending the script)
  kill -0 "$GAME_PID" 2>/dev/null || break
done
echo "wq: game exited with code $GAME_RC"
for _ in 1 2 3 4 5; do kill -0 "$MONITOR_PID" 2>/dev/null || break; sleep 1; done
wait "$MONITOR_PID" 2>/dev/null || true

post_run "$GAME_RC"
exit "$GAME_RC"
