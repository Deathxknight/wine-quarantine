#!/bin/bash
set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$QROOT/config.sh"
. "$QROOT/lib-extract.sh"

usage() {
  echo "Usage: new-quarantine.sh <GameName> [path-to-exe-or-archive-or-iso]"
  exit 1
}

[ $# -eq 0 ] && usage
GAMENAME="$1"
SOURCE="${2:-}"
GAMEDIR="$QROOT/$GAMENAME"

case "$GAMENAME" in
  ""|*/*|.|..|_*|.*|-*|*$'\n'*) echo "Error: invalid game name '$GAMENAME' (no slashes, and not starting with _ . or -)" >&2; exit 1 ;;
esac

[ -e "$GAMEDIR" ] && { echo "Error: $GAMEDIR already exists." >&2; exit 1; }
check_deps || exit 1

# check the source before creating anything
if [ -n "$SOURCE" ]; then
  [ -e "$SOURCE" ] || { echo "Error: source '$SOURCE' not found." >&2; exit 1; }
fi

echo "Setting up quarantine for '$GAMENAME'..."

# remove the partial dir if anything below fails (installed before mkdir, so a half-made tree is cleaned too)
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -d "$GAMEDIR" ]; then
    echo "Setup failed (rc=$rc), removing $GAMEDIR" >&2
    rm -rf "$GAMEDIR"
  fi
}
trap cleanup EXIT
mkdir -p "$GAMEDIR/game" "$GAMEDIR/prefix" "$GAMEDIR/logs" "$GAMEDIR/.reg-snapshot"

# first use: bootstrap the shared umu data dir
if ! ls "$UMU_DATA/umu"/steamrt* >/dev/null 2>&1; then
  echo "Bootstrapping umu data at $UMU_DATA..."
  mkdir -p "$UMU_DATA/umu"
  BOOTSTRAP_PROTONPATH="$(find_proton "$GAMEDIR" || true)"
  if [ -n "$BOOTSTRAP_PROTONPATH" ]; then
    XDG_DATA_HOME="$UMU_DATA" PROTONPATH="$BOOTSTRAP_PROTONPATH" GAMEID=umu-default \
      python3 "$LUTRIS_UMU" /bin/true \
      || echo "Warning: umu bootstrap failed."
  fi
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' is required for this archive." >&2; exit 1; }; }

if [ -n "$SOURCE" ]; then
  case "$SOURCE" in -*) SOURCE="./$SOURCE" ;; esac
  if [ -d "$SOURCE" ]; then
    cp -a "$SOURCE"/. "$GAMEDIR/game/"
  else
    case "${SOURCE,,}" in
      *.zip)            wq_extract_zip "$SOURCE" "$GAMEDIR/game" ;;
      *.rar)            need unrar; wq_xrun "$GAMEDIR/game" unrar x -inul "$SOURCE" "$GAMEDIR/game/" ;;
      *.7z)             SEVENZ="$(command -v 7z || command -v 7zz || command -v 7za || true)"
                        [ -n "$SEVENZ" ] || { echo "Error: 7z (7zz / 7za) is required for this archive." >&2; exit 1; }
                        wq_xrun "$GAMEDIR/game" "$SEVENZ" x -y -o"$GAMEDIR/game" "$SOURCE" >/dev/null ;;
      *.iso)            wq_extract_iso "$SOURCE" "$GAMEDIR/game" ;;
      *.tar.gz|*.tgz)   need tar;   wq_xrun "$GAMEDIR/game" tar -xzf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.xz|*.txz)   need tar;   wq_xrun "$GAMEDIR/game" tar -xJf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.bz2|*.tbz2) need tar;   wq_xrun "$GAMEDIR/game" tar -xjf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar)            need tar;   wq_xrun "$GAMEDIR/game" tar -xf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *)                cp "$SOURCE" "$GAMEDIR/game/" ;;
    esac
  fi
fi

[ -d "$GAMEDIR/game" ] || { echo "Error: game dir missing after extraction" >&2; exit 1; }
# whatever the source was (archive, folder, iso): no symlink may point out of game/. Later steps on this
# machine (permission fixes, scans, the exe check) follow links, and the game controls what they say.
wq_sanitize_extracted "$GAMEDIR/game"

echo
echo "Scanning for .exe files..."
mapfile -d '' -t EXES < <(find "$GAMEDIR/game" -iname "*.exe" \
  -not -iname "unins*" -not -iname "*redist*" -not -iname "*vcredist*" \
  -not -iname "*directx*" -not -iname "dxsetup*" -not -iname "*crashhandler*" \
  -not -iname "*crashpad*" -printf '%d\t%p\0' 2>/dev/null \
  | sort -z -t $'\t' -k1,1n -k2,2 | sed -z 's/^[0-9]*\t//')      # shallowest first, like the app's Set executable list

# Rank the candidates: prerequisite installers (.NET, DirectX, VC++ runtimes, setup/install helpers) go last,
# so the default pick, and the top of the list, is the game itself. Order is otherwise unchanged.
if [ "${#EXES[@]}" -gt 1 ]; then
  _good=(); _meh=()
  for _e in "${EXES[@]}"; do
    case "${_e##*/}" in
      [Dd]ot[Nn]et*|*[Nn]et[Ff]x*|*[Ss]etup*|*[Ii]nstall*|*[Pp]hys[Xx]*|[Xx]na*|[Oo]alinst*|[Dd]x[Ww]eb*|*[Uu]nity[Cc]rash*|*[Cc]onfig[Tt]ool*|*[Uu]pdater*)
        _meh+=("$_e") ;;
      *) _good+=("$_e") ;;
    esac
  done
  EXES=("${_good[@]+"${_good[@]}"}" "${_meh[@]+"${_meh[@]}"}")
fi

EXEPATH=""
if [ "${#EXES[@]}" -eq 0 ]; then
  echo "No .exe found - edit EXE= in $GAMEDIR/game.conf later."
elif [ "${#EXES[@]}" -eq 1 ]; then
  EXEPATH="${EXES[0]}"
  echo "Found: $EXEPATH"
else
  echo "Multiple candidates:"
  if [ ! -t 0 ]; then
    echo "  (stdin not a TTY, taking first: ${EXES[0]})"
    EXEPATH="${EXES[0]}"
  else
    PS3="Start file (number): "
    select choice in "${EXES[@]}" "__MANUAL__"; do
      [ -n "$choice" ] || { echo "Pick a number from the list."; continue; }
      if [ "$choice" = "__MANUAL__" ]; then
        EXEPATH=""
      else
        EXEPATH="$choice"
      fi
      break
    done
  fi
fi

if [ -n "$EXEPATH" ]; then
  EXE="${EXEPATH#"$GAMEDIR/game/"}"
  valid_exe_rel "$EXE" || { echo "Error: refusing exe with an unsafe path" >&2; exit 1; }
else
  EXE="CHANGE_ME.exe"
fi

case "${EXE##*/}" in
  *[Ss]etup*|*[Ii]nstall*)
    echo "Note: $EXE looks like an installer, not the game. In wq-ui use Add > Run setup file to run it once," \
         "then Add > Set executable to pick the program it installed." ;;
esac

# per-game settings are plain data, read by _launch-core.sh without evaluating anything
printf '# exe path, relative to game/\nEXE=%s\n' "$EXE" > "$GAMEDIR/game.conf"

# convenience wrapper: no embedded data, resolves everything from its own location
wq_launcher_text windows > "$GAMEDIR/launch-quarantine.sh"
chmod +x "$GAMEDIR/launch-quarantine.sh"

trap - EXIT

# X-Ray baseline: the populated game folders become the reference the X-Ray tab compares later runs with.
# Taken before the scan so cancelling the scan keeps it. Best effort; WQ_XRAY_BASELINE=0 turns it off.
if [ "${WQ_XRAY_BASELINE:-1}" != 0 ] && command -v python3 >/dev/null 2>&1; then
  python3 "$QROOT/wq-ui/wq_xray_core.py" --baseline "$GAMEDIR" \
    || echo "(X-Ray baseline not saved; use 'Set baseline now' on the X-Ray tab)"
fi

# ClamAV scan of what was just added. wq-scan.sh skips itself (and says why) when ClamAV or its
# database is missing. Cancelling during the scan keeps the game, it only stops the scan.
if [ "${WQ_SKIP_SCAN:-0}" != 1 ]; then
  trap 'echo; echo "ClamAV scan cancelled. The game was added but not scanned (run: ./wq-scan.sh \"$GAMENAME\")"; exit 0' TERM INT HUP
  "$QROOT/wq-scan.sh" "$GAMENAME" --when add || true
  trap - TERM INT HUP
fi

echo
echo "=== Done ==="
echo "Game dir:  $GAMEDIR"
echo "Exe:       $EXE"
echo "Proton:    $(find_proton "$GAMEDIR" || echo 'none found')"
echo "Launcher:  $GAMEDIR/launch-quarantine.sh"
