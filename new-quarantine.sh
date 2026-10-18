#!/bin/bash
set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
. "$QROOT/config.sh"

usage() {
  echo "Usage: new-quarantine.sh <GameName> [path-to-exe-or-archive]"
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
mkdir -p "$GAMEDIR/game" "$GAMEDIR/prefix" "$GAMEDIR/logs" "$GAMEDIR/.reg-snapshot"

# remove the partial dir if anything below fails
cleanup() {
  local rc=$?
  [ "$rc" -ne 0 ] && [ -d "$GAMEDIR" ] && {
    echo "Setup failed (rc=$rc), removing $GAMEDIR" >&2
    rm -rf "$GAMEDIR"
  }
}
trap cleanup EXIT

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
      *.zip)            need unzip; unzip -q "$SOURCE" -d "$GAMEDIR/game" ;;
      *.rar)            need unrar; unrar x -inul "$SOURCE" "$GAMEDIR/game/" ;;
      *.7z)             SEVENZ="$(command -v 7z || command -v 7zz || command -v 7za || true)"
                        [ -n "$SEVENZ" ] || { echo "Error: 7z (7zz / 7za) is required for this archive." >&2; exit 1; }
                        "$SEVENZ" x -y -o"$GAMEDIR/game" "$SOURCE" >/dev/null ;;
      *.tar.gz|*.tgz)   need tar;   tar -xzf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.xz|*.txz)   need tar;   tar -xJf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.bz2|*.tbz2) need tar;   tar -xjf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar)            need tar;   tar -xf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *)                cp "$SOURCE" "$GAMEDIR/game/" ;;
    esac
  fi
fi

[ -d "$GAMEDIR/game" ] || { echo "Error: game dir missing after extraction" >&2; exit 1; }

echo
echo "Scanning for .exe files..."
mapfile -d '' -t EXES < <(find "$GAMEDIR/game" -iname "*.exe" \
  -not -iname "unins*" -not -iname "*redist*" -not -iname "*vcredist*" \
  -not -iname "*directx*" -not -iname "dxsetup*" -not -iname "*crashhandler*" \
  -not -iname "*crashpad*" -print0 2>/dev/null | sort -z)

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

# per-game settings are plain data, read by _launch-core.sh without evaluating anything
printf '# exe path, relative to game/\nEXE=%s\n' "$EXE" > "$GAMEDIR/game.conf"

# convenience wrapper: no embedded data, resolves everything from its own location
wq_launcher_text windows > "$GAMEDIR/launch-quarantine.sh"
chmod +x "$GAMEDIR/launch-quarantine.sh"

trap - EXIT

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
