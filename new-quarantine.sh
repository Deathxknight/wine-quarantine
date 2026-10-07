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
  ""|*/*|.|..) echo "Error: invalid game name '$GAMENAME'" >&2; exit 1 ;;
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

if [ -n "$SOURCE" ]; then
  case "$SOURCE" in
    *.zip) unzip -q "$SOURCE" -d "$GAMEDIR/game" ;;
    *.rar) unrar x -inul "$SOURCE" "$GAMEDIR/game/" ;;
    *.7z)  7z x -o"$GAMEDIR/game" "$SOURCE" >/dev/null ;;
    *.exe) cp "$SOURCE" "$GAMEDIR/game/" ;;
    *)     cp -r "$SOURCE" "$GAMEDIR/game/" ;;
  esac
fi

[ -d "$GAMEDIR/game" ] || { echo "Error: game dir missing after extraction" >&2; exit 1; }

echo
echo "Scanning for .exe files..."
mapfile -d '' -t EXES < <(find "$GAMEDIR/game" -iname "*.exe" \
  -not -iname "unins*" -not -iname "*redist*" -not -iname "*vcredist*" \
  -not -iname "*directx*" -not -iname "dxsetup*" -not -iname "*crashhandler*" \
  -not -iname "*crashpad*" -print0 2>/dev/null)

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
    select choice in "${EXES[@]}" "__MANUAL__"; do
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

# per-game settings are plain data, read by launch.sh without evaluating anything
printf '# exe path, relative to game/\nEXE=%s\n' "$EXE" > "$GAMEDIR/game.conf"

trap - EXIT

echo
echo "=== Done ==="
echo "Game dir:  $GAMEDIR"
echo "Exe:       $EXE"
echo "Proton:    $(find_proton "$GAMEDIR" || echo 'none found')"
echo "Run it:    $QROOT/launch.sh \"$GAMENAME\""
