#!/bin/bash
# new-native.sh <GameName> [source]  - set up a native Linux game (start.sh, binary, AppImage)
# source can be a folder, an archive (.zip .tar.gz .tgz .tar.xz .tar.bz2 .tar .rar .7z) or one file.
# makes <QROOT>/<GameName>/{game,logs,game.conf,launch-quarantine.sh}, game.conf gets RUNNER=native
set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"

[ $# -ge 1 ] || { echo "Usage: new-native.sh <GameName> [folder|archive|file]" >&2; exit 1; }
GAMENAME="$1"
SOURCE="${2:-}"
GAMEDIR="$QROOT/$GAMENAME"

case "$GAMENAME" in
  ""|*/*|.|..|_*|.*|-*) echo "Error: invalid game name '$GAMENAME'" >&2; exit 1 ;;
esac
[ -e "$GAMEDIR" ] && { echo "Error: $GAMEDIR already exists." >&2; exit 1; }
command -v firejail >/dev/null 2>&1 || { echo "Error: firejail is not installed." >&2; exit 1; }
if [ -n "$SOURCE" ] && [ ! -e "$SOURCE" ]; then
  echo "Error: source '$SOURCE' not found." >&2; exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' is required for this archive." >&2; exit 1; }; }

echo "Setting up native quarantine for '$GAMENAME'..."
mkdir -p "$GAMEDIR/game" "$GAMEDIR/logs"
cleanup() {
  local rc=$?
  [ "$rc" -ne 0 ] && [ -d "$GAMEDIR" ] && { echo "Setup failed (rc=$rc), removing $GAMEDIR" >&2; rm -rf "$GAMEDIR"; }
}
trap cleanup EXIT

if [ -n "$SOURCE" ]; then
  if [ -d "$SOURCE" ]; then
    cp -a "$SOURCE"/. "$GAMEDIR/game/"
  else
    case "${SOURCE,,}" in
      *.zip)             need unzip; unzip -q "$SOURCE" -d "$GAMEDIR/game" ;;
      *.tar.gz|*.tgz)    need tar;   tar -xzf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.xz|*.txz)    need tar;   tar -xJf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.bz2|*.tbz2)  need tar;   tar -xjf "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar)             need tar;   tar -xf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.rar)             need unrar; unrar x -inul "$SOURCE" "$GAMEDIR/game/" ;;
      *.7z)              need 7z;    7z x -o"$GAMEDIR/game" "$SOURCE" >/dev/null ;;
      *)                 cp "$SOURCE" "$GAMEDIR/game/"; chmod u+x "$GAMEDIR/game/$(basename "$SOURCE")" ;;
    esac
  fi
fi

echo
echo "Looking for something to start..."
mapfile -d '' -t CANDS < <(find "$GAMEDIR/game" -maxdepth 3 -type f \
  \( -iname '*.sh' -o -iname '*.appimage' -o -iname '*.x86_64' \) \
  -not -iname 'unins*' -not -iname 'uninstall*' -not -iname 'install*' -print0 2>/dev/null | sort -z)

PICK=""
for pref in start.sh run.sh launch.sh play.sh; do
  for c in "${CANDS[@]}"; do
    [ "$(basename "${c,,}")" = "$pref" ] && { PICK="$c"; break 2; }
  done
done
[ -z "$PICK" ] && [ "${#CANDS[@]}" -ge 1 ] && PICK="${CANDS[0]}"

if [ -n "$PICK" ]; then
  EXE="${PICK#"$GAMEDIR/game/"}"
  echo "Found: $EXE   (${#CANDS[@]} candidate(s); change it later with Add > Set executable)"
else
  EXE="CHANGE_ME.sh"
  echo "Nothing found - set the start script later with Add > Set executable."
fi
case "$EXE" in ""|/*|..|../*|*/..|*/../*|*$'\n'*|*$'\r'*) echo "Error: unsafe path" >&2; exit 1 ;; esac

printf '# start script / binary, relative to game/\nEXE=%s\nRUNNER=native\n' "$EXE" > "$GAMEDIR/game.conf"

cat > "$GAMEDIR/launch-quarantine.sh" <<'EOS'
#!/bin/bash
D="$(dirname "$(readlink -f "$0")")"
exec "$(dirname "$D")/wq-ui/_launch-native.sh" "$(basename "$D")"
EOS
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
echo "Start:     $EXE"
echo "Launcher:  $GAMEDIR/launch-quarantine.sh"
