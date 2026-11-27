#!/bin/bash
# new-native.sh <GameName> [source]  - set up a native Linux game (start.sh, binary, AppImage)
# source can be a folder, an archive (.zip .tar.gz .tgz .tar.xz .tar.bz2 .tar .rar .7z), an .iso or one file.
# makes <QROOT>/<GameName>/{game,logs,game.conf,launch-quarantine.sh}, game.conf gets RUNNER=native
set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
# shellcheck source=/dev/null
. "$QROOT/config.sh"
# shellcheck source=/dev/null
. "$QROOT/lib-extract.sh"

[ $# -ge 1 ] || { echo "Usage: new-native.sh <GameName> [folder|archive|file]" >&2; exit 1; }
GAMENAME="$1"
SOURCE="${2:-}"
GAMEDIR="$QROOT/$GAMENAME"

case "$GAMENAME" in
  ""|*/*|.|..|_*|.*|-*|*$'\n'*) echo "Error: invalid game name '$GAMENAME' (no slashes or newlines, and not starting with _ . or -)" >&2; exit 1 ;;
esac
[ -e "$GAMEDIR" ] && { echo "Error: $GAMEDIR already exists." >&2; exit 1; }
command -v firejail >/dev/null 2>&1 || { echo "Error: firejail is not installed." >&2; exit 1; }
if [ -n "$SOURCE" ] && [ ! -e "$SOURCE" ]; then
  echo "Error: source '$SOURCE' not found." >&2; exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' is required for this archive." >&2; exit 1; }; }

echo "Setting up native quarantine for '$GAMENAME'..."
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ -d "$GAMEDIR" ]; then
    echo "Setup failed (rc=$rc), removing $GAMEDIR" >&2
    rm -rf "$GAMEDIR"
  fi
}
trap cleanup EXIT
mkdir -p "$GAMEDIR/game" "$GAMEDIR/logs"

if [ -n "$SOURCE" ]; then
  case "$SOURCE" in -*) SOURCE="./$SOURCE" ;; esac     # a file called -x.zip must not read as an option
  if [ -d "$SOURCE" ]; then
    cp -a "$SOURCE"/. "$GAMEDIR/game/"
  else
    case "${SOURCE,,}" in
      *.zip)             wq_extract_zip "$SOURCE" "$GAMEDIR/game" ;;
      *.tar.gz|*.tgz)    need tar;   wq_xrun "$GAMEDIR/game" tar -xzf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.xz|*.txz)    need tar;   wq_xrun "$GAMEDIR/game" tar -xJf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar.bz2|*.tbz2)  need tar;   wq_xrun "$GAMEDIR/game" tar -xjf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.tar)             need tar;   wq_xrun "$GAMEDIR/game" tar -xf  "$SOURCE" --no-same-owner -C "$GAMEDIR/game" ;;
      *.rar)             need unrar; wq_xrun "$GAMEDIR/game" unrar x -inul "$SOURCE" "$GAMEDIR/game/" ;;
      *.7z)              SEVENZ="$(wq_find_7z)"
                         [ -n "$SEVENZ" ] || { echo "Error: 7z (7zz / 7za) is required for this archive." >&2; exit 1; }
                         wq_xrun "$GAMEDIR/game" "$SEVENZ" x -y -o"$GAMEDIR/game" "$SOURCE" >/dev/null ;;
      *.iso)             wq_extract_iso "$SOURCE" "$GAMEDIR/game" ;;
      *)                 cp "$SOURCE" "$GAMEDIR/game/"; chmod u+x "$GAMEDIR/game/$(basename "$SOURCE")" ;;
    esac
  fi
fi

# whatever the source was (archive, folder, iso): no symlink may point out of game/. Later steps on this
# machine (chmod, scans, the exe check) follow links, and the game controls what they say.
wq_sanitize_extracted "$GAMEDIR/game"

echo
echo "Looking for something to start..."
# Same list the app's "Set executable" shows (wq_core.find_exes): shallowest first, and it also takes
# extensionless ELF binaries and .bin/.x86 files, which a plain find on file names misses.
CANDS=(); SETUPS=()
if command -v python3 >/dev/null 2>&1; then
  mapfile -t CANDS < <(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import wq_core as c
print("\n".join(c.find_exes(c.Path(sys.argv[2]), "native")))' "$QROOT/wq-ui" "$GAMEDIR" 2>/dev/null || true)
  mapfile -t SETUPS < <(python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import wq_core as c
print("\n".join(c.find_setups(c.Path(sys.argv[2]), "native")))' "$QROOT/wq-ui" "$GAMEDIR" 2>/dev/null || true)
fi
if [ "${#CANDS[@]}" -eq 0 ] || [ -z "${CANDS[0]:-}" ]; then
  # no python (or it found nothing): plain find, shallowest first
  CANDS=()
  while IFS= read -r -d '' c; do CANDS+=("${c#"$GAMEDIR/game/"}"); done < <(
    find "$GAMEDIR/game" -maxdepth 3 -type f \
      \( -iname '*.sh' -o -iname '*.appimage' -o -iname '*.x86_64' -o -iname '*.x86' -o -iname '*.run' -o -iname '*.bin' \) \
      -not -iname 'unins*' -not -iname 'uninstall*' -not -iname 'install*' -printf '%d\t%p\0' 2>/dev/null \
      | sort -z -t $'\t' -k1,1n -k2,2 | sed -z 's/^[0-9]*\t//')
fi
[ -n "${SETUPS[0]:-}" ] || SETUPS=()

PICK=""
for pref in start.sh run.sh launch.sh play.sh; do
  for c in "${CANDS[@]}"; do
    [ "$(basename "${c,,}")" = "$pref" ] && { PICK="$c"; break 2; }
  done
done
[ -z "$PICK" ] && [ "${#CANDS[@]}" -ge 1 ] && PICK="${CANDS[0]}"
if [ -n "$PICK" ]; then PICK="$GAMEDIR/game/$PICK"; fi

if [ -n "$PICK" ]; then
  EXE="${PICK#"$GAMEDIR/game/"}"
  echo "Found: $EXE   (${#CANDS[@]} candidate(s); change it later with Add > Set executable)"
else
  EXE="CHANGE_ME.sh"
  if [ "${#SETUPS[@]}" -ge 1 ]; then
    echo "Found an installer (${SETUPS[0]}), no start file yet: run it with Add > Run setup file, then pick the installed program with Add > Set executable."
  else
    echo "Nothing found - set the start script later with Add > Set executable."
  fi
fi
case "$EXE" in ""|/*|..|../*|*/..|*/../*|*$'\n'*|*$'\r'*) echo "Error: unsafe path" >&2; exit 1 ;; esac

printf '# start script / binary, relative to game/\nEXE=%s\nRUNNER=native\n' "$EXE" > "$GAMEDIR/game.conf"

wq_launcher_text native > "$GAMEDIR/launch-quarantine.sh"
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
echo "Start:     $EXE"
echo "Launcher:  $GAMEDIR/launch-quarantine.sh"
