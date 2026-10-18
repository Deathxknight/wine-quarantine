#!/bin/bash
# update-launchers.sh - bring every game's launch-quarantine.sh up to date.
#
# A launcher is a three-line wrapper around _launch-core.sh (Windows games) or
# wq-ui/_launch-native.sh (native games, RUNNER=native in game.conf). All the logic lives in
# those scripts, so this only matters for games made by an older version, which got a
# big self-contained launcher, and for a launcher that went missing.
#
# Usage:
#   ./update-launchers.sh                  dry-run, all games
#   ./update-launchers.sh --apply          write changes
#   ./update-launchers.sh <GameName>       one game, dry-run
#   ./update-launchers.sh --apply <Game>   one game, apply
#
# An old launcher is kept as launch-quarantine.sh.bak. A game that predates game.conf gets one,
# with EXE= taken from its old launcher.

set -euo pipefail

QROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
# shellcheck source=config.sh
. "$QROOT/config.sh"

APPLY=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    --apply|-a) APPLY=1 ;;
    -h|--help)  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)         echo "Unknown flag: $arg" >&2; exit 1 ;;
    *)          TARGET="${arg%/}" ;;
  esac
done

# value of KEY="..." in an old self-contained launcher
extract_quoted() {
  local file="$1" key="$2"
  [ -f "$file" ] || return 1
  grep -m1 -E "^${key}=\"" "$file" 2>/dev/null | sed -E "s/^${key}=\"(.*)\"\$/\\1/"
}

# EXE for game.conf, recovered from an old launcher (EXEDIR is absolute, EXE_REL_PATH is ./name)
legacy_exe() {
  local gamedir="$1" launcher="$1/launch-quarantine.sh" dir name rel
  dir="$(extract_quoted "$launcher" EXEDIR || true)"
  name="$(extract_quoted "$launcher" EXE_REL_PATH || true)"
  [ -n "$dir" ] && [ -n "$name" ] || return 1
  rel="${dir#"$gamedir/game"}"; rel="${rel#/}"
  name="${name#./}"
  [ "$dir" = "${dir#"$gamedir/game"}" ] && return 1     # not under game/
  printf '%s' "${rel:+$rel/}$name"
}

update_one() {
  local gamedir="$1" name runner launcher want tmp
  name="$(basename "$gamedir")"
  launcher="$gamedir/launch-quarantine.sh"

  runner=windows
  [ "$(read_game_conf "$gamedir" RUNNER 2>/dev/null || true)" = native ] && runner=native
  want="$(wq_launcher_text "$runner")"

  # a game from before game.conf: keep its exe choice
  local note=""
  if ! read_game_conf "$gamedir" EXE >/dev/null 2>&1; then
    local exe
    if exe="$(legacy_exe "$gamedir")" && valid_exe_rel "$exe"; then
      note="game.conf would get EXE=$exe"
      if [ "$APPLY" -eq 1 ]; then
        { [ -f "$gamedir/game.conf" ] && cat "$gamedir/game.conf"; printf 'EXE=%s\n' "$exe"; } > "$gamedir/game.conf.new"
        mv "$gamedir/game.conf.new" "$gamedir/game.conf"
        note="game.conf written with EXE=$exe"
      fi
    else
      note="no EXE= in game.conf and none recoverable: set it in the app (Add > Set executable)"
    fi
  fi

  if [ -f "$launcher" ] && [ "$(cat "$launcher")" = "$want" ]; then
    printf '  %-24s up to date (%s)%s\n' "$name" "$runner" "${note:+  - $note}"
    return 0
  fi

  if [ -f "$launcher" ]; then
    printf '  %-24s REPLACE (%s), old launcher kept as launch-quarantine.sh.bak%s\n' "$name" "$runner" "${note:+  - $note}"
  else
    printf '  %-24s CREATE (%s)%s\n' "$name" "$runner" "${note:+  - $note}"
  fi

  if [ "$APPLY" -eq 1 ]; then
    [ -f "$launcher" ] && cp -p "$launcher" "$launcher.bak"
    tmp="$(mktemp "$gamedir/.launcher.XXXXXX")"
    printf '%s\n' "$want" > "$tmp"
    chmod +x "$tmp"
    mv -f "$tmp" "$launcher"
  fi
}

echo "Mode: $([ "$APPLY" -eq 1 ] && echo APPLY || echo DRY-RUN)"
echo

if [ -n "$TARGET" ]; then
  case "$TARGET" in ""|*/*|.|..) echo "Error: invalid game name '$TARGET'" >&2; exit 1 ;; esac
  [ -d "$QROOT/$TARGET/game" ] || { echo "Error: no such game: $QROOT/$TARGET" >&2; exit 1; }
  update_one "$(readlink -f "$QROOT/$TARGET")"
else
  n=0
  for d in "$QROOT"/*/; do
    g="${d%/}"
    case "$(basename "$g")" in _*|.*|wq-ui) continue ;; esac
    [ -d "$g/game" ] || continue
    update_one "$(readlink -f "$g")" || true
    n=$((n+1))
  done
  echo
  echo "Checked $n game(s)."
fi

[ "$APPLY" -eq 0 ] && { echo; echo "Dry-run only. Use --apply to write."; }
exit 0
