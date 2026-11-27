#!/bin/bash
# new-native.sh picks the start file the same way the app's Set executable list does, and notices installers.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cp -r "$HERE/.." "$T/q"; mkdir "$T/bin"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/firejail"; chmod +x "$T/bin/firejail"
export PATH="$T/bin:$PATH" WQ_SKIP_SCAN=1 WQ_XRAY_BASELINE=0
fail=0
check() { # name want
  got="$(grep '^EXE=' "$T/q/$1/game.conf" | cut -d= -f2-)"
  [ "$got" = "$2" ] && echo "ok   $1 -> $got" || { echo "FAIL $1: want '$2' got '$got'"; fail=1; }
}
mkdir -p "$T/s1/tools" "$T/s1/bin"
printf '#!/bin/sh\n' > "$T/s1/tools/aaa.sh"; printf '#!/bin/sh\n' > "$T/s1/start.sh"; printf '#!/bin/sh\n' > "$T/s1/install.sh"
cp /bin/true "$T/s1/bin/Game"
mkdir -p "$T/s2/a/b"; printf '#!/bin/sh\n' > "$T/s2/a/b/deep.sh"; printf '#!/bin/sh\n' > "$T/s2/top_game.sh"
printf '#!/bin/sh\necho hi\n' > "$T/install.sh"
cp /bin/true "$T/mygame"
( cd "$T/q/wq-ui" || exit 1
  bash new-native.sh Folder "$T/s1" >/dev/null 2>&1
  bash new-native.sh Shallow "$T/s2" >/dev/null 2>&1
  bash new-native.sh OnlySetup "$T/install.sh" > "$T/setup.out" 2>&1
  bash new-native.sh Binary "$T/mygame" >/dev/null 2>&1 )
check Folder start.sh
check Shallow top_game.sh          # shallowest wins, not alphabetical path order
check OnlySetup CHANGE_ME.sh       # an installer is never made the game
grep -q "Run setup file" "$T/setup.out" && echo "ok   installer hint printed" || { echo "FAIL no installer hint"; fail=1; }
check Binary mygame                # an extensionless ELF is found
exit $fail
