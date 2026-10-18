#!/bin/bash
# verify-sandbox.sh: the mount-propagation parser, native mode, the self-hash, and the
# WQ_VERIFY_SKIP_EXTRA escape hatch. Runs on the host (no firejail), so the checks that need a real
# jail are switched off through QVERIFY_SKIP the same way a profile would.
#   bash wq-ui/test_verify.sh
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 500 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected /$2/ in: $(head -c 500 <<< "$3")" || ok; }

Q="$T/q"; mkdir -p "$Q"; cp -a "$SRC"/. "$Q"/; rm -rf "$Q/.git"

echo "== shipped hash matches the script"
eq "verify-sandbox.sha256 is current" "$(sha256sum "$SRC/verify-sandbox.sh" | cut -d' ' -f1)" "$(tr -d '[:space:]' < "$SRC/verify-sandbox.sha256")"

echo "== mountinfo parser"
# the function itself, lifted from the script
eval "$(sed -n '/^shared_mounts() {/,/^}/p' "$SRC/verify-sandbox.sh")"
sm() { printf '%s\n' "$1" | shared_mounts; }
eq "no optional fields"                  ""      "$(sm '36 35 98:0 /mnt1 /mnt2 rw,noatime - ext3 /dev/root rw')"
eq "slave (master:N) is what firejail sets up" "" "$(sm '36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw')"
eq "shared is flagged, by mount point"   "/mnt2" "$(sm '36 35 98:0 /mnt1 /mnt2 rw,noatime shared:7 - ext3 /dev/root rw')"
eq "shared + master"                     "/x"    "$(sm '36 35 98:0 / /x rw shared:7 master:3 - tmpfs t rw')"
eq "master then shared"                  "/x"    "$(sm '36 35 98:0 / /x rw master:3 shared:7 - tmpfs t rw')"
eq "propagate_from / unbindable are fine" ""     "$(sm '36 35 98:0 / /x rw master:3 propagate_from:2 unbindable - tmpfs t rw')"
eq "escaped space in the mount point"    '/a\040b' "$(sm '36 35 98:0 / /a\040b rw shared:1 - tmpfs t rw')"
eq "'shared' in the SOURCE is not a mount flag" "" "$(sm '36 35 98:0 / /x rw - tmpfs shared:9 rw')"
eq "garbage lines are ignored"           ""      "$(sm 'nonsense')"
multi="$(printf '%s\n' '1 0 0:1 / / rw master:1 - ext4 /dev/a rw' '2 1 0:2 / /a rw shared:5 - tmpfs t rw' '3 1 0:3 / /b rw - tmpfs t rw' '4 1 0:4 / /c rw shared:6 - tmpfs t rw' | shared_mounts | tr '\n' ' ')"
eq "several lines" "/a /c " "$multi"

echo "== native mode (checks that need a real jail are skipped, as a profile would)"
G="$T/game1"; mkdir -p "$G/game"
SKIP="caps,nnp,seccomp,sockets"
run() { ( cd "$T" && env "$@" bash "$Q/verify-sandbox.sh" 2>&1; echo "rc=$?" ); }
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered)"
has "native mode passes with only game/ present" 'rc=0$' "$out"
has "reports the native home note" 'native mode: .*HOME' "$out"
hasnt "does not ask for prefix/" 'prefix' "$out"
hasnt "does not ask for UMU_DATA" 'UMU_DATA' "$out"
has "mount propagation was checked" 'no shared mounts visible' "$out"

touch "$G/game.conf"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered)"
has "game.conf visible in the jail fails (exit 90)" 'rc=90$' "$out"; has "says which" 'game.conf is visible' "$out"
rm "$G/game.conf"; mkdir "$G/home"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered)"
has "the private home path visible fails" 'home is visible' "$out"; rmdir "$G/home"
mkdir "$G/.home-snapshot"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered)"
has "snapshot dir visible fails" '\.home-snapshot is visible' "$out"; rmdir "$G/.home-snapshot"

out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="caps,nnp,sockets" QVERIFY_NET=filtered)"
has "a missing seccomp filter fails without the profile opt-out" 'rc=90$' "$out"
rm -rf "$G/game"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered)"
has "game/ missing fails" 'game/ not visible' "$out"; mkdir "$G/game"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered SSH_AUTH_SOCK=/x)"
has "ssh agent in the environment fails" 'SSH_AUTH_SOCK=/x' "$out"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP" QVERIFY_NET=filtered DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus)"
has "real session bus in the environment fails" 'reaches real bus' "$out"

echo "== windows mode is unchanged"
out="$(run QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP")"
has "still requires UMU_DATA" 'QVERIFY_UMU_DATA' "$out"
mkdir -p "$G/prefix" "$T/umu"
out="$(run QVERIFY_GAMEDIR="$G" QVERIFY_UMU_DATA="$T/umu" QVERIFY_HOST_USER=u QVERIFY_SKIP="$SKIP,home" QVERIFY_NET=filtered)"
has "windows mode checks prefix/ and UMU_DATA" 'prefix/ visible' "$out"; has "and UMU_DATA" 'UMU_DATA visible' "$out"

echo "== self-hash"
cp "$Q/verify-sandbox.sh" "$Q/verify-sandbox.sh.good"; echo '# tampered' >> "$Q/verify-sandbox.sh"
out="$(run QVERIFY_MODE=native QVERIFY_GAMEDIR="$G" QVERIFY_SKIP="$SKIP")"
has "an edited verifier is refused (exit 91)" 'rc=91$' "$out"; mv "$Q/verify-sandbox.sh.good" "$Q/verify-sandbox.sh"

echo "== WQ_VERIFY_SKIP_EXTRA reaches QVERIFY_SKIP"
printf 'FJ_SECCOMP=0\n' > "$T/g.conf"
sk() {   # sk [extra tokens]: QVERIFY_SKIP as apply_game_profile computes it for a game with FJ_SECCOMP=0
  ( cd "$Q" && QROOT="$Q" . ./config.sh >/dev/null 2>&1; mkdir -p "$T/gx"; cp "$T/g.conf" "$T/gx/game.conf"
    [ $# -gt 0 ] && WQ_VERIFY_SKIP_EXTRA="$1"
    WQ_RUNNER=native WQ_LIMITS_SUPPORTED=1; apply_game_profile "$T/gx" >/dev/null 2>&1; echo "${QVERIFY_SKIP:-UNSET}" )
}
sk0="$(sk)"; has "profile opt-outs are still there" 'seccomp' "$sk0"; hasnt "nothing extra by default" 'propagation' "$sk0"
sk1="$(sk propagation)"
has "extra token is appended" 'seccomp.*propagation|propagation.*seccomp' "$sk1"; hasnt "no stray leading/trailing comma" '^,|,$|,,' "$sk1"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
