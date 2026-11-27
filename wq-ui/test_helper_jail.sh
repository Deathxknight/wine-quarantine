#!/bin/bash
# Tests for the hardened helper jail (lib-firejail.sh), the jailed archive extraction (lib-extract.sh)
# and the new game-jail flags in profile.sh (FJ_IPC_NS, FJ_PROTOCOL).
#
# A stub firejail stands in for the real one: it records the options it was given, can be told to
# refuse one of them, and then runs the command after "--". So this checks the arguments and the
# plumbing (what is writable, what happens when the jail is unavailable, that every extractor goes
# through it). It does NOT prove that firejail isolates anything; ./wq-ui/probe.sh and the verifier
# (verify-sandbox.sh) check that on a real jail.
#   bash wq-ui/test_helper_jail.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
has()  { grep -qF -- "$2" <<<"$3" && ok || fail "$1" "missing [$2] in: $(head -c 300 <<<"$3")"; }
hasnt(){ grep -qF -- "$2" <<<"$3" && fail "$1" "unexpected [$2]" || ok; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }

# --- stub firejail -------------------------------------------------------------------------------
BIN="$T/bin"; mkdir -p "$BIN"
cat > "$BIN/firejail" <<'EOS'
#!/bin/bash
# stub: log options, refuse $FJ_STUB_REFUSE, optionally fail writes, run what follows "--"
opts=()
while [ $# -gt 0 ]; do
  [ "$1" = "--" ] && { shift; break; }
  opts+=("$1"); shift
done
printf '%s\n' "${opts[*]}" >> "$FJ_STUB_LOG"
if [ -n "${FJ_STUB_REFUSE:-}" ]; then
  for o in "${opts[@]}"; do
    case "$o" in $FJ_STUB_REFUSE) echo "Error: invalid option $o" >&2; exit 1 ;; esac
  done
fi
if [ "${FJ_STUB_NOWRITE:-0}" = 1 ] && [ "${1:-}" = sh ]; then exit 1; fi
exec "$@"
EOS
chmod +x "$BIN/firejail"
export FJ_STUB_LOG="$T/fj.log"; : > "$FJ_STUB_LOG"
export PATH="$BIN:$PATH"

QROOT="$T/Q"; mkdir -p "$QROOT/Game/game"
export QROOT HOME="$T/home"; mkdir -p "$HOME"

# shellcheck source=/dev/null
. "$SRC/lib-firejail.sh"

echo "== helper jail arguments"
wq_helper_jail --ro "$QROOT/Game"; rc=$?
a=" ${WQ_HJAIL[*]} "
eq "builds" 0 "$rc"
for f in --net=none --nonewprivs --caps.drop=all --nodbus --seccomp --nogroups --restrict-namespaces \
         --ipc-namespace --protocol=unix,inet,inet6,netlink --private-dev --private-tmp \
         "--read-only=$HOME" "--read-only=$(readlink -f "$QROOT")" "--read-only=$(readlink -f "$QROOT/Game")"; do
  has "jail has $f" " $f " "$a"
done
hasnt "no write access added without --rw" "--read-write" "$a"

echo "== --rw opens only that path, and comes after every --read-only"
wq_helper_jail --rw "$QROOT/Game/game"; rc=$?
eq "builds with --rw" 0 "$rc"
last_ro=-1; rw_at=-1
for i in "${!WQ_HJAIL[@]}"; do
  case "${WQ_HJAIL[$i]}" in --read-only=*) last_ro=$i ;; --read-write=*) rw_at=$i ;; esac
done
[ "$rw_at" -gt "$last_ro" ] && ok || fail "--read-write must come last (rw=$rw_at last ro=$last_ro)"
eq "exactly one --read-write" 1 "$(printf '%s\n' "${WQ_HJAIL[@]}" | grep -c '^--read-write=')"
has "the rw path is the game folder" "--read-write=$(readlink -f "$QROOT/Game/game")" " ${WQ_HJAIL[*]} "

echo "== input file in /tmp"
wq_helper_jail --host-tmp-ro >/dev/null 2>&1
a=" ${WQ_HJAIL[*]} "
has "host /tmp is read-only" " --read-only=/tmp " "$a"
hasnt "no private /tmp then" "--private-tmp" "$a"

echo "== a firejail that refuses an option"
export FJ_STUB_REFUSE='--ipc-namespace'
wq_helper_jail >/dev/null 2>"$T/fb.err"; rc=$?; err="$(cat "$T/fb.err")"   # not in $(...): WQ_HJAIL must reach this shell
eq "falls back (rc 0)" 0 "$rc"
has "says so" "hardened helper jail not usable" "$err"
a=" ${WQ_HJAIL[*]} "
has "fallback is the old plain jail" " --net=none " "$a"
hasnt "fallback has no --ipc-namespace" "--ipc-namespace" "$a"
WQ_HELPER_JAIL_STRICT=1 wq_helper_jail >/dev/null 2>&1; rc=$?
eq "strict mode refuses (rc 1)" 1 "$rc"
eq "strict mode leaves no jail array behind" 0 "${#WQ_HJAIL[@]}"
unset FJ_STUB_REFUSE

echo "== a --rw path the jail cannot write to"
mkdir -p "$T/rwtest"
FJ_STUB_NOWRITE=1 wq_helper_jail --rw "$T/rwtest" >/dev/null 2>&1; rc=$?
eq "fails closed (rc 1) when the write probe fails" 1 "$rc"

echo "== no firejail at all"
( PATH="/usr/bin:/bin"; command -v firejail >/dev/null 2>&1 && exit 9
  wq_helper_jail >/dev/null 2>&1; echo "rc=$?" ) > "$T/nofj.out" 2>&1
if grep -q '^rc=1$' "$T/nofj.out"; then ok; elif [ "$(cat "$T/nofj.out")" = "" ]; then ok   # a real firejail is installed here
else fail "no firejail: rc 1" "$(cat "$T/nofj.out")"; fi

echo "== extraction goes through the jail"
. "$SRC/lib-extract.sh"
command -v zip >/dev/null 2>&1 || python3 - "$T" <<'PY'
import sys, zipfile, os
t = sys.argv[1]
with zipfile.ZipFile(os.path.join(t, "g.zip"), "w") as z:
    z.writestr("game/run.exe", "MZ")
    z.writestr("game/readme.txt", "hi")
PY
[ -f "$T/g.zip" ] || (cd "$T" && mkdir -p zsrc/game && echo MZ > zsrc/game/run.exe && echo hi > zsrc/game/readme.txt && zip -qr g.zip zsrc/game)
mkdir -p "$T/dest1"; : > "$FJ_STUB_LOG"
wq_extract_zip "$T/g.zip" "$T/dest1" >/dev/null 2>&1; rc=$?
eq "zip unpacks" 0 "$rc"
[ -n "$(find "$T/dest1" -name run.exe 2>/dev/null)" ] && ok || fail "run.exe was not extracted"
log="$(cat "$FJ_STUB_LOG")"
has "extraction ran under firejail" "--net=none" "$log"
has "with only the destination writable" "--read-write=$(readlink -f "$T/dest1")" "$log"
has "with a time limit" "--timeout=" "$log"

echo "== input under /tmp is still readable (host /tmp read-only instead of a private one)"
: > "$FJ_STUB_LOG"; mkdir -p "$T/dest1b"
wq_extract_zip "$T/g.zip" "$T/dest1b" >/dev/null 2>&1
case "$(readlink -f "$T/g.zip")" in
  /tmp/*|/var/tmp/*) has "uses host /tmp read-only" "--read-only=/tmp" "$(cat "$FJ_STUB_LOG")" ;;
  *) ok ;;
esac

echo "== tar through the jail"
mkdir -p "$T/tsrc" "$T/dest2"; echo x > "$T/tsrc/a.sh"; tar -cf "$T/g.tar" -C "$T/tsrc" .
: > "$FJ_STUB_LOG"
wq_xrun "$T/dest2" tar -xf "$T/g.tar" --no-same-owner -C "$T/dest2" >/dev/null 2>&1; rc=$?
eq "tar unpacks" 0 "$rc"
[ -f "$T/dest2/a.sh" ] && ok || fail "a.sh not extracted"
has "tar ran under firejail" "--read-write=$(readlink -f "$T/dest2")" "$(cat "$FJ_STUB_LOG")"

echo "== jail unavailable: nothing is unpacked, unless the user opts out"
mkdir -p "$T/dest3"
FJ_STUB_REFUSE='--net=none' wq_xrun "$T/dest3" tar -xf "$T/g.tar" -C "$T/dest3" >/dev/null 2>&1; rc=$?
eq "refuses (rc 97)" 97 "$rc"
[ ! -e "$T/dest3/a.sh" ] && ok || fail "extraction happened without a jail"
mkdir -p "$T/dest4"
WQ_EXTRACT_SANDBOX=0 FJ_STUB_REFUSE='--net=none' wq_xrun "$T/dest4" tar -xf "$T/g.tar" -C "$T/dest4" >"$T/o4" 2>&1
[ -f "$T/dest4/a.sh" ] && ok || fail "WQ_EXTRACT_SANDBOX=0 did not unpack"
has "and it warns" "without a sandbox" "$(cat "$T/o4")"

echo "== setuid bits are stripped"
mkdir -p "$T/dest5"; echo x > "$T/dest5/s"; chmod 4755 "$T/dest5/s"
wq_sanitize_extracted "$T/dest5" 2>/dev/null
[ ! -u "$T/dest5/s" ] && ok || fail "setuid bit survived"

echo "== no call site still unpacks on the host"
for f in new-quarantine.sh wq-ui/new-native.sh lib-extract.sh; do
  bad="$(grep -nE '^[^#]*[^_a-z](unrar x|tar -x[zJj]?f|"\$SEVENZ" x|"\$sevenz" x|bsdtar -xf|unzip -qq)' "$SRC/$f" | grep -v 'wq_xrun' || true)"
  [ -z "$bad" ] && ok || fail "$f unpacks outside the jail" "$bad"
done

echo "== game jail: new flags"
mkdir -p "$T/G/game"
run() {
  printf '%s\n' "$@" > "$T/G/game.conf"
  bash -c '
    set -euo pipefail
    QROOT="$1"; SECCOMP_DROP=keyctl
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
    . "$2/profile.sh"
    apply_game_profile "$1/G"
    printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
    printf "SKIP %s\n" "$QVERIFY_SKIP"
  ' _ "$T" "$HERE" 2>"$T/err"
}
out="$(run EXE=a.exe)"
has "ipc namespace is on by default" "ARG --ipc-namespace" "$out"
has "socket families are limited by default" "ARG --protocol=unix,inet,inet6,netlink" "$out"
out="$(run EXE=a.exe FJ_IPC_NS=0 FJ_PROTOCOL=0)"
hasnt "FJ_IPC_NS=0 turns it off" "--ipc-namespace" "$out"
hasnt "FJ_PROTOCOL=0 turns it off" "--protocol" "$out"
has "and the verifier is told" "SKIP" "$out"
sk="$(grep '^SKIP' <<<"$out")"
has "ipc check skipped" "ipc" "$sk"
has "protocol check skipped" "protocol" "$sk"
out="$(run EXE=a.exe)"
hasnt "memfd_create is allowed by default" "memfd_create" "$out"
has "and the verifier skips the memfd check" "memfd" "$(grep '^SKIP' <<<"$out")"
out="$(run EXE=a.exe FJ_MEMFD=1)"
has "FJ_MEMFD=1 adds memfd_create to the seccomp drop list" "ARG --seccomp.drop=keyctl,memfd_create" "$out"
hasnt "and the verifier no longer skips it" "memfd" "$(grep '^SKIP' <<<"$out")"
out="$(run EXE=a.exe FJ_MEMFD=1 FJ_SECCOMP=0)"
hasnt "FJ_MEMFD without the seccomp filter adds nothing" "memfd_create" "$out"
has "and the memfd check is skipped" "memfd" "$(grep '^SKIP' <<<"$out")"
out="$(run EXE=a.exe)"
hasnt "write+execute denial is off by default" "memory-deny-write-execute" "$out"
has "and the verifier skips the mdwx check" "mdwx" "$(grep '^SKIP' <<<"$out")"
out="$(run EXE=a.exe FJ_MDWX=1)"
has "FJ_MDWX=1 adds --memory-deny-write-execute" "ARG --memory-deny-write-execute" "$out"
hasnt "and the verifier no longer skips it" "mdwx" "$(grep '^SKIP' <<<"$out")"
[ "$(grep -c -- 'memory-deny-write-execute' <<<"$out")" = 1 ] && ok || fail "the flag appears once"
out="$(run EXE=a.exe FJ_MDWX=1 FJ_SECCOMP=0)"
has "FJ_MDWX does not depend on the seccomp.drop filter" "ARG --memory-deny-write-execute" "$out"
out="$(run EXE=a.exe FJ_MDWX=0)"
hasnt "FJ_MDWX=0 leaves it out" "memory-deny-write-execute" "$out"
out="$(run EXE=a.exe FJ_EXTRA_ARGS=--protocol=packet)"; hasnt "FJ_EXTRA_ARGS cannot widen the socket families" "--protocol=packet" "$out"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
