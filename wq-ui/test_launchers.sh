#!/bin/bash
# Tests for the launcher flow: exit codes reach the verdict, Stop still produces a verdict,
# alert counting, update-launchers.sh, term_run. firejail and inotifywait are stubs.
#   bash wq-ui/test_launchers.sh
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 400 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected /$2/ in: $(head -c 400 <<< "$3")" || ok; }

Q="$T/q"; mkdir -p "$Q"; cp -a "$SRC"/. "$Q"/; rm -rf "$Q/.git"
# the stub jail enforces nothing, so the in-jail verifier is off except in the test that wants it
printf 'CLAM_SCAN_ON_ADD=0\nCLAM_SCAN_AFTER_RUN=0\nNATIVE_VERIFY="${NATIVE_VERIFY:-0}"\n' > "$Q/config.local.sh"

# ---- stubs: firejail runs whatever follows "--"; inotifywait just idles
BIN="$T/bin"; mkdir -p "$BIN"
cat > "$BIN/firejail" <<'S'
#!/bin/bash
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done; shift
exec "$@"
S
printf '#!/bin/bash\nexec sleep 300\n' > "$BIN/inotifywait"
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"
QROOT="$Q"; # shellcheck source=/dev/null
. "$Q/config.sh"

mkgame() {   # mkgame <name> <start.sh body>
  local g="$Q/$1"; mkdir -p "$g/game" "$g/logs" "$g/home"
  printf 'EXE=start.sh\nRUNNER=native\nFJ_RESTRICT_NS=0\n' > "$g/game.conf"
  printf '#!/bin/bash\n%s\n' "$2" > "$g/game/start.sh"
  wq_launcher_text native > "$g/launch-quarantine.sh"
  chmod +x "$g/launch-quarantine.sh"
}

echo "== summarize-run.sh"
S="$Q/summarize-run.sh"
G="$T/sg"; mkdir -p "$G/logs"; A="$G/alerts.log"
sum() { WQ_FORCE_COLOR=1 bash "$S" "$G" "$A" "${1:-0}" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }

: > "$A"; rm -f "$G"/logs/launch-*.log
has "clean run" 'VERDICT: CLEAN' "$(sum 0)"

printf '[2026-10-18 09:06:40] [ALERT] ClamAV: home/eicar-test.com: Eicar-Signature\n[2026-10-18 09:06:40] [ALERT] ClamAV flagged 1 of 4 scanned file(s) in g. Treat this game as hostile [output: c.log]\n' > "$A"
has "one detection counts once (not 2)" 'REVIEW NEEDED.* 1 alert' "$(sum 0)"

printf '[t] [ALERT] Suspicious process running: pid=1 cmd=curl\n[2026-10-18 09:00:00] [ALERT] Kill switch triggered - terminating sandbox.\n' > "$A"
has "kill switch line is not a second alert" 'REVIEW NEEDED.* 1 alert' "$(sum 143)"

printf '[t] [ALERT] A\n[t] [ALERT] B\n' > "$A"
has "two real alerts count as two" 'REVIEW NEEDED.* 2 alert' "$(sum 0)"

: > "$A"
printf '[SANDBOX-VERIFY] FAIL: Seccomp=0 (no filter)\n[SANDBOX-VERIFY] ABORT: sandbox not enforced\n' > "$G/logs/launch-20261018-000000.log"
out="$(sum 90)"
has "failed verify with exit 90 is LAUNCH BLOCKED, not CLEAN" 'VERDICT: LAUNCH BLOCKED' "$out"
has "the failing check is shown" 'Seccomp=0' "$out"
hasnt "never CLEAN when the game did not run" 'VERDICT: CLEAN' "$out"
has "exit 90 without the marker is just a game exit code" 'VERDICT: CLEAN' "$(rm "$G"/logs/launch-*.log; sum 90)"
echo 'wq: aborting launch' > "$G/logs/launch-20261018-000001.log"
has "native preflight abort (97)" 'LAUNCH BLOCKED' "$(sum 97)"
rm -f "$G"/logs/launch-*.log
has "non-numeric exit code does not crash" 'VERDICT' "$(sum abc)"

echo "== native launcher: normal run, exit code reaches the summary"
mkgame ok 'echo hello-from-game; exit 3'
out="$(cd "$Q/ok" && timeout 60 ./launch-quarantine.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"; rc=$?
has "game ran" 'hello-from-game' "$out"
has "exit code reported" 'game exited with code 3' "$out"
has "summary printed" 'Quarantine Run Summary' "$out"

echo "== native launcher: Stop (SIGTERM to the whole group) still ends with a verdict"
mkgame stopme 'echo started; while :; do sleep 1; done'
L="$T/stop.out"; : > "$L"
setsid bash -c "cd '$Q/stopme' && exec ./launch-quarantine.sh" > "$L" 2>&1 &
LP=$!
for _ in $(seq 1 100); do grep -q '^started' "$L" 2>/dev/null && break; sleep 0.1; done
has "game is running before Stop" '^started' "$(cat "$L")"
PG="$(ps -o pgid= -p "$LP" | tr -d ' ')"
kill -TERM -- "-$PG" 2>/dev/null
for _ in $(seq 1 150); do kill -0 "$LP" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$LP" 2>/dev/null; then fail "launcher exits after Stop"; kill -KILL -- "-$PG" 2>/dev/null; else ok; fi
out="$(sed 's/\x1b\[[0-9;]*m//g' "$L")"
has "verdict printed after Stop" 'VERDICT' "$out"
has "game exit code recorded after Stop" 'game exited with code' "$out"
alerts="$(cat "$Q"/stopme/logs/alerts-*.log 2>/dev/null)"
has "monitor still flushed its final line" 'Game process ended' "$alerts"
sleep 1
left="$(pgrep -f "$Q/stopme" | wc -l)"; eq "no leftover processes from the stopped game" 0 "$left"

echo "== native launcher: the in-jail verifier blocks a launch (stub jail hides nothing)"
mkgame leaky 'echo SHOULD-NOT-RUN'
out="$(cd "$Q/leaky" && NATIVE_VERIFY=1 timeout 60 ./launch-quarantine.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')"
hasnt "the game never ran" 'SHOULD-NOT-RUN' "$out"
has "verifier output reaches the log" 'SANDBOX-VERIFY\] (ok|FAIL)' "$out"
has "game.conf visible is caught" 'game.conf is visible inside the sandbox' "$out"
has "game exit code 90 reported" 'game exited with code 90' "$out"
has "verdict is LAUNCH BLOCKED, not CLEAN" 'VERDICT: LAUNCH BLOCKED' "$out"
hasnt "never CLEAN" 'VERDICT: CLEAN' "$out"

echo "== term_run / find_proton"
for t in foot alacritty gnome-terminal xfce4-terminal kitty konsole; do
  printf '#!/bin/bash\necho "$(basename $0) $*"\n' > "$BIN/$t"; chmod +x "$BIN/$t"; done
has "foot uses --app-id" 'foot --title T --app-id c x' "$(term_run foot T c x)"
has "alacritty needs -e" 'alacritty --title T --class c -e x' "$(term_run alacritty T c x)"
has "gnome-terminal needs --" 'gnome-terminal --title=T -- x' "$(term_run gnome-terminal T c x)"
has "xfce4-terminal needs -x" 'xfce4-terminal --title T -x x' "$(term_run xfce4-terminal T c x)"
PD="$T/pr"; mkdir -p "$PD/GE-Proton10-9" "$PD/GE-Proton10-10"
touch "$PD/GE-Proton10-9/toolmanifest.vdf" "$PD/GE-Proton10-10/toolmanifest.vdf"
PROTON_SEARCH_DIRS=("$PD"); PROTON_PREFERRED=""
eq "newest Proton, not first alphabetically" GE-Proton10-10 "$(basename "$(find_proton '')")"

echo "== update-launchers.sh"
mkdir -p "$Q/legacy/game/bin"
printf '#!/bin/bash\nEXE_REL_PATH="./G.exe"\nEXEDIR="%s/legacy/game/bin"\n' "$Q" > "$Q/legacy/launch-quarantine.sh"
out="$(cd "$Q" && ./update-launchers.sh 2>&1)"
has "dry run changes nothing" 'Dry-run only' "$out"; has "legacy launcher flagged" 'legacy .*REPLACE' "$out"
grep -q 'EXE_REL_PATH' "$Q/legacy/launch-quarantine.sh" && ok || fail "dry run left the file alone"
out="$(cd "$Q" && ./update-launchers.sh --apply 2>&1)"
eq "game.conf recovered from legacy launcher" "EXE=bin/G.exe" "$(cat "$Q/legacy/game.conf")"
ls "$Q/legacy/launch-quarantine.sh.bak" >/dev/null 2>&1 && ok || fail "old launcher backed up"
has "native game keeps native launcher" '_launch-native.sh' "$(cat "$Q/ok/launch-quarantine.sh")"
out="$(cd "$Q" && ./update-launchers.sh 2>&1)"; hasnt "second run changes nothing" 'REPLACE|CREATE' "$out"

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
