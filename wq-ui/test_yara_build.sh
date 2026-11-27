#!/bin/bash
# Tests wq-yara-build.sh selection and reporting with a stub yarac. The real yarac is not needed:
# the stub fails on files containing BROKEN (per-file) and on a DUPE rule across files (combined).
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok()  { echo "ok   - $1"; pass=$((pass+1)); }
bad() { echo "FAIL - $1"; fail=$((fail+1)); }

cat > "$T/yarac" << 'STUB'
#!/bin/bash
# last arg is the output file; the rest are inputs
out="${@: -1}"; ins=(); for a in "${@:1:$#-1}"; do case "$a" in -d|*=*) ;; *) ins+=("$a") ;; esac; done
[ "${#ins[@]}" -ge 1 ] || exit 1
for f in "${ins[@]}"; do
  if grep -q BROKEN "$f" 2>/dev/null; then echo "$f(3): error: syntax error, unexpected end of file"; exit 1; fi
done
if [ "${#ins[@]}" -gt 1 ] && grep -q DUPE "${ins[@]}" 2>/dev/null; then echo "error: duplicated rule identifier"; exit 1; fi
: > "$out"
STUB
chmod +x "$T/yarac"

R="$T/src"; mkdir -p "$R/signature-base/yara" "$R/rules/malware" "$R/rules/webshells"
echo 'rule good1 { condition: true }' > "$R/signature-base/yara/good1.yar"
echo 'rule bad { BROKEN' > "$R/signature-base/yara/broken.yar"
echo 'rule good2 { condition: true }' > "$R/rules/malware/good2.yar"
echo 'rule shell { condition: true }' > "$R/rules/webshells/shell.yar"
echo 'import "androguard"
rule andro { condition: true }' > "$R/rules/malware/andro.yar"

D="$T/out"
YARAC="$T/yarac" "$HERE/wq-yara-build.sh" "$D" "$R/signature-base" "$R/rules" >"$T/log" 2>&1
[ -f "$D/rules.yarc" ] && ok "compiled ruleset written" || bad "compiled ruleset written"
[ "$(find "$D/rules" -type f | wc -l)" = 2 ] && ok "only the two good files kept" || bad "only the two good files kept ($(find "$D/rules" -type f | wc -l))"
grep -q "broken.yar: does not compile" "$D/SKIPPED.txt" && ok "compile failure listed with reason" || bad "compile failure listed"
grep -q "shell.yar: folder not used" "$D/SKIPPED.txt" && ok "webshell folder skipped and listed" || bad "webshell folder skipped and listed"
grep -q "andro.yar: imports a module" "$D/SKIPPED.txt" && ok "unsupported module import skipped and listed" || bad "module import skipped"

# a rule name defined in two files: the later file is skipped and listed, the earlier one stays
echo 'rule good1 { condition: true }' > "$R/rules/malware/samename.yar"
D5="$T/out5"; YARAC="$T/yarac" "$HERE/wq-yara-build.sh" "$D5" "$R/signature-base" "$R/rules" >/dev/null 2>&1
grep -q "samename.yar: duplicate rule name good1" "$D5/SKIPPED.txt" && ok "duplicate rule name skipped and listed" || bad "duplicate rule name skipped and listed"
[ "$(find "$D5/rules" -name 'good1.yar' | wc -l)" = 1 ] && ok "first definition kept" || bad "first definition kept"
rm -f "$R/rules/malware/samename.yar"

# index files are skipped and listed, not compiled
echo 'include "./x.yar"' > "$R/rules/malware_index.yar"
D0="$T/out0"; YARAC="$T/yarac" "$HERE/wq-yara-build.sh" "$D0" "$R/signature-base" "$R/rules" >/dev/null 2>&1
grep -q "malware_index.yar: index file" "$D0/SKIPPED.txt" && ok "index files skipped and listed" || bad "index files skipped and listed"
rm -f "$R/rules/malware_index.yar"

# combined failure: duplicate rule names across files -> no .yarc, per-file fallback kept
echo 'rule only_in_combined { condition: true } // DUPE' > "$R/rules/malware/dupe.yar"
D2="$T/out2"
YARAC="$T/yarac" "$HERE/wq-yara-build.sh" "$D2" "$R/signature-base" "$R/rules" >"$T/log2" 2>&1
[ ! -f "$D2/rules.yarc" ] && ok "combined failure leaves no rules.yarc" || bad "combined failure leaves no rules.yarc"
grep -q "falling back to per-file" "$T/log2" && ok "combined failure is reported" || bad "combined failure is reported"
[ -d "$D2/rules" ] && ok "per-file fallback folder kept" || bad "per-file fallback folder kept"

# yara-skip.txt: a listed rule file is skipped with its reason, others are untouched
SK="$T/skip"; mkdir -p "$SK"; cp "$HERE/wq-yara-build.sh" "$SK/"
printf '# c\nmalware/good2.yar  # flags clean files\n' > "$SK/yara-skip.txt"
DS="$T/outskip"; YARAC="$T/yarac" "$SK/wq-yara-build.sh" "$DS" "$R/signature-base" "$R/rules" >/dev/null 2>&1
grep -q "good2.yar: skip list: flags clean files" "$DS/SKIPPED.txt" && ok "skip-list entry skipped with its reason" || bad "skip-list entry skipped with its reason"
[ ! -e "$DS/rules/malware/good2.yar" ] && [ -e "$DS/rules/good1.yar" -o -e "$DS/rules/yara/good1.yar" ] && ok "other rules still built" || bad "other rules still built"

# --check writes nothing
D3="$T/out3"
YARAC="$T/yarac" "$HERE/wq-yara-build.sh" --check "$D3" "$R/signature-base" >/dev/null 2>&1
[ ! -e "$D3" ] && ok "--check writes nothing" || bad "--check writes nothing"

# missing yarac is a clear error
YARAC=/nonexistent/yarac "$HERE/wq-yara-build.sh" "$T/out4" "$R/rules" >/dev/null 2>&1; [ $? -ne 0 ] && ok "missing yarac fails cleanly" || bad "missing yarac fails cleanly"

# a yarac that cannot start at all is reported once, with its own error, and builds nothing
printf '#!/bin/bash\necho "yarac: error while loading shared libraries: libcrypto.so.4: cannot open shared object file" >&2; exit 127\n' > "$T/yarac-broken"; chmod +x "$T/yarac-broken"
DB="$T/outbroken"; msg="$(YARAC="$T/yarac-broken" "$HERE/wq-yara-build.sh" "$DB" "$R/signature-base" "$R/rules" 2>&1)"; rc=$?
[ "$rc" = 1 ] && echo "$msg" | grep -q 'yarac does not run: .*libcrypto.so.4' && ok "broken yarac reported once" || bad "broken yarac reported once ($rc: $msg)"
[ ! -e "$DB/rules.yarc" ] && ok "broken yarac writes nothing" || bad "broken yarac writes nothing"

echo; echo "$pass passed, $fail failed"; [ "$fail" -eq 0 ]
