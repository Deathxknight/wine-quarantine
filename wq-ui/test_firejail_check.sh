#!/bin/bash
# Tests lib-firejail.sh: a firejail that refuses an option must block the launch (exit 97, "aborting
# launch"), and a firejail that accepts the options must let it through. A stand-in firejail is used.
#   bash wq-ui/test_firejail_check.sh
set -u
SRC="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; [ -n "${2:-}" ] && echo "      $2"; }

mkdir -p "$T/bin"
cat > "$T/bin/firejail" <<'S'
#!/bin/bash
# refuses --x11=xephyr the way the real one did, accepts everything else
for a in "$@"; do
  if [ "$a" = "--x11=xephyr" ]; then echo "Error: invalid --x11=xephyr command line option" >&2; exit 1; fi
done
exit 0
S
chmod +x "$T/bin/firejail"
export PATH="$T/bin:$PATH"
. "$SRC/lib-firejail.sh"

out="$(wq_firejail_check --private --x11=xephyr 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok || bad "refused option returns non-zero" "rc=$rc"
[[ "$out" == *"invalid --x11=xephyr"* ]] && ok || bad "firejail's own message is shown" "$out"
[[ "$out" == *"wq: aborting launch"* ]] && ok || bad "'aborting launch' line present (summary shows LAUNCH BLOCKED)" "$out"

out="$(wq_firejail_check --private --net=none 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && [ -z "$out" ] && ok || bad "accepted options pass silently" "rc=$rc out=$out"

# the launcher turns a refusal into exit 97, which summarize-run.sh reports as LAUNCH BLOCKED
( wq_firejail_check --x11=xephyr || exit 97 ); [ $? -eq 97 ] && ok || bad "refusal makes the launcher exit 97"

# wiring: both launchers must load the lib and dry-run the exact arguments before starting anything
for f in _launch-core.sh wq-ui/_launch-native.sh; do
  grep -q 'lib-firejail.sh' "$SRC/$f" && grep -q '^if ! wq_firejail_check ' "$SRC/$f" \
    && ok "$f calls wq_firejail_check" || bad "$f does not source lib-firejail.sh / call wq_firejail_check"
done

echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" -eq 0 ]
