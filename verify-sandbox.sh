#!/bin/bash
# verify-sandbox.sh - refuse to run the game unless the sandbox is enforced.
#
# Runs inside the firejail sandbox before the game is exec'd.
# Exit codes: 0 all checks passed, 90 a check failed, 91 self-hash mismatch.

set -u

SELF="$(readlink -f "$0")"
HASHFILE="$(dirname "$SELF")/verify-sandbox.sha256"
EXPECTED_HASH=""
[ -f "$HASHFILE" ] && EXPECTED_HASH="$(head -n1 "$HASHFILE" | tr -d '[:space:]')"

if [ "${1:-}" = "--update-hash" ]; then
  sha256sum "$SELF" | awk '{print $1}' > "$HASHFILE"
  echo "wrote $HASHFILE" >&2
  exit 0
fi

if [ -z "$EXPECTED_HASH" ]; then
  echo "[SANDBOX-VERIFY] FAIL: no hash file at $HASHFILE" >&2
  echo "  Create it with: $SELF --update-hash" >&2
  exit 91
fi

ACTUAL_HASH="$(sha256sum "$SELF" | awk '{print $1}')"
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo "[SANDBOX-VERIFY] FAIL: self-hash mismatch" >&2
  echo "  expected: $EXPECTED_HASH" >&2
  echo "  actual:   $ACTUAL_HASH" >&2
  echo "  If you intentionally edited this script, run: $SELF --update-hash" >&2
  exit 91
fi

GAMEDIR="${QVERIFY_GAMEDIR:?QVERIFY_GAMEDIR not set}"
UMU_DATA="${QVERIFY_UMU_DATA:?QVERIFY_UMU_DATA not set}"
HOST_USER="${QVERIFY_HOST_USER:?QVERIFY_HOST_USER not set}"

PASS=0
FAIL=0

pass() { echo "[SANDBOX-VERIFY] ok:   $*" >&2; PASS=$((PASS+1)); }
fail() { echo "[SANDBOX-VERIFY] FAIL: $*" >&2; FAIL=$((FAIL+1)); }

# capabilities
for cap in CapEff CapPrm CapBnd CapAmb; do
  v=$(awk -v k="^$cap:" '$0 ~ k {print $2}' /proc/self/status)
  if [ -z "$v" ]; then
    fail "could not read $cap from /proc/self/status"
  elif [ "$v" = "0000000000000000" ]; then
    pass "$cap is all-zero"
  else
    fail "$cap is $v, expected all-zero"
  fi
done

# no_new_privs
nnp=$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)
[ "$nnp" = "1" ] && pass "NoNewPrivs=1" || fail "NoNewPrivs=$nnp, expected 1"

# seccomp
sec=$(awk '/^Seccomp:/ {print $2}' /proc/self/status)
case "$sec" in
  2) pass "Seccomp=2 (filter mode)" ;;
  1) fail "Seccomp=1 (strict mode - some games need 2)" ;;
  0) fail "Seccomp=0 (no filter - sandbox is not enforcing syscall limits)" ;;
  *) fail "Seccomp=$sec (unexpected)" ;;
esac

# network: only lo should be visible
NON_LO=""
while IFS=: read -r iface rest; do
  iface="${iface// /}"
  [ -z "$iface" ] && continue
  [ "$iface" = "lo" ] && continue
  case "$iface" in
    *[!A-Za-z0-9_.-]*) continue ;;
  esac
  NON_LO="$NON_LO $iface"
done < /proc/self/net/dev
NON_LO="${NON_LO# }"
[ -z "$NON_LO" ] && pass "network namespace contains only lo" \
                 || fail "non-loopback interfaces visible: $NON_LO"

# $HOME should be a fresh tmpfs with at most firejail's shell startup files
ALLOWED_HOME_ENTRIES=(.inputrc .zshrc .bashrc .Xauthority)  # firejail --private copies this in for X11
while IFS= read -r wl; do
  case "$wl" in
    "$HOME"/*) rest="${wl#"$HOME"/}"; ALLOWED_HOME_ENTRIES+=("${rest%%/*}") ;;
  esac
done <<< "${QVERIFY_WL_PATHS:-}"
HOME_BAD=0
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  allowed=0
  for a in "${ALLOWED_HOME_ENTRIES[@]}"; do
    [ "$entry" = "$a" ] && { allowed=1; break; }
  done
  if [ "$allowed" -eq 0 ]; then
    fail "\$HOME/$entry present - real home leaked"
    HOME_BAD=1
  fi
done < <(ls -A "$HOME" 2>/dev/null)
[ "$HOME_BAD" -eq 0 ] && pass "\$HOME contains only expected shell files ($HOME)"

# /proc/1/root
if [ -r /proc/1/root ]; then
  init_root="$(readlink -f /proc/1/root 2>/dev/null || echo '?')"
  self_root="$(readlink -f / 2>/dev/null || echo '?')"
  if [ "$init_root" = "$self_root" ]; then
    pass "/proc/1/root matches own root ($init_root)"
  else
    fail "/proc/1/root ($init_root) differs from own root ($self_root)"
  fi
fi

# mount propagation
prop_ok=1
if [ -r /proc/self/mountinfo ]; then
  while read -r _ _ _ _ _ _ _ _ _ _ _ _ _ opts _; do
    case "$opts" in
      *shared:*|*slave:*)
        prop_ok=0
        break
        ;;
    esac
  done < /proc/self/mountinfo
fi
[ "$prop_ok" -eq 1 ] && pass "no shared/slave mounts visible" \
                     || fail "shared mount propagation detected"

# environment
dbus_val="${DBUS_SESSION_BUS_ADDRESS:-}"
case "$dbus_val" in
  "")
    pass "DBUS_SESSION_BUS_ADDRESS unset"
    ;;
  *"/run/firejail/mnt/dbus/"*)
    pass "DBUS_SESSION_BUS_ADDRESS points at firejail proxy ($dbus_val)"
    ;;
  *)
    fail "DBUS_SESSION_BUS_ADDRESS reaches real bus: $dbus_val"
    ;;
esac

[ -z "${SSH_AUTH_SOCK:-}" ] && pass "SSH_AUTH_SOCK unset" \
                            || fail "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"

# whitelisted paths
for sub in game prefix; do
  [ -d "$GAMEDIR/$sub" ] && pass "$sub/ visible ($GAMEDIR/$sub)" \
                         || fail "$sub/ not visible ($GAMEDIR/$sub)"
done
[ -d "$UMU_DATA" ] && pass "UMU_DATA visible ($UMU_DATA)" \
                   || fail "UMU_DATA not visible ($UMU_DATA)"

# the game must not be able to see its own config, logs or snapshots
LEAK=0
for h in game.conf logs .reg-snapshot launch-quarantine.sh; do
  if [ -e "$GAMEDIR/$h" ]; then
    fail "$GAMEDIR/$h is visible inside the sandbox"
    LEAK=1
  fi
done
[ "$LEAK" -eq 0 ] && pass "game.conf, logs and snapshots are not visible"

# game/ and prefix/ must be writable
for sub in game prefix; do
  if touch "$GAMEDIR/$sub/.verify-write-probe" 2>/dev/null; then
    rm -f "$GAMEDIR/$sub/.verify-write-probe"
    pass "$sub/ is writable"
  else
    fail "$sub/ is not writable - game saves will fail"
  fi
done

echo "[SANDBOX-VERIFY] $PASS passed, $FAIL failed" >&2

if [ "$FAIL" -gt 0 ]; then
  echo "[SANDBOX-VERIFY] ABORT: sandbox not enforced" >&2
  exit 90
fi
exit 0
