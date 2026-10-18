#!/bin/bash
# wq-ui integration: checks are relaxed only for protections the profile disabled
# verify-sandbox.sh - refuse to run the game unless the sandbox is enforced.
#
# Runs inside the firejail sandbox before the game is exec'd.
# Exit codes: 0 all checks passed, 90 a check failed, 91 self-hash mismatch.
#
# QVERIFY_MODE=native (set by wq-ui/_launch-native.sh) runs the checks that apply to any game:
# capabilities, no_new_privs, seccomp, network, resolver sockets, mount propagation, D-Bus and
# ssh-agent, and that the game folder cannot see its own config and logs. The Wine-specific ones
# (prefix, umu data, $HOME contents: a native game's $HOME is its own persistent folder) are skipped.

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

MODE="${QVERIFY_MODE:-windows}"
GAMEDIR="${QVERIFY_GAMEDIR:?QVERIFY_GAMEDIR not set}"
if [ "$MODE" = native ]; then
  SUBDIRS=(game)
  UMU_DATA=""
else
  SUBDIRS=(game prefix)
  UMU_DATA="${QVERIFY_UMU_DATA:?QVERIFY_UMU_DATA not set}"
  HOST_USER="${QVERIFY_HOST_USER:?QVERIFY_HOST_USER not set}"
fi

PASS=0
FAIL=0

pass() { echo "[SANDBOX-VERIFY] ok:   $*" >&2; PASS=$((PASS+1)); }
fail() { echo "[SANDBOX-VERIFY] FAIL: $*" >&2; FAIL=$((FAIL+1)); }
# profile-disabled protections (QVERIFY_SKIP is set outside the sandbox)
skipped() { case ",${QVERIFY_SKIP:-}," in *",$1,"*) return 0 ;; esac; return 1; }

# capabilities
for cap in CapEff CapPrm CapBnd CapAmb; do
if skipped caps; then pass "capability check skipped by profile"; break; fi
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
if skipped nnp; then pass "NoNewPrivs check skipped by profile"; else
[ "$nnp" = "1" ] && pass "NoNewPrivs=1" || fail "NoNewPrivs=$nnp, expected 1"
fi

# seccomp
sec=$(awk '/^Seccomp:/ {print $2}' /proc/self/status)
if skipped seccomp; then sec=skip; fi
case "$sec" in
skip) pass "Seccomp check skipped by profile" ;;
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
|| { if [ "${QVERIFY_NET:-off}" != off ]; then pass "network enabled by profile (${QVERIFY_NET}): $NON_LO"; else fail "non-loopback interfaces visible: $NON_LO"; fi; }

# DNS resolver sockets answer lookups without a network interface, so --net=none does not cover them
if skipped sockets || [ "${QVERIFY_NET:-off}" = open ]; then
  pass "resolver socket check not applicable (profile)"
else
  RES_BAD=""
  for s in /run/systemd/resolve/io.systemd.Resolve /run/nscd/socket /var/run/nscd/socket; do
    [ -S "$s" ] && RES_BAD="$RES_BAD $s"
  done
  [ -z "$RES_BAD" ] && pass "no DNS resolver socket visible" \
  || fail "DNS resolver socket visible (bypasses --net=none):$RES_BAD"
fi

if [ "$MODE" = native ]; then
  pass "native mode: \$HOME is the game's own private home, contents not checked"
else
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
  if skipped home; then HOME_BAD=0; else
  fail "\$HOME/$entry present - real home leaked"
  HOME_BAD=1
  fi
    fi
  done < <(ls -A "$HOME" 2>/dev/null)
  [ "$HOME_BAD" -eq 0 ] && pass "\$HOME contains only expected shell files ($HOME)"
fi

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

# mount propagation: a "shared" mount would carry mounts and unmounts made inside the jail out to
# the host. /proc/self/mountinfo is
#   ID parent maj:min root mountpoint options [optional fields...] - fstype source superopts
# and the optional fields (shared:N, master:N, propagate_from:N, unbindable) sit between field 6 and
# the " - " separator, so the number of fields before it varies. "master:" is a slave mount, which
# only receives events and is what firejail sets up; only "shared:" leaks.
shared_mounts() {
  local line pre
  local -a f
  while IFS= read -r line; do
    case "$line" in *" - "*) ;; *) continue ;; esac
    pre="${line%% - *}"
    read -ra f <<< "$pre"
    [ "${#f[@]}" -ge 7 ] || continue
    local opt
    for opt in "${f[@]:6}"; do
      case "$opt" in shared:*) printf '%s\n' "${f[4]}"; break ;; esac
    done
  done
}
if skipped propagation; then
  pass "mount propagation check skipped"
elif [ ! -r /proc/self/mountinfo ]; then
  pass "mountinfo not readable, propagation not checked"
else
  SHARED="$(shared_mounts < /proc/self/mountinfo | head -n 5 | tr '\n' ' ')"
  [ -z "$SHARED" ] && pass "no shared mounts visible" \
                   || fail "shared mount propagation: ${SHARED% } (if this firejail does not make mounts slave here, set WQ_VERIFY_SKIP_EXTRA=propagation in config.local.sh)"
fi

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
for sub in "${SUBDIRS[@]}"; do
  [ -d "$GAMEDIR/$sub" ] && pass "$sub/ visible ($GAMEDIR/$sub)" \
                         || fail "$sub/ not visible ($GAMEDIR/$sub)"
done
if [ "$MODE" != native ]; then
  [ -d "$UMU_DATA" ] && pass "UMU_DATA visible ($UMU_DATA)" \
                     || fail "UMU_DATA not visible ($UMU_DATA)"
fi

# the game must not be able to see its own config, logs or snapshots
LEAK=0
HIDDEN=(game.conf logs .reg-snapshot .home-snapshot launch-quarantine.sh)
[ "$MODE" = native ] && HIDDEN+=(home)     # the private home is mounted as $HOME, not at this path
for h in "${HIDDEN[@]}"; do
  if [ -e "$GAMEDIR/$h" ]; then
    fail "$GAMEDIR/$h is visible inside the sandbox"
    LEAK=1
  fi
done
[ "$LEAK" -eq 0 ] && pass "game.conf, logs and snapshots are not visible"

# game/ and prefix/ must be writable
for sub in "${SUBDIRS[@]}"; do
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
