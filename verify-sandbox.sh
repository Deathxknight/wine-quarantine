#!/bin/bash
# wq-ui integration: checks are relaxed only for protections the profile disabled
# verify-sandbox.sh - refuse to run the game unless the sandbox is enforced.
#
# Runs inside the firejail sandbox before the game is exec'd.
# Exit codes: 0 all checks passed, 90 a check failed, 91 self-hash mismatch.
#
# QVERIFY_MODE=native (set by wq-ui/_launch-native.sh) runs the checks that apply to any game:
# capabilities, no_new_privs, seccomp, network, resolver sockets, mount propagation, D-Bus and
# ssh-agent, and that the game can't see its own config and logs. The Wine ones (prefix, umu data,
# $HOME contents, since a native game's $HOME is its own persistent folder) are skipped.

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
DEGRADED=0

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

# Same-user sockets in the runtime dir are reachable by path whatever the network setup is.
# systemd/private is the user manager's own socket (a way to start units outside the jail), the
# rest are gpg/ssh agents and desktop app controls, and hypr/ is the Hyprland IPC directory (its
# socket can run commands as you). profile.sh blacklists the ones that exist. Uwsm's launcher FIFOs
# are listed too: writing to them starts programs outside the jail.
# A blacklisted entry is either a /dev/null placeholder (file), a mode-000 directory, or absent.
chk_hidden() {   # chk_hidden <path>: prints the path if something reachable is behind it
  # What firejail leaves behind for a hidden entry: a /dev/null character device (files), a mode-000
  # directory, or an empty root-owned file the user cannot read (sockets, FIFOs, lock files).
  # Real reachable entries: a socket, a FIFO we can write to, a readable file, or a directory we can enter.
  local p="$1"
  [ -e "$p" ] || return 0
  [ -c "$p" ] && return 0
  if [ -d "$p" ]; then
    [ -x "$p" ] || return 0
  elif [ -S "$p" ]; then
    :                                  # a live socket: reachable by path
  elif [ -p "$p" ]; then
    [ -w "$p" ] || return 0            # FIFO we cannot write to is not a control channel
  elif [ -f "$p" ]; then
    [ -r "$p" ] || return 0            # unreadable placeholder file
  fi
  printf ' %s' "$p"
}
if skipped sockets; then
  pass "user runtime socket check skipped by profile"
else
  RT_BAD=""
  RT_DIR="${WQ_RUNTIME_DIR:-/run/user/$(id -u)}"
  for s in systemd gnupg gcr keyring ssh-agent.socket hypr \
           uwsm uwsm-app-daemon-in uwsm-app-daemon-out uwsm-app.lock \
           discord-ipc-0 discord-ipc-1 vesktop.sock walker elephant waywallen \
           at-spi p11-kit .flatpak .flatpak-helper; do
    RT_BAD="$RT_BAD$(chk_hidden "$RT_DIR/$s")"
  done
  [ -z "$RT_BAD" ] && pass "no systemd/gpg/ssh-agent socket visible in the runtime dir" \
  || fail "same-user control socket visible:$RT_BAD"

  SYS_BAD=""
  for p in /run/tailscale /run/polkit /run/ssh-unix-local /run/seatd.sock \
           /run/systemd/private /run/systemd/userdb /run/systemd/machine /run/systemd/report \
           /run/systemd/inaccessible /run/systemd/resolve.hook /run/udev/io.systemd.Udev \
           /run/systemd/coredump /run/systemd/journal; do
    SYS_BAD="$SYS_BAD$(chk_hidden "$p")"
  done
  for p in /run/systemd/io.systemd.*; do
    SYS_BAD="$SYS_BAD$(chk_hidden "$p")"
  done
  [ -z "$SYS_BAD" ] && pass "no system control socket visible (tailscale, polkit, systemd services)" \
  || fail "system control socket visible:$SYS_BAD"
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
    # firejail's own PulseAudio setup puts a small ~/.config/pulse (client.conf) into the fresh tmpfs home.
    # Accept .config only when it holds nothing but that; a real home's .config has many more entries.
    if [ "$allowed" -eq 0 ] && [ "$entry" = ".config" ]; then
      cfg_extra="$(ls -A "$HOME/.config" 2>/dev/null | grep -vx 'pulse')"
      pulse_extra="$(ls -A "$HOME/.config/pulse" 2>/dev/null | grep -vxE 'client\.conf|cookie')"
      [ -z "$cfg_extra" ] && [ -z "$pulse_extra" ] && allowed=1
    fi
    if [ "$allowed" -eq 0 ]; then
  if skipped home; then HOME_BAD=0; else
  extra=""
  [ "$entry" = ".config" ] && extra=" (contains: $(ls -A "$HOME/.config" 2>/dev/null | head -n8 | tr '\n' ' '))"
  fail "\$HOME/$entry present - real home leaked$extra"
  HOME_BAD=1
  fi
    fi
  done < <(ls -A "$HOME" 2>/dev/null)
  [ "$HOME_BAD" -eq 0 ] && pass "\$HOME contains only expected shell files ($HOME)"
fi

# other drives: only the paths the profile actually hid are checked (profile.sh exports them)
if skipped media; then
  pass "other-drives check skipped by profile"
elif [ -z "${QVERIFY_MEDIA_BLOCKED:-}" ]; then
  pass "no other-drive paths to hide (none exist, or they hold the game)"
else
  MEDIA_BAD=""
  while IFS= read -r mp; do
    [ -n "$mp" ] || continue
    [ -c "$mp" ] && continue
    [ -d "$mp" ] || continue
    # a blacklisted directory is left as an empty or mode-000 placeholder
    [ -n "$(ls -A "$mp" 2>/dev/null)" ] && MEDIA_BAD="$MEDIA_BAD $mp"
  done <<< "$QVERIFY_MEDIA_BLOCKED"
  [ -z "$MEDIA_BAD" ] && pass "other drives (/media, /run/media, /mnt) are hidden" \
  || fail "other drives readable:$MEDIA_BAD"
fi

# neighbours of the game folder: only the ones the profile hid are checked (profile.sh exports them)
if skipped siblings; then
  pass "neighbour check skipped by profile"
elif [ -z "${QVERIFY_SIBLINGS_HIDDEN:-}" ]; then
  pass "no neighbours of the game folder to hide"
else
  SIB_BAD=""
  while IFS= read -r sp; do
    [ -n "$sp" ] || continue
    [ -c "$sp" ] && continue
    if [ -d "$sp" ]; then
      [ -n "$(ls -A "$sp" 2>/dev/null)" ] && SIB_BAD="$SIB_BAD $sp"
    elif [ -e "$sp" ]; then
      SIB_BAD="$SIB_BAD $sp"
    fi
  done <<< "$QVERIFY_SIBLINGS_HIDDEN"
  [ -z "$SIB_BAD" ] && pass "neighbours of the game folder are hidden" \
  || fail "neighbours readable:$SIB_BAD"
fi

# raw input devices (FJ_NOINPUT): /dev/input is either gone (--private-dev) or an empty placeholder
if skipped input; then
  pass "input device check skipped by profile"
elif [ -d /dev/input ] && [ -n "$(ls -A /dev/input 2>/dev/null)" ]; then
  fail "/dev/input is readable (raw keyboard/mouse events): $(ls -A /dev/input 2>/dev/null | head -n 3 | tr '\n' ' ')"
else
  pass "no raw input devices visible"
fi

# own PID namespace: PID 1 must be firejail's init, not the host's init or systemd. If the sandbox shared
# the host's process table, the game could see (and signal, as you) everything you run.
if [ -r /proc/1/comm ]; then
  p1="$(cat /proc/1/comm 2>/dev/null)"
  case "$p1" in
    systemd|init|runit|openrc-init|s6-svscan|dinit) fail "PID 1 is '$p1': the sandbox shares the host's process table" ;;
    *) pass "own PID namespace (PID 1 is '$p1')" ;;
  esac
fi

# own IPC namespace (FJ_IPC_NS): the host's SysV shared memory, semaphores and message queues stay out of reach
if skipped ipc; then
  pass "IPC namespace check skipped by profile"
else
  ipc_seen=0
  for f in shm sem msg; do
    [ -r "/proc/sysvipc/$f" ] || continue
    n="$(awk 'NR>1' "/proc/sysvipc/$f" 2>/dev/null | wc -l)"
    ipc_seen=$((ipc_seen + n))
  done
  [ "$ipc_seen" -eq 0 ] && pass "no host SysV IPC objects visible" \
                         || fail "$ipc_seen host SysV IPC object(s) visible (own IPC namespace not in effect)"
fi

# obscure socket families (FJ_PROTOCOL): creating one must fail. AF_ALG (38), AF_VSOCK (40), AF_KEY (15),
# AF_RDS (21), AF_TIPC (30) and AF_BLUETOOTH (31) are where kernel exploits have come in from
if skipped protocol; then
  pass "socket family check skipped by profile"
elif ! command -v python3 >/dev/null 2>&1; then
  pass "socket family check skipped (no python3 in the sandbox)"
else
  FAM_BAD="$(python3 - <<'PY' 2>/dev/null
import socket
bad = []
for name, num, typ in (("AF_ALG", 38, socket.SOCK_SEQPACKET), ("AF_VSOCK", 40, socket.SOCK_STREAM),
                       ("AF_KEY", 15, socket.SOCK_RAW), ("AF_RDS", 21, socket.SOCK_SEQPACKET),
                       ("AF_TIPC", 30, socket.SOCK_RDM), ("AF_BLUETOOTH", 31, socket.SOCK_STREAM)):
    try:
        s = socket.socket(num, typ)
        s.close()
        bad.append(name)
    except OSError:
        pass
print(" ".join(bad))
PY
)"
  [ -z "$FAM_BAD" ] && pass "unusual socket families (AF_ALG, AF_VSOCK, AF_KEY, AF_RDS, AF_TIPC, AF_BLUETOOTH) are refused" \
                    || fail "socket families that can be created: $FAM_BAD (FJ_PROTOCOL not in effect)"
fi

# memfd_create (FJ_MEMFD): fileless payloads start here, so with the box ticked the call must fail
if skipped memfd || skipped seccomp; then
  pass "memfd_create check skipped by profile"
elif ! command -v python3 >/dev/null 2>&1; then
  pass "memfd_create check skipped (no python3 in the sandbox)"
else
  if python3 -c 'import os,sys; os.close(os.memfd_create("wq")); sys.exit(0)' 2>/dev/null; then
    fail "memfd_create works (FJ_MEMFD not in effect)"
  else
    pass "memfd_create is refused"
  fi
fi

# write+execute memory (FJ_MDWX): mapping a page that is writable and executable must fail
if skipped mdwx; then
  pass "write+execute memory check skipped by profile"
elif ! command -v python3 >/dev/null 2>&1; then
  pass "write+execute memory check skipped (no python3 in the sandbox)"
else
  if python3 -c 'import mmap,sys; mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)' 2>/dev/null; then
    fail "a writable and executable memory page can be mapped (FJ_MDWX not in effect)"
  else
    pass "writable+executable memory is refused"
  fi
fi

# new namespaces (FJ_RESTRICT_NS): creating a user namespace opens a lot of kernel attack surface to the game
if skipped ns; then
  pass "namespace restriction check skipped by profile"
elif ! command -v python3 >/dev/null 2>&1; then
  pass "namespace restriction check skipped (no python3 in the sandbox)"
else
  if python3 -c 'import ctypes,sys; sys.exit(0 if ctypes.CDLL(None, use_errno=True).unshare(0x10000000) == 0 else 1)' 2>/dev/null; then
    fail "a new user namespace can be created (FJ_RESTRICT_NS not in effect)"
  else
    pass "creating new namespaces is refused"
  fi
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
# the host. /proc/self/mountinfo looks like
#   ID parent maj:min root mountpoint options [optional fields...] - fstype source superopts
# The optional fields (shared:N, master:N, propagate_from:N, unbindable) sit between field 6 and
# the " - " separator, so how many fields come before it varies. "master:" is a slave mount, which
# only receives events and is what firejail sets up. Only "shared:" leaks.
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
  if [ "$sub" = game ] && [ "${QVERIFY_GAME_RO:-0}" = 1 ]; then
    # FJ_GAME_RO: the profile asked for a read-only game/, so a writable one is the failure
    if touch "$GAMEDIR/$sub/.verify-write-probe" 2>/dev/null; then
      rm -f "$GAMEDIR/$sub/.verify-write-probe"
      fail "$sub/ is writable but the profile asked for read-only (FJ_GAME_RO)"
    else
      pass "$sub/ is read-only (FJ_GAME_RO)"
    fi
  elif touch "$GAMEDIR/$sub/.verify-write-probe" 2>/dev/null; then
    rm -f "$GAMEDIR/$sub/.verify-write-probe"
    pass "$sub/ is writable"
  else
    fail "$sub/ is not writable - game saves will fail"
  fi
done

# supplementary groups: firejail silently ignores --nogroups on some systems (NVIDIA: "Warning: NVIDIA card detected,
# nogroups command ignored"). The profile asked for it, so a game that still has docker/input/disk/... group membership
# is a setting that is not in effect. Fail closed like every other check; WQ_NOGROUPS_STRICT=0 (set outside the sandbox)
# turns it into a DEGRADED line that the run summary reports instead of cancelling the launch.
if skipped groups; then
  pass "supplementary groups check skipped by profile"
else
  PRIMARY_GID="$(id -g)"; EXTRA_GROUPS=""
  read -ra GIDS <<< "$(id -G)"; read -ra GNAMES <<< "$(id -nG 2>/dev/null)"
  for i in "${!GIDS[@]}"; do
    [ "${GIDS[$i]}" = "$PRIMARY_GID" ] || [ "${GIDS[$i]}" = 65534 ] || EXTRA_GROUPS="$EXTRA_GROUPS ${GNAMES[$i]:-${GIDS[$i]}}"
  done
  if [ -z "${EXTRA_GROUPS// /}" ]; then
    pass "no supplementary groups (--nogroups in effect)"
  elif [ "${QVERIFY_NOGROUPS_STRICT:-${WQ_NOGROUPS_STRICT:-1}}" = 1 ]; then
    fail "--nogroups is requested but not in effect: still a member of:$EXTRA_GROUPS (firejail ignores it on NVIDIA systems; turn off 'Drop supplementary groups' for this game to accept that)"
  else
    DEGRADED=$((DEGRADED+1))
    echo "[SANDBOX-VERIFY] DEGRADED: --nogroups is requested but not in effect: still a member of:$EXTRA_GROUPS" >&2
  fi
fi

if [ "$DEGRADED" -gt 0 ]; then
  echo "[SANDBOX-VERIFY] $PASS passed, $FAIL failed, $DEGRADED degraded" >&2
else
  echo "[SANDBOX-VERIFY] $PASS passed, $FAIL failed" >&2
fi

if [ "$FAIL" -gt 0 ]; then
  echo "[SANDBOX-VERIFY] ABORT: sandbox not enforced" >&2
  exit 90
fi
exit 0
