#!/bin/bash
# lib-firejail.sh - sourced by _launch-core.sh and wq-ui/_launch-native.sh (not run).

# wq_firejail_check <firejail args...>
# Dry-run the exact firejail arguments with `true` as the program. firejail refuses some option
# combinations before anything runs (an option its build does not support, a missing helper). Without
# this check the launcher only sees a failed process, and the game-exit path then reports the run as
# "OK, minor notes". On failure this prints firejail's own message, then "wq: aborting launch", which
# makes summarize-run.sh report LAUNCH BLOCKED. Returns non-zero when firejail refuses.
wq_firejail_check() {
  local err rc=0
  err="$(firejail "$@" -- true 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "wq: firejail refused these options (exit $rc):" >&2
    printf '%s\n' "$err" | sed 's/^/wq:   /' >&2
    echo "wq: aborting launch" >&2
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------------------------
# Helper jail: the tools that parse files the game controls.
#
# ClamAV, YARA, capa/diec (via wq-prescan.py) and the archive extractors all open files that an
# attacker chose, and a parser bug in any of them is code execution as YOU. They used to run on the
# host (extractors, prescan, capa) or in a jail that left your home, the launcher scripts and the
# user's control sockets reachable (clamscan, yara). A game can't write to the launcher, but a
# compromised scanner could, and the launcher runs unsandboxed on the next start.
#
# wq_helper_jail [--rw PATH]... [--ro PATH]... [--host-tmp-ro]
#   Fills WQ_HJAIL with a firejail command line: no network, no new privileges, no capabilities,
#   default seccomp filter, no supplementary groups, no new namespaces, own IPC namespace, only
#   unix/inet/netlink sockets, minimal /dev, none of the user's or system control sockets, and
#   everything that could carry a persistent change read-only ($HOME, the launcher folder, other
#   drives). --rw PATH opens one path for writing again (extraction target). --host-tmp-ro shows the
#   host's /tmp and /var/tmp read-only instead of an empty private /tmp (for an input file that lives
#   there). Reading is not
#   restricted, but with no network and no sockets there is nowhere for what it reads to go.
#   If this firejail refuses the options (older version), it says so and falls back to the previous
#   plain jail, unless WQ_HELPER_JAIL_STRICT=1, which makes that an error (rc 1).
WQ_HJAIL=()
wq_helper_jail() {
  local rw=() ro=() p rp home rtd hosttmp=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --rw) rw+=("$2"); shift 2 ;;
      --ro) ro+=("$2"); shift 2 ;;
      --host-tmp-ro) hosttmp=1; shift ;;
      *) echo "wq_helper_jail: bad argument $1" >&2; return 2 ;;
    esac
  done
  command -v firejail >/dev/null 2>&1 || { WQ_HJAIL=(); return 1; }

  home="$(readlink -f "${HOME:-/nonexistent}" 2>/dev/null || true)"
  rtd="${WQ_RUNTIME_DIR:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}}"

  WQ_HJAIL=(firejail --quiet --noprofile --net=none --private-dev --nonewprivs
            --caps.drop=all --nodbus --seccomp --nogroups --restrict-namespaces --ipc-namespace
            --protocol=unix,inet,inet6,netlink)
  if [ "$hosttmp" = 1 ]; then
    WQ_HJAIL+=(--read-only=/tmp --read-only=/var/tmp)
  else
    WQ_HJAIL+=(--private-tmp)
  fi

  # whole-directory blacklists: a hidden directory takes its sockets with it (the per-file entries
  # are not reliably hidden for sockets, see profile.sh)
  for p in "$rtd" /run/systemd /run/udev /run/tailscale /run/polkit /run/ssh-unix-local /run/seatd.sock \
           /run/docker.sock /var/run/docker.sock /run/libvirt /var/run/libvirt /run/podman /run/containerd \
           /run/nscd /var/run/nscd; do
    [ -e "$p" ] && WQ_HJAIL+=("--blacklist=$p")
  done

  # nothing persistent is writable: the home folder, the launcher and every game, other drives
  for p in "$home" "${QROOT:-}" /media /run/media /mnt; do
    [ -n "$p" ] && [ -e "$p" ] || continue
    rp="$(readlink -f -- "$p" 2>/dev/null || true)"
    [ -n "$rp" ] && [ "$rp" != / ] || continue
    WQ_HJAIL+=("--read-only=$rp")
  done
  for p in ${ro[@]+"${ro[@]}"}; do
    [ -e "$p" ] && WQ_HJAIL+=("--read-only=$(readlink -f -- "$p")")
  done
  # writable exceptions come last: firejail applies mount options in command order
  for p in ${rw[@]+"${rw[@]}"}; do
    [ -e "$p" ] || continue
    WQ_HJAIL+=("--read-write=$(readlink -f -- "$p")")
  done

  # dry run, including a real write into every --rw path from inside the jail
  local err rc=0 probe
  err="$("${WQ_HJAIL[@]}" -- true 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    for p in ${rw[@]+"${rw[@]}"}; do
      [ -d "$p" ] || continue
      probe="$(readlink -f -- "$p")/.wq-jail-write-probe.$$"
      if ! "${WQ_HJAIL[@]}" -- sh -c 'touch "$1" && rm -f "$1"' sh "$probe" >/dev/null 2>&1; then
        rc=98; err="cannot write to $p from inside the jail"
        break
      fi
    done
  fi
  if [ "$rc" -ne 0 ]; then
    echo "wq: hardened helper jail not usable here: $(printf '%s' "$err" | head -n 2 | tr '\n' ' ')" >&2
    if [ "${WQ_HELPER_JAIL_STRICT:-0}" = 1 ] || [ "$rc" -eq 98 ]; then
      WQ_HJAIL=(); return 1
    fi
    echo "wq: using the previous plain jail (set WQ_HELPER_JAIL_STRICT=1 to refuse instead)" >&2
    WQ_HJAIL=(firejail --quiet --noprofile --net=none --private-tmp --nonewprivs --caps.drop=all --nodbus --seccomp)
    return 0
  fi
  return 0
}
