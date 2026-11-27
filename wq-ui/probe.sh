#!/bin/bash
# probe.sh - run this AS a native wine-quarantine game (EXE=probe.sh, RUNNER=native) to see what the
# jail really lets a program do. It only looks and tries harmless calls; it changes nothing
# except a small probe file in the current directory.
#
#   LEAK  = something a hostile game could use
#   ok    = blocked / hidden as hoped
#   info  = depends on your profile choices (shown so you can judge)
#
# Extra args:  --quiet  (only LEAK + summary)      --net-target HOST:PORT (default 1.1.1.1:443)
# Run it a second time with different toggles and diff the two outputs.

set -u
QUIET=0; NET_TARGET="1.1.1.1:443"
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --net-target) shift; NET_TARGET="${1:-$NET_TARGET}" ;;
  esac
  shift
done

LEAKS=0; OKS=0; INFOS=0
say()  { [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
sec()  { say ""; say "== $*"; }
ok()   { OKS=$((OKS+1));     say "  ok    $*"; }
leak() { LEAKS=$((LEAKS+1)); printf '  LEAK  %s\n' "$*"; }
info() { INFOS=$((INFOS+1)); say "  info  $*"; }
have() { command -v "$1" >/dev/null 2>&1; }
# readable_nonempty <dir>: dir lists something (a firejail-blacklisted dir is empty / mode 000)
nonempty() { [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; }

say "wq probe  $(date '+%F %T')  user=$(id -un) host=$(cat /proc/sys/kernel/hostname 2>/dev/null || uname -n) arch=$(uname -m)"
say "cwd=$(pwd)  HOME=$HOME"

# ---- identity / privileges
sec "identity and privileges"
grp="$(id -Gn)"
info "groups: $grp"
for g in docker libvirt kvm input disk wheel sudo video; do
  case " $grp " in *" $g "*) leak "member of group '$g' (supplementary groups kept - FJ_NOGROUPS off, or NVIDIA)";; esac
done
for cap in CapEff CapPrm CapBnd CapAmb; do
  v="$(awk -v k="^$cap:" '$0 ~ k {print $2}' /proc/self/status)"
  [ "$v" = "0000000000000000" ] && ok "$cap empty" || leak "$cap=$v"
done
nnp="$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
[ "$nnp" = 1 ] && ok "NoNewPrivs=1" || leak "NoNewPrivs=$nnp"
sc="$(awk '/^Seccomp:/ {print $2}' /proc/self/status)"
[ "$sc" = 2 ] && ok "seccomp filter active" || leak "Seccomp=$sc (no filter)"
if [ -r /proc/self/status ]; then
  info "seccomp filters: $(awk '/^Seccomp_filters:/ {print $2}' /proc/self/status)"
fi
if have sudo && timeout 3 sudo -n true 2>/dev/null; then leak "passwordless sudo works"; else ok "no passwordless sudo"; fi

# ---- namespaces / syscalls
sec "syscalls (python3 + ctypes, x86_64 only)"
if [ "$(uname -m)" = x86_64 ] && have python3; then
  SYS_OUT="$(python3 - <<'PY' 2>&1
import ctypes, os, errno
libc = ctypes.CDLL(None, use_errno=True)
# name: (nr, args). Args are chosen so that a call that reaches the kernel fails harmlessly
# (EINVAL/EFAULT/EBADF/EIO) while a seccomp block gives EPERM (firejail default) or kills us.
S = {
 "add_key":248, "request_key":249, "keyctl":250, "bpf":321, "io_uring_setup":425,
 "userfaultfd":323, "perf_event_open":298, "kcmp":312, "name_to_handle_at":303,
 "open_by_handle_at":304, "mount":165, "umount2":166, "pivot_root":155, "chroot":161,
 "fanotify_init":300, "process_vm_readv":310, "process_vm_writev":311, "ptrace":101,
 "unshare(NEWUSER)":272, "kexec_load":246, "init_module":175, "swapon":167, "reboot":169,
}
expect_blocked_default = {"add_key","request_key","keyctl","bpf","io_uring_setup","userfaultfd",
  "perf_event_open","open_by_handle_at","kexec_load","init_module","swapon","reboot"}
def probe(name, nr):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        ctypes.set_errno(0)
        a = [0]*6
        if name == "unshare(NEWUSER)": a[0] = 0x10000000
        if name == "ptrace":           a[0] = 0x7fff          # bogus request: EIO if it gets through
        if name == "reboot":           a = [0x1234, 0x1234, 0x1234, 0, 0, 0]  # bad magic: EINVAL, no reboot
        if name == "kexec_load":       a = [0, 0, 0, 0, 0, 0]
        if name == "swapon":           a = [0, 0, 0, 0, 0, 0]
        res = libc.syscall(nr, *[ctypes.c_long(x) for x in a])
        e = ctypes.get_errno()
        os.write(w, f"{res} {e}".encode())
        os._exit(0)
    os.close(w)
    data = os.read(r, 64).decode()
    _, st = os.waitpid(pid, 0)
    if os.WIFSIGNALED(st):
        return "killed by signal %d (seccomp kill)" % os.WTERMSIG(st), True
    res, e = (data.split() + ["?", "0"])[:2]
    e = int(e)
    if e == errno.EPERM:  return "blocked (EPERM)", True
    if e == errno.ENOSYS: return "not available (ENOSYS)", True
    if name == "unshare(NEWUSER)" and res == "0": return "SUCCEEDED (can create user namespaces)", False
    if e == 0: return "reached the kernel (call returned %s)" % res, False
    return "reached the kernel (errno %d %s)" % (e, errno.errorcode.get(e, "?")), False
for name, nr in S.items():
    msg, blocked = probe(name, nr)
    tag = "ok   " if blocked else ("LEAK " if name in expect_blocked_default else "info ")
    print(f"{tag} {name:18s} {msg}")
PY
)"
  while IFS= read -r l; do
    case "$l" in
      "ok "*)   OKS=$((OKS+1));     say "  $l" ;;
      "LEAK "*) LEAKS=$((LEAKS+1)); printf '  %s\n' "$l" ;;
      "info "*) INFOS=$((INFOS+1)); say "  $l" ;;
      *) say "  $l" ;;
    esac
  done <<< "$SYS_OUT"
else
  info "skipped (needs x86_64 and python3)"
fi

# ---- filesystem
sec "filesystem"
# firejail --whitelist under /media or /mnt swaps that directory for a tmpfs holding only the
# whitelisted paths, so a game that lives under /mnt legitimately sees its own path there and nothing else
check_drive_root() {
  local r="$1" cur nxt rel e extras=""
  [ -d "$r" ] || { ok "$r does not exist"; return; }
  [ -n "$(ls -A "$r" 2>/dev/null)" ] || { ok "$r empty or hidden"; return; }
  case "$PWD/" in
    "$r"/*)
      cur="$r"
      while :; do
        rel="${PWD#"$cur"/}"; nxt="${rel%%/*}"
        while IFS= read -r e; do
          [ "$e" = "$nxt" ] && continue
          case "$e" in verify-sandbox.sh|verify-sandbox.sha256|_umu-run-wrapper) continue ;; esac
          extras="$extras $cur/$e"
        done < <(ls -A "$cur" 2>/dev/null)
        cur="$cur/$nxt"
        [ "$cur" = "$PWD" ] && break
      done
      if [ -z "$extras" ]; then ok "$r only shows the game's own path (firejail whitelist)"
      else leak "$r shows more than the game's path:$extras"; fi ;;
    *) leak "$r has contents: $(ls -A "$r" | head -n 5 | tr '\n' ' ')" ;;
  esac
}
for d in /media /run/media /mnt; do check_drive_root "$d"; done
n_home="$(ls -A "$HOME" 2>/dev/null | wc -l)"
info "\$HOME entries: $n_home -> $(ls -A "$HOME" 2>/dev/null | head -n 12 | tr '\n' ' ')"
for d in .ssh .gnupg .aws .kube .docker .config/chromium .mozilla .config/google-chrome .local/share/keyrings .bash_history .netrc .password-store; do
  [ -e "$HOME/$d" ] && leak "\$HOME/$d exists"
done
for f in /etc/shadow /etc/sudoers /root /etc/ssl/private; do
  if [ -r "$f" ] && { [ -f "$f" ] || [ -n "$(ls -A "$f" 2>/dev/null)" ]; }; then leak "$f readable"; else ok "$f not readable"; fi
done
others="$(ls /home 2>/dev/null | grep -vx "$(id -un)" | head -n 5 | tr '\n' ' ')"
[ -n "$others" ] && info "/home lists other entries: $others" || ok "/home shows nothing but yourself"
for d in /usr /etc /boot /bin; do
  if touch "$d/.wq-probe" 2>/dev/null; then rm -f "$d/.wq-probe"; leak "$d is writable"; else ok "$d not writable"; fi
done
if touch ./.wq-probe 2>/dev/null; then rm -f ./.wq-probe; info "cwd is writable ($(pwd))"; else info "cwd is read-only (FJ_GAME_RO?) ($(pwd))"; fi
for f in game.conf logs .reg-snapshot .home-snapshot launch-quarantine.sh; do
  for base in .. ../..; do
    [ -e "$base/$f" ] && leak "launcher file visible: $base/$f"
  done
done
tmpn="$(ls -A /tmp 2>/dev/null | wc -l)"
[ "$tmpn" -le 3 ] && ok "/tmp looks private ($tmpn entries)" || info "/tmp has $tmpn entries (FJ_PRIVATE_TMP off, or the game made them): $(ls -A /tmp | head -n 6 | tr '\n' ' ')"
info "/etc/machine-id: $(head -c 8 /etc/machine-id 2>/dev/null)... (compare with the host's: differs = spoofed)"
if [ -r /proc/1/root ]; then
  [ "$(readlink -f /proc/1/root)" = "$(readlink -f /)" ] && ok "/proc/1/root is our own root" || leak "/proc/1/root differs: $(readlink -f /proc/1/root)"
fi
mnt_shared="$(awk '{for(i=7;i<=NF&&$i!="-";i++) if ($i ~ /^shared:/) {print $5; break}}' /proc/self/mountinfo | head -n 3 | tr '\n' ' ')"
[ -z "$mnt_shared" ] && ok "no shared mount propagation" || leak "shared mounts: $mnt_shared"

# ---- devices
sec "devices"
[ -d /dev/input ] && nonempty /dev/input && leak "/dev/input readable: $(ls /dev/input | head -n 4 | tr '\n' ' ')" || ok "no raw input devices"
n_dev="$(ls -A /dev 2>/dev/null | wc -l)"
[ "$n_dev" -gt 60 ] && info "/dev has $n_dev entries (full host /dev: FJ_PRIVATE_DEV off?)" || ok "/dev is small ($n_dev entries)"
for d in /dev/mem /dev/kmem /dev/port /dev/kvm /dev/fuse /dev/uinput /dev/tun /dev/net/tun /dev/vhost-net; do
  [ -e "$d" ] && { [ -r "$d" ] || [ -w "$d" ]; } && leak "$d accessible"
done
ls /dev/sd* /dev/nvme* /dev/mmcblk* /dev/disk 2>/dev/null | head -n 3 | grep -q . && leak "block devices visible: $(ls -d /dev/sd* /dev/nvme* /dev/mmcblk* 2>/dev/null | head -n 4 | tr '\n' ' ')" || ok "no block devices visible"
for d in /dev/dri /dev/snd /dev/video0 /dev/bus/usb; do [ -e "$d" ] && info "$d visible"; done

# ---- sockets and environment
sec "host sockets and environment"
RT="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
# firejail --blacklist leaves a placeholder (an empty mode-000 file or directory), so the name can
# still exist. Only a real socket, or a directory you can still list, counts as reachable.
check_sock() {
  local s="$1"
  [ -e "$s" ] || return 0
  if [ -S "$s" ]; then
    if have python3; then
      if python3 -c 'import socket,sys; c=socket.socket(socket.AF_UNIX); c.settimeout(2); c.connect(sys.argv[1])' "$s" 2>/dev/null; then
        leak "socket accepts connections: $s"
      else
        info "socket exists but connect failed (permission or refused): $s"
      fi
    else
      leak "socket visible: $s"
    fi
  elif [ -d "$s" ]; then
    if [ -x "$s" ] && nonempty "$s"; then leak "directory readable: $s"; else ok "$s hidden (placeholder dir)"; fi
  else
    ok "$s is a placeholder, not a socket"
  fi
}
for s in /run/docker.sock /var/run/docker.sock /run/podman /run/libvirt /run/containerd \
         /run/systemd/private /run/systemd/resolve/io.systemd.Resolve /run/nscd/socket \
         "$RT/systemd/private" "$RT/gnupg" "$RT/gcr" "$RT/keyring" "$RT/ssh-agent.socket" "$RT/bus" "$RT/podman"; do
  check_sock "$s"
done
[ -z "${SSH_AUTH_SOCK:-}" ] && ok "SSH_AUTH_SOCK unset" || leak "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
case "${DBUS_SESSION_BUS_ADDRESS:-}" in
  "") ok "no session D-Bus address" ;;
  *firejail*) ok "D-Bus goes through firejail's filter" ;;
  *) leak "DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION_BUS_ADDRESS" ;;
esac
if [ -d /tmp/.X11-unix ] && [ -n "$(ls -A /tmp/.X11-unix 2>/dev/null)" ]; then
  info "X11 socket(s): $(ls /tmp/.X11-unix | tr '\n' ' ') DISPLAY=${DISPLAY:-unset}  (host X11 shared unless this is Xephyr: keystrokes/screens of other windows readable)"
fi
[ -n "${WAYLAND_DISPLAY:-}" ] && info "WAYLAND_DISPLAY=$WAYLAND_DISPLAY (Xephyr off, or the socket is still reachable)"
secrets="$(env | awk -F= 'toupper($1) !~ /^WQ_/ && toupper($1) ~ /(TOKEN|SECRET|PASSW|API_?KEY|CREDENTIAL|PRIVATE_?KEY)/ {print $1}' | tr '\n' ' ')"
[ -z "$secrets" ] && ok "no secret-looking environment variables" || leak "secret-looking env vars present: $secrets"

# ---- network
sec "network (target $NET_TARGET)"
ifs="$(awk -F: 'NR>2 {gsub(/ /,"",$1); if ($1!="lo") print $1}' /proc/net/dev | tr '\n' ' ')"
[ -z "$ifs" ] && ok "only loopback in this namespace" || info "interfaces: $ifs"
host="${NET_TARGET%:*}"; port="${NET_TARGET##*:}"
if timeout 4 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
  info "TCP connect to $NET_TARGET SUCCEEDED (expected only if you allowed it)"
else
  ok "TCP connect to $NET_TARGET failed"
fi
if have getent; then
  if timeout 4 getent hosts example.com >/dev/null 2>&1; then
    info "DNS lookup of example.com worked (leak channel if the network is meant to be off)"
  else
    ok "DNS lookup failed"
  fi
fi
if have python3; then
  python3 - <<'PY' 2>&1 | sed 's/^/  /'
import socket
for fam, name in ((socket.AF_INET6, "IPv6"), (socket.AF_PACKET if hasattr(socket, "AF_PACKET") else None, "AF_PACKET raw"), (getattr(socket, "AF_NETLINK", None), "AF_NETLINK")):
    if fam is None: continue
    try:
        s = socket.socket(fam, socket.SOCK_RAW if name != "IPv6" else socket.SOCK_STREAM)
        s.close(); print(f"info  {name} socket can be created")
    except OSError as e:
        print(f"ok    {name} socket refused ({e.strerror})")
PY
fi

# ---- fileless execution
sec "memfd_create (FJ_MEMFD)"
if have python3; then
  if python3 -c 'import os,sys; os.close(os.memfd_create("wq")); sys.exit(0)' 2>/dev/null; then
    info "memfd_create works: a payload can be built and run from memory without touching disk (FJ_MEMFD off)"
  else
    ok "memfd_create refused"
  fi
else
  info "no python3 in the sandbox, memfd_create not tested"
fi

# ---- write+execute memory
sec "write+execute memory (FJ_MDWX)"
if have python3; then
  if python3 -c 'import mmap,sys; mmap.mmap(-1, 4096, prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)' 2>/dev/null; then
    info "a writable+executable page can be mapped: in-process shellcode and loaders work (FJ_MDWX off)"
  else
    ok "writable+executable memory refused"
  fi
else
  info "no python3 in the sandbox, write+execute memory not tested"
fi

# ---- limits and visibility
sec "limits and process visibility"
cg="$(cut -d: -f3 /proc/self/cgroup 2>/dev/null | head -n1)"
for f in pids.max memory.max; do
  v="$(cat "/sys/fs/cgroup$cg/$f" 2>/dev/null || true)"
  [ -n "$v" ] && info "cgroup $f = $v" || info "cgroup $f not readable here"
done
nproc_vis="$(ls /proc 2>/dev/null | grep -c '^[0-9]\+$')"
[ "$nproc_vis" -le 30 ] && ok "own PID namespace ($nproc_vis processes visible)" || info "$nproc_vis processes visible (host processes shared?)"
if ls /proc/[0-9]*/environ >/dev/null 2>&1; then
  n_env=0
  for e in /proc/[0-9]*/environ; do [ -r "$e" ] && [ "${e#/proc/}" != "self/environ" ] && n_env=$((n_env+1)); done
  [ "$n_env" -gt 3 ] && leak "can read the environment of $n_env other processes (same uid): secrets in other apps' env"
fi

# ---- summary
echo ""
echo "== summary: $LEAKS leak(s), $OKS ok, $INFOS info"
[ "$LEAKS" -eq 0 ] && echo "   nothing above counts as a hole for the current profile" || echo "   re-read the LEAK lines: each one is something this game could use"
exit 0
