#!/bin/bash
# Tests for the /dev blocking, launch script and xephyr bits of profile.sh.
# No firejail or game needed, it only checks the arguments profile.sh builds.
#   bash wq-ui/test_profile.sh
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
ok()  { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; fail=1; }

# any real device node that isn't essential
DEV="$(find /dev -maxdepth 1 \( -type c -o -type b \) ! -name null ! -name zero ! -name full ! -name random \
        ! -name urandom ! -name tty ! -name ptmx -print 2>/dev/null | head -n1)"
[ -n "$DEV" ] || { echo "no usable /dev node on this machine, skipping"; exit 0; }

mkdir -p "$T/G/game"
printf 'echo pre; touch "$WQ_GAMEDIR/pre.ran"\n'   > "$T/pre.sh"
printf 'echo post; touch "$WQ_GAMEDIR/post.ran"\n' > "$T/post.sh"
printf 'exit 3\n'                                   > "$T/fail.sh"

run() {   # run <conf lines...>  -> prints the resulting firejail args, one per line
    printf '%s\n' "$@" > "$T/G/game.conf"
    rm -f "$T/G/pre.ran" "$T/G/post.ran"
    bash -c '
        set -euo pipefail
        QROOT="$1"; SECCOMP_DROP=keyctl
        QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
        WQ_LIMITS_SUPPORTED="${TEST_LIMITS_SUPPORTED:-1}"
        . "$2/profile.sh"
        apply_game_profile "$1/G"
        printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
    ' _ "$T" "$HERE" 2>"$T/err"
}

out="$(run EXE=a.exe "FJ_DEV_BLOCK=$DEV" "FJ_DEV_BLOCK=$DEV")"
[ "$(grep -c -- "--blacklist=$(readlink -f "$DEV")" <<<"$out")" -eq 1 ] && ok "device blocked once (duplicates collapsed)" || bad "device blacklist"

out="$(run EXE=a.exe FJ_DEV_BLOCK=/dev/null FJ_DEV_BLOCK=/dev/tty FJ_DEV_BLOCK=/dev/shm FJ_DEV_BLOCK=/etc/passwd \
          FJ_DEV_BLOCK=/dev/../etc/passwd FJ_DEV_BLOCK=/dev/ FJ_DEV_BLOCK=/dev/does-not-exist)"
grep -qE -- '--blacklist=/(dev|etc)' <<<"$out" && bad "unsafe device entries were not refused" || ok "essential / outside-/dev / traversal / missing entries refused"

out="$(run EXE=a.exe "FJ_HOOK_PRE=$T/pre.sh" "FJ_HOOK_POST=$T/post.sh")"; rc=$?
[ -e "$T/G/pre.ran" ] && ok "before-launch script ran" || bad "pre hook did not run"
[ -e "$T/G/post.ran" ] && ok "after-exit script ran at launcher exit" || bad "post hook did not run"

run EXE=a.exe "FJ_HOOK_PRE=$T/fail.sh" "FJ_HOOK_POST=$T/post.sh" >/dev/null; rc=$?
[ "$rc" -ne 0 ] && ok "failing before-launch script cancels the launch" || bad "launch not cancelled"
[ ! -e "$T/G/post.ran" ] && ok "no after-exit script when the launch was cancelled" || bad "post hook ran after cancel"

run EXE=a.exe FJ_HOOK_PRE=relative.sh FJ_HOOK_POST=/nonexistent.sh >/dev/null; rc=$?
[ "$rc" -eq 0 ] && ok "relative / missing script paths are ignored, launch continues" || bad "bad hook paths broke the launch"

# hook paths are only honoured per game, never from the shared defaults file
printf 'FJ_HOOK_PRE=%s\n' "$T/pre.sh" > "$T/profile.defaults.conf"
run EXE=a.exe >/dev/null
[ ! -e "$T/G/pre.ran" ] && ok "defaults file cannot attach scripts" || bad "hook taken from defaults file"

# xephyr mode should hide the wayland sockets too (exact paths, .lock included)
mkdir -p "$T/bin" "$T/xdg"; printf '#!/bin/sh\n' > "$T/bin/Xephyr"; chmod +x "$T/bin/Xephyr"
touch "$T/xdg/wayland-9" "$T/xdg/wayland-9.lock" "$T/xdg/bus"
out="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
grep -q -- '--x11=xephyr' <<<"$out" && grep -q -- '--rmenv=WAYLAND_DISPLAY' <<<"$out" \
  && grep -qx "ARG --blacklist=$T/xdg/wayland-9" <<<"$out" && grep -qx "ARG --blacklist=$T/xdg/wayland-9.lock" <<<"$out" \
  && ! grep -q -- "xdg/bus" <<<"$out" && ok "Xephyr mode hides the Wayland sockets (and only those)" || bad "wayland not hidden: $out"

# ---------------------------------------------------------------------------
# resolver sockets, machine-id, seccomp extras, extra options, cgroup limits
# ---------------------------------------------------------------------------
rm -f "$T/profile.defaults.conf"

runp() {   # like run, but also prints the cgroup prefix and the stderr
    printf '%s\n' "$@" > "$T/G/game.conf"
    bash -c '
        set -euo pipefail
        QROOT="$1"; SECCOMP_DROP=keyctl
        QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
        WQ_LIMITS_SUPPORTED="${TEST_LIMITS_SUPPORTED:-1}"
        . "$2/profile.sh"
        apply_game_profile "$1/G"
        printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
        printf "PFX %s\n" ${WQ_LIMIT_PREFIX[@]+"${WQ_LIMIT_PREFIX[@]}"}
    ' _ "$T" "$HERE" 2>"$T/err"
}

out="$(run EXE=a.exe)"
for a in --machine-id --blacklist=/run/systemd/resolve --blacklist=/run/nscd --blacklist=/var/run/nscd \
         --blacklist=/run/systemd/private --blacklist=/run/containerd; do
    grep -qx -- "ARG $a" <<<"$out" || bad "default profile is missing $a"
done
grep -qx -- 'ARG --machine-id' <<<"$out" && grep -qx -- 'ARG --blacklist=/run/systemd/resolve' <<<"$out" \
    && ok "defaults: machine-id spoofed, DNS resolver and manager sockets hidden"
[ "$(grep -c -- '--machine-id' <<<"$out")" -eq 1 ] && ok "machine-id appears once" || bad "machine-id duplicated"

out="$(run EXE=a.exe FJ_MACHINE_ID=0)"
grep -q -- '--machine-id' <<<"$out" && bad "FJ_MACHINE_ID=0 ignored" || ok "FJ_MACHINE_ID=0 turns machine-id spoofing off"

out="$(run EXE=a.exe FJ_BLOCK_SOCKETS=0)"
grep -q -- 'systemd/resolve' <<<"$out" && bad "FJ_BLOCK_SOCKETS=0 still blocks the resolver" || ok "FJ_BLOCK_SOCKETS=0 leaves the resolver socket alone"

out="$(run EXE=a.exe FJ_NET=1 FJ_NET_OPEN=1)"
grep -q -- 'systemd/resolve' <<<"$out" && bad "resolver hidden in open-network mode" || ok "open-network mode keeps the resolver (it needs the stub)"

# a stale config.local.sh array that already has these flags must not duplicate them
out="$(printf 'EXE=a.exe\n' > "$T/G/game.conf"; bash -c '
    set -euo pipefail; QROOT="$1"; SECCOMP_DROP=keyctl
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --machine-id --blacklist=/run/systemd/resolve --rlimit-nofile=5000)
    . "$2/profile.sh"; apply_game_profile "$1/G"; printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"' _ "$T" "$HERE")"
[ "$(grep -c -- '--machine-id' <<<"$out")" -eq 1 ] && [ "$(grep -c -- 'systemd/resolve' <<<"$out")" -eq 1 ] \
    && grep -qx -- 'ARG --rlimit-nofile=5000' <<<"$out" && ok "managed flags in config.local.sh are not duplicated, unmanaged ones are kept" \
    || bad "duplicate/lost flags from a local array: $out"

# --- seccomp extras
out="$(run EXE=a.exe FJ_SECCOMP_EXTRA=bpf,ptrace)"
grep -qx -- 'ARG --seccomp.drop=keyctl,bpf,ptrace' <<<"$out" && ok "FJ_SECCOMP_EXTRA is appended to the drop list" || bad "seccomp extra: $out"
run EXE=a.exe 'FJ_SECCOMP_EXTRA=bpf;reboot' >/dev/null; rc=$?
[ "$rc" -ne 0 ] && ok "bad syscall list cancels the launch" || bad "bad syscall list accepted"

# --- extra firejail options
out="$(run EXE=a.exe FJ_EXTRA_ARGS=--timeout=02:00:00 FJ_EXTRA_ARGS=--rlimit-fsize=2000000000 FJ_EXTRA_ARGS=--blacklist=/mnt/secret \
        'FJ_EXTRA_ARGS=# a comment' FJ_EXTRA_ARGS=--nosound FJ_EXTRA_ARGS=--machine-id FJ_EXTRA_ARGS=--rlimit-nproc=99999999)"; rc=$?
ok_all=1
for a in --timeout=02:00:00 --rlimit-fsize=2000000000 --blacklist=/mnt/secret --nosound --rlimit-nproc=99999999; do
    grep -qx -- "ARG $a" <<<"$out" || ok_all=0
done
grep -q -- 'comment' <<<"$out" && ok_all=0
[ "$(grep -c -- '--machine-id' <<<"$out")" -eq 1 ] || ok_all=0
[ "$rc" -eq 0 ] && [ "$ok_all" -eq 1 ] && ok "allowed extra options pass through (comment skipped, duplicate collapsed)" || bad "extra options: rc=$rc $out"

for badarg in --net=eth0 --noprofile --ignore=nonewprivs --whitelist=/home --netfilter=/tmp/x --allow-debuggers \
              --blacklist=/a/../b --blacklist='/a b' '--blacklist=$HOME' --seccomp.drop=keyctl --timeout=99 \
              --nice=-5 --nice=20 --rlimit-nproc=abc --shell=none --private-etc=x 'nosound' '--nosound --net=eth0'; do
    run EXE=a.exe "FJ_EXTRA_ARGS=$badarg" >/dev/null; rc=$?
    [ "$rc" -ne 0 ] || bad "extra option was accepted: $badarg"
done
ok "options that loosen the sandbox, or are malformed, cancel the launch"

run EXE=a.exe FJ_EXTRA_ARGS=--rlimit-nproc=300 >/dev/null; rc=$?
[ "$rc" -ne 0 ] && grep -q 'FJ_TASKS_MAX' "$T/err" && ok "--rlimit-nproc below the user's task count is refused, with a pointer to FJ_TASKS_MAX" \
    || bad "low --rlimit-nproc accepted (rc=$rc)"

# defaults file vs game.conf: game.conf wins as a whole, an empty line means "none"
printf 'FJ_EXTRA_ARGS=--timeout=01:00:00\n' > "$T/profile.defaults.conf"
out="$(run EXE=a.exe)"
grep -qx -- 'ARG --timeout=01:00:00' <<<"$out" && ok "extra options fall back to the defaults file" || bad "defaults not used"
out="$(run EXE=a.exe FJ_EXTRA_ARGS=--timeout=03:00:00)"
grep -qx -- 'ARG --timeout=03:00:00' <<<"$out" && ! grep -q -- '01:00:00' <<<"$out" && ok "game.conf replaces the defaults" || bad "game did not override: $out"
out="$(run EXE=a.exe FJ_EXTRA_ARGS=)"
grep -q -- '--timeout' <<<"$out" && bad "empty FJ_EXTRA_ARGS= did not clear the defaults" || ok "an empty FJ_EXTRA_ARGS= line means none"
rm -f "$T/profile.defaults.conf"

# --- cgroup limits (systemd-run is stubbed: the real thing needs a user session)
mkdir -p "$T/sd-ok" "$T/sd-bad"
printf '#!/bin/sh\nexit 0\n'  > "$T/sd-ok/systemd-run";  chmod +x "$T/sd-ok/systemd-run"
printf '#!/bin/sh\nexit 1\n'  > "$T/sd-bad/systemd-run"; chmod +x "$T/sd-bad/systemd-run"

out="$(PATH="$T/sd-ok:$PATH" runp EXE=a.exe)"
[ "$(grep -c '^PFX' <<<"$out")" -eq 1 ] && ! grep -q 'systemd-run' <<<"$out" && ok "no limits set: launcher is not wrapped" || bad "unexpected wrapper: $out"

out="$(PATH="$T/sd-ok:$PATH" runp EXE=a.exe FJ_TASKS_MAX=4096 FJ_MEMORY_MAX=8G)"
grep -qx 'PFX systemd-run' <<<"$out" && grep -qx 'PFX TasksMax=4096' <<<"$out" && grep -qx 'PFX MemoryMax=8G' <<<"$out" \
    && grep -qx 'PFX --user' <<<"$out" && grep -qx 'PFX --scope' <<<"$out" && grep -qx 'PFX --' <<<"$out" \
    && ok "task and memory limits become a systemd-run --user --scope prefix" || bad "limit prefix: $out"

out="$(PATH="$T/sd-ok:$PATH" runp EXE=a.exe FJ_TASKS_MAX=4096)"
grep -q 'MemoryMax' <<<"$out" && bad "memory limit set without being asked" || ok "only the requested limits are applied"

PATH="$T/sd-bad:$PATH" run EXE=a.exe FJ_TASKS_MAX=4096 >/dev/null; rc=$?
[ "$rc" -ne 0 ] && grep -q 'systemd-run' "$T/err" && ok "limits requested but systemd-run fails: launch cancelled (fail closed)" || bad "limits silently dropped (rc=$rc)"

for badv in FJ_TASKS_MAX=0 FJ_TASKS_MAX=abc FJ_TASKS_MAX=-5 FJ_TASKS_MAX='10 20' FJ_MEMORY_MAX=8GB FJ_MEMORY_MAX=0 FJ_MEMORY_MAX='8G;ls'; do
    PATH="$T/sd-ok:$PATH" run EXE=a.exe "$badv" >/dev/null; rc=$?
    [ "$rc" -ne 0 ] || bad "bad limit accepted: $badv"
done
ok "malformed limits cancel the launch"

# a launcher that does not wrap firejail must not be allowed to run a game "limited"
TEST_LIMITS_SUPPORTED=0 PATH="$T/sd-ok:$PATH" run EXE=a.exe FJ_TASKS_MAX=4096 >/dev/null; rc=$?
[ "$rc" -ne 0 ] && grep -q 'does not apply' "$T/err" && ok "limits requested but the launcher cannot apply them: launch cancelled" || bad "limits ignored by an unaware launcher (rc=$rc)"
TEST_LIMITS_SUPPORTED=0 run EXE=a.exe >/dev/null; rc=$?
[ "$rc" -eq 0 ] && ok "an unaware launcher still works when no limits are set" || bad "unaware launcher broke without limits"

printf 'FJ_TASKS_MAX=2048\n' > "$T/profile.defaults.conf"
out="$(PATH="$T/sd-ok:$PATH" runp EXE=a.exe)"
grep -qx 'PFX TasksMax=2048' <<<"$out" && ok "limits can come from the defaults file" || bad "defaults limit ignored"
rm -f "$T/profile.defaults.conf"

exit $fail
