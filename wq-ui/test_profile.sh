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

# blhidden <path>: true if <path> ends up blacklisted via the generated firejail profile file
# (siblings and other-drive mounts are collapsed into one --profile=<file> instead of many
# --blacklist=<path> arguments, to stay under firejail's own argument-count limit; see profile.sh)
blhidden() {
    grep -qxF -- "ARG --profile=$T/G/logs/.fj-blacklist.profile" <<<"$2" || return 1
    grep -qxF -- "blacklist $1" "$T/G/logs/.fj-blacklist.profile" 2>/dev/null
}

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

# a hook the game could rewrite must not run on the host (rc 2 in _wq_hook_path)
rm -f "$T/profile.defaults.conf"
mkdir -p "$T/G/game" "$T/wlrw"
printf 'touch "$WQ_GAMEDIR/evil.ran"\n' > "$T/G/game/hook.sh"; cp "$T/G/game/hook.sh" "$T/wlrw/hook.sh"
rm -f "$T/G/evil.ran"
run EXE=a.exe "FJ_HOOK_PRE=$T/G/game/hook.sh" >/dev/null; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$T/G/evil.ran" ] && ok "before-launch script inside game/ is refused and cancels the launch" || bad "hook inside game/ was run (rc=$rc)"
grep -q 'refusing' "$T/err" && ok "and says why" || bad "no explanation for the refused hook"
run EXE=a.exe "FJ_HOOK_PRE=$T/wlrw/hook.sh" "FJ_WL_RW=$T/wlrw" >/dev/null; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$T/G/evil.ran" ] && ok "a script in a read-write whitelisted folder is refused too" || bad "hook in a rw whitelisted folder was run"
run EXE=a.exe "FJ_HOOK_POST=$T/G/game/hook.sh" >/dev/null; rc=$?
[ "$rc" -eq 0 ] && [ ! -e "$T/G/evil.ran" ] && ok "after-exit script inside game/ never runs" || bad "post hook inside game/ ran"
ln -sf "$T/G/game/hook.sh" "$T/link-to-hook.sh"
run EXE=a.exe "FJ_HOOK_PRE=$T/link-to-hook.sh" >/dev/null; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$T/G/evil.ran" ] && ok "a symlink to a script inside game/ is refused (path is resolved)" || bad "symlinked hook was run"

# same-user sockets in the runtime dir (systemd/private, gpg-agent, ssh-agent) are blacklisted when present
mkdir -p "$T/rt/systemd" "$T/rt/gnupg"; touch "$T/rt/ssh-agent.socket"
out="$(WQ_RUNTIME_DIR="$T/rt" run EXE=a.exe)"
for n in systemd gnupg ssh-agent.socket; do
  grep -qxF -- "ARG --blacklist=$T/rt/$n" <<<"$out" && ok "runtime socket $n is blacklisted" || bad "runtime socket $n not blacklisted"
done
grep -qF -- "$T/rt/gcr" <<<"$out" && bad "absent socket was listed" || ok "sockets that do not exist are not listed"
out="$(WQ_RUNTIME_DIR="$T/rt" run EXE=a.exe FJ_BLOCK_SOCKETS=0)"
# $T/rt itself is a neighbour of the game folder (hidden by the neighbour rule), so test its children
grep -qF -- "$T/rt/" <<<"$out" && bad "FJ_BLOCK_SOCKETS=0 still blacklisted runtime sockets" || ok "FJ_BLOCK_SOCKETS=0 turns the runtime socket blacklist off"

# xephyr mode should hide the wayland sockets too (exact paths, .lock included)
mkdir -p "$T/bin" "$T/xdg"; printf '#!/bin/sh\n' > "$T/bin/Xephyr"; chmod +x "$T/bin/Xephyr"
# stub firejail so the result doesn't depend on whatever is installed here (new firejail by default)
fjstub() { printf '#!/bin/sh\n[ "$1" = --version ] && { echo "firejail version %s"; exit 0; }\nexit 0\n' "$1" > "$T/bin/firejail"; chmod +x "$T/bin/firejail"; }
fjstub 0.9.82.2
touch "$T/xdg/wayland-9" "$T/xdg/wayland-9.lock" "$T/xdg/bus"
out="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
grep -qx -- 'ARG --x11' <<<"$out" && ! grep -q -- '--x11=xephyr' <<<"$out" && grep -q -- '--rmenv=WAYLAND_DISPLAY' <<<"$out" \
  && grep -qx "ARG --blacklist=$T/xdg/wayland-9" <<<"$out" && grep -qx "ARG --blacklist=$T/xdg/wayland-9.lock" <<<"$out" \
  && ! grep -q -- "xdg/bus" <<<"$out" && ok "Xephyr mode hides the Wayland sockets (and only those)" || bad "wayland not hidden: $out"

# firejail < 0.9.82 still needs the explicit --x11=xephyr; >= 0.9.82 removed it (plain --x11 is Xephyr)
for v in 0.9.72 0.9.80 0.9.81.9; do
  fjstub "$v"
  o="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
  grep -qx -- 'ARG --x11=xephyr' <<<"$o" && ! grep -qx -- 'ARG --x11' <<<"$o" && ok "firejail $v gets --x11=xephyr" || bad "firejail $v: $o"
done
for v in 0.9.82 0.9.82.2 0.9.84 1.0.0; do
  fjstub "$v"
  o="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
  grep -qx -- 'ARG --x11' <<<"$o" && ! grep -q -- '--x11=xephyr' <<<"$o" && ok "firejail $v gets plain --x11" || bad "firejail $v: $o"
done
printf '#!/bin/sh\nexit 1\n' > "$T/bin/firejail"; chmod +x "$T/bin/firejail"
o="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
grep -qx -- 'ARG --x11' <<<"$o" && ok "unreadable firejail version falls back to plain --x11" || bad "unknown version: $o"
fjstub 0.9.82.2
# a bare --x11 already in QUARANTINE_FIREJAIL_ARGS must not be duplicated
o="$(printf '%s\n' EXE=a.exe FJ_XEPHYR=1 > "$T/G/game.conf"; PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" bash -c '
    set -euo pipefail
    QROOT="$1"; SECCOMP_DROP=keyctl; WQ_LIMITS_SUPPORTED=1
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all --x11)
    . "$2/profile.sh"; apply_game_profile "$1/G"
    printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"' _ "$T" "$HERE" 2>/dev/null)"
[ "$(grep -cx -- 'ARG --x11' <<<"$o")" -eq 1 ] && ok "a pre-existing bare --x11 is not duplicated" || bad "x11 duplicated: $o"

# xephyr mode must also force an X11-only environment (a leaked PROTON_ENABLE_WAYLAND=1 leaves Wine with no
# monitors), dropping SDL_VIDEODRIVER (never forcing it), and flags already in QUARANTINE_FIREJAIL_ARGS must not be duplicated
grep -qx -- 'ARG --env=PROTON_ENABLE_WAYLAND=0' <<<"$out" && grep -qx -- 'ARG --env=XDG_SESSION_TYPE=x11' <<<"$out" \
  && grep -qx -- 'ARG --rmenv=SDL_VIDEODRIVER' <<<"$out" && ! grep -q -- '--env=SDL_VIDEODRIVER' <<<"$out" && [ "$(grep -c -- 'PROTON_ENABLE_WAYLAND' <<<"$out")" -eq 1 ] \
  && ok "Xephyr mode forces an X11-only environment" || bad "no X11-only env in Xephyr mode: $out"
out="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe)"
grep -q -- 'PROTON_ENABLE_WAYLAND' <<<"$out" && bad "X11-only env leaked into a non-Xephyr launch" || ok "X11-only env only applied in Xephyr mode"

# the wrapper sizes the Wine virtual desktop from the Xephyr size: default and explicit
out="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1)"
out2="$(PATH="$T/bin:$PATH" XDG_RUNTIME_DIR="$T/xdg" run EXE=a.exe FJ_XEPHYR=1 FJ_XEPHYR_SIZE=1920x1080)"
grep -qx -- 'ARG --env=WQ_XEPHYR_SIZE=800x600' <<<"$out" && ! grep -q -- '--xephyr-screen' <<<"$out" \
  && grep -qx -- 'ARG --env=WQ_XEPHYR_SIZE=1920x1080' <<<"$out2" && grep -qx -- 'ARG --xephyr-screen=1920x1080' <<<"$out2" \
  && ok "Xephyr size is passed to the wrapper (default 800x600)" || bad "WQ_XEPHYR_SIZE wrong: $out / $out2"

# resolver sockets, machine-id, seccomp extras, extra options, cgroup limits
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

# other drives (FJ_BLOCK_MEDIA) and read-only game/ (FJ_GAME_RO)
for d in /media /run/media /mnt; do
    [ -e "$d" ] || continue
    out="$(run EXE=a.exe)"
    blhidden "$(readlink -f "$d")" "$out" && ok "$d hidden by default" || bad "$d not hidden by default"
    out="$(run EXE=a.exe FJ_BLOCK_MEDIA=0)"
    grep -q -- "--blacklist=$(readlink -f "$d")\$" <<<"$out" && bad "FJ_BLOCK_MEDIA=0 still hides $d" || ok "FJ_BLOCK_MEDIA=0 leaves $d alone"
    mkdir -p "$T/wl"
    out="$(run EXE=a.exe "FJ_WL_RO=$(readlink -f "$d")")"
    grep -q 'not hiding' "$T/err" && ! grep -qx -- "ARG --blacklist=$(readlink -f "$d")" <<<"$out" \
        && ok "$d left visible when a whitelisted path is under it" || bad "$d hidden although a whitelisted path is under it"
    break
done

gr() {   # gr <conf lines...> -> extra whitelist args
    printf '%s\n' "$@" > "$T/G/game.conf"
    bash -c 'QROOT="$1"; . "$2/profile.sh"; GAMEDIR="$1/G"; profile_extra_whitelist_args' _ "$T" "$HERE" 2>/dev/null
}
gr EXE=a.exe | grep -q -- '--read-only=.*/G/game$' && bad "game/ read-only without FJ_GAME_RO" || ok "game/ stays writable by default"
gr EXE=a.exe FJ_GAME_RO=1 | grep -q -- "--read-only=$(readlink -f "$T/G/game")\$" && ok "FJ_GAME_RO=1 makes game/ read-only" || bad "FJ_GAME_RO=1 gave no --read-only"

# the five formerly hidden toggles really switch their flag off
for pair in FJ_NOGROUPS:--nogroups FJ_PRIVATE_DEV:--private-dev FJ_NOINPUT:--noinput; do
    k="${pair%%:*}"; f="${pair#*:}"
    # capture first: grep -q exiting early would SIGPIPE run under pipefail and flip the result
    out="$(run EXE=a.exe)"
    grep -qx -- "ARG $f" <<<"$out" && ok "$k on by default" || bad "$k not on by default"
    out="$(run EXE=a.exe "$k=0")"
    grep -qx -- "ARG $f" <<<"$out" && bad "$k=0 still passes $f" || ok "$k=0 drops $f"
done

# a project folder with lots of siblings (many games/files next to this one) must still produce
# a SHORT argument list: this is the exact bug firejail hit as "too many arguments: argc (N) >=
# arg-max-count (128)" when every sibling was its own --blacklist=<path> argument.
rm -rf "$T/manysibs"; mkdir -p "$T/manysibs/G/game" "$T/manysibs/G/logs"
printf 'EXE=a.exe\n' > "$T/manysibs/G/game.conf"
for i in $(seq 1 150); do : > "$T/manysibs/sib$i"; done
out="$(bash -c '
    set -euo pipefail
    QROOT="$1"; SECCOMP_DROP=keyctl
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
    WQ_LIMITS_SUPPORTED=1
    . "$2/profile.sh"
    apply_game_profile "$1/manysibs/G"
    printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
' _ "$T" "$HERE" 2>"$T/err150")"
n=$(grep -c '^ARG ' <<<"$out")
[ "$n" -lt 40 ] && ok "150 siblings still produce a short argument list ($n args)" \
    || bad "150 siblings produce a short argument list" "$n arguments (expected well under firejail's 128 cap)"
grep -qxF -- "ARG --profile=$T/manysibs/G/logs/.fj-blacklist.profile" <<<"$out" \
    && ok "150 siblings: collapsed into the generated profile file" || bad "150 siblings: no generated profile file referenced"
# the file also carries the default media-mount blacklist entries; count only the sibling ones
[ "$(grep -c -- "^blacklist $T/manysibs/sib" "$T/manysibs/G/logs/.fj-blacklist.profile" 2>/dev/null)" -eq 150 ] \
    && ok "150 siblings: all 150 are listed in the generated profile file" || bad "150 siblings: not all listed in the generated profile file"

# firejail refuses --noprofile together with --profile=<file>; the launch then dies before the game
# starts. Whenever the generated profile is passed, --noprofile must be gone from the final arguments.
out="$(bash -c '
    set -euo pipefail
    QROOT="$1"; SECCOMP_DROP=keyctl
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
    WQ_LIMITS_SUPPORTED=1
    . "$2/profile.sh"
    apply_game_profile "$1/manysibs/G"
    printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
' _ "$T" "$HERE" 2>"$T/errnp")"
grep -qxF -- "ARG --profile=$T/manysibs/G/logs/.fj-blacklist.profile" <<<"$out" \
    && ! grep -qxF -- "ARG --noprofile" <<<"$out" \
    && ok "--profile=<file> and --noprofile never appear together" \
    || bad "--noprofile still passed alongside --profile=<file> (firejail refuses this)"
# with no generated profile (siblings and media hiding off), --noprofile is left alone
out="$(run EXE=a.exe FJ_HIDE_SIBLINGS=0 FJ_BLOCK_MEDIA=0)"
grep -qxF -- "ARG --noprofile" <<<"$out" && ! grep -q -- "^ARG --profile=" <<<"$out" \
    && ok "no generated profile: --noprofile is kept" || bad "--noprofile wrongly dropped when no profile file is used"
# a stand-in firejail that refuses the pair the way the real one does
mkdir -p "$T/fjbin"
cat > "$T/fjbin/firejail" <<'S'
#!/bin/bash
np=0; pr=0
for a in "$@"; do case "$a" in --noprofile) np=1 ;; --profile=*) pr=1 ;; esac; done
[ "$np$pr" = 11 ] && { echo "Error: --noprofile and --profile options are mutually exclusive" >&2; exit 1; }
exit 0
S
chmod +x "$T/fjbin/firejail"
out="$(PATH="$T/fjbin:$PATH" bash -c '
    set -euo pipefail
    QROOT="$1"; SECCOMP_DROP=keyctl
    QUARANTINE_FIREJAIL_ARGS=(--noprofile --net=none --private --nonewprivs --caps.drop=all)
    WQ_LIMITS_SUPPORTED=1
    . "$2/profile.sh"; . "$2/../lib-firejail.sh"
    apply_game_profile "$1/manysibs/G"
    wq_firejail_check "${QUARANTINE_FIREJAIL_ARGS[@]}" && echo DRYRUN_OK
' _ "$T" "$HERE" 2>&1)"
grep -q DRYRUN_OK <<<"$out" && ok "dry-run of the final argument list is accepted by a strict firejail" \
    || bad "strict firejail refuses the final argument list" "$out"

# neighbours of the game folder: hidden, except the launcher files the sandbox needs
mkdir -p "$T/otherGame" && : > "$T/verify-sandbox.sh" && : > "$T/config.sh"
out="$(run EXE=a.exe)"
blhidden "$T/otherGame" "$out" && ok "a neighbouring game folder is hidden" || bad "neighbouring game folder not hidden"
blhidden "$T/config.sh" "$out" && ok "launcher config.sh is hidden" || bad "config.sh not hidden"
grep -qF -- "--blacklist=$T/verify-sandbox.sh" <<<"$out" && bad "verify-sandbox.sh was hidden (the sandbox needs it)" || ok "verify-sandbox.sh stays visible"
out="$(run EXE=a.exe FJ_HIDE_SIBLINGS=0)"
grep -qF -- "--blacklist=$T/otherGame" <<<"$out" && bad "FJ_HIDE_SIBLINGS=0 still hid neighbours" || ok "FJ_HIDE_SIBLINGS=0 turns the neighbour rule off"

exit $fail
