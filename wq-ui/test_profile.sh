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
        . "$2/profile.sh"
        apply_game_profile "$1/G"
        printf "ARG %s\n" "${QUARANTINE_FIREJAIL_ARGS[@]}"
    ' _ "$T" "$HERE" 2>"$T/err"
}

out="$(run EXE=a.exe "FJ_DEV_BLOCK=$DEV" "FJ_DEV_BLOCK=$DEV")"
[ "$(grep -c -- "--blacklist=$(readlink -f "$DEV")" <<<"$out")" -eq 1 ] && ok "device blocked once (duplicates collapsed)" || bad "device blacklist"

out="$(run EXE=a.exe FJ_DEV_BLOCK=/dev/null FJ_DEV_BLOCK=/dev/tty FJ_DEV_BLOCK=/dev/shm FJ_DEV_BLOCK=/etc/passwd \
          FJ_DEV_BLOCK=/dev/../etc/passwd FJ_DEV_BLOCK=/dev/ FJ_DEV_BLOCK=/dev/does-not-exist)"
grep -q -- '--blacklist' <<<"$out" && bad "unsafe device entries were not refused" || ok "essential / outside-/dev / traversal / missing entries refused"

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

exit $fail
