# wq-ui/profile.sh - per-game firejail profile, written by the Qt UI.
#
# Sourced at the end of config.sh (see integrate.py). Settings are read as
# DATA from, in order of priority:
#     <game>/game.conf            per-game overrides
#     <QROOT>/profile.defaults.conf   defaults saved from the UI
#     built-in defaults below     identical to the stock wine-quarantine sandbox
# Nothing is ever sourced or eval'd, same rule as read_game_conf.
#
# Keys (value 1/0 unless noted):
#   FJ_PRIVATE_HOME FJ_PRIVATE_TMP FJ_NONEWPRIVS FJ_CAPS_DROP FJ_NODBUS
#   FJ_SECCOMP FJ_NOROOT FJ_NOSOUND FJ_NOU2F FJ_NOVIDEO FJ_NOTV FJ_NODVD
#   FJ_NET          1 = give the sandbox a network interface (0 = --net=none)
#   FJ_NET_OPEN     1 = no filtering at all (only meaningful with FJ_NET=1)
#   FJ_NET_IFACE    host interface for --net=IFACE (e.g. enp5s0, br0)
#   FJ_NET_DNS      1 = also allow udp/53 out
#   FJ_NET_LOG      1 = firejail --trace (log connect() attempts)
#   FJ_NET_ALLOW    repeatable, "tcp:1.2.3.4:443" / "udp:10.0.0.0/8:*"
#   FJ_XEPHYR       1 = --x11=xephyr (private X server)
#   FJ_XEPHYR_SIZE  "1920x1080"
#   FJ_WL_RW / FJ_WL_RO   repeatable absolute paths to whitelist
#   FJ_DEV_BLOCK    repeatable, a /dev node to hide (--blacklist)
#   FJ_HOOK_PRE     absolute path of a script to run on the host before the sandbox
#                   starts (per game only, a non-zero exit cancels the launch)
#   FJ_HOOK_POST    same, runs when the launcher exits

WQ_DEFAULTS_FILE="${WQ_DEFAULTS_FILE:-$QROOT/profile.defaults.conf}"

# _wq_kv <file> <key>  -> first value; rc 1 when missing
_wq_kv() {
    local f="$1" want="$2" k v
    [ -f "$f" ] || return 1
    while IFS='=' read -r k v || [ -n "$k" ]; do
        if [ "$k" = "$want" ]; then
            printf '%s' "${v%$'\r'}"
            return 0
        fi
    done < "$f"
    return 1
}

# _wq_kv_all <file> <key>  -> every value, one per line
_wq_kv_all() {
    local f="$1" want="$2" k v
    [ -f "$f" ] || return 0
    while IFS='=' read -r k v || [ -n "$k" ]; do
        if [ "$k" = "$want" ]; then
            printf '%s\n' "${v%$'\r'}"
        fi
    done < "$f"
    return 0
}

# _wq_get <gamedir> <key> <builtin>
_wq_get() {
    local v
    if v="$(_wq_kv "$1/game.conf" "$2")"; then :
    elif v="$(_wq_kv "$WQ_DEFAULTS_FILE" "$2")"; then :
    else v="$3"
    fi
    printf '%s' "$v"
}

# _wq_on <gamedir> <key> <builtin 0|1>   -> rc 0 when the effective value is 1
_wq_on() {
    [ "$(_wq_get "$1" "$2" "$3")" = "1" ]
}

# strict checks for FJ_NET_ALLOW: iptables-restore rejects the whole file on one bad entry
_wq_ip_ok() {
    local ip="${1%%/*}" n="" o
    [[ "$1" == */* ]] && n="${1#*/}"
    local IFS=.
    set -- $ip
    [ "$#" -eq 4 ] || return 1
    for o in "$@"; do
        case "$o" in 0?*) return 1 ;; esac
        [ "$o" -le 255 ] || return 1
    done
    [ -z "$n" ] || { [ "$n" -ge 1 ] && [ "$n" -le 32 ]; }
}
_wq_port_ok() {
    [ "$1" = "*" ] || { [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
}

_wq_write_netfilter() {
    local gd="$1" out="$2" dns="${3:-}" e proto ip port
    local re='^(tcp|udp):([0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?):([0-9]{1,5}|\*)$'
    {
        echo '*filter'
        echo ':INPUT DROP [0:0]'
        echo ':FORWARD DROP [0:0]'
        echo ':OUTPUT DROP [0:0]'
        echo '-A INPUT -i lo -j ACCEPT'
        echo '-A OUTPUT -o lo -j ACCEPT'
        echo '-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT'
        if _wq_on "$gd" FJ_NET_DNS 0; then
            if [ -n "$dns" ]; then
                echo "-A OUTPUT -p udp -d $dns --dport 53 -j ACCEPT"
                echo "-A OUTPUT -p tcp -d $dns --dport 53 -j ACCEPT"
            else
                echo '-A OUTPUT -p udp --dport 53 -j ACCEPT'
            fi
        fi
        if _wq_on "$gd" FJ_NET_LOG 0; then
            local tag
            tag="$(basename "$gd")"; tag="${tag//[^A-Za-z0-9 ._-]/_}"; tag="${tag:0:19}"
            echo "-A OUTPUT -m state --state NEW -j LOG --log-prefix \"wq-net[$tag]: \" --log-level 4"
        fi
        while IFS= read -r e; do
            [ -n "$e" ] || continue
            if [[ "$e" =~ $re ]] && _wq_ip_ok "${BASH_REMATCH[2]}" && _wq_port_ok "${BASH_REMATCH[5]}"; then
                proto="${BASH_REMATCH[1]}"
                ip="${BASH_REMATCH[2]}"
                port="${BASH_REMATCH[5]}"
                if [ "$port" = "*" ]; then
                    echo "-A OUTPUT -p $proto -d $ip -j ACCEPT"
                else
                    echo "-A OUTPUT -p $proto -d $ip --dport $port -j ACCEPT"
                fi
            else
                echo "wq: ignoring malformed FJ_NET_ALLOW entry: $e" >&2
            fi
        done < <({ _wq_kv_all "$gd/game.conf" FJ_NET_ALLOW; _wq_kv_all "$WQ_DEFAULTS_FILE" FJ_NET_ALLOW; })
        if _wq_on "$gd" FJ_NET_LEARN 0; then
            echo '-A OUTPUT -j ACCEPT'
        else
            echo '-A OUTPUT -j REJECT --reject-with icmp-port-unreachable'
        fi
        echo 'COMMIT'
    } > "$out"
    return 0
}

# --- launch scripts ---------------------------------------------------------
# the path comes from <game>/game.conf only (not the defaults file) and is passed
# to bash, never sourced or eval'd. the script runs on the host, not in firejail.

# _wq_hook_path <gamedir> <key>: prints the path, rc 1 if unset or bad
_wq_hook_path() {
    local p
    p="$(_wq_kv "$1/game.conf" "$2")" || return 1
    [ -n "$p" ] || return 1
    case "$p" in
        /*) ;;
        *) echo "wq: ignoring non-absolute $2: $p" >&2; return 1 ;;
    esac
    if [ ! -f "$p" ]; then
        echo "wq: $2 script not found: $p" >&2
        return 1
    fi
    printf '%s' "$p"
}

# _wq_run_hook <label> <gamedir> <key>: rc 0 if unset, otherwise the script's rc
_wq_run_hook() {
    local label="$1" gd="$2" key="$3" p rc=0
    p="$(_wq_hook_path "$gd" "$key")" || return 0
    echo "wq: running $label script: $p"
    ( cd "$gd" && WQ_GAMEDIR="$gd" WQ_GAME="$(basename "$gd")" WQ_QROOT="${QROOT:-}" bash "$p" ) || rc=$?
    [ "$rc" -eq 0 ] || echo "wq: $label script exited with code $rc" >&2
    return "$rc"
}

# runs from an EXIT trap, must not change the launcher's exit code
_wq_post_hook() {
    _wq_run_hook "after-exit" "$1" FJ_HOOK_POST || true
}

# apply_game_profile <gamedir>
# Rebuilds QUARANTINE_FIREJAIL_ARGS from the profile and exports what
# verify-sandbox.sh needs to know about it. Flags the profile does not manage
# (e.g. ones you added in config.local.sh) are kept as they are.
apply_game_profile() {
    local gd="$1" a size iface mode nf nf6 dns p rp
    local keep=() add=() skip=()

    for a in "${QUARANTINE_FIREJAIL_ARGS[@]}"; do
        case "$a" in
            --net=*|--netfilter=*|--netfilter6=*|--private|--private-tmp|--nonewprivs|--caps.drop=*|\
            --nodbus|--seccomp.drop=*|--noroot|--nosound|--nou2f|--novideo|--notv|\
            --nodvd|--x11=*|--xephyr-screen=*|--trace|--trace=*) ;;
            *) keep+=("$a") ;;
        esac
    done

    if _wq_on "$gd" FJ_PRIVATE_HOME 1; then add+=(--private);       else skip+=(home); fi
    if _wq_on "$gd" FJ_PRIVATE_TMP  1; then add+=(--private-tmp); fi
    if _wq_on "$gd" FJ_NONEWPRIVS   1; then add+=(--nonewprivs);    else skip+=(nnp); fi
    if _wq_on "$gd" FJ_CAPS_DROP    1; then add+=(--caps.drop=all); else skip+=(caps); fi
    if _wq_on "$gd" FJ_NODBUS       1; then add+=(--nodbus); fi
    if _wq_on "$gd" FJ_SECCOMP      1; then add+=("--seccomp.drop=$SECCOMP_DROP"); else skip+=(seccomp); fi
    if _wq_on "$gd" FJ_NOROOT       0; then add+=(--noroot); fi
    if _wq_on "$gd" FJ_NOSOUND      0; then add+=(--nosound); fi
    if _wq_on "$gd" FJ_NOU2F        0; then add+=(--nou2f); fi
    if _wq_on "$gd" FJ_NOVIDEO      0; then add+=(--novideo); fi
    if _wq_on "$gd" FJ_NOTV         0; then add+=(--notv); fi
    if _wq_on "$gd" FJ_NODVD        0; then add+=(--nodvd); fi

    # --- network -----------------------------------------------------------
    mode=off
    if _wq_on "$gd" FJ_NET 0; then
        mode=filtered
        if _wq_on "$gd" FJ_NET_OPEN 0; then mode=open; fi
    fi
    case "$mode" in
        off)  add+=(--net=none) ;;
        open) ;;   # host network namespace, no filter
        filtered)
            iface="$(_wq_get "$gd" FJ_NET_IFACE "")"
            if [[ "$iface" =~ ^[A-Za-z0-9_.-]+$ ]] && [ -d "/sys/class/net/$iface" ]; then
                nf="$gd/.wq-netfilter"
                dns=""
                if _wq_on "$gd" FJ_NET_DNS 0; then
                    dns="$(_wq_get "$gd" FJ_NET_DNS_SERVER "")"
                    if [ -z "$dns" ]; then
                        dns="$(ip -4 route show default dev "$iface" 2>/dev/null | awk '/default/ {print $3; exit}')"
                    fi
                    if [[ "$dns" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                        add+=("--dns=$dns")
                    else
                        dns=""
                    fi
                fi
                _wq_write_netfilter "$gd" "$nf" "$dns"
                nf6="$gd/.wq-netfilter6"   # IPv6: loopback only (the whitelist is IPv4)
                printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT DROP [0:0]' \
                    '-A INPUT -i lo -j ACCEPT' '-A OUTPUT -o lo -j ACCEPT' 'COMMIT' > "$nf6"
                add+=("--net=$iface" "--netfilter=$nf" "--netfilter6=$nf6")
            else
                echo "wq: network enabled but interface '${iface}' not found - staying offline" >&2
                add+=(--net=none)
                mode=off
            fi
            ;;
    esac
    # FJ_NET_LOG is honoured via an iptables LOG rule in .wq-netfilter (see
    # _wq_write_netfilter). firejail --trace is deliberately NOT used: it
    # preloads a 64-bit-only libtrace.so that every 32-bit process in the
    # Proton/umu stack fails to load, slowing startup by minutes.

    # --- private X11 -------------------------------------------------------
    if _wq_on "$gd" FJ_XEPHYR 0; then
        if ! command -v Xephyr >/dev/null 2>&1; then
            echo "wq: FJ_XEPHYR is set but Xephyr is not installed" >&2
            return 1
        fi
        add+=(--x11=xephyr)
        # xephyr only covers X11, so hide the wayland socket too or SDL/GTK/Qt
        # just talk to the real compositor
        # exact paths, the wildcard blacklist didn't take
        add+=(--rmenv=WAYLAND_DISPLAY)
        for p in "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"/wayland-*; do
            [ -e "$p" ] || [ -S "$p" ] || continue
            add+=("--blacklist=$p")
        done
        size="$(_wq_get "$gd" FJ_XEPHYR_SIZE "")"
        if [[ "$size" =~ ^[0-9]{3,5}x[0-9]{3,5}$ ]]; then
            add+=("--xephyr-screen=$size")
        fi
    fi

    # --- extra /dev nodes hidden from the game -------------------------------
    # only existing paths under /dev, and never the essential ones (null, zero,
    # tty, pts, shm ...)
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        case "$p" in
            /dev/|/dev) echo "wq: refusing to block /dev itself" >&2; continue ;;
            /dev/*) ;;
            *) echo "wq: ignoring FJ_DEV_BLOCK outside /dev: $p" >&2; continue ;;
        esac
        case "/$p/" in
            */../*) echo "wq: ignoring FJ_DEV_BLOCK with '..': $p" >&2; continue ;;
        esac
        case "$p" in
            /dev/null|/dev/zero|/dev/full|/dev/random|/dev/urandom|/dev/tty|/dev/ptmx|\
            /dev/pts|/dev/pts/*|/dev/shm|/dev/shm/*|/dev/fd|/dev/fd/*|/dev/stdin|/dev/stdout|/dev/stderr)
                echo "wq: refusing to block essential device: $p" >&2; continue ;;
        esac
        if [ ! -e "$p" ] && [ ! -L "$p" ]; then
            echo "wq: blocked device does not exist (skipped): $p" >&2
            continue
        fi
        rp="$(readlink -f "$p")"
        case "$rp" in
            /dev/*) ;;
            *) echo "wq: $p resolves outside /dev ($rp) - skipped" >&2; continue ;;
        esac
        case "$rp" in
            /dev/null|/dev/zero|/dev/full|/dev/random|/dev/urandom|/dev/tty|/dev/ptmx|/dev/pts|/dev/pts/*|/dev/shm|/dev/shm/*)
                echo "wq: $p resolves to essential device $rp - skipped" >&2; continue ;;
        esac
        add+=("--blacklist=$rp")
        [ "$rp" = "$p" ] || add+=("--blacklist=$p")
    done < <({ _wq_kv_all "$gd/game.conf" FJ_DEV_BLOCK; _wq_kv_all "$WQ_DEFAULTS_FILE" FJ_DEV_BLOCK; } | awk '!seen[$0]++')

    QUARANTINE_FIREJAIL_ARGS=("${keep[@]}" "${add[@]}")

    # what verify-sandbox.sh should expect (set outside the sandbox, read once
    # by the verifier before the game starts)
    export QVERIFY_NET="$mode"
    QVERIFY_SKIP="$(IFS=,; echo "${skip[*]:-}")"
    export QVERIFY_SKIP

    # --- launch scripts (host side, per game) --------------------------------
    if ! _wq_run_hook "before-launch" "$gd" FJ_HOOK_PRE; then
        echo "wq: before-launch script failed - launch cancelled" >&2
        return 1
    fi
    if _wq_hook_path "$gd" FJ_HOOK_POST >/dev/null 2>&1; then
        _WQ_POST_GD="$gd"
        trap '_wq_post_hook "$_WQ_POST_GD"' EXIT
    fi
    return 0
}

# Extra --whitelist args for FJ_WL_RW / FJ_WL_RO (per game + defaults).
# Usage in _launch-core.sh:  mapfile -t -O "${#WL_ARGS[@]}" WL_ARGS < <(profile_extra_whitelist_args)
profile_extra_whitelist_args() {
    local gd="${GAMEDIR:?GAMEDIR not set}" kind p rp
    for kind in RW RO; do
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            case "$p" in
                /*) ;;
                *) echo "wq: ignoring non-absolute whitelist path: $p" >&2; continue ;;
            esac
            if [ ! -e "$p" ]; then
                echo "wq: whitelist path does not exist: $p" >&2
                continue
            fi
            rp="$(readlink -f "$p")"
            printf -- '--whitelist=%s\n' "$rp"
            if [ "$kind" = RW ]; then
                printf -- '--read-write=%s\n' "$rp"
            else
                printf -- '--read-only=%s\n' "$rp"
            fi
        done < <({ _wq_kv_all "$gd/game.conf" "FJ_WL_$kind"; _wq_kv_all "$WQ_DEFAULTS_FILE" "FJ_WL_$kind"; })
    done
    return 0
}
