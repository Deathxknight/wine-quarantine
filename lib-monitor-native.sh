#!/bin/bash
# lib-monitor-native.sh - detection rules for native Linux games.
#
# Sourced by monitor.sh when game.conf says RUNNER=native (and by the tests).
# This is the Linux counterpart of the Windows rules that live inside monitor.sh
# (Startup folders, system32, reg.exe, rundll32 ...). Everything here is a pure
# function: it prints  LEVEL<TAB>KIND<TAB>message  or nothing, and keeps no
# state, so it can be tested without inotify or a running game.
#
#   LEVEL  ALERT | WARN
#   KIND   rc     a shell/session startup file. monitor.sh compares its hash with the
#                 baseline taken when the monitor started before it raises the alert
#                 (firejail may copy skeleton dotfiles into a private home)
#          plain  report as is

# --- processes ---------------------------------------------------------------
# matched against the executable's name AND argv[0], anchored
NATIVE_ALERT_PROCS='nc|ncat|netcat|socat|telnet|ssh|ssh-[a-z]+|scp|sftp|ftp|tftp|curl|wget|chisel|ngrok|nmap|masscan|tcpdump|tshark|sudo|su|pkexec|doas|crontab|at|atd|batch|systemctl|systemd-run|loginctl|setcap|nsenter|chroot|insmod|modprobe|passwd|chsh|gdb|strace|ltrace'
NATIVE_WARN_PROCS='xclip|xsel|wl-paste|wl-copy|xdotool|xinput|xev|xwd|scrot|maim|import|grim|gnome-screenshot|spectacle|xdg-open|xdg-desktop-menu|xdg-desktop-icon|xdg-mime|update-desktop-database|gio|dbus-send|gdbus|busctl|ss|netstat|ifconfig|arp'
NATIVE_ALERT_PROCS_RE="^(${NATIVE_ALERT_PROCS})$"
NATIVE_WARN_PROCS_RE="^(${NATIVE_WARN_PROCS})$"

# interpreters are NOT flagged by name (Ren'Py and plenty of itch.io games ship their own
# python); only when they are handed inline code that opens sockets or spawns a shell
NATIVE_INTERP_RE='^(python[0-9.]*|perl|ruby|php|node|nodejs|lua[0-9.]*)$'
NATIVE_INLINE_CODE_RE='[[:space:]]-(c|e|r)[[:space:]]'
NATIVE_NET_CODE_RE='(socket|pty\.spawn|child_process|fsockopen|TCPSocket|os\.dup2|/bin/(ba|da)?sh)'

# native_classify_proc <exe_basename> <argv0_basename> <cmdline> [exe_link]
native_classify_proc() {
  local exe="$1" a0="$2" cmd="$3" link="${4:-}" n

  for n in "$exe" "$a0"; do
    [ -n "$n" ] || continue
    if [[ "$n" =~ $NATIVE_ALERT_PROCS_RE ]]; then
      printf 'ALERT\tplain\tSuspicious process: %s\n' "$n"; return 0
    fi
  done

  if [[ "$cmd" =~ /dev/(tcp|udp)/ ]]; then
    printf 'ALERT\tplain\tShell network redirection (/dev/tcp, /dev/udp), reverse-shell pattern\n'; return 0
  fi
  if [[ "$cmd" =~ base64[[:space:]]+(-d|--decode)[^|]*\|[[:space:]]*(ba|z|da)?sh ]]; then
    printf 'ALERT\tplain\tDecoded payload piped into a shell\n'; return 0
  fi
  if [[ "$cmd" =~ (curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh ]]; then
    printf 'ALERT\tplain\tDownload piped into a shell\n'; return 0
  fi
  if [[ "$cmd" =~ (authorized_keys|\.ssh/id_|/etc/shadow|/etc/sudoers|ld\.so\.preload) ]]; then
    printf 'ALERT\tplain\tCommand line touches a sensitive file (%s)\n' "${BASH_REMATCH[1]}"; return 0
  fi
  for n in "$exe" "$a0"; do
    [ -n "$n" ] || continue
    if [[ "$n" =~ $NATIVE_INTERP_RE ]] && [[ "$cmd" =~ $NATIVE_INLINE_CODE_RE ]] && [[ "$cmd" =~ $NATIVE_NET_CODE_RE ]]; then
      printf 'ALERT\tplain\tInterpreter running inline code with socket/shell primitives: %s\n' "$n"; return 0
    fi
  done

  case "$link" in
    /memfd:*)
      printf 'ALERT\tplain\tRunning from an anonymous memory file (fileless exec): %s\n' "$link"; return 0 ;;
    *" (deleted)")
      printf 'WARN\tplain\tRunning a binary that was deleted from disk: %s\n' "$link"; return 0 ;;
    /tmp/.mount_*|/tmp/_MEI*|/tmp/appimage_extracted_*|/tmp/.org.chromium.*) ;;   # AppImage, PyInstaller, Chromium
    /tmp/*|/dev/shm/*|/var/tmp/*)
      printf 'WARN\tplain\tRunning a binary from a temp directory: %s\n' "$link"; return 0 ;;
  esac

  for n in "$exe" "$a0"; do
    [ -n "$n" ] || continue
    if [[ "$n" =~ $NATIVE_WARN_PROCS_RE ]]; then
      printf 'WARN\tplain\tProcess a game rarely needs (clipboard, screenshot, input snooping, desktop integration, socket listing): %s\n' "$n"
      return 0
    fi
  done
  return 0
}

# --- files -------------------------------------------------------------------
NATIVE_RC_RE='^(\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile|\.zshrc|\.zshenv|\.zprofile|\.zlogin|\.xprofile|\.xinitrc|\.xsession|\.xsessionrc|\.pam_environment|\.config/fish/config\.fish)$'

# native_is_skeleton <file> <path relative to home>
# firejail copies the skeleton .bashrc/.zshrc into a private home (or creates an empty one) when the
# jail starts. That is the sandbox, not the game. A file that is empty or identical to /etc/skel's is
# treated as such.
native_is_skeleton() {
  [ -f "$1" ] || return 1
  [ ! -s "$1" ] && return 0
  [ -f "/etc/skel/$2" ] && cmp -s "$1" "/etc/skel/$2"
}

# native_is_elf <file>
native_is_elf() {
  local m=""
  [ -f "$1" ] && [ -r "$1" ] || return 1
  { LC_ALL=C IFS= read -r -N 4 m < "$1"; } 2>/dev/null || true
  [ "$m" = $'\x7f'ELF ]
}

# native_classify_path <file> <inotify events> <effective home> <game dir>
# <home> is where the game thinks $HOME is (<game>/home with a private home, the real
# $HOME otherwise). <game dir> is <game>/game.
native_classify_path() {
  local file="$1" event="$2" home="$3" gamebin="$4" rel="" base lbase where=""
  base="${file##*/}"; lbase="${base,,}"
  case "$event" in *ISDIR*) return 0 ;; esac

  if [ -n "$home" ] && [[ "$file" == "$home"/* ]]; then
    rel="${file#"$home"/}"
    where="home"
    if [[ "$rel" =~ $NATIVE_RC_RE ]]; then
      printf 'ALERT\trc\tShell/session startup file written: ~/%s (%s)\n' "$rel" "$event"; return 0
    fi
    case "$rel" in
      .config/autostart/*)
        printf 'ALERT\tplain\tAutostart entry written: ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
      .config/systemd/user/*|.local/share/systemd/user/*)
        printf 'ALERT\tplain\tsystemd user unit written: ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
      .config/environment.d/*)
        printf 'ALERT\tplain\tSession environment file written (can set LD_PRELOAD/PATH): ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
      .ssh|.ssh/*)
        printf 'ALERT\tplain\tSSH directory touched: ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
      .local/bin/*)
        printf 'ALERT\tplain\tFile dropped into ~/.local/bin (on PATH): ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
      .local/share/applications/*)
        printf 'WARN\tplain\tDesktop launcher written: ~/%s (%s)\n' "$rel" "$event"; return 0 ;;
    esac
  elif [ -n "$gamebin" ] && [[ "$file" == "$gamebin"/* ]]; then
    where="game folder"
  else
    return 0
  fi

  # new code appearing at runtime
  # judge new code once it is fully written (a CREATE is always followed by a CLOSE_WRITE,
  # and the file is still empty at CREATE time), so each dropped file is reported once
  case "$event" in *CLOSE_WRITE*|*MOVED_TO*) ;; *) return 0 ;; esac
  [ -f "$file" ] || return 0
  if native_is_elf "$file"; then
    printf 'WARN\tplain\tNew executable (ELF) written in %s: %s (%s)\n' "$where" "${rel:-${file#"$gamebin"/}}" "$event"; return 0
  fi
  case "$lbase" in
    *.desktop|*.service|*.timer|*.socket|*.path)
      printf 'WARN\tplain\tLauncher/unit file written in %s: %s (%s)\n' "$where" "${rel:-${file#"$gamebin"/}}" "$event"; return 0 ;;
    *.sh|*.bash|*.zsh|*.py|*.pl|*.rb|*.run|*.appimage|*.bin)
      printf 'WARN\tplain\tNew script/executable written in %s: %s (%s)\n' "$where" "${rel:-${file#"$gamebin"/}}" "$event"; return 0 ;;
  esac
  return 0
}
