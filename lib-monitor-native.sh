#!/bin/bash
# lib-monitor-native.sh - detection rules for native Linux games.
#
# Sourced by monitor.sh when game.conf says RUNNER=native, and by the tests. It's the Linux
# version of the Windows rules inside monitor.sh (Startup folders, system32, reg.exe, rundll32...).
# Everything here is a pure function that prints  LEVEL<TAB>KIND<TAB>message  or nothing and keeps
# no state, so it can be tested without inotify or a running game.
#
#   LEVEL  ALERT | WARN
#   KIND   rc     a shell/session startup file. monitor.sh compares its hash with the baseline
#                 taken when the monitor started before alerting (firejail may copy skeleton
#                 dotfiles into a private home)
#          plain  report as is

# processes
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

# Names of programs/scripts. A file that is called reverse_shell.py or keylogger.sh is not a game file; payload,
# exploit, dropper, beacon, spawner alone is only worth a warning (tools and mods use such words too).
NATIVE_MALNAME_RE='(reverse[_ -]?shell|revshell|keylog|backdoor|stealer|ransom|rootkit|meterpreter|mimikatz|webshell|botnet|cryptolocker|trojan)|(^|[^a-z])rat([^a-z]|$)'
NATIVE_WEAKNAME_RE='(payload|exploit|dropper|implant|beacon|spawner)'

# Shells and interpreters, matched on the KERNEL's name for the program (/proc/PID/exe, comm), never on argv[0]:
# a symlink called "helper" that points at /bin/sh, or a "#!/bin/sh" script run through such a link, has no
# interpreter name anywhere in its argv.
NATIVE_SHELL_RE='^(bash|sh|dash|zsh|ksh|ash|busybox)$'

# native_is_tmp <path>: a world-writable scratch directory (AppImage / PyInstaller / Chromium unpack dirs excluded)
native_is_tmp() {
  case "$1" in
    /tmp/.mount_*|/tmp/_MEI*|/tmp/appimage_extracted_*|/tmp/.org.chromium.*) return 1 ;;
    /tmp|/tmp/*|/var/tmp|/var/tmp/*|/dev/shm|/dev/shm/*) return 0 ;;
  esac
  return 1
}

# native_classify_proc <exe_basename> <argv0_basename> <cmdline> [exe_link] [script_basename] [cwd] [script_path]
# script_basename is the file an interpreter was told to run (bash start.sh -> start.sh), when there is one.
# cwd and script_path (full path) are used for the temp-directory rules.
native_classify_proc() {
  local exe="$1" a0="$2" cmd="$3" link="${4:-}" scr="${5:-}" cwd="${6:-}" spath="${7:-}" n lscr
  if [ -n "$scr" ]; then
    scr="${scr##*/}"; lscr="${scr,,}"
    if [[ "$lscr" =~ $NATIVE_MALNAME_RE ]]; then
      printf 'ALERT\tplain\tProgram or script with an attack-tool name: %s\n' "$scr"; return 0
    elif [[ "$lscr" =~ $NATIVE_WEAKNAME_RE ]]; then
      printf 'WARN\tplain\tProgram or script named like an attack stage (%s): %s\n' "${BASH_REMATCH[1]}" "$scr"; return 0
    fi
  fi

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

  # shells and interpreters working out of a temp directory (keyed on the kernel name, see NATIVE_SHELL_RE)
  if [[ "$exe" =~ $NATIVE_SHELL_RE ]] || [[ "$exe" =~ $NATIVE_INTERP_RE ]]; then
    if [ -n "$spath" ] && native_is_tmp "$spath"; then
      printf 'WARN\tplain\tScript run from a temp directory (%s): %s\n' "$exe" "$spath"; return 0
    fi
    if [[ "$exe" =~ $NATIVE_SHELL_RE ]] && [[ "$cmd" =~ [[:space:]]-[a-z]*c[[:space:]] ]]; then
      if [ -n "$cwd" ] && native_is_tmp "$cwd"; then
        printf 'WARN\tplain\tShell command run from a temp directory (%s): cwd %s\n' "$exe" "$cwd"; return 0
      fi
      if [[ "$cmd" =~ (/tmp|/var/tmp|/dev/shm)/[^[:space:]\'\"]* ]] && native_is_tmp "${BASH_REMATCH[0]}"; then
        printf 'WARN\tplain\tShell command that uses a temp directory path (%s): %s\n' "$exe" "${BASH_REMATCH[0]}"; return 0
      fi
    fi
  fi

  for n in "$exe" "$a0"; do
    [ -n "$n" ] || continue
    if [[ "$n" =~ $NATIVE_WARN_PROCS_RE ]]; then
      printf 'WARN\tplain\tProcess a game rarely needs (clipboard, screenshot, input snooping, desktop integration, socket listing): %s\n' "$n"
      return 0
    fi
  done
  return 0
}

# native_scan_script <file>
# What a script SAYS it does, judged from its text (first MiB). Used for the script an interpreter was handed
# (bash x.sh, python3 y.py). Prints LEVEL<TAB>plain<TAB>message or nothing. One pure function, no state.
native_scan_script() {
  local f="$1" t
  [ -f "$f" ] && [ -r "$f" ] || return 0
  t="$(head -c 1048576 "$f" 2>/dev/null | tr '\0' ' ')" || return 0
  [ -n "$t" ] || return 0
  _ns() { [[ "$t" =~ $1 ]]; }
  local sh='[[:space:]]*(/bin/)?(ba|da|z)?sh'
  # reverse / bind shell: a connection AND something that gives it a shell
  if _ns '/dev/(tcp|udp)/[^[:space:]/]+/[0-9]' \
     || { _ns '(^|[^a-z_])(nc|ncat|netcat)[[:space:]][^'$'\n'']*[[:space:]]-[ec][[:space:]]*(/bin/)?(ba|da|z)?sh' ; } \
     || _ns 'mkfifo[^'$'\n'']*(nc|ncat|netcat|telnet|openssl)' \
     || _ns 'socat[^'$'\n'']*exec:[^'$'\n'']*sh' \
     || { _ns 'socket' && _ns '(dup2\([^)]{0,40}fileno|pty\.spawn|/bin/(ba|da|z)?sh["'"'"']?[[:space:],]*["'"'"']?-i)' && _ns '(\.connect\(|fsockopen|TCPSocket\.new|net\.connect|new[[:space:]]+Socket)'; }; then
    printf 'ALERT\tplain\tScript opens a socket and hands it a shell (reverse-shell pattern)\n'; return 0
  fi
  if _ns '(curl|wget)[^|'$'\n'']*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da)?sh' || _ns 'base64[[:space:]]+(-d|--decode)[^|'$'\n'']*\|[[:space:]]*(ba|z|da)?sh'; then
    printf 'ALERT\tplain\tScript pipes a download or decoded data into a shell\n'; return 0
  fi
  if _ns '(exec|eval)[[:space:]]*\([[:space:]]*(base64\.)?b64decode' || _ns '(^|[^a-z_])eval[[:space:]]*\([[:space:]]*(atob|base64_decode|gzinflate)' || _ns '(exec|eval)[[:space:]]*\([[:space:]]*marshal\.loads'; then
    printf 'ALERT\tplain\tScript decodes data and runs it (exec/eval of decoded text)\n'; return 0
  fi
  # several different credential stores in one script
  local n=0 p
  for p in '\.ssh/' '\.gnupg' '\.aws/|\.kube/|\.config/gcloud' '\.mozilla|\.config/(google-chrome|chromium|BraveSoftware)|Login Data|logins\.json' '\.bash_history|\.zsh_history' '\.electrum|wallet\.dat|\.bitcoin|\.local/share/keyrings'; do
    _ns "$p" && n=$((n+1))
  done
  if [ "$n" -ge 3 ]; then
    printf 'ALERT\tplain\tScript reaches into several credential stores (ssh/gpg/cloud/browser/wallet/history)\n'; return 0
  fi
  # installs itself for later: a write (>>, tee, cp, crontab -) next to a startup place
  if _ns '(>>?|tee[[:space:]]+(-a[[:space:]]+)?|cp[[:space:]][^'$'\n'']*)[[:space:]]*[^[:space:]]*(\.bashrc|\.zshrc|\.bash_profile|\.profile|authorized_keys|ld\.so\.preload|\.config/autostart/|\.config/systemd/user/)' \
     || _ns '\|[[:space:]]*crontab[[:space:]]+-' || _ns 'systemctl[[:space:]]+--user[[:space:]]+enable'; then
    printf 'ALERT\tplain\tScript installs itself for later (shell startup, autostart, cron, ssh keys, LD_PRELOAD)\n'; return 0
  fi
  return 0
}

# files
NATIVE_RC_RE='^(\.bashrc|\.bash_profile|\.bash_login|\.bash_logout|\.profile|\.zshrc|\.zshenv|\.zprofile|\.zlogin|\.xprofile|\.xinitrc|\.xsession|\.xsessionrc|\.pam_environment|\.config/fish/config\.fish)$'

# native_is_skeleton <file> <path relative to home>
# firejail copies the skeleton .bashrc/.zshrc into a private home (or makes an empty one) when the
# jail starts. That's the sandbox, not the game, so a file that is empty or identical to
# /etc/skel's gets ignored.
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

# native_has_shebang <file>: starts with "#!"
native_has_shebang() {
  local m=""
  [ -f "$1" ] && [ -r "$1" ] || return 1
  { LC_ALL=C IFS= read -r -N 2 m < "$1"; } 2>/dev/null || true
  [ "$m" = '#!' ]
}

# native_classify_path <file> <inotify events> <effective home> <game dir> [<temp prefix>]
# <home> is where the game thinks $HOME is (<game>/home with a private home, otherwise the real
# $HOME). <game dir> is <game>/game. <temp prefix> is where the game's own /tmp, /var/tmp and /dev/shm can be
# reached from the monitor (/proc/<pid>/root), so a file under <prefix>/tmp/... is judged as /tmp/...
# The file rules look at what a file IS (execute bit, "#!" line, ELF header) as well as what it is called: a
# script renamed notes.txt is still a script.
native_classify_path() {
  local file="$1" event="$2" home="$3" gamebin="$4" tmpfx="${5:-}" rel="" base lbase where="" shown disp
  base="${file##*/}"; lbase="${base,,}"
  case "$event" in *ISDIR*) return 0 ;; esac

  if [ -n "$home" ] && [[ "$file" == "$home"/* ]]; then
    rel="${file#"$home"/}"
    where="home"
    shown="$rel"
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
    shown="${file#"$gamebin"/}"
  elif [ -n "$tmpfx" ] && [[ "$file" =~ ^"$tmpfx"/(tmp|var/tmp|dev/shm)/ ]]; then
    disp="${file#"$tmpfx"}"
    # the X sockets, and the unpack dirs of AppImage / PyInstaller / Chromium, are not the game dropping files
    case "$disp" in /tmp/.X11-unix/*|/tmp/.ICE-unix/*|/tmp/.XIM-unix/*|/tmp/.font-unix/*) return 0 ;; esac
    native_is_tmp "$disp" || return 0
    where="temp dir"
    shown="$disp"
  else
    return 0
  fi

  # new code appearing at runtime
  # Judge it once it's fully written (CLOSE_WRITE / MOVED_TO), or when its mode changes (ATTRIB: chmod +x on a
  # file that was written earlier). The caller reports each file once.
  case "$event" in *CLOSE_WRITE*|*MOVED_TO*|*ATTRIB*) ;; *) return 0 ;; esac
  [ -f "$file" ] || return 0
  if native_is_elf "$file"; then
    printf 'WARN\tplain\tNew executable (ELF) written in %s: %s (%s)\n' "$where" "$shown" "$event"; return 0
  fi
  case "$lbase" in
    *.desktop|*.service|*.timer|*.socket|*.path)
      printf 'WARN\tplain\tLauncher/unit file written in %s: %s (%s)\n' "$where" "$shown" "$event"; return 0 ;;
    *.sh|*.bash|*.zsh|*.py|*.pl|*.rb|*.run|*.appimage|*.bin)
      printf 'WARN\tplain\tNew script/executable written in %s: %s (%s)\n' "$where" "$shown" "$event"; return 0 ;;
  esac
  # what the file is, whatever it is called
  local sb=0 xb=0
  native_has_shebang "$file" && sb=1
  [ -x "$file" ] && xb=1
  if [ "$sb" = 1 ] && [ "$xb" = 1 ]; then
    printf 'WARN\tplain\tExecutable script (#! line + execute bit) under an ordinary name, written in %s: %s (%s)\n' "$where" "$shown" "$event"
  elif [ "$sb" = 1 ]; then
    printf 'WARN\tplain\tScript (#! line) under an ordinary name, written in %s: %s (%s)\n' "$where" "$shown" "$event"
  elif [ "$xb" = 1 ]; then
    printf 'WARN\tplain\tFile with execute permission under an ordinary name, written in %s: %s (%s)\n' "$where" "$shown" "$event"
  fi
  return 0
}
