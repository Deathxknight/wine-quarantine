# wine-quarantine

I like trying games from itch.io and other such websites . I don't like double-clicking an unknown `.exe` on the machine that holds my files and passwords. So I built a place to put those games first.

wine-quarantine runs each game in its own [firejail](https://firejail.wordpress.com/) sandbox, with no network unless you allow it, all while a monitor watches for the kind of behaviour a game has no reason to show. It handles bindows games (through Proton) and native Linux games (shell scripts, binaries, AppImages). A small Qt app ties it together.

<img width="1903" height="1009" alt="wine-quarantine main window" src="https://github.com/user-attachments/assets/659aa1e9-97cb-449f-8c18-198792502f10" />

## What this is not 

It makes running something sketchy _less risky_. It does not make it safe, it is VERY important to understand that first . 

- It's a firejail sandbox, not a VM. The game shares your kernel and runs as your user.
- The monitor is a tripwire. It matches names and polls every few seconds, so a careful piece of malware can slip past it.
- X11 is only isolated if you turn on the private X server (Xephyr) for that game. 
- Multiplayer games need the network, and that weakens the sandbox. The allow-list helps, but it isn't a guarantee.
- The cybersecurity space is ever evolving - this is the best i can do alone.

If you think a file is real malware, use a VM, or don't run it.

## How it works

**It checks itself before every run.** Before the game starts, `verify-sandbox.sh` runs _inside_ the jail and looks at the facts: capabilities dropped, no-new-privileges set, seccomp filter active, only a loopback interface, no DNS resolver socket reachable, your real `$HOME` not visible, no D-Bus or SSH agent leaking in. If any check fails, the game doesn't start. The script also hashes itself, so a tampered copy refuses to run.

**It watches while the game runs.** The monitor follows the game's process tree and the files it touches. It raises an alert for things like a script or executable dropped in a Startup folder, writes to `system32`, a registry hive changing at runtime, or a game spawning `powershell`, `certutil`, `curl` or `rundll32`. **The first alert stops the sandbox** and opens a terminal with the log. For Windows games it also snapshots the registry before the run and diffs it afterwards, looking for persistence keys such as `Run`, services and `AppInit_DLLs`.

**Native Linux games get the same treatment.** `monitor.sh` switches to a Linux rule set (`lib-monitor-native.sh`) when `game.conf` says `RUNNER=native`. It watches the game's home and `game/` for a shell startup file (`.bashrc`, `.profile`, `.zshrc` ...) changing, autostart entries, systemd user units, `~/.config/environment.d`, `~/.ssh`, anything dropped in `~/.local/bin`, and new ELF binaries or scripts appearing at runtime. It flags processes such as `nc`/`ncat`/`socat`, `ssh`, `curl`/`wget`, `sudo`/`su`, `crontab`/`systemctl`, reverse-shell command lines (`/dev/tcp`, `base64 -d | sh`, `python -c` with sockets), fileless `memfd` execution, and warns on clipboard, screenshot and input-snooping tools. Interpreters are not flagged by name, because plenty of games ship their own Python. `home-diff.sh` is the registry diff's counterpart: it snapshots those startup spots and the executables under `game/` before the run and diffs them afterwards.

**ClamAV scans the game's files.** When a game is added, `wq-scan.sh` scans `game/`. After every run it scans what the run changed in `game/` plus `prefix/` (Windows) or `home/` (native). Detections become `ALERT` lines in the run's log, so the verdict turns into `REVIEW NEEDED` and they show up in the Monitor tab. See [ClamAV scanning](#clamav-scanning).

**Every run ends with a verdict.** `CLEAN`, `OK, minor notes`, `REVIEW NEEDED`, `LAUNCH BLOCKED` (a preflight check failed and the game never ran) or `SANDBOX LEAK` (the jail exposed something it shouldn't have). Logs are kept per game and pruned after 30 days.

**The defaults lean strict.** No network, a private `$HOME` and `/tmp`, all capabilities dropped, no D-Bus, a seccomp filter that blocks things like `bpf`, `io_uring` and `keyctl`, and a random machine ID so a game can't fingerprint you. Name lookups are closed off too: `--net=none` alone doesn't stop a game leaking data through the systemd-resolved or nscd sockets, so those are hidden as well.

## What you can do with it

**Sandboxing**

- One firejail profile per game, plus a shared default you can save and reset to.
- Switches for isolation (hide your home folder, private `/tmp`, no new privileges, drop capabilities, block D-Bus, seccomp, no root namespace) and for devices (audio, webcams, security keys, TV tuners, optical drives, or any single `/dev` node).
- Only the game's own folder is writable. You can whitelist extra read-write or read-only paths per game.
- Optional private X server (Xephyr, any window size). With it on, the game can't see your host display or Wayland socket.
- Resource limits: a cap on processes and threads (fork-bomb protection) and a memory cap, enforced through systemd. If a limit is set and can't be applied, the launch is cancelled rather than run unlimited.
- An extra-options box that only accepts options that make the sandbox _tighter_. Anything that would loosen it, like `--net` or `--whitelist`, is refused, not quietly skipped.

**Network**

- Off by default.
- Filtered mode with an allow-list of hosts and ports, a chosen interface, and optional DNS.
- Learn mode lets everything through and records it, so you can build an allow-list from what the game really does.
- A live Network tab shows connection attempts as the kernel firewall sees them.

**Games**

- Windows games run through [umu-launcher](https://github.com/Open-Wine-Components/umu-launcher) and Proton, each with its own Wine prefix.
- Native Linux games keep a private `$HOME` so saves survive between runs.
- Add a game from a folder, an archive (`.zip`, `.rar`, `.7z`, `.tar.*`) or a single file. If there are several start files you choose one, and you can change it later.
- Remove a game from the app. The folder goes to the Trash, and is deleted for good only if you type its name.
- Optional scripts that run before launch or after exit, on your machine and outside the sandbox.

**The app**

- The game list shows location, network, display and state at a glance. Select several games to change them together.
- Tri-state checkboxes show where selected games disagree. Only real changes count as unsaved, and the app asks before you lose any.
- One **Add** menu for new games, the start file, launch scripts and hidden devices. Right-click a game for more.
- Light, dark or follow-system themes, plus your own CSS that reloads when you save it.
- A Debug window that checks dependencies and builds a redacted report you can paste into a bug report.

## Getting started

**Put it outside your home folder.** firejail's private mode hides `$HOME` from the game, and that includes this project. `install.sh` will offer to move it to `/mnt/wine-quarantine` for you.

bash

```bash
git clone https://github.com/Deathxknight/wine-quarantine
cd wine-quarantine
./install.sh
./wq
```

`install.sh` is safe to re-run. It checks for what's missing (and offers to install it with pacman, apt or dnf), can download GE-Proton and the umu runtime for you, wires in the app, creates the `./wq` launcher and an optional menu entry, and offers to turn on the kernel setting the Network tab needs
( Ive tried to test cross distro installs , if you have any issues let me know )

**What it needs:** `firejail`, `inotify-tools`, `python3`, and `PySide6` for the app. Optional: `Xephyr` for the private X server, `unzip`/`unrar`/`7z` for archives, and `journalctl` access (a member of `systemd-journal`, `adm` or `wheel`) for live connection logging. Windows games also need `umu-run` and a Proton build.

**Live connection logging** also needs `net.netfilter.nf_log_all_netns=1`, which `install.sh` offers to set. Without it the Network tab stays empty even though connections are happening. To do it by hand:

bash

```bash
sudo sysctl -w net.netfilter.nf_log_all_netns=1
echo 'net.netfilter.nf_log_all_netns = 1' | sudo tee /etc/sysctl.d/99-wq.conf
```

If Steam or `umu-run` live somewhere unusual, create `config.local.sh` next to `config.sh`:

bash

```bash
STEAM_ROOT="/path/to/Steam"
LUTRIS_UMU="/path/to/umu-run"
```

## ClamAV scanning

Optional. Install `clamav` and download signatures once with `sudo freshclam` (`install.sh` offers both). Without ClamAV or a database the scan is skipped with a note in the log and nothing else changes.

- **On add:** `game/` is scanned right after the game is created. Cancelling during the scan keeps the game and only stops the scan.
- **After a run:** only files changed since the last scan are scanned, so it stays quick. A full scan of everything runs the first time and then every `CLAM_FULL_EVERY_DAYS` (7), so new signatures also hit old files.
- **By hand:** `./wq-scan.sh "My Game"` (full scan), `./wq-scan.sh --check` shows whether ClamAV and its database are usable. The scanner's full output is saved as `logs/clamscan-*.log`.
- **Sandboxed:** `clamscan` runs inside a firejail with no network, since it parses untrusted archives and documents. Set `CLAM_SANDBOX=0` if firejail gets in its way.

Settings go in `config.local.sh`: `CLAM_SCAN_ON_ADD`, `CLAM_SCAN_AFTER_RUN` (both 1), `CLAM_FULL_EVERY_DAYS`, `CLAM_STALE_DAYS`, `CLAM_MAX_FILESIZE` (200M), `CLAM_SANDBOX`, `CLAM_USE_DAEMON` (use `clamdscan`), `CLAM_DB_DIR`, `CLAM_BIN`, `CLAM_EXCLUDE_REGEX`. Per game, `CLAM_SCAN=0` or `1` in `game.conf` overrides `CLAM_SCAN_AFTER_RUN`. `WQ_SKIP_SCAN=1` skips the scan on add.

A signature scan finds known malware. It does not find new or custom malware, and files above `CLAM_MAX_FILESIZE` are skipped. A clean scan is not a safe game.

## Everyday use

In the app: **Add > New game…**, choose Windows or Native Linux, name it, pick a source, then **Launch**.

Or from the command line:

bash

```bash
./new-quarantine.sh "My Game" ~/Downloads/mygame.zip            # Windows game
./wq-ui/new-native.sh "My Native Game" ~/Downloads/game.tar.gz  # native Linux game
"./My Game/launch-quarantine.sh"
```

Both create a `launch-quarantine.sh` in the game's folder that starts the game in the sandbox with the monitor attached. If it picked the wrong start file, use **Add > Set executable…** or edit `EXE=` in `game.conf`. Logs go in the game's `logs/` folder.

From inside the sandbox, the game sees only its own `game/` folder, plus `prefix/` (Windows) or `home/` (native). `game.conf` and the logs stay hidden from it.

After you change the launcher template, `./update-launchers.sh` (a dry run by default, `--apply` to write) brings your existing games up to date. If you edit `verify-sandbox.sh` by hand, refresh its hash with `./verify-sandbox.sh --update-hash`.

More detail on the app, every `game.conf` key and the limits box is in `wq-ui/README.md`.

## Known gaps

I'd rather list these than have you find them.

- The shared `_umu-data` folder is writable by every Windows game, so one bad game could tamper with the runtime the others use.
- Your whole Steam folder is mounted read-only inside the Windows-game sandbox.
- Registry persistence detection can miss a value added to a key that already existed.
- Native games don't get the Windows-specific sandbox verification. Their monitor, `home-diff.sh` and ClamAV checks are described above, and are tripwires of the same kind.
- If "Hide home directory" is off for a native game, its monitoring of your real `$HOME` is best-effort: only the usual persistence spots are watched.
- The ClamAV scan runs after the fact. It tells you what a run left behind, it does not stop the run.
- Sound, input and GPU devices stay visible unless you block them.

## Tests

bash

```bash
python3 wq-ui/test_core.py
bash wq-ui/test_profile.sh
bash wq-ui/test_native_monitor_scan.sh
```

The last one covers the native monitor rules, `home-diff.sh`, `wq-scan.sh` and a full native launch, with stand-ins for `clamscan`, `inotifywait` and `firejail`. These cover the parsing and the way settings become firejail arguments. They don't need firejail and don't test a real sandbox.

Issues and pull requests are welcome.

Thanks for taking interest - help me improve my harder than expected project that has consumed me for a bit over a year.

-  Patrick.
