# wq-ui

The Qt front end for wine-quarantine: list your games, edit each game's sandbox profile, launch, and watch the network and monitor.

This is the app reference. For what wine-quarantine is and how to install it, see the [main README](../README.md); for how it works underneath, see the [technical guide](../docs/TECHNICAL.md).

```bash
python3 wq-ui/integrate.py     # once: wires wq-ui into config.sh, _launch-core.sh and verify-sandbox.sh
python3 wq-ui/wq_ui.py
```

Needs PySide6. `integrate.py` keeps backups as `<file>.wq-orig` and supports `--dry-run` and `--revert`.

## Files

| File | What it does |
|---|---|
| `wq_ui.py` | The main window, themes and settings |
| `wq_dialogs.py` | Add-game dialog, `/dev` picker, executable picker |
| `wq_core.py` | Qt-free logic: parsing, validation, game discovery, theme tokens |
| `wq_xray.py` | The X-Ray tab: treemap widget and background scanning |
| `wq_notify.py` | Desktop notifications (notify-send) for new monitor alerts and run results; Qt-free, tested by `test_notify.py` |
| `wq_xray_core.py` | Qt-free logic for X-Ray: snapshots, baseline, diff, tree, treemap layout, program detection |
| `wq_relax.py`, `wq_relax_dialog.py` | The Relax button: the ladder of restrictions and what a trial's result means (Qt-free, `test_relax.py`), and the dialog that drives it |
| `wq_posture.py` | Qt-free shield score: what a profile leaves switched on |
| `wq_runlog.py` | Qt-free run log reading: history, timeline, sandbox check, connection attempts, host stats |
| `wq_visuals.py` | The widgets for the above: shield ring, Runs tab, host map |
| `wq_themes.py` | The built-in colour themes and the loader for your own |
| `profile.sh` | Turns a game's settings into firejail arguments |
| `new-native.sh`, `_launch-native.sh` | Create and launch native Linux games |
| `../lib-extract.sh` | Unpacking helpers shared by both creation scripts (`.iso`, symlink clean-up) |
| `wq_debug.py` | Dependency checks and a redacted bug-report builder |
| `integrate.py` | One-time wiring into the main scripts |
| `test_core.py`, `test_xray.py`, `test_posture.py`, `test_runlog.py`, `test_profile.sh`, `test_native_monitor_scan.sh` | Tests |

## Toolbar

* **Add** opens a menu: New game…, Set executable…, Attach a shell script (before launch / after exit), Hide a /dev device…, Open game folder.
* **Launch / Stop** start and stop the selected games. Double-click a game to launch it.
* **Rescan** re-reads the games from disk. **Remove** moves the selected game to the Trash.
* **Settings** sets the quarantine folder, theme and custom CSS. **Debug** opens the checks and report builder.
* Right-click a game for Launch, Stop, Set executable, Open folder and Remove.

## Game list

* **Shield** ring next to each game's name: a score from 0 to 100 and a grade (A 90+, B 75+, C 55+, D 35+, F), green, amber or red. It says how much of the sandbox is still switched on for that game, read from the same effective settings the launcher uses. Hover for what is costing points. See [Shield](#shield).
* **Filter** box above the list (Ctrl+F) narrows it by name or executable. Selected games always stay visible.
* **Last run** shows the result of each game's latest run, read from its logs: `✓ clean`, `⚠ N notes`, `✗ N alerts`, `✗ launch blocked` or `✗ sandbox leak`, plus how long ago. It follows the same priority as the verdict printed by `summarize-run.sh`. When a run ends with a problem and you are on another tab, the Monitor and Runs tabs get a dot.
* **Right-click the header** to show or hide columns. Display is hidden by default; the choice is remembered.
* The status bar shows the game count and how many are running. The window, splitter, tab, selected games and columns are restored next start (kept in `~/.config/wq-ui/settings.json`).
* Shortcuts: Ctrl+N new game, Ctrl+Enter launch, Ctrl+. stop, Ctrl+F filter, Ctrl+1 to Ctrl+6 switch tabs, Ctrl+S apply, Ctrl+, settings, F5 rescan.

## Adding a game

**Add > New game…** starts on *Auto-detect*. As soon as you pick a source the type is guessed without unpacking or running anything: `.exe`, `.bat`, `.cmd`, `.msi` mean Windows; `.sh`, AppImage, `.x86_64` and ELF binaries mean native Linux. For folders it looks a few levels down, for `.zip` and `.tar.*` it reads the file list, for `.iso`, `.7z` and `.rar` it asks `7z`, `bsdtar` or `unrar` for the list, and for a single unlabelled file it checks the first bytes (MZ, ELF or `#!`). Files near the top win, so a Windows game with a stray helper script is still Windows. If a source has both kinds at the top, or neither, the dialog says so and you choose. If you pick a type that disagrees with the guess you get a warning, not a block.

`.iso` images are unpacked with `7z` (or `bsdtar`) and never mounted, so no root is needed. Afterwards the files are made writable and any symlink pointing outside the game folder is removed.

An `.iso` or archive that holds an *installer* is unpacked, not installed: the start-file picker lists what is inside `game/`.

## Game types

**Windows** games are created by `new-quarantine.sh` and run through umu/Proton with their own prefix.

**Native Linux** games are created by `new-native.sh`. `game.conf` has `RUNNER=native` and `EXE=start.sh`. They use the same protection boxes and whitelists as Windows games, with these differences:

* Only `game/` is writable.
* With "Hide home directory" on, `$HOME` is `<game>/home`, so saves persist between runs.
* `verify-sandbox.sh` runs in its native mode (the Wine-only checks are skipped). In place of the registry check, `home-diff.sh` compares startup files, autostart entries, systemd user units, `~/.local/bin`, `~/.ssh` and the executables under `game/` before and after the run.
* `monitor.sh` runs in native mode (`lib-monitor-native.sh`), see the main README.
* `wq-scan.sh` (ClamAV) scans `game/` and `home/` after each run.
* The launcher exits with the game's own exit code.

## Relax…

**Relax…** (Ctrl+R) is for a game that exits at once because one of the restrictions is in its way, which is common under Proton. It launches the selected game through the normal launcher. If the sandbox ends inside the *quick-launch window* (20 s by default), it switches off the next restriction for that game in `game.conf` and launches again, until one launch stays up. The first trial uses your current settings, so a game that already works is left alone.

* **Order.** The ladder is in `wq_relax.LADDER`, most likely culprit and cheapest first: namespaces, extra seccomp syscalls, read-only game folder, audio, raw input, IPC namespace, minimal /dev, and so on. After a failed launch the game's own output (not the firejail banner or the verifier lines) is searched for hints, such as `Bad system call` or `Cannot open display`, and the matching step goes first. Untick any step you never want switched off.
* **The window starts when the sandbox does.** The launcher spends time on pre-launch scans and prefix setup before any sandbox exists, and on registry diffs and scans after the game ends. So success means the `firejail` process stayed up for the window, not that the launcher was still running.
* **What it never does.** It never touches PRESCAN, ClamAV, YARA, capa, MONITOR_KILL or any network setting, and never relaxes anything to get past a refused launch, a sandbox-verifier failure, a missing Proton or a monitor alert. Those are findings or setup problems and it stops and says so. No new privileges, dropped capabilities and the private home are listed but unticked; steps with a large cost (the private X server, and those three) always ask first.
* **Ask before each step** pauses after every failure with *Relax it and retry*, *Skip this one* and *That launch was fine, stop here* (for a launcher that starts something else and exits by design).
* **Undo.** Before the first change the dialog saves the old lines (or their absence) in `~/.cache/wq-ui/relax/`, outside anything the game can write. *Undo all* restores `game.conf` exactly, and if wq-ui dies mid-session the next Relax… offers to restore. When it works you choose *Keep changes*, and they become the game's own settings on the Protection tab.

## Shield

The ring next to each game is a summary of its profile, not a measurement. It starts at 100 and loses points for every protection that is off or weakened. The biggest costs are things that let a game see or touch your real data: your home folder visible (14), no syscall filter (10), sharing your display instead of using the private X server (10), an unrestricted network (45) or learn mode (30), a whole home folder whitelisted as writable (25), and launch scripts that run outside the sandbox (6 each). Comfort switches such as audio cost 1. Every switch that is weaker than Strict costs something, whatever way it got that way (ticked by hand, a preset, or *Relax*), and for every runner: `memfd_create` (2), write+execute memory (3) and namespace restriction (3) are charged for Wine and Proton games too, even though those usually need them off. The full table is `PENALTY` in `wq_posture.py`, and it is deliberately blunt and easy to change.

A stock Wine game scores in the high 60s (C, amber): the host display, webcams, security keys, a writable game folder and the compatibility relaxations (namespaces, `memfd_create`, write+execute memory) are the gaps. The Strict preset with the private X server on scores 100.

The Protection tab shows the same ring, larger, with the biggest weaknesses listed. It follows the boxes as you tick them, before you press Apply, so you can see what a change costs. When several games are selected, boxes where they differ count as relaxed.

What it doesn't tell you: whether the sandbox actually works (that is what *Test sandbox* and the pre-launch check are for) or whether the game is hostile. A score of 100 means every switch is on, not that the game is safe.

## Runs tab

Everything about how a game's runs went, read from the logs the launcher and monitor already write. It needs no change to the monitor.

* **History strip**: one bar per run, oldest on the left, coloured by verdict (green clean, amber notes, red alert, blocked or leak). Taller bars have more findings. Click one to open that run. If the newest run is worse than at least three clean runs in a row before it, a line says so, because a game that behaves until it has been trusted for a while is a known pattern.
* **Sandbox check before launch**: the verifier's checks as a bar of segments (green passed, red failed) with the checks grouped under Privileges, Network, Files and Display and IPC. It fills in live while a game launches, and stays collapsed while everything passes.
* **Timeline**: lanes for processes, files and persistence, ClamAV and network, plus a lane for the monitor itself when it logged something. A dot is the events in that stretch of time; bigger means more, and the colour is the worst of them. Hover for the messages, click to jump to the row in the list below. The time the game ran takes most of the width and the work after it exited (home and registry diffs, ClamAV) is shaded and gets its own scale, so a three-hour game and a ten-second scan are both readable. Blocked and allowed connection attempts appear on the network lane.
* **Since the run before**: warnings and alerts that are new in this run and ones that went away. Pids, counts and timestamps are ignored when comparing, so "ClamAV database is 21 days old" and "22 days old" are the same finding.
* **Warnings and alerts in this run**: the list behind the timeline, with the time offset from launch.

The monitor logs a process start without its parent, so processes appear as events on a lane and not as a tree. Connection attempts are kept in `logs/net-attempts.jsonl` by wq-ui while it is open, so a run only has network events if wq-ui was running during it. The file is capped at 512 KB and each destination is logged at most once a second.

## X-Ray tab

Shows what a game did to its own folders, as a treemap of `game/`, `prefix/`, `home/` and any whitelisted paths. Tile area is file size. Green is a file that was already there, amber is one whose size or date changed, red is one that didn't exist before the run.

Just before each launch wq-ui saves a list of those folders (path, size, date) as the baseline, in `~/.cache/wq-ui/xray/` so it sits outside the game folder. When the game exits the tab rescans and compares, and a dot appears on the tab if the run changed something. If a huge game folder makes that pause annoying, untick *Snapshot before each launch*. *Set baseline now* accepts the current state as the reference. A first baseline is also saved when a game is added (`new-quarantine.sh` / `new-native.sh`, from the app or the command line), right after its files are in place and before the ClamAV scan, so a new game opens all green. Set `WQ_XRAY_BASELINE=0` to skip that, or run `python3 wq-ui/wq_xray_core.py --baseline "<game folder>"` to take one by hand.

Dates alone don't work, because Wine and installers keep the dates of the files they copy. So a file counts as modified when its size or date differs from the baseline, and as new when its path isn't in the baseline. Removed files are counted but not drawn.

**Programs.** A new `.png` and a new `.exe` are not the same news, so new and modified files get a quick look at their first bytes. Windows programs (MZ and PE headers), Linux ELF files, scripts (a `#!` line, or `.sh`, `.bat`, `.ps1`, `.vbs` and similar), and launchers and shortcuts (`.desktop`, `.lnk`, `.service`) get a heavy frame and a label on their tile, and the summary line counts them. A dotted fill means a program's bytes look packed or encrypted (entropy of 7.2 or more bits per byte over its first 64 KB, programs of 8 KB and up only). Ordinary game data such as pak files, audio and textures is compressed too, so a high entropy number is only ever reported for programs. Up to 400 changed files are looked at per scan, new ones first, in a background thread. Symlinks are never opened and a pipe or device a game leaves behind can't block the scan. This is a hint about what a file is, not a verdict: legitimate patchers and mod tools write programs too.

Click a tile to open a folder, right-click or Backspace to go up, or use the path above the map. Folders with changes inside get a red or amber border and a count, so a new file can't hide in a collapsed folder.

*Size ratio* (default 35) sets how much file size counts for tile area. At 0 every file gets the same tile, at 100 it's true proportions. Somewhere in between a 2 KB save file stays visible next to a 4 GB archive. *Max tile share* caps how much of its folder one tile can take, so a single huge file doesn't squeeze everything else into slivers. Double-click a slider to reset it.

Whitelisted paths are on the map too. Anything you add on the Paths tab that lives outside the game folder gets a tile named after the folder, so a save folder or asset library is tracked like `game/`. Hover a tile to see which rule made it read-write or read-only. Paths nested inside another whitelisted path share its tile. Paths so broad that they'd contain the game folder or your home directory aren't scanned and are listed under the map as "off this map". A folder you add after the baseline was taken shows as existing (not all red) until the next baseline. A big read-only library makes the pre-launch snapshot slower, so untick the snapshot or drop it from the whitelist if that bothers you.

Only the folders themselves are scanned and symlinks are never followed. `logs/` and the launcher's own files aren't part of the picture.

*Show sandbox access* (on by default) lays the profile over the same map. Hatched tiles are read-only for the game, cross-hatched with a dashed edge means hidden from it, and a corner mark on a folder means it holds both. Hover a tile to see which rule decided it. A line under the summary counts them and warns when a changed file sits somewhere the profile doesn't let the game write (a host-side launch script, an installer run outside the sandbox, or a profile edited since the run). Places that aren't under `game/`, `prefix/` or `home/` can't be drawn, so they're listed under the map, and entries skipped at launch (missing or relative paths) are counted there too.

The overlay takes its rules from the same places `profile.sh` does: `game/` is read-write, plus `prefix/` for Windows games or `home/` for native games with a private home; the extra whitelists (`FJ_WL_RW`, `FJ_WL_RO`) from both `game.conf` and `profile.defaults.conf`; and `--blacklist=`, `--read-only=` and `--noexec=` from the extra firejail options (the game's own list, else the default profile's). Where rules overlap the most specific mount wins, read-only wins a tie, and a blacklist beats everything. Anything no rule mounts counts as hidden. It's a model of the arguments `profile.sh` builds, read as data. It doesn't query a running sandbox, and it leaves out the launcher's fixed hides (docker, libvirt and resolver sockets) and `HOME_BLACKLIST` / `BLACKLIST_PATHS` from `config.sh`.

## Entropy tab

Plots how random each part of a file looks, because malware is often encrypted or packed and that shows up as a long stretch of near-random bytes inside something that should be code or text. Pick a file with *Open file…* (the dialog starts in the selected game's folder) and it plots straight away.

Each point is one block of the file: 0 bits per byte is a single repeated byte, around 4 to 5 is source code or ordinary text, 8 is noise. Blocks at or above *Flag above* (7.2, the same cut-off the X-Ray uses for packed programs) are drawn red, and runs of two or more are listed on the right. The strip along the top is the whole file in one view, and clicking it jumps there; hold the button and drag to scrub through the file. The plot underneath scrolls along the file with the wheel, the scrollbar, the arrow keys or by dragging it, and *Zoom* sets how many pixels each block gets. Click any block (a click that doesn't move) to see its bytes, its offset and how much of it is printable text. *Next flagged* steps through the runs and wraps round at the end.

*Block* is 1 KB by default. Random data only reaches about 7.2 in a 256-byte block roughly a third of the time, so the 256 B setting is noisy: use it to look closely at a spot you've already found, not to scan.

A high reading is a lead and not a verdict. PNG and JPEG images, zip archives, audio and game `.pak` files are compressed on purpose and read high all the way through. What deserves a look is a flagged run inside an `.exe`, `.dll`, script or other file that shouldn't be compressed, or a high patch in the middle of a file that is otherwise low. The file is read one block at a time on a worker thread (files over 512 MB are refused), symlinks are never followed, and nothing is written. The analysis is in `wq_entropy.py` and is covered by `test_entropy.py`.

## Findings tab

One table of what the scanners found, read from the game's alert logs. Each row has a level (Alert, Warning, Info), a source (YARA, capa, Encrypted data, Packing, Indicators, Structure, Heuristics, ClamAV or Launch), the rule or check that fired, its details and the file inside the game folder it concerns. Hover a row for the full details and path.

* The drop-down above the table picks which log to read, newest first. *Show informational* adds the Info rows, which are hidden by default.
* **Scan now** runs the same pre-launch scan a launch would run (YARA, capa, packing and encrypted-block checks, ClamAV) without starting the game, then shows the result. It can take a minute on a big game folder.
* **Open log** opens the raw alert log.

A finding is a lead, not a verdict. See [pre-launch scanning](../docs/TECHNICAL.md#pre-launch-scanning) for how points and rule severities decide whether a launch is refused.

## Themes

Settings > Theme offers *Follow system*, *Light*, *Dark* and these built-in themes:

* Dark: **Pixel** (pixel-art frames and font), **Cyberpunk**, **Synthwave**, **Matrix** (neon, monospace, sharp corners), **Anime** (sakura pink and sky blue on night-sky indigo, soft rounded corners, pastel gradient buttons), Dracula, Nord, Gruvbox Dark, Catppuccin Mocha, Tokyo Night, Rosé Pine, One Dark, Solarized Dark.
* Light: Catppuccin Latte, Gruvbox Light, Solarized Light.

The palettes come from the open-source themes of those names (MIT or similar). The neon three are in the style of the usual editor themes, not copies, and Anime is an original palette. `test_core.py` checks that every theme keeps readable text, button and alert contrast.

**Pixel** is a built-in dark theme drawn for wq-ui: chunky nine-slice pixel frames with notched corners on buttons, group boxes and text fields, a faint dither tile behind the window, square corners everywhere, amber on night-violet, and the Pixelify Sans font (bundled in `theme_assets/fonts/`, SIL Open Font License). The frames are made by `python3 tools/make_pixel_assets.py`; change the palette there and in `wq_themes.py` to re-skin it.

A theme's QSS can refer to images as `@assets/<file>`, which resolves to `theme_assets/`. Font credit is in `NOTICE.md`.

Your own themes: put a `.css` file in `~/.config/wq-ui/themes/` and it appears in the list under "(yours)". It reloads live when saved. Same format as any wq-ui CSS file:

```css
/* theme: My Theme */
@define-color mode dark;            /* dark or light: which defaults fill any colour you skip */
@define-color primary #ff00aa;
@define-color surface #101018;
QPushButton { border-radius: 0; }   /* anything below is plain QSS for this theme */
```

To port a theme from another project, copy its palette into the tokens (`surface`, `surface_container`, `surface_container_high`, `on_surface`, `on_surface_variant`, `primary`, `on_primary`, `outline`, `error`, `ok`, `warn`).

**CSS order.** Existing setups are unaffected. The order is base light/dark, then the theme's colours, the shared stylesheet, the theme's extras, and last your CSS file from Settings, so it still overrides everything. `{mode}` in the CSS path becomes the chosen theme's base (`light` or `dark`), so matugen files keep working. Names that no longer exist fall back to Follow system.

## Tabs

* **Protection**: isolation and device switches, hidden `/dev` nodes, limits and extra options, private X server and size.
* **Paths**: the folders the sandbox can see, extra whitelisted paths, and launch scripts.
* **Network**: off, filtered or learn mode, allow-list, interface, DNS, connection logging, a live view of attempts and a map of the destinations a game has tried to reach.
* **Monitor**: alerts and run summaries for the selected game.
* **X-Ray**: what a run changed in the game's folders, with new programs picked out.
* **Runs**: history of recent runs, the sandbox's own pre-launch check and a timeline of what happened.
* **Entropy**: how random each part of a file looks, to spot packed or encrypted code. See [Entropy tab](#entropy-tab).
* **Findings**: everything YARA, capa, ClamAV and the pre-launch checks found, in one table. See [Findings tab](#findings-tab).

Boxes show the effective value: this game's setting, else the default profile, else stock. A box in the middle state means the selected games differ.

## Keys in game.conf and profile.defaults.conf

The header of `profile.sh` lists them all. The ones added with native support: `RUNNER` (`native`), `FJ_DEV_BLOCK` (repeatable), `FJ_HOOK_PRE` and `FJ_HOOK_POST` (per game only, never read from the defaults file).

## ClamAV keys in game.conf

`CLAM_SCAN=0|1` overrides the global `CLAM_SCAN_AFTER_RUN` for this game. The global settings live in `config.sh` / `config.local.sh`, see the [configuration reference](../docs/TECHNICAL.md#configuration-reference). The Monitor and Findings tabs show the results because they are written to the run's alert log. There is no checkbox for them in the app yet.

## Limits and extra options

The Protection tab has a **Limits and extra options** box.

| Field | Key | What it does |
|---|---|---|
| Max processes and threads | `FJ_TASKS_MAX` | Fork-bomb protection. cgroup `TasksMax` for this game only. 4096 is a safe start for Wine/Proton. |
| Max memory | `FJ_MEMORY_MAX` | cgroup `MemoryMax`, e.g. `8G`. |
| Extra blocked syscalls | `FJ_SECCOMP_EXTRA` | Appended to `SECCOMP_DROP` (needs the seccomp filter on). |
| Extra firejail options | `FJ_EXTRA_ARGS` | One option per line. |

The two limits run the whole launch inside `systemd-run --user --scope`, so they need a systemd user
session. If one is set and the scope cannot be created, the launch is **cancelled** rather than run
unlimited. `FJ_TASKS_MAX` is used instead of `--rlimit-nproc` because that limit counts every process
of your user, not just the game's. A value below what your desktop already runs would stop the game from
forking at all, so `profile.sh` refuses it.

The extra options box only accepts options that make the sandbox tighter:
`--rlimit-nofile|fsize|cpu|as|sigpending=N`, `--timeout=hh:mm:ss`, `--nice=0..19`, `--cpu=0,1`,
`--blacklist=/path`, `--noexec=/path`, `--read-only=/path`, `--rmenv=NAME`, `--machine-id`, `--nosound`,
`--novideo`, `--nou2f`, `--notv`, `--nodvd`, `--noroot`. Anything else, such as `--net`, `--whitelist`,
`--ignore` or `--noprofile`, cancels the launch with a message instead of being skipped. The list lives in
`_wq_extra_arg_ok` (`profile.sh`) and `check_extra_arg` (`wq_core.py`); `test_core.py` runs both on the
same inputs. As with the checkboxes, a game's own list replaces the default profile's list, and an empty
`FJ_EXTRA_ARGS=` line in `game.conf` means "none".

## DNS and the other sockets

`--net=none` does not stop name lookups: `nss-resolve` and `nscd` answer over Unix sockets that need no
network interface, so a game could leak data as hostnames. The default profile now hides
`/run/systemd/resolve`, `/run/nscd`, `/run/systemd/private` and `/run/containerd` (`FJ_BLOCK_SOCKETS=0`
to opt out; they are left alone in unrestricted-network mode, which needs the stub resolver). Both
launchers check at start-up that the resolver socket is really gone. `FJ_MACHINE_ID` (on by default)
gives the game a random `/etc/machine-id`, and `bpf` is in the default seccomp drop list.

## Launch scripts

A before-launch or after-exit script runs on your machine with your permissions, not inside the sandbox. A failing before-launch script cancels the launch. Scripts get `WQ_GAME`, `WQ_GAMEDIR` and `WQ_QROOT` in the environment. Only attach scripts you trust.

## Network destinations

Under the attempts table, the Network tab draws the destinations the selected game has tried to reach over the last 30 days as bars, busiest first. Red is blocked, amber is a mix or learn mode, green is let through by a filtered allow-list, and a pill marks a destination first seen in the latest run. Hover for ports, protocol, counts and first and last seen.

Underneath is a preview of what the learn-mode recording would become: how many destinations are already whitelisted, how many can be added now, how many still need tcp or udp chosen (the kernel log says which for most), and how many can't be whitelisted at all (IPv6, multicast). *Stage learned entries…* lists exactly what would be added and asks first; it stages them like any other edit, so nothing is saved until Apply. A game that misbehaved while you were recording would get its destinations whitelisted too, so use it only for games you trust.

## Tests

```bash
python3 wq-ui/test_core.py
python3 wq-ui/test_xray.py
python3 wq-ui/test_posture.py
python3 wq-ui/test_runlog.py
bash wq-ui/test_profile.sh
```

`test_profile.sh` checks the argument building (blocked devices, hidden Wayland socket, launch scripts) without needing firejail. It doesn't test a real sandbox; for that, run a small probe script as a native game and read its output.


## Added checkboxes and options

- Isolation group now shows `FJ_NOGROUPS`, `FJ_PRIVATE_DEV`, `FJ_NOINPUT`, `FJ_BLOCK_SOCKETS` and
  `FJ_RESTRICT_NS` (RESTRICT_NS defaults on for native games, off for Wine/Proton).
- `FJ_BLOCK_MEDIA` (default on): hides `/media`, `/run/media` and `/mnt`. A path that contains the game,
  umu data or a whitelisted path is left visible and a note is printed. `verify-sandbox.sh` checks
  whatever was hidden, and also that `/dev/input` is not readable (skip token `input`).
- `FJ_GAME_RO` (default off): mounts `game/` read-only. The verifier then expects it to be unwritable.
- `FJ_MDWX` (default off, Advanced group): firejail's `--memory-deny-write-execute`. Memory can't be writable and executable at once,
  and a program can't add execute to memory it wrote, which stops in-process shellcode and loaders. Wine/Proton, DXVK and
  every JIT need that, so it's for native games without a JIT (Strict turns it on; Balanced and Compatibility leave it off).
  It doesn't depend on `FJ_SECCOMP`. The verifier tries to map a writable+executable page (skip token `mdwx`), and Test
  sandbox has a matching row.
- `FJ_MEMFD` (default off, Advanced group): blocks `memfd_create` through the seccomp filter, so a program can't build an
  executable in anonymous memory and run it without touching disk. Wine/Proton, Mesa, SDL and Wayland all use
  `memfd_create`, so it's meant for native games or one game at a time (Strict turns it on, Balanced and Compatibility
  leave it off). It needs `FJ_SECCOMP` on. The verifier checks that the call fails (skip token `memfd`), and the
  Test sandbox button has a `memfd_create` row.

## Test sandbox (toolbar button, Ctrl+T)

Runs `wq-ui/probe.sh` inside the real sandbox and shows what gets through. Select a game first to
test **its** profile (defaults + game.conf, resolved the same way the launcher does); with no game
selected it tests the saved defaults.

- It builds a throwaway native game, `<QROOT>/_sandbox-test`, with the game's profile copied in. The
  folder is recreated for every test and ignored by the games list and `update-launchers.sh`.
  Hooks (`FJ_HOOK_*`) are never copied, ClamAV is off and the kill switch is off for the test so an alert
  can't cut the report short. A Wine game is tested as a native game, so a few checks (the Wine prefix,
  umu data) don't apply.
- Results are `ok` / `LEAK` / `info`. `info` depends on your toggles, so read it rather than fixing it.
  If `verify-sandbox.sh` refuses the launch, the dialog shows the failed checks instead.
- The last 5 results per game are kept in `<QROOT>/.sandbox-tests/`. The **Changes since last run** tab lists the
  settings that differ and the checks that flipped, which is the quick way to confirm a checkbox does what its
  label says. A setting that changed with no result changing means the probe has no check for it.
- **Copy report** puts the full result and the diff on the clipboard. `probe.sh` can also be run by hand as a
  native game (`--quiet`, `--net-target HOST:PORT`).
- Tests: `python3 wq-ui/test_probe.py`, `python3 wq-ui/test_sandboxtest_qt.py` (offscreen, needs PySide6).
