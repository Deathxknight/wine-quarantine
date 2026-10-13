# wq-ui

The Qt front end for wine-quarantine: list your games, edit each game's sandbox profile, launch, and watch the network and monitor.

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
| `profile.sh` | Turns a game's settings into firejail arguments |
| `new-native.sh`, `_launch-native.sh` | Create and launch native Linux games |
| `wq_debug.py` | Dependency checks and a redacted bug-report builder |
| `integrate.py` | One-time wiring into the main scripts |
| `test_core.py`, `test_profile.sh` | Tests |

## Toolbar

* **Add** opens a menu: New game…, Set executable…, Attach a shell script (before launch / after exit), Hide a /dev device…, Open game folder.
* **Launch / Stop** start and stop the selected games. Double-click a game to launch it.
* **Rescan** re-reads the games from disk. **Remove** moves the selected game to the Trash.
* **Settings** sets the quarantine folder, theme and custom CSS. **Debug** opens the checks and report builder.
* Right-click a game for Launch, Stop, Set executable, Open folder and Remove.

## Game types

**Windows** games are created by `new-quarantine.sh` and run through umu/Proton with their own prefix.

**Native Linux** games are created by `new-native.sh`. `game.conf` has `RUNNER=native` and `EXE=start.sh`. They use the same protection boxes and whitelists as Windows games, with these differences:

* Only `game/` is writable.
* With "Hide home directory" on, `$HOME` is `<game>/home`, so saves persist between runs.
* `verify-sandbox.sh` is not run and there is no registry check.
* The launcher exits with the game's own exit code.

## Tabs

* **Protection**: isolation and device switches, hidden `/dev` nodes, limits and extra options, private X server and size.
* **Paths**: the folders the sandbox can see, extra whitelisted paths, and launch scripts.
* **Network**: off, filtered or learn mode, allow-list, interface, DNS, connection logging and a live view of attempts.
* **Monitor**: alerts and run summaries for the selected game.

Boxes show the effective value: this game's setting, else the default profile, else stock. A box in the middle state means the selected games differ.

## Keys in game.conf and profile.defaults.conf

The header of `profile.sh` lists them all. The ones added with native support: `RUNNER` (`native`), `FJ_DEV_BLOCK` (repeatable), `FJ_HOOK_PRE` and `FJ_HOOK_POST` (per game only, never read from the defaults file).

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

## Tests

```bash
python3 wq-ui/test_core.py
bash wq-ui/test_profile.sh
```

`test_profile.sh` checks the argument building (blocked devices, hidden Wayland socket, launch scripts) without needing firejail. It doesn't test a real sandbox; for that, run a small probe script as a native game and read its output.
