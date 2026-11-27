# Bundled rule sets

These are unmodified copies of upstream rule sets. Each folder keeps its own license file.

| Folder | Upstream | License | Used by |
|---|---|---|---|
| `signature-base-yara/` | https://github.com/Neo23x0/signature-base (`yara/`) | Detection Rule License 1.1 (`LICENSE.txt`) | `wq-yara-build.sh` (default) |
| `yara-rules/` | https://github.com/Yara-Rules/rules | GPL-2.0 (`LICENSE.txt`) | `wq-yara-build.sh` (default) |
| `capa-rules/` | https://github.com/mandiant/capa-rules | Apache-2.0 (`LICENSE.txt`) | `wq-prescan.py`, when the separate `capa` program is installed (these are capa's YAML rules, not YARA) |

Copies are from the snapshots supplied on 22 November 2026. Check upstream for newer rules.

## License note for the project

`yara-rules/` is GPL-2.0. Anyone who distributes this project with those files has to license the combined work in a way that GPL-2.0 allows, which generally means GPL-2.0-only or GPL-2.0-or-later. If you want a more permissive license for the project itself, remove `yara-rules/` and clone it yourself, as described in [Rule sets and licensing](../docs/TECHNICAL.md#rule-sets-and-licensing).

The Detection Rule License asks that distributed copies keep the rule authors' attribution and a link to the source. Keep these folders and their license files intact when you redistribute.
