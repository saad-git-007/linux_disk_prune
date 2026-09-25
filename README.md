<div align="center">

# ◆ Disk Prune

**A fast, good-looking disk analyzer and *safe* cleanup assistant for Ubuntu 22.04, written in Rust.**

See where your space goes as a treemap or sunburst, then reclaim it with a recommendation engine that knows Ubuntu: APT caches, old kernels, snap revisions, the journal, browser and Electron app caches, developer caches and build output. It shows exactly how much each item frees and the exact command it will run.

<img src="docs/screenshots/sunburst-intro.gif" width="640" alt="Sunburst view animating in">

**[⬇️ Download the .deb](https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb)** · [Install instructions](#install) · [Screenshots](#screenshots)

*Inspired by [disktree](https://github.com/tobi/disktree) by Tobi Lütke ♥*

</div>

---

## Screenshots

| Treemap | Sunburst |
|---|---|
| ![Treemap](docs/screenshots/treemap.png) | ![Sunburst](docs/screenshots/sunburst.png) |
| **Prune dashboard** | **Review before anything runs** |
| ![Prune](docs/screenshots/prune.png) | ![Review](docs/screenshots/review.png) |
| **Scanning (sonar)** | **Tree** |
| ![Scan](docs/screenshots/scan.png) | ![Tree](docs/screenshots/tree.png) |
| **Bloom-in animation** | **About & credits** |
| ![Bloom-in](docs/screenshots/bloom-in.png) | ![About](docs/screenshots/about.png) |

<sub>The screenshots use a synthetic demo home folder.</sub>

## Why Disk Prune? How it compares to disktree

[disktree](https://github.com/tobi/disktree) is a lovely treemap for finding what fills a disk, built for Omarchy (Arch) with GPUI. Disk Prune started from its ideas and goes further in the direction of **telling you what is safe to delete on Ubuntu, and doing it for you, safely**.

| | disktree | **Disk Prune** |
|---|---|---|
| What gets flagged as reclaimable | Hatched by folder *kind*: caches, sync history, package stores, build output | A **rule engine for Ubuntu 22.04** with 40+ checks: APT, old kernels and their leftovers, disabled snap revisions, orphaned snapd downloads, `apt autoremove`, unused Flatpak runtimes, journal, logs, crash and core dumps, browser and Electron app caches, old IDE versions, pip/uv/cargo/npm/Go/Gradle caches, Docker, Rust `target/`, `node_modules`. Each finding has a size, a risk tier and the exact command |
| System cleanup | Refuses package-managed trees and points you to the right tools | **Runs those tools for you**: `apt-get clean`, kernel purge (dry-run with `apt-get -s` first), `snap remove --revision`, `journalctl --vacuum-size`, all behind **one** `pkexec` password prompt with a live log |
| Risk guidance | Remove or keep | **SAFE / MODERATE / CAUTION** tiers, with a plain-language reason and a "free now vs. after" gauge |
| Views | Treemap | Treemap, **sunburst**, size tree and a prune dashboard |
| Hardware | Needs a GPU that GPUI can drive (Vulkan) on Wayland/X11 | Vulkan on the integrated GPU when it can present, **automatic OpenGL fallback**, and it works on virtual/remote displays |
| No display? | — | **Terminal UI** (`--tui`) over SSH, plus `--summary` / `--json` for scripts and cron |
| Install on Ubuntu | Build from source or tarball | **`.deb` package** with launcher entry, icon and *Open with* for folders |
| Verification | Removal rules are unit-tested | 103 unit tests, an **independent black-box suite (178 checks)** against GNU `du`, and a **live-system validator** that re-derives every recommendation from `apt`, `dpkg`, `snap`, `journalctl`, `find` and `pgrep` |

**Where disktree is still ahead.** It has an *Age* colouring mode, name filtering, git status for checkouts (changes, stashes, unpushed commits), smooth magnify-zoom and panning, btrfs subvolume awareness, and a memoised scan that widens from `~` to `/` without rescanning. If you are on Omarchy/Arch, use disktree. If you are on Ubuntu and want to reclaim space rather than just find it, that's what Disk Prune is for.

## Features

### Four ways to look at a disk
- **▦ Treemap:** a nested, squarified mosaic.
  - Colour shows the *kind* of data: code, git, build output, caches, toolchains, media, documents, VMs & containers, logs, system.
  - Space you can reclaim gets marching lime stripes.
  - Tiles bloom in, and zooming (double-click or scroll) animates into place.
- **◉ Sunburst:** the hierarchy as concentric rings, with a clock-wipe intro, radial labels and lime rims on reclaimable space. Click the glowing hub to go up.
- **☰ Tree:** a virtualised size tree with gradient share bars and a tag on every item that has a cleanup suggestion.
- **♻ Prune:** an animated donut of everything reclaimable, cards per risk tier, and a checklist. Each item shows its exact command, with a Copy button.
- **Top savings:** the side panel of every view lists the biggest wins, so you can jump straight to them.

### The "Abyssal" look
A deep-sea bioluminescence theme: ink-violet depths, glowing cyan, jellyfish magenta and plankton lime.

Animations:
- drifting aurora light behind the content
- a breathing selection glow with HUD brackets
- a tab pill that slides between tabs
- numbers that count up
- a sonar radar while scanning
- notifications that slide in

Ambient motion pauses by itself after a few idle seconds, so an idle window uses **0% CPU**. The ✨ Motion button turns it off entirely.

### Ubuntu 22.04 recommendation engine

Every rule asks the owning tool what is safe, instead of guessing from folder names. Only the data that tool would recreate or no longer needs is proposed.

**System** (admin actions are batched behind one password prompt)

| Check | Finds | Tier | Runs |
|---|---|---|---|
| APT cache | downloaded `*.deb` archives and partial downloads (package lists are rebuilt on the next `apt`, so they aren't counted) | SAFE | `sudo apt-get clean` |
| Kernels | installed kernels other than the **running one and the two newest** | MODERATE | `sudo apt-get purge -y <exact packages>`, simulated with `apt-get -s` first; becomes a manual step if the simulation would remove anything else |
| Kernel leftovers | `/lib/modules/<ver>` dirs no installed package owns, plus the matching `rc` dpkg records | MODERATE | `sudo dpkg --purge <rc packages>; sudo rm -rf -- <dirs>` |
| Snap | revisions `snap list --all` marks **disabled**, including each revision's saved data; shows what is freed now vs. after snapd drops its cached copy | MODERATE | `sudo snap remove <name> --revision=<rev>` |
| Orphaned snap downloads | files in snapd's cache that no installed snap links to any more | SAFE | `sudo rm -f --` (exact list) |
| Unused packages | what `apt-get -s autoremove` would remove, excluding kernels (sized from dpkg) | MODERATE | `sudo apt-get purge -y <exact packages>`, manual if purging them would take anything else with it |
| Flatpak | runtimes no installed app uses | MODERATE | `sudo flatpak uninstall --system --unused` |
| Journal | the exact archived journal files `--vacuum-size` would delete (default keep 500 MiB) | MODERATE | `sudo journalctl --vacuum-size=500M` |
| Logs & dumps | rotated logs (`*.gz`, `*.1` …), `/var/crash` reports, systemd core dumps | MODERATE / SAFE | `sudo rm -f --` (exact list) |
| Docker | dangling images, unused **non-shared** builder cache | SAFE | `docker image prune -f`, `docker builder prune -f` |

**Your home folder**

| Check | Finds | Tier |
|---|---|---|
| Browsers | Chrome, Chromium, Brave, Edge `Cache` / `Code Cache` / `GPUCache`; Firefox (deb and snap) `cache2`; Flatpak app caches. Profiles, logins and history are never touched | SAFE; a manual step while the browser is running |
| Electron apps | the Chromium caches of VS Code, Slack, Discord, … (only folders that really are a Chromium disk cache) | SAFE; skipped while the app is running |
| Editors & IDEs | extension versions VS Code/Cursor list in `.obsolete`; caches of **older** JetBrains IDE versions (the newest is kept) | SAFE |
| Python | pip, uv (only data not hard-linked into a venv), Poetry, Conda packages, `__pycache__` | SAFE |
| Node | npm `_cacache`, npx, Yarn, `pnpm store prune` | SAFE |
| Go / Java / Rust | Go build cache (SAFE), Go module cache, Gradle, Cargo registry (MODERATE), Cargo git checkouts | SAFE / MODERATE |
| Tools | Selenium and Playwright browsers, Mesa shader cache | SAFE |
| Desktop | thumbnails (SAFE), GNOME search index `tracker3` (MODERATE), Trash, including `.Trash-<uid>` on other drives (MODERATE) | |
| AI models | Hugging Face hub cache: only a manual step, since re-downloading can be many GB | CAUTION |
| Projects | Rust `target/` next to a `Cargo.toml` or with `CACHEDIR.TAG`; `node_modules/` next to a `package.json` | CAUTION |

**How it decides something is safe**
- **Ask the owner.** Kernels come from dpkg plus `uname -r`, snaps from `snap list --all`, unused packages from an `apt-get -s` simulation, Flatpak runtimes from `flatpak list`. Caches are cleaned with the tool that owns them (`uv cache clean`, `go clean -cache`, `pnpm store prune`, `tracker3 reset`) when it's installed.
- **Empty caches, keep the folders.** Cache rules delete only a cache's *contents*. Settings, profiles, logins, history, local storage and virtualenvs stay.
- **Don't pull the rug.** Browsers, Electron apps and npx programs that are running (lock file or process check) become a manual step. Stale locks left by a crash are recognised. Missing tools also turn a rule into a manual step instead of a guess.
- **Count only what is actually freed.** Sizes are real blocks on disk. Hard-linked data still used elsewhere (uv/pnpm/conda stores, snapd's cache) isn't counted. The journal figure replays journald's own vacuum.
- **Never flagged:** Ollama/LLM models, browser profiles, Docker volumes, `/var/lib/apt/lists`, rustup toolchains, anything in hidden app folders apart from the caches above, `~/snap` app data.

**Works on any Ubuntu 22.04 machine.** Nothing is tied to one user or layout:
- User paths follow `$HOME`, `XDG_CACHE_HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME`, `CARGO_HOME`, `PIP_CACHE_DIR` and `npm_config_cache`. Under `sudo`, environment overrides are ignored.
- System paths are discovered at runtime from `apt-config dump`, `snap debug paths`, `flatpak --installations`, journald's persistent or volatile store and `APPORT_REPORT_DIR`.
- Fonts come from fontconfig, and `pkexec` is found on `PATH`.

## Safety model

- **Read-only by default.** Nothing happens until you tick items or mark tiles, open *Review & clean*, and confirm. `--no-exec` turns the app into a pure viewer.
- **The command you see is the command that runs.** All admin actions of one cleanup run together through `pkexec`, so Ubuntu asks for your password **once**. Output streams live into a log window.
- **Your own marks go to the Trash** (recoverable) by default. Permanent deletion is an explicit choice.
- **Guards:**
  - Refuses `/`, top-level system dirs, your home folder, the scan root, and anything outside the scan root.
  - Refuses package-managed trees (`/usr`, `/etc`, `/boot`, `/var/lib`, `/snap`, …).
  - Refuses paths with symlinked parents.
  - **Never crosses into another mounted filesystem.** Deletion stops at a device boundary, and it refuses when `/proc/self/mountinfo` lists a mount point below the path.
  - Symlinks are unlinked, never followed.
- **Exact paths.** Folder names that aren't valid UTF-8 are acted on by their exact bytes. A shell command is never built from a lossy name.

## Accuracy & testing

Sizes are real disk usage (`st_blocks × 512`, what `du` reports). Hard links are counted once and credited deterministically; symlinks are not followed; the scan stays on one filesystem (`-x` to cross).

| Suite | What it proves | Result |
|---|---|---|
| `cargo test` (103 tests) | measuring rules (sparse files, hard links, symlinks, unreadable dirs, small-file folding), kernel/snap/log/Docker decisions from captured real-world inputs, removal guards incl. mount and symlink boundaries, and shell safety: generated commands run against 16 hostile file names (`$(…)`, backticks, quotes, newlines, leading `-`, globs, unicode) with no injection; every new rule against fixtures (running apps, missing tools, hard-linked stores, stale locks, env overrides) | ✅ 103 / 103 |
| [`tests/blackbox/run_blackbox_tests.py`](tests/blackbox/run_blackbox_tests.py) | an independent black-box run of the CLI against GNU `du`: sizes, detection with false-positive traps, command quoting via `shlex`, commands executed on fixtures, robustness, performance | ✅ 178 / 178 |
| [`tests/system/validate_ubuntu_rules.py`](tests/system/validate_ubuntu_rules.py) | read-only ground truth on a live Ubuntu 22.04 machine. For each rule it recomputes the answer independently (`apt-get -s`, `dpkg-query`, `snap list --all`, a replay of journald's vacuum, `find -links 1`, `du`, `pgrep`) and compares paths and bytes. It also lists large `~/.cache` folders that no rule covers | ✅ 39 / 39 rules exact |

A full scan of a real 66 GB home folder matches `du -sx` **to the byte**. On an i7-1165G7 with NVMe it takes about **0.6 s** and **76 MB** of RAM. The whole root filesystem (about 1 M files) takes about 1–2 s.

```sh
cargo test
cargo build --release && python3 tests/blackbox/run_blackbox_tests.py   # add --skip-perf / --skip-home to shorten
python3 tests/system/validate_ubuntu_rules.py                            # live system; needs `sudo -n` for read-only checks
```

## Install

### ⬇️ Download the .deb (Ubuntu 22.04 LTS or newer, x86_64)

[![Download .deb](https://img.shields.io/badge/download-linux--disk--prune__0.2.0__amd64.deb-00f2de?style=for-the-badge&logo=ubuntu&logoColor=white)](https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb)

**[linux-disk-prune_0.2.0_amd64.deb](https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb)** (about 5.5 MB) · [SHA-256](https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb.sha256) · [all releases](https://github.com/saad-git-007/linux_disk_prune/releases)

Tested on Ubuntu 22.04. The binary only needs glibc ≥ 2.35, so it also installs on newer Ubuntu releases; the cleanup rules are written for 22.04.

**Install in a terminal:**

```sh
# 1. Download the package and its checksum
wget https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb
wget https://github.com/saad-git-007/linux_disk_prune/releases/latest/download/linux-disk-prune_0.2.0_amd64.deb.sha256

# 2. (Recommended) verify the download
sha256sum -c linux-disk-prune_0.2.0_amd64.deb.sha256

# 3. Install. apt pulls in any missing dependencies automatically
sudo apt install ./linux-disk-prune_0.2.0_amd64.deb
```

Then open **Disk Prune** from the app launcher (Activities → search "Disk Prune"), or run `linux_disk_prune` in a terminal. Right-click the launcher icon for **Scan the whole disk**, or right-click a folder in Files → **Open With → Disk Prune**.

**Install by double-clicking:** download the `.deb`, right-click it in Files → **Open With → Software Install** → **Install**.

**Update:** download the newer `.deb` and run `sudo apt install ./linux-disk-prune_<version>_amd64.deb` again.

**Uninstall:**

```sh
sudo apt remove linux-disk-prune
```

<details>
<summary>What the package installs and depends on</summary>

- `/usr/bin/linux_disk_prune` (and the alias `linux-disk-prune`)
- `/usr/share/applications/linux-disk-prune.desktop` and its icon
- docs in `/usr/share/doc/linux-disk-prune/`

It **depends on** standard desktop libraries that every Ubuntu desktop already has: `libc6`, `libxkbcommon`, X11 libs, `libegl1`/`libgl1`. It **recommends** `libvulkan1` + `mesa-vulkan-drivers` (GPU rendering), `pkexec` (one password prompt for admin cleanups), `libglib2.0-bin` (`gio trash`) and `fonts-dejavu-core`.
</details>

### Build the .deb yourself

```sh
./packaging/build-deb.sh                   # needs cargo + dpkg-deb
sudo apt install ./dist/linux-disk-prune_0.2.0_amd64.deb
```

`cargo deb` works too (see `[package.metadata.deb]`).

### From source

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh    # Rust 1.95+
cargo build --release
./target/release/linux_disk_prune
```

## Usage

```sh
linux_disk_prune                  # desktop app, scanning / (one filesystem)
linux_disk_prune ~                # scan your home folder
linux_disk_prune --tui            # terminal UI (used automatically without a display / over SSH)
linux_disk_prune --summary        # plain-text report
linux_disk_prune --json           # machine-readable report
```

| Option | Meaning |
|---|---|
| `-s, --summary` / `--json` | non-interactive report (`--rules-only` skips the tree scan) |
| `-x, --cross-filesystems` | descend into other mounts |
| `--min-file-size 1M` | smaller files are grouped as `<N small files>` (keeps memory low) |
| `--journal-keep 500M` | journal size to keep when vacuuming |
| `--home DIR`, `--dev-root DIR` | where user caches / projects live |
| `--threads N` | scanner threads (default: 2× CPUs on SSD/NVMe, ≤ 4 on HDD) |
| `--renderer auto\|vulkan\|gl` | GPU renderer for the window |
| `--tui`, `--color auto\|truecolor\|256` | terminal UI and its colour depth |
| `--no-exec` | disable cleanup execution |

**Keys:** `1` `2` `3` `4` switch views · click / double-click / scroll to select and zoom · arrows move between tiles · `Enter` / `Backspace` zoom in / out · `Space` or `X` marks · `[` `]` sets depth / rings · `C` opens Review & clean · `F5` rescans · right-click for Zoom, Mark, Open in Files, Copy path.

### GPU rendering

The window is drawn with **wgpu**, which uses **Vulkan** on Linux and prefers the low-power *integrated* GPU (for example Intel Iris Xe through Mesa's ANV driver). If no hardware GPU can present to the display, it relaunches itself with OpenGL. The renderer in use is shown at the bottom right.

On remote-desktop setups that use Xorg's `dummy` video driver, no program can use the GPU on that display (Mesa reports `No DRI3 support detected`). The app still runs there, drawing on the CPU.

## Project layout

```
src/main.rs            CLI, summary/JSON report, picks GUI or TUI
src/scanner.rs         parallel scanner → arena tree; exact OS names; hard-link dedupe; du()
src/engine.rs          background scan and rule runs, reclaimable overlays (shared by both UIs)
src/rules/mod.rs       Finding / Risk / Action model, report merging, shell-safe command text
src/rules/ubuntu.rs    Ubuntu 22.04 system rules: APT, kernels, snap, journal, logs, Docker, user caches, projects
src/rules/extra.rs     browser/Electron/IDE/tool caches, snapd orphans, autoremove, Flatpak, core dumps
src/sysdirs.rs         runtime discovery of system paths (apt-config, snap, flatpak, journald, fontconfig)
src/classify.rs        kind-of-data classification for colours
src/cleanup.rs         guarded removal (mount- and symlink-aware), Trash / permanent
src/gui/               eframe/egui desktop app: treemap, sunburst, views, theme, pkexec runner
src/ui.rs              ratatui terminal UI
tests/blackbox/        independent black-box validation suite (Python stdlib)
tests/system/          read-only ground-truth validator for a live Ubuntu machine
packaging/             .deb build script, desktop entry, icon
```

## Credits

- **[disktree](https://github.com/tobi/disktree)** by Tobi Lütke (MIT) inspired the core ideas:
  - the treemap coloured by kind of data, with hatched reclaimable space and a reserved selection colour
  - the *mark → review → remove* flow
  - measuring real disk usage with hard links counted once

  No disktree code is included. This is an independent implementation, with a sunburst view, its own theme, a terminal UI and an Ubuntu-specific recommendation engine.
- Built with [egui/eframe](https://github.com/emilk/egui), [wgpu](https://wgpu.rs), [ratatui](https://ratatui.rs), [rayon](https://github.com/rayon-rs/rayon), [clap](https://github.com/clap-rs/clap) and [sysinfo](https://github.com/GuillaumeGomez/sysinfo).

## License

[MIT](LICENSE). See [NOTICE](NOTICE) for the disktree acknowledgement.
