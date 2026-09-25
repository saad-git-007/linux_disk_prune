//! Desktop and developer bloat beyond the core Ubuntu rules: browser and
//! Electron caches, language-tool caches, orphaned snapd cache files, unused
//! Flatpak runtimes, orphaned packages, Trash on other drives, core dumps.
//!
//! Every rule is a pure function over explicit roots (so it can be tested
//! against a fake home) plus a thin reader of the real system. Caches whose
//! app is running are reported as a manual step instead of an action.

use super::ubuntu::{self, RuleContext};
use super::{sudo_rm_files, Action, CheckOutput, Finding, Risk};
use crate::scanner;
use crate::util::{shq, tilde};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ------------------------------------------------------------------ environment

/// Where per-user caches live, honouring the usual overrides.
#[derive(Clone, Debug)]
pub struct Dirs {
    pub home: PathBuf,
    pub cache: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub cargo: PathBuf,
    pub pip: Option<PathBuf>,
    pub npm: Option<PathBuf>,
}

/// Environment lookup; tests use an empty environment so they never pick up
/// the developer's own settings (rustup, for one, exports CARGO_HOME).
type Env<'a> = &'a dyn Fn(&str) -> Option<std::ffi::OsString>;

fn real_env(var: &str) -> Option<std::ffi::OsString> {
    if cfg!(test) {
        None
    } else {
        std::env::var_os(var)
    }
}

impl Dirs {
    pub fn resolve(ctx: &RuleContext) -> Self {
        Self::from_env(&ctx.home, ctx.is_root, &real_env)
    }

    /// Environment overrides are only trusted when running as the user: under
    /// sudo the environment belongs to root, not to the scanned home.
    pub fn from_env(home: &Path, is_root: bool, env: Env) -> Self {
        let var = |name: &str| -> Option<PathBuf> {
            if is_root {
                return None;
            }
            env(name).map(PathBuf::from).filter(|p| p.is_absolute())
        };
        Dirs {
            cache: var("XDG_CACHE_HOME").unwrap_or_else(|| home.join(".cache")),
            config: var("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            data: var("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share")),
            cargo: var("CARGO_HOME").unwrap_or_else(|| home.join(".cargo")),
            pip: var("PIP_CACHE_DIR"),
            npm: var("npm_config_cache"),
            home: home.to_path_buf(),
        }
    }

    /// pip's cache: PIP_CACHE_DIR, else <cache>/pip.
    pub fn pip_cache(&self, _is_root: bool) -> PathBuf {
        self.pip.clone().unwrap_or_else(|| self.cache.join("pip"))
    }

    /// npm's cache root: npm_config_cache, else ~/.npm.
    pub fn npm_cache(&self, _is_root: bool) -> PathBuf {
        self.npm.clone().unwrap_or_else(|| self.home.join(".npm"))
    }
}

/// Running processes as (comm, cmdline with spaces).
pub fn processes() -> Vec<(String, String)> {
    let Ok(rd) = fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|e| {
            let comm = fs::read_to_string(e.path().join("comm")).ok()?.trim().to_string();
            let cmd = fs::read(e.path().join("cmdline")).ok()?;
            let cmd = String::from_utf8_lossy(&cmd).replace('\0', " ");
            Some((comm, cmd))
        })
        .collect()
}

use crate::sysdirs::which;

/// Chromium/Electron hold a `SingletonLock` symlink in their profile dir while
/// running; Firefox a `lock` symlink in each profile. A lock left behind by a
/// crash names a process that no longer exists and is ignored; anything we
/// can't verify (another host, unreadable target) counts as held.
fn has_lock(dir: &Path, name: &str) -> bool {
    let p = dir.join(name);
    if fs::symlink_metadata(&p).is_err() {
        return false;
    }
    let Ok(target) = fs::read_link(&p) else { return true };
    !lock_is_stale(&target.to_string_lossy(), &hostname())
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Chromium: `<hostname>-<pid>`. Firefox: `<ip>:+<pid>` (always local).
fn lock_is_stale(target: &str, host: &str) -> bool {
    let pid = if let Some((_, pid)) = target.rsplit_once(":+") {
        pid
    } else if let Some(pid) = target.strip_prefix(host).and_then(|r| r.strip_prefix('-')).filter(|_| !host.is_empty()) {
        pid
    } else {
        return false;
    };
    match pid.parse::<u32>() {
        Ok(pid) if pid > 0 => !Path::new(&format!("/proc/{pid}")).exists(),
        _ => false,
    }
}

// ------------------------------------------------------------------ measuring

fn blocks(md: &fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// Bytes inside `d`, excluding `d`'s own block (the directory is kept).
fn contents_bytes(d: &Path) -> u64 {
    let own = fs::symlink_metadata(d).map_or(0, |m| blocks(&m));
    scanner::du(d).0.saturating_sub(own)
}

/// Bytes that deleting everything inside `d` would actually free: files still
/// hard-linked elsewhere (uv/pnpm/conda link their stores into environments)
/// keep their data, so only files with a single link count.
pub fn unique_bytes(d: &Path) -> u64 {
    fn walk(p: &Path, dev: u64, acc: &mut u64) {
        let Ok(rd) = fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                if md.dev() == dev {
                    *acc += blocks(&md);
                    walk(&e.path(), dev, acc);
                }
            } else if md.nlink() <= 1 || md.is_symlink() {
                *acc += blocks(&md);
            }
        }
    }
    let Ok(md) = fs::symlink_metadata(d) else { return 0 };
    let mut acc = 0;
    if md.is_dir() {
        walk(d, md.dev(), &mut acc);
    }
    acc
}

fn existing(dirs: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter().filter(|d| d.is_dir()).cloned().collect()
}

/// A finding that empties `dirs` (keeping the dirs), or runs `command` instead.
#[allow(clippy::too_many_arguments)]
fn contents_finding(
    home: &Path,
    id: &str,
    category: &str,
    title: &str,
    dirs: Vec<PathBuf>,
    bytes: u64,
    risk: Risk,
    detail: String,
    command: Option<String>,
) -> Option<Finding> {
    if dirs.is_empty() || bytes == 0 {
        return None;
    }
    let shown: Vec<String> = dirs.iter().map(|d| tilde(d, home)).collect();
    Some(Finding {
        id: id.into(),
        category: category.into(),
        title: format!("{title} ({})", shown.join(", ")),
        risk,
        bytes,
        detail,
        paths: dirs.clone(),
        action: match command {
            Some(command) => Action::Shell { command },
            None => Action::Remove { paths: dirs, keep_dir: true },
        },
        needs_root: false,
    })
}

/// Turn a finding into a manual step (e.g. the owning app is running).
fn manual(mut f: Finding, why: &str) -> Finding {
    f.detail = format!("{why}\n\n{}", f.detail);
    f.action = Action::Manual;
    f
}

// ------------------------------------------------------------------ browsers

/// Chromium-family disk caches: <cache>/<browser>/<profile>/{Cache,Code Cache,GPUCache}.
/// Profiles, cookies and history live under ~/.config and are never touched.
pub fn browser_findings(d: &Dirs, procs: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let chromium_like: [(&str, &str, PathBuf, PathBuf); 5] = [
        ("chrome-cache", "Google Chrome", d.cache.join("google-chrome"), d.config.join("google-chrome")),
        ("chromium-cache", "Chromium", d.cache.join("chromium"), d.config.join("chromium")),
        ("chromium-snap-cache", "Chromium (snap)", d.home.join("snap/chromium/common/.cache/chromium"), d.home.join("snap/chromium/common/chromium")),
        ("brave-cache", "Brave", d.cache.join("BraveSoftware/Brave-Browser"), d.config.join("BraveSoftware/Brave-Browser")),
        ("edge-cache", "Microsoft Edge", d.cache.join("microsoft-edge"), d.config.join("microsoft-edge")),
    ];
    for (id, name, cache_root, profile_root) in chromium_like {
        let Ok(rd) = fs::read_dir(&cache_root) else { continue };
        let mut dirs = Vec::new();
        for e in rd.flatten() {
            for sub in ["Cache", "Code Cache", "GPUCache"] {
                let p = e.path().join(sub);
                if p.is_dir() {
                    dirs.push(p);
                }
            }
        }
        dirs.sort();
        let bytes = dirs.iter().map(|p| contents_bytes(p)).sum();
        let detail = format!(
            "{name}'s disk cache (web pages, images, compiled scripts). The browser rebuilds it \
             while you browse. Bookmarks, passwords, history and cookies are stored elsewhere \
             and are not touched."
        );
        if let Some(f) = contents_finding(&d.home, id, "Browser", &format!("{name} disk cache"), dirs, bytes, Risk::Safe, detail, None) {
            out.push(if has_lock(&profile_root, "SingletonLock") { manual(f, &format!("{name} is running: close it first, then Re-analyze.")) } else { f });
        }
    }

    // Firefox (deb and snap): <cache>/mozilla/firefox/<profile>/cache2.
    let firefox: [(&str, &str, PathBuf, PathBuf); 2] = [
        ("firefox-cache", "Firefox", d.cache.join("mozilla/firefox"), d.home.join(".mozilla/firefox")),
        ("firefox-snap-cache", "Firefox (snap)", d.home.join("snap/firefox/common/.cache/mozilla/firefox"), d.home.join("snap/firefox/common/.mozilla/firefox")),
    ];
    for (id, name, cache_root, profiles) in firefox {
        let Ok(rd) = fs::read_dir(&cache_root) else { continue };
        let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path().join("cache2")).filter(|p| p.is_dir()).collect();
        dirs.sort();
        let bytes = dirs.iter().map(|p| contents_bytes(p)).sum();
        let running = fs::read_dir(&profiles).map_or(false, |rd| rd.flatten().any(|e| has_lock(&e.path(), "lock")));
        let detail = format!("{name}'s disk cache. Firefox rebuilds it while you browse; profiles and bookmarks are not touched.");
        if let Some(f) = contents_finding(&d.home, id, "Browser", &format!("{name} disk cache"), dirs, bytes, Risk::Safe, detail, None) {
            out.push(if running { manual(f, &format!("{name} is running: close it first, then Re-analyze.")) } else { f });
        }
    }

    // Flatpak apps keep their XDG cache in ~/.var/app/<id>/cache.
    if let Ok(rd) = fs::read_dir(d.home.join(".var/app")) {
        let mut idle = Vec::new();
        let mut busy = Vec::new();
        for e in rd.flatten() {
            let app = e.file_name().to_string_lossy().into_owned();
            let cache = e.path().join("cache");
            if !cache.is_dir() {
                continue;
            }
            if procs.iter().any(|(_, cmd)| cmd.contains(&app)) {
                busy.push(app);
            } else {
                idle.push(cache);
            }
        }
        idle.sort();
        let bytes = idle.iter().map(|p| contents_bytes(p)).sum();
        let mut detail = "Caches of Flatpak apps (their private ~/.cache). Apps rebuild them on demand.".to_string();
        if !busy.is_empty() {
            detail.push_str(&format!("\nSkipped because running: {}.", busy.join(", ")));
        }
        out.extend(contents_finding(&d.home, "flatpak-app-cache", "Browser", "Flatpak app caches", idle, bytes, Risk::Safe, detail, None));
    }
    out
}

/// Electron / Chromium-embedding apps in ~/.config (VS Code, Cursor, Slack,
/// Discord, …): only their HTTP / code / GPU cache children, and only when
/// they really are Chromium disk caches.
pub fn electron_findings(d: &Dirs) -> Vec<Finding> {
    const CHILDREN: [&str; 4] = ["Cache", "Code Cache", "GPUCache", "CachedData"];
    const SKIP: [&str; 4] = ["google-chrome", "chromium", "BraveSoftware", "microsoft-edge"];
    let Ok(rd) = fs::read_dir(&d.config) else { return Vec::new() };
    let mut idle = Vec::new();
    let mut busy = Vec::new();
    let mut apps: Vec<_> = rd.flatten().collect();
    apps.sort_by_key(|e| e.file_name());
    for e in apps {
        let name = e.file_name().to_string_lossy().into_owned();
        if SKIP.contains(&name.as_str()) || !e.file_type().map_or(false, |t| t.is_dir()) {
            continue;
        }
        let app = e.path();
        // A Chromium disk cache has an `index` (or Cache_Data/index) file.
        let cache = app.join("Cache");
        let is_chromium = cache.join("index").exists() || cache.join("Cache_Data/index").exists();
        if !is_chromium {
            continue;
        }
        let dirs: Vec<PathBuf> = CHILDREN.iter().map(|c| app.join(c)).filter(|p| p.is_dir()).collect();
        if has_lock(&app, "SingletonLock") || has_lock(&app, "code.lock") {
            busy.push(name);
        } else {
            idle.extend(dirs);
        }
    }
    let bytes = idle.iter().map(|p| contents_bytes(p)).sum();
    let mut detail = "HTTP, script and GPU caches of Electron apps (editors, chat apps, …). Only the \
                      Cache, Code Cache, GPUCache and CachedData folders are emptied; settings, \
                      logins and local storage are kept. Apps rebuild them on the next start."
        .to_string();
    if !busy.is_empty() {
        detail.push_str(&format!("\nSkipped because running: {}.", busy.join(", ")));
    }
    contents_finding(&d.home, "electron-cache", "App cache", "Electron app caches", idle, bytes, Risk::Safe, detail, None)
        .into_iter()
        .collect()
}

// ------------------------------------------------------------------ language tools

/// Caches of language tooling, each via its own clean command when installed.
pub fn tool_cache_findings(d: &Dirs, is_root: bool, procs: &[(String, String)], have: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let h = &d.home;
    let mut add = |f: Option<Finding>| out.extend(f);

    // uv links its cache into virtualenvs: count only what nothing else holds.
    let uv = d.cache.join("uv");
    if uv.is_dir() {
        let cmd = have("uv").then(|| "uv cache clean".to_string());
        add(contents_finding(h, "uv-cache", "Python", "uv cache", vec![uv.clone()], unique_bytes(&uv), Risk::Safe,
            "Wheels and sources cached by uv. Virtualenvs hard-link from it, so only data \
             that no environment still uses is counted. Equivalent: uv cache clean".into(), cmd));
    }
    let poetry = d.cache.join("pypoetry/cache");
    add(contents_finding(h, "poetry-cache", "Python", "Poetry cache", existing(&[poetry.clone()]), contents_bytes(&poetry), Risk::Safe,
        "Package archives cached by Poetry; re-downloaded on demand.".into(), None));
    for (id, name, dir) in [
        ("selenium-cache", "Selenium browsers & drivers", d.cache.join("selenium")),
        ("playwright-cache", "Playwright browsers", d.cache.join("ms-playwright")),
    ] {
        add(contents_finding(h, id, "Testing", name, existing(&[dir.clone()]), contents_bytes(&dir), Risk::Safe,
            format!("{name} downloaded by the test tooling; fetched again on the next run (needs network)."), None));
    }
    let mesa: Vec<PathBuf> = existing(&[d.cache.join("mesa_shader_cache"), d.cache.join("mesa_shader_cache_db")]);
    let mesa_bytes = mesa.iter().map(|p| contents_bytes(p)).sum();
    add(contents_finding(h, "mesa-shader-cache", "Graphics", "GPU shader cache", mesa, mesa_bytes, Risk::Safe,
        "Compiled GPU shaders; games and apps recompile them (a brief stutter the first time).".into(), None));

    // npm's npx cache: in use while an npx-launched tool (e.g. an MCP server) runs.
    let npx = d.npm_cache(is_root).join("_npx");
    if let Some(f) = contents_finding(h, "npx-cache", "Node", "npx package cache", existing(&[npx.clone()]), contents_bytes(&npx), Risk::Safe,
        "Packages fetched by `npx`; downloaded again when next used.".into(), None)
    {
        let running = procs.iter().any(|(_, cmd)| cmd.contains("/_npx/"));
        out.push(if running { manual(f, "An npx-launched program is running from this cache: stop it first.") } else { f });
    }
    let yarn = d.cache.join("yarn");
    out.extend(contents_finding(h, "yarn-cache", "Node", "Yarn cache", existing(&[yarn.clone()]), contents_bytes(&yarn), Risk::Safe,
        "Yarn's package cache. Equivalent: yarn cache clean".into(), None));
    // pnpm projects hard-link into the store: only `pnpm store prune` is safe.
    let pnpm = d.data.join("pnpm/store");
    if pnpm.is_dir() {
        let f = contents_finding(h, "pnpm-store", "Node", "pnpm store (unreferenced)", vec![pnpm.clone()], unique_bytes(&pnpm), Risk::Safe,
            "Packages in the pnpm store that no project links to any more.".into(), Some("pnpm store prune".into()));
        out.extend(f.map(|f| if have("pnpm") { f } else { manual(f, "pnpm is not on PATH; run `pnpm store prune` where it is installed.") }));
    }

    // Go: build cache is pure cache; the module cache is read-only on disk.
    let gobuild = d.cache.join("go-build");
    out.extend(contents_finding(h, "go-build-cache", "Go", "Go build cache", existing(&[gobuild.clone()]), contents_bytes(&gobuild), Risk::Safe,
        "Compiled Go packages; rebuilt as needed. Equivalent: go clean -cache".into(), have("go").then(|| "go clean -cache".to_string())));
    let gomod = h.join("go/pkg/mod");
    if let Some(f) = contents_finding(h, "go-mod-cache", "Go", "Go module cache", existing(&[gomod.clone()]), contents_bytes(&gomod), Risk::Moderate,
        "Downloaded Go modules; re-downloaded by the next build (needs network). The files are \
         read-only, so only `go clean -modcache` can remove them.".into(), Some("go clean -modcache".into()))
    {
        out.push(if have("go") { f } else { manual(f, "go is not on PATH; run `go clean -modcache` where it is installed.") });
    }

    // Gradle downloads and wrapper distributions.
    let gradle: Vec<PathBuf> = existing(&[h.join(".gradle/caches"), h.join(".gradle/wrapper/dists")]);
    let gradle_bytes = gradle.iter().map(|p| contents_bytes(p)).sum();
    out.extend(contents_finding(h, "gradle-cache", "Java", "Gradle caches", gradle, gradle_bytes, Risk::Moderate,
        "Downloaded dependencies and Gradle distributions; the next build fetches them again.".into(), None));

    // Conda package caches (hard-linked into environments).
    for base in ["anaconda3", "miniconda3", "miniforge3", ".conda"] {
        let pkgs = h.join(base).join("pkgs");
        if !pkgs.is_dir() {
            continue;
        }
        let conda = h.join(base).join("bin/conda");
        let cmd = conda.is_file().then(|| format!("{} clean -a -y", shq(&conda.to_string_lossy())));
        out.extend(contents_finding(h, &format!("conda-pkgs:{base}"), "Python", "Conda package cache", vec![pkgs.clone()], unique_bytes(&pkgs), Risk::Safe,
            "Package tarballs and unpacked packages no environment still links to.".into(), cmd));
    }

    // Hugging Face models: may be large, gated or the only copy of a fine-tune.
    let hf = d.cache.join("huggingface/hub");
    if let Some(f) = contents_finding(h, "huggingface-hub", "AI models", "Hugging Face model cache", existing(&[hf.clone()]), contents_bytes(&hf), Risk::Caution,
        "Downloaded models and datasets. Public models can be downloaded again, but gated or \
         private ones may not be. Pick what to delete interactively with \
         `huggingface-cli delete-cache`.".into(), None)
    {
        out.push(manual(f, "Review models individually: `huggingface-cli delete-cache`."));
    }

    // GNOME search index.
    let tracker = d.cache.join("tracker3");
    if let Some(f) = contents_finding(h, "tracker3", "Desktop", "GNOME search index (tracker3)", existing(&[tracker.clone()]), contents_bytes(&tracker), Risk::Moderate,
        "The file-search index; GNOME rebuilds it in the background (uses CPU for a while).".into(), Some("tracker3 reset -s -r".into()))
    {
        out.push(if have("tracker3") { f } else { manual(f, "tracker3 is not installed here.") });
    }
    out
}

/// Editor extension versions that VS Code-family editors have marked obsolete
/// in `<extensions>/.obsolete` (a JSON object of dir-name → true).
pub fn obsolete_extension_findings(d: &Dirs) -> Vec<Finding> {
    let mut dirs = Vec::new();
    for base in [".vscode/extensions", ".vscode-oss/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-server/extensions"] {
        let root = d.home.join(base);
        dirs.extend(obsolete_extensions(&root));
    }
    let bytes = dirs.iter().map(|p| scanner::du(p).0).sum();
    if dirs.is_empty() {
        return Vec::new();
    }
    vec![Finding {
        id: "obsolete-extensions".into(),
        category: "Editor".into(),
        title: format!("Obsolete editor extension versions ({})", dirs.len()),
        risk: Risk::Safe,
        bytes,
        detail: "Old extension versions the editor itself has marked obsolete (listed in \
                 extensions/.obsolete) after an update. The editor would delete them on a later \
                 start."
            .into(),
        paths: dirs.clone(),
        action: Action::Remove { paths: dirs, keep_dir: false },
        needs_root: false,
    }]
}

pub fn obsolete_extensions(root: &Path) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(root.join(".obsolete")) else { return Vec::new() };
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(&text) else { return Vec::new() };
    let mut out: Vec<PathBuf> = map
        .iter()
        .filter(|(_, v)| v.as_bool() == Some(true))
        // A plain directory name only: nothing that could escape `root`.
        .filter(|(k, _)| !k.is_empty() && !k.contains('/') && *k != "." && *k != "..")
        .map(|(k, _)| root.join(k))
        .filter(|p| fs::symlink_metadata(p).map_or(false, |m| m.is_dir()))
        .collect();
    out.sort();
    out
}

/// Split "PyCharmCE2023.1" into ("PyCharmCE", [2023, 1]).
pub fn jetbrains_version(name: &str) -> Option<(String, Vec<u64>)> {
    let idx = name.find(|c: char| c.is_ascii_digit())?;
    let (product, ver) = name.split_at(idx);
    if product.is_empty() || !ver.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    let v: Vec<u64> = ver.split('.').filter_map(|x| x.parse().ok()).collect();
    (!v.is_empty()).then(|| (product.to_string(), v))
}

/// Caches of JetBrains IDE versions superseded by a newer install of the same IDE.
pub fn jetbrains_findings(d: &Dirs) -> Vec<Finding> {
    let root = d.cache.join("JetBrains");
    let Ok(rd) = fs::read_dir(&root) else { return Vec::new() };
    let mut by_product: HashMap<String, Vec<(Vec<u64>, PathBuf)>> = HashMap::new();
    for e in rd.flatten() {
        if let Some((product, ver)) = jetbrains_version(&e.file_name().to_string_lossy()) {
            by_product.entry(product).or_default().push((ver, e.path()));
        }
    }
    let mut old = Vec::new();
    for (_, mut v) in by_product {
        v.sort();
        v.pop(); // the newest version stays
        old.extend(v.into_iter().map(|(_, p)| p));
    }
    old.sort();
    if old.is_empty() {
        return Vec::new();
    }
    let bytes = old.iter().map(|p| scanner::du(p).0).sum();
    vec![Finding {
        id: "jetbrains-old-caches".into(),
        category: "Editor".into(),
        title: format!("Caches of old JetBrains IDE versions ({})", old.len()),
        risk: Risk::Safe,
        bytes,
        detail: "Index and cache folders of IDE versions that a newer version of the same IDE \
                 has replaced. The current version's cache is kept."
            .into(),
        paths: old.clone(),
        action: Action::Remove { paths: old, keep_dir: false },
        needs_root: false,
    }]
}

// ------------------------------------------------------------------ system

/// Files in snapd's download cache that no installed snap links to any more.
/// snapd keeps a few such entries around indefinitely.
pub fn snapd_orphan_findings(cache: &Path) -> CheckOutput {
    let rd = match fs::read_dir(cache) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return CheckOutput::note(
                "snapd's download cache (/var/lib/snapd/cache) is readable only by root: run \
                 with sudo to check it for orphaned snap files (often 1 GB or more).",
            )
        }
        Err(_) => return CheckOutput::default(),
    };
    let mut files: Vec<(PathBuf, u64)> = rd
        .flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            (md.is_file() && md.nlink() == 1 && e.file_name().to_str().is_some()).then(|| (e.path(), blocks(&md)))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return CheckOutput::default();
    }
    let paths: Vec<PathBuf> = files.iter().map(|f| f.0.clone()).collect();
    CheckOutput::one(Finding {
        id: "snapd-cache-orphans".into(),
        category: "Snap".into(),
        title: format!("Orphaned snapd download cache ({} files)", paths.len()),
        risk: Risk::Safe,
        bytes: files.iter().map(|f| f.1).sum(),
        detail: "Downloaded snap files in /var/lib/snapd/cache that no installed revision uses \
                 any more (link count 1). Installed snaps are hard-linked here with link count 2 \
                 and are never listed."
            .into(),
        action: Action::Shell { command: sudo_rm_files(&paths) },
        paths,
        needs_root: true,
    })
}

/// `Remv`/`Purg` package names from `apt-get -s autoremove` output.
pub fn autoremove_candidates(sim: &str) -> Vec<String> {
    let kernel = |p: &str| {
        p.starts_with("linux-image-") || p.starts_with("linux-modules-") || p.starts_with("linux-headers-")
            || p.starts_with("linux-tools-") || p.starts_with("linux-hwe-")
    };
    let mut v: Vec<String> = sim
        .lines()
        .filter_map(|l| l.strip_prefix("Remv ").or_else(|| l.strip_prefix("Purg ")))
        .filter_map(|r| r.split_whitespace().next())
        .map(|p| p.split(':').next().unwrap_or(p).to_string())
        .filter(|p| !kernel(p)) // kernels are handled (more carefully) by their own rule
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Installed-Size (KiB) per package from dpkg's status file.
pub fn installed_sizes(status: &str) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    for stanza in status.split("\n\n") {
        let (mut name, mut size, mut installed) = (None, 0u64, false);
        for l in stanza.lines() {
            if let Some(n) = l.strip_prefix("Package: ") {
                name = Some(n.trim().to_string());
            } else if let Some(s) = l.strip_prefix("Installed-Size: ") {
                size = s.trim().parse().unwrap_or(0);
            } else if let Some(s) = l.strip_prefix("Status: ") {
                installed = s.trim().ends_with(" installed");
            }
        }
        if let (Some(n), true) = (name, installed) {
            out.insert(n, size * 1024);
        }
    }
    out
}

/// Packages installed only as dependencies that nothing needs any more.
pub fn autoremove_findings(sim_autoremove: &str, dpkg_status: &str, simulate_purge: &dyn Fn(&[String]) -> Option<String>) -> CheckOutput {
    let pkgs = autoremove_candidates(sim_autoremove);
    if pkgs.is_empty() {
        return CheckOutput::default();
    }
    let sizes = installed_sizes(dpkg_status);
    let bytes: u64 = pkgs.iter().filter_map(|p| sizes.get(p)).sum();
    let mut f = Finding {
        id: "apt-autoremove".into(),
        category: "APT".into(),
        title: format!("Orphaned packages ({})", pkgs.len()),
        risk: Risk::Moderate,
        bytes,
        detail: format!(
            "Packages installed automatically as dependencies that no installed package needs \
             any more (what `apt autoremove` reports). Old kernels are left to the kernel rule. \
             Size from dpkg's Installed-Size.\nPackages: {}",
            pkgs.join(", ")
        ),
        paths: Vec::new(),
        action: Action::Shell {
            command: format!("sudo apt-get -o DPkg::Lock::Timeout=120 purge -y {}", pkgs.iter().map(|p| shq(p)).collect::<Vec<_>>().join(" ")),
        },
        needs_root: true,
    };
    // Same guard as kernels: the purge must remove exactly this list.
    match simulate_purge(&pkgs) {
        Some(sim) => {
            let listed: HashSet<&str> = pkgs.iter().map(|s| s.as_str()).collect();
            let extra: Vec<String> = ubuntu::apt_sim_removals(&sim).into_iter().filter(|p| !listed.contains(p.as_str())).collect();
            if !extra.is_empty() {
                f = manual(f, &format!("Purging these would also remove: {}. Review with `apt-get -s autoremove`.", extra.join(", ")));
            }
        }
        None => f = manual(f, "Could not simulate the purge with apt-get; review with `apt-get -s autoremove`."),
    }
    CheckOutput::one(f)
}

/// Trash folders on other mounted drives (`<mount>/.Trash-<uid>`).
pub fn other_trash_findings(mountinfo: &str, uid: u32, home: &Path) -> Vec<Finding> {
    let mut dirs = Vec::new();
    for m in crate::cleanup::parse_mountinfo(mountinfo) {
        let snap = &crate::sysdirs::get().snap_mount;
        if m == Path::new("/") || m.starts_with("/proc") || m.starts_with("/sys") || m.starts_with("/dev") || m.starts_with("/run/user") || m.starts_with(snap) {
            continue;
        }
        for t in [m.join(format!(".Trash-{uid}")), m.join(".Trash").join(uid.to_string())] {
            for sub in ["files", "info"] {
                let p = t.join(sub);
                if p.is_dir() {
                    dirs.push(p);
                }
            }
        }
    }
    dirs.sort();
    dirs.dedup();
    let bytes = dirs.iter().map(|p| contents_bytes(p)).sum();
    contents_finding(home, "trash-other-drives", "User files", "Trash on other drives", dirs, bytes, Risk::Moderate,
        "Files you deleted from other drives (USB disks, second partitions) sit in that drive's \
         own Trash. Emptying it is permanent."
            .into(),
        None)
    .into_iter()
    .collect()
}

/// systemd-coredump's stored core dumps.
pub fn coredump_findings(dir: &Path) -> CheckOutput {
    let Ok(rd) = fs::read_dir(dir) else { return CheckOutput::default() };
    let mut files: Vec<(PathBuf, u64)> = rd
        .flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            (md.is_file() && e.file_name().to_str().is_some()).then(|| (e.path(), blocks(&md)))
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return CheckOutput::default();
    }
    let paths: Vec<PathBuf> = files.iter().map(|f| f.0.clone()).collect();
    CheckOutput::one(Finding {
        id: "coredumps".into(),
        category: "Crash dumps".into(),
        title: format!("systemd core dumps ({} files)", paths.len()),
        risk: Risk::Safe,
        bytes: files.iter().map(|f| f.1).sum(),
        detail: "Memory images of crashed programs kept by systemd-coredump for debugging.".into(),
        action: Action::Shell { command: sudo_rm_files(&paths) },
        paths,
        needs_root: true,
    })
}

/// Unused Flatpak runtimes: runtimes (not extensions) that no installed app
/// uses. The estimate counts only data that the runtime alone holds (its files
/// are hard-linked with the OSTree repo); `flatpak uninstall --unused` may also
/// remove unused extensions, so the real gain can be a bit higher.
pub fn flatpak_unused(apps: &str, runtimes: &str) -> Vec<String> {
    // Apps: "app-id\truntime-ref" ; runtimes: "ref" (id/arch/branch).
    let used: HashSet<String> = apps
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty())
        .collect();
    let used_ids: HashSet<String> = used.iter().filter_map(|r| r.split('/').next()).map(str::to_string).collect();
    let mut out: Vec<String> = runtimes
        .lines()
        .map(str::trim)
        .filter(|r| r.split('/').count() == 3)
        .filter(|r| {
            let id = r.split('/').next().unwrap_or("");
            let is_base = id.ends_with(".Platform") || id.ends_with(".Sdk");
            // Keep SDKs of used platforms (builders), and anything referenced.
            let sdk_of_used = id.ends_with(".Sdk") && used_ids.contains(&id.replace(".Sdk", ".Platform"));
            is_base && !used.contains(*r) && !sdk_of_used
        })
        .map(str::to_string)
        .collect();
    out.sort();
    out
}

fn flatpak_findings(procs_ok: bool) -> CheckOutput {
    if which("flatpak").is_none() || !procs_ok {
        return CheckOutput::default();
    }
    let run = |args: &[&str]| -> String {
        Command::new("flatpak").args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    };
    let apps = run(&["list", "--app", "--columns=application,runtime"]);
    let runtimes = run(&["list", "--runtime", "--columns=ref"]);
    let unused = flatpak_unused(&apps, &runtimes);
    if unused.is_empty() {
        return CheckOutput::default();
    }
    let mut bytes = 0;
    let mut paths = Vec::new();
    for r in &unused {
        for inst in &crate::sysdirs::get().flatpak_system {
            let p = inst.join("runtime").join(r);
            if p.is_dir() {
                bytes += unique_ostree_bytes(&p);
                paths.push(p);
            }
        }
    }
    CheckOutput::one(Finding {
        id: "flatpak-unused".into(),
        category: "Flatpak".into(),
        title: format!("Unused Flatpak runtimes ({})", unused.len()),
        risk: Risk::Moderate,
        bytes,
        detail: format!(
            "Runtimes no installed Flatpak app uses (left behind after apps were removed or \
             updated): {}. Estimate counts data only these runtimes hold; unused extensions \
             removed along with them can add more.",
            unused.join(", ")
        ),
        paths,
        action: Action::Shell { command: "sudo flatpak uninstall --system --unused -y --noninteractive".into() },
        needs_root: true,
    })
}

/// Bytes of files in a Flatpak deployment that only it and the OSTree repo
/// hold (link count 2): what uninstall + repo prune gives back.
fn unique_ostree_bytes(d: &Path) -> u64 {
    fn walk(p: &Path, acc: &mut u64) {
        let Ok(rd) = fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                *acc += blocks(&md);
                walk(&e.path(), acc);
            } else if md.nlink() <= 2 {
                *acc += blocks(&md);
            }
        }
    }
    let mut acc = 0;
    walk(d, &mut acc);
    acc
}

// ------------------------------------------------------------------ entry point

pub fn run_checks(ctx: &RuleContext) -> CheckOutput {
    let d = Dirs::resolve(ctx);
    let procs = processes();
    let have = |bin: &str| which(bin).is_some();
    let uid = std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok()).filter(|_| ctx.is_root).unwrap_or_else(crate::util::euid);
    let jobs: Vec<Box<dyn Fn() -> CheckOutput + Send + Sync + '_>> = vec![
        Box::new(|| CheckOutput { findings: browser_findings(&d, &procs), notes: Vec::new() }),
        Box::new(|| CheckOutput { findings: electron_findings(&d), notes: Vec::new() }),
        Box::new(|| CheckOutput { findings: tool_cache_findings(&d, ctx.is_root, &procs, &have), notes: Vec::new() }),
        Box::new(|| CheckOutput { findings: obsolete_extension_findings(&d), notes: Vec::new() }),
        Box::new(|| CheckOutput { findings: jetbrains_findings(&d), notes: Vec::new() }),
        Box::new(|| snapd_orphan_findings(&crate::sysdirs::get().snapd_state.join("cache"))),
        Box::new(|| coredump_findings(&crate::sysdirs::get().coredump)),
        Box::new(|| {
            let mi = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
            CheckOutput { findings: other_trash_findings(&mi, uid, &d.home), notes: Vec::new() }
        }),
        Box::new(|| {
            let sim = Command::new("apt-get").args(["-s", "autoremove", "--purge"]).output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
            let status = fs::read_to_string(&crate::sysdirs::get().dpkg_status).unwrap_or_default();
            autoremove_findings(&sim, &status, &ubuntu::apt_simulate_purge)
        }),
        Box::new(|| flatpak_findings(true)),
    ];
    let outs: Vec<CheckOutput> = jobs.par_iter().map(|j| j()).collect();
    let mut all = CheckOutput::default();
    for o in outs {
        all.extend(o);
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::{alloc, TempDir};
    use std::os::unix::fs::symlink;

    fn dirs(d: &TempDir) -> Dirs {
        let h = d.path().to_path_buf();
        Dirs::from_env(&h, false, &|_| None)
    }
    fn removed_paths(f: &Finding) -> Vec<PathBuf> {
        match &f.action {
            Action::Remove { paths, .. } => paths.clone(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn unique_bytes_ignores_data_still_linked_elsewhere() {
        let d = TempDir::new("uniq");
        let only = d.file("cache/only.bin", 2 << 20);
        let shared = d.file("cache/shared.bin", 3 << 20);
        fs::hard_link(&shared, d.join("venv-copy.bin")).unwrap();
        let got = unique_bytes(&d.join("cache"));
        // The single-link file counts; the one also linked from a venv does not.
        assert!(got >= alloc(&only) && got < alloc(&only) + alloc(&shared), "{got}");
    }

    #[test]
    fn stale_locks_from_crashed_apps_are_ignored() {
        let me = std::process::id();
        // Live process on this host / Firefox-style: held.
        assert!(!lock_is_stale(&format!("myhost-{me}"), "myhost"));
        assert!(!lock_is_stale(&format!("127.0.1.1:+{me}"), "myhost"));
        // Dead pid: stale.
        assert!(lock_is_stale("myhost-999999999", "myhost"));
        assert!(lock_is_stale("127.0.1.1:+999999999", "myhost"));
        // Other host or unparsable: can't tell, so held.
        assert!(!lock_is_stale("otherhost-999999999", "myhost"));
        assert!(!lock_is_stale("myhost-abc", "myhost"));
        assert!(!lock_is_stale("whatever", ""));
        // A real stale lock dir is not "running".
        let d = std::env::temp_dir().join(format!("ldp-lock-{me}"));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink(format!("{}-999999999", hostname()), d.join("SingletonLock")).unwrap();
        assert_eq!(has_lock(&d, "SingletonLock"), hostname().is_empty());
        fs::remove_file(d.join("SingletonLock")).unwrap();
        std::os::unix::fs::symlink(format!("{}-{me}", hostname()), d.join("SingletonLock")).unwrap();
        assert!(has_lock(&d, "SingletonLock"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn chrome_cache_only_cache_children_and_blocked_while_running() {
        let d = TempDir::new("chrome");
        d.file(".cache/google-chrome/Default/Cache/Cache_Data/data_1", 2 << 20);
        d.file(".cache/google-chrome/Default/Code Cache/js/x", 1 << 20);
        d.file(".cache/google-chrome/Default/Other/keep", 1 << 20);
        d.file(".config/google-chrome/Default/Bookmarks", 1 << 20);
        let f = browser_findings(&dirs(&d), &[]).into_iter().find(|f| f.id == "chrome-cache").unwrap();
        assert_eq!(f.risk, Risk::Safe);
        let paths = removed_paths(&f);
        assert_eq!(paths, vec![d.join(".cache/google-chrome/Default/Cache"), d.join(".cache/google-chrome/Default/Code Cache")]);
        assert!(matches!(f.action, Action::Remove { keep_dir: true, .. }));
        assert!(paths.iter().all(|p| !p.starts_with(d.join(".config"))), "profile data untouched");
        // Running browser (SingletonLock symlink) → manual step only.
        symlink("host-1234", d.join(".config/google-chrome/SingletonLock")).unwrap();
        let f = browser_findings(&dirs(&d), &[]).into_iter().find(|f| f.id == "chrome-cache").unwrap();
        assert!(matches!(f.action, Action::Manual) && f.detail.contains("running"));
    }

    #[test]
    fn firefox_cache2_only_and_lock_blocks() {
        let d = TempDir::new("ff");
        d.file(".cache/mozilla/firefox/abc.default/cache2/entries/E1", 2 << 20);
        d.file(".cache/mozilla/firefox/abc.default/startupCache/x", 1 << 20);
        d.dir(".mozilla/firefox/abc.default");
        let f = browser_findings(&dirs(&d), &[]).into_iter().find(|f| f.id == "firefox-cache").unwrap();
        assert_eq!(removed_paths(&f), vec![d.join(".cache/mozilla/firefox/abc.default/cache2")]);
        symlink(format!("127.0.0.1:+{}", std::process::id()), d.join(".mozilla/firefox/abc.default/lock")).unwrap();
        let f = browser_findings(&dirs(&d), &[]).into_iter().find(|f| f.id == "firefox-cache").unwrap();
        assert!(matches!(f.action, Action::Manual));
    }

    #[test]
    fn flatpak_app_cache_skips_running_apps() {
        let d = TempDir::new("fpcache");
        d.file(".var/app/org.a.App/cache/x", 2 << 20);
        d.file(".var/app/org.b.Busy/cache/y", 2 << 20);
        d.file(".var/app/org.a.App/data/keep", 2 << 20);
        let procs = vec![("bwrap".to_string(), "bwrap --args org.b.Busy".to_string())];
        let f = browser_findings(&dirs(&d), &procs).into_iter().find(|f| f.id == "flatpak-app-cache").unwrap();
        assert_eq!(removed_paths(&f), vec![d.join(".var/app/org.a.App/cache")]);
        assert!(f.detail.contains("org.b.Busy"));
    }

    #[test]
    fn electron_caches_only_for_real_chromium_caches_and_idle_apps() {
        let d = TempDir::new("electron");
        // A real Electron app: Cache/index marks a Chromium disk cache.
        d.file(".config/Editor/Cache/index", 4096);
        d.file(".config/Editor/Cache/data_1", 2 << 20);
        d.file(".config/Editor/GPUCache/data_0", 1 << 20);
        d.file(".config/Editor/Local Storage/leveldb/000003.log", 1 << 20);
        d.file(".config/Editor/User/settings.json", 1024);
        // A folder merely named Cache (no index): not an Electron cache.
        d.file(".config/SomeTool/Cache/important.db", 2 << 20);
        // A running app is skipped.
        d.file(".config/Chat/Cache/Cache_Data/index", 4096);
        d.file(".config/Chat/Cache/Cache_Data/data_1", 2 << 20);
        symlink("host-1", d.join(".config/Chat/SingletonLock")).unwrap();
        let f = electron_findings(&dirs(&d)).pop().unwrap();
        assert_eq!(removed_paths(&f), vec![d.join(".config/Editor/Cache"), d.join(".config/Editor/GPUCache")]);
        assert!(f.detail.contains("Chat"));
    }

    #[test]
    fn obsolete_extensions_only_listed_plain_dirs() {
        let d = TempDir::new("ext");
        let root = d.dir(".vscode/extensions");
        d.file(".vscode/extensions/pub.old-1.0.0/x.js", 2 << 20);
        d.file(".vscode/extensions/pub.new-2.0.0/x.js", 2 << 20);
        d.file("outside/secret", 1024);
        fs::write(
            root.join(".obsolete"),
            r#"{"pub.old-1.0.0": true, "pub.new-2.0.0": false, "../../outside": true, "a/b": true, "..": true, "missing-9": true}"#,
        )
        .unwrap();
        assert_eq!(obsolete_extensions(&root), vec![root.join("pub.old-1.0.0")]);
        let f = obsolete_extension_findings(&dirs(&d)).pop().unwrap();
        assert!(matches!(f.action, Action::Remove { keep_dir: false, .. }));
        // Malformed JSON: nothing.
        fs::write(root.join(".obsolete"), "not json").unwrap();
        assert!(obsolete_extensions(&root).is_empty());
    }

    #[test]
    fn jetbrains_keeps_newest_version_of_each_ide() {
        assert_eq!(jetbrains_version("PyCharmCE2023.1"), Some(("PyCharmCE".into(), vec![2023, 1])));
        assert_eq!(jetbrains_version("IntelliJIdea2024.3"), Some(("IntelliJIdea".into(), vec![2024, 3])));
        assert_eq!(jetbrains_version("remote-dev"), None);
        let d = TempDir::new("jb");
        for v in ["PyCharmCE2023.1", "PyCharmCE2024.10", "PyCharmCE2024.9", "GoLand2024.1"] {
            d.file(format!(".cache/JetBrains/{v}/caches/x"), 1 << 20);
        }
        let f = jetbrains_findings(&dirs(&d)).pop().unwrap();
        // 2024.10 > 2024.9 numerically; the only GoLand version is kept.
        assert_eq!(
            removed_paths(&f),
            vec![d.join(".cache/JetBrains/PyCharmCE2023.1"), d.join(".cache/JetBrains/PyCharmCE2024.9")]
        );
    }

    #[test]
    fn snapd_orphans_only_single_link_files() {
        let d = TempDir::new("snapcache");
        let cache = d.dir("cache");
        let orphan = d.file("cache/aaa", 2 << 20);
        let used = d.file("cache/bbb", 2 << 20);
        fs::hard_link(&used, d.join("installed_1.snap")).unwrap();
        let out = snapd_orphan_findings(&cache);
        let f = &out.findings[0];
        assert_eq!(f.paths, vec![orphan]);
        assert!(f.needs_root && f.command_text().contains("sudo rm -f --"));
        assert!(snapd_orphan_findings(&d.join("nope")).findings.is_empty());
    }

    #[test]
    fn autoremove_excludes_kernels_and_refuses_collateral_removals() {
        let sim = "Remv libfoo1 [1.0]\nRemv linux-image-6.8.0-100-generic [x]\nPurg python3-bar:amd64 [2]\nInst x\n";
        assert_eq!(autoremove_candidates(sim), vec!["libfoo1".to_string(), "python3-bar".to_string()]);
        let status = "Package: libfoo1\nStatus: install ok installed\nInstalled-Size: 2048\n\nPackage: python3-bar\nStatus: install ok installed\nInstalled-Size: 1024\n";
        let ok = |_: &[String]| Some("Remv libfoo1 [1]\nRemv python3-bar [2]\n".to_string());
        let f = &autoremove_findings(sim, status, &ok).findings[0];
        assert_eq!(f.bytes, 3 * 1024 * 1024);
        assert!(f.is_actionable() && f.command_text().contains("purge -y libfoo1 python3-bar"));
        let extra = |_: &[String]| Some("Remv libfoo1 [1]\nRemv ubuntu-desktop [2]\n".to_string());
        let f = &autoremove_findings(sim, status, &extra).findings[0];
        assert!(!f.is_actionable() && f.detail.contains("ubuntu-desktop"));
        assert!(autoremove_findings("", status, &ok).findings.is_empty());
    }

    #[test]
    fn trash_on_other_drives_from_mountinfo() {
        let d = TempDir::new("mounts");
        let usb = d.dir("media/usb");
        d.file("media/usb/.Trash-1000/files/old.iso", 2 << 20);
        d.file("media/usb/.Trash-1000/info/old.iso.trashinfo", 100);
        d.file("media/usb/.Trash-1001/files/other-user", 2 << 20);
        let mi = format!("36 25 8:17 / {} rw - ext4 /dev/sdb1 rw\n22 1 8:2 / / rw - ext4 /dev/sda2 rw\n", usb.display());
        let f = other_trash_findings(&mi, 1000, d.path()).pop().unwrap();
        assert_eq!(removed_paths(&f), vec![usb.join(".Trash-1000/files"), usb.join(".Trash-1000/info")]);
        assert_eq!(f.risk, Risk::Moderate);
    }

    #[test]
    fn flatpak_unused_runtimes_only_unreferenced_bases() {
        let apps = "org.app.One\torg.gnome.Platform/x86_64/45\norg.app.Two\torg.freedesktop.Platform/x86_64/23.08\n";
        let runtimes = "org.gnome.Platform/x86_64/45\norg.gnome.Platform/x86_64/44\norg.freedesktop.Platform/x86_64/23.08\n\
                        org.freedesktop.Platform.GL.default/x86_64/23.08\norg.gnome.Sdk/x86_64/45\norg.kde.Platform/x86_64/5.15\n";
        assert_eq!(
            flatpak_unused(apps, runtimes),
            vec!["org.gnome.Platform/x86_64/44".to_string(), "org.kde.Platform/x86_64/5.15".to_string()]
        );
    }

    #[test]
    fn tool_caches_use_owning_tool_and_respect_running_or_missing_tools() {
        let d = TempDir::new("tools");
        d.file(".cache/uv/wheels/a.whl", 2 << 20);
        d.file(".npm/_npx/abc/node_modules/x.js", 2 << 20);
        d.file("go/pkg/mod/cache/x", 2 << 20);
        d.file(".cache/huggingface/hub/models--x/blob", 2 << 20);
        let dd = dirs(&d);
        let have_all = |_: &str| true;
        let none = |_: &str| false;
        let f = tool_cache_findings(&dd, true, &[], &have_all);
        let by = |id: &str| f.iter().find(|x| x.id == id).cloned().unwrap();
        assert_eq!(by("uv-cache").command_text(), "uv cache clean");
        assert!(by("npx-cache").is_actionable());
        assert!(!by("huggingface-hub").is_actionable() && by("huggingface-hub").risk == Risk::Caution);
        let busy = vec![("node".to_string(), format!("node {}/.npm/_npx/abc/node_modules/.bin/srv", d.path().display()))];
        let f2 = tool_cache_findings(&dd, true, &busy, &none);
        let by2 = |id: &str| f2.iter().find(|x| x.id == id).cloned().unwrap();
        assert!(!by2("npx-cache").is_actionable(), "npx program running");
        assert!(!by2("go-mod-cache").is_actionable(), "go not installed → manual");
        assert!(matches!(by2("uv-cache").action, Action::Remove { keep_dir: true, .. }), "no uv → remove contents");
    }

    #[test]
    fn dirs_honour_xdg_cargo_pip_npm_overrides() {
        let env = |v: &str| -> Option<std::ffi::OsString> {
            match v {
                "XDG_CACHE_HOME" => Some("/data/cache".into()),
                "CARGO_HOME" => Some("/opt/cargo".into()),
                "PIP_CACHE_DIR" => Some("/data/pip".into()),
                "npm_config_cache" => Some("relative/npm".into()), // ignored: not absolute
                _ => None,
            }
        };
        let d = Dirs::from_env(Path::new("/home/x"), false, &env);
        assert_eq!(d.cache, PathBuf::from("/data/cache"));
        assert_eq!(d.cargo, PathBuf::from("/opt/cargo"));
        assert_eq!(d.data, PathBuf::from("/home/x/.local/share"));
        assert_eq!(d.pip_cache(false), PathBuf::from("/data/pip"));
        assert_eq!(d.npm_cache(false), PathBuf::from("/home/x/.npm"));
        // Under sudo the environment is root's: ignored.
        let r = Dirs::from_env(Path::new("/home/x"), true, &env);
        assert_eq!(r.cache, PathBuf::from("/home/x/.cache"));
        assert_eq!(r.cargo, PathBuf::from("/home/x/.cargo"));
    }

    #[test]
    fn dirs_ignore_environment_when_running_as_root() {
        let ctx = RuleContext { home: "/home/x".into(), dev_roots: vec![], journal_keep: 0, is_root: true };
        let d = Dirs::resolve(&ctx);
        assert_eq!(d.cache, PathBuf::from("/home/x/.cache"));
        assert_eq!(d.cargo, PathBuf::from("/home/x/.cargo"));
        assert_eq!(d.pip_cache(true), PathBuf::from("/home/x/.cache/pip"));
        assert_eq!(d.npm_cache(true), PathBuf::from("/home/x/.npm"));
    }
}
