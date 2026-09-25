//! Heuristics for disk bloat on Ubuntu 22.04 LTS.
//!
//! Every check here is read-only: it inspects metadata and produces findings
//! that carry the exact command needed to reclaim the space.

use super::{sudo_delete_files, Action, CheckOutput, Finding, Risk};
use crate::scanner::{self, marker, NodeKind, Progress, ScanOptions, Tree};
use crate::util::{fmt_size, running_kernel, shq, tilde};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct RuleContext {
    /// Home of the real user (resolved through SUDO_USER when needed).
    pub home: PathBuf,
    /// Where to look for project build artifacts.
    pub dev_roots: Vec<PathBuf>,
    /// How much journal to keep when vacuuming.
    pub journal_keep: u64,
    pub is_root: bool,
}

type Check = fn(&RuleContext) -> CheckOutput;

/// All checks that do not need the directory tree. Run in parallel.
pub fn run_system_checks(ctx: &RuleContext) -> CheckOutput {
    let checks: Vec<Check> = vec![
        check_apt,
        check_kernels,
        check_snaps,
        check_journal,
        check_rotated_logs,
        check_crash,
        check_user_caches,
        check_docker,
        super::extra::run_checks,
    ];
    let outputs: Vec<CheckOutput> = checks.par_iter().map(|c| c(ctx)).collect();
    let mut all = CheckOutput::default();
    for o in outputs {
        all.extend(o);
    }
    if !ctx.is_root {
        all.notes.push(
            "Running unprivileged: some system directories are unreadable, so system \
             totals may be underestimated. Run with sudo for exact figures."
                .into(),
        );
    }
    all
}

// ---------------------------------------------------------------- helpers

fn file_bytes(md: &fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// Regular files directly inside `dir` whose name satisfies `pred`.
fn list_files(dir: &Path, pred: impl Fn(&str) -> bool) -> Vec<(PathBuf, u64)> {
    let Ok(rd) = fs::read_dir(dir) else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| {
            let md = e.metadata().ok()?;
            let name = e.file_name().to_string_lossy().into_owned();
            (md.is_file() && pred(&name)).then(|| (e.path(), file_bytes(&md)))
        })
        .collect()
}

/// Numeric sort key for version strings such as `6.8.0-138-generic`.
fn version_key(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Names of installed packages according to a dpkg status database.
fn installed_packages(status: &str) -> Vec<String> {
    let mut out = Vec::new();
    for stanza in status.split("\n\n") {
        let mut name = None;
        let mut installed = false;
        for line in stanza.lines() {
            if let Some(n) = line.strip_prefix("Package: ") {
                name = Some(n.trim());
            } else if let Some(s) = line.strip_prefix("Status: ") {
                installed = s.trim().ends_with(" installed");
            }
        }
        if let (Some(n), true) = (name, installed) {
            out.push(n.to_string());
        }
    }
    out
}

fn cache_dir_finding(
    ctx: &RuleContext,
    id: &str,
    category: &str,
    title: &str,
    dirs: &[PathBuf],
    risk: Risk,
    detail: &str,
) -> Option<Finding> {
    // Real directories only: a symlinked cache folder is left alone.
    let existing: Vec<PathBuf> = dirs.iter().filter(|d| fs::symlink_metadata(d).is_ok_and(|m| m.is_dir())).cloned().collect();
    // The directories themselves are kept (only their contents go), so their
    // own blocks are not reclaimable.
    let bytes: u64 = existing
        .iter()
        .map(|d| {
            // Cargo's git checkouts hard-link pack files from git/db: only
            // data nothing else links to comes back.
            if id == "cargo-git" {
                return super::extra::unique_bytes(d);
            }
            let own = fs::symlink_metadata(d).map_or(0, |m| file_bytes(&m));
            scanner::du(d).0.saturating_sub(own)
        })
        .sum();
    if existing.is_empty() || bytes == 0 {
        return None;
    }
    let shown: Vec<String> = existing.iter().map(|d| tilde(d, &ctx.home)).collect();
    Some(Finding {
        id: id.into(),
        category: category.into(),
        title: format!("{title} ({})", shown.join(", ")),
        risk,
        bytes,
        detail: detail.into(),
        paths: existing.clone(),
        action: Action::Remove { paths: existing, keep_dir: true },
        needs_root: false,
    })
}

// ---------------------------------------------------------------- checks

/// 1. APT package archives.
fn check_apt(_: &RuleContext) -> CheckOutput {
    let s = crate::sysdirs::get();
    apt_findings_at(&s.apt_cache, &s.apt_archives)
}

/// APT cache check against an injectable cache root (`/var/cache/apt`).
#[cfg(test)]
fn apt_findings(apt: &Path) -> CheckOutput {
    apt_findings_at(apt, &apt.join("archives"))
}

/// `apt` is Dir::Cache, `archives` is Dir::Cache::archives (from apt-config).
fn apt_findings_at(apt: &Path, archives: &Path) -> CheckOutput {
    let mut debs = list_files(archives, |n| n.ends_with(".deb"));
    debs.extend(list_files(&archives.join("partial"), |_| true));
    let deb_count = debs.iter().filter(|f| f.0.extension().is_some_and(|e| e == "deb")).count();
    let bins = list_files(apt, |n| n.ends_with(".bin"));
    let (deb_bytes, bin_bytes): (u64, u64) =
        (debs.iter().map(|f| f.1).sum(), bins.iter().map(|f| f.1).sum());
    // apt rebuilds pkgcache.bin/srcpkgcache.bin on its very next run (even
    // `apt-get -s`), so they are not lasting savings: only .debs count.
    if deb_bytes == 0 {
        return CheckOutput::default();
    }
    let mut what = Vec::new();
    let mut detail = Vec::new();
    if deb_bytes > 0 {
        what.push(format!("{deb_count} .deb archives, {}", fmt_size(deb_bytes)));
        detail.push(
            "Downloaded .deb packages are kept in /var/cache/apt/archives after \
             installation. They are only needed to reinstall offline; apt downloads them \
             again on demand.",
        );
    }
    if bin_bytes > 0 {
        detail.push(
            "apt-get clean also deletes the package-list caches (pkgcache.bin, \
             srcpkgcache.bin), but apt rebuilds them on its next run, so they are not \
             counted as savings.",
        );
    }
    CheckOutput::one(Finding {
        id: "apt-cache".into(),
        category: "APT".into(),
        title: format!("APT cache ({})", what.join("; ")),
        risk: Risk::Safe,
        bytes: deb_bytes,
        detail: detail.join(" "),
        paths: debs.into_iter().chain(bins).map(|f| f.0).collect(),
        action: Action::Shell { command: "sudo apt-get clean".into() },
        needs_root: true,
    })
}

/// 2. Old, inactive kernels.
fn check_kernels(_: &RuleContext) -> CheckOutput {
    let sys = crate::sysdirs::get();
    let status = fs::read_to_string(&sys.dpkg_status).unwrap_or_default();
    let roots = KernelRoots {
        boot: &sys.boot,
        modules: &sys.modules,
        usr_src: &sys.usr_src,
        usr_lib: &sys.usr_lib,
    };
    kernel_findings(&roots, &running_kernel(), &status, &apt_simulate_purge)
}

/// Where kernel files live (injectable for tests).
struct KernelRoots<'a> {
    boot: &'a Path,
    modules: &'a Path,
    usr_src: &'a Path,
    usr_lib: &'a Path,
}

/// Output of `apt-get -s purge <pkgs>` (a simulation: no root, no changes),
/// or None when apt-get cannot run or fails.
pub(super) fn apt_simulate_purge(pkgs: &[String]) -> Option<String> {
    let o = Command::new("apt-get")
        .arg("-s")
        .arg("purge")
        .args(pkgs)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Output of `apt-get -s remove <pkgs>` (what `apt autoremove` does), or None.
pub(super) fn apt_simulate_remove(pkgs: &[String]) -> Option<String> {
    let o = Command::new("apt-get")
        .arg("-s")
        .arg("remove")
        .args(pkgs)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Packages an `apt-get -s` run would change: its `Remv` / `Purg` lines, plus
/// any `Inst` line as "<pkg> (install)" — removing something should never
/// pull in a replacement unnoticed.
pub(super) fn apt_sim_removals(sim: &str) -> Vec<String> {
    let name = |rest: &str| rest.split_whitespace().next().map(|p| p.split(':').next().unwrap_or(p).to_string());
    sim.lines()
        .filter_map(|l| {
            if let Some(rest) = l.strip_prefix("Remv ").or_else(|| l.strip_prefix("Purg ")) {
                name(rest)
            } else {
                l.strip_prefix("Inst ").and_then(name).map(|n| format!("{n} (install)"))
            }
        })
        .collect()
}

/// dpkg state of every package: name → last word of `Status:` (`installed`,
/// `unpacked`, `half-configured`, `config-files`, …).
fn package_states(status: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for stanza in status.split("\n\n") {
        let mut name = None;
        let mut state = None;
        for line in stanza.lines() {
            if let Some(n) = line.strip_prefix("Package: ") {
                name = Some(n.trim().to_string());
            } else if let Some(s) = line.strip_prefix("Status: ") {
                state = s.split_whitespace().last().map(str::to_string);
            }
        }
        if let (Some(n), Some(st)) = (name, state) {
            out.insert(n, st);
        }
    }
    out
}

/// Does dpkg know kernel `ver` in any state other than removed? True while a
/// kernel is being installed (e.g. `unpacked` during an unattended upgrade).
fn kernel_version_live(states: &HashMap<String, String>, ver: &str) -> bool {
    let suffix = format!("-{ver}");
    states
        .iter()
        .any(|(p, st)| p.starts_with("linux-") && p.ends_with(&suffix) && st != "config-files" && st != "not-installed")
}

/// Root command removing a leftover module dir, re-checking right before
/// deleting that no kernel of that version appeared in the meantime.
fn leftover_rm_command(ver: &str, dir: &Path) -> String {
    format!(
        "sudo sh -c 'if [ -e \"/boot/vmlinuz-$1\" ] || dpkg-query -W -f=\"\\${{Status}}\\n\" \"linux-*-$1\" 2>/dev/null | grep -Evq \"(config-files|not-installed)$\"; then echo \"kept $2: kernel $1 is installed now\"; else rm -rf --one-file-system -- \"$2\"; fi' _ {} {}",
        shq(ver),
        shq(&dir.to_string_lossy())
    )
}

/// Numeric ABI part of a kernel release: `6.8.0-100-generic` -> `6.8.0-100`,
/// `6.8.0-100-generic-64k` -> `6.8.0-100`. The flavour starts at the first
/// `-` followed by a letter.
fn kernel_base(ver: &str) -> &str {
    let b = ver.as_bytes();
    (0..b.len())
        .find(|&i| b[i] == b'-' && b.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic()))
        .map_or(ver, |i| &ver[..i])
}

/// Does dpkg package `pkg` belong to kernel `ver`? Flavoured packages end in
/// the full release (`linux-image-6.8.0-100-generic`); the flavour-less
/// `linux-headers-<base>`, `linux-tools-<base>`, `linux-hwe-*-headers-<base>`
/// and `linux-hwe-*-tools-<base>` only count when no kept kernel shares that
/// base. Matches are on whole `-` tokens, so `6.8.0-10` never matches `6.8.0-100`.
fn kernel_pkg_matches(pkg: &str, ver: &str, base: &str, base_shared: bool) -> bool {
    let token_suffix = |t: &str| pkg.strip_suffix(t).and_then(|p| p.strip_suffix('-'));
    if !pkg.starts_with("linux-") {
        return false;
    }
    if token_suffix(ver).is_some() {
        return true;
    }
    if base_shared {
        return false;
    }
    match token_suffix(base) {
        Some("linux-headers" | "linux-tools") => true,
        Some(p) => p.strip_prefix("linux-hwe-").is_some_and(|hwe| {
            hwe.strip_suffix("-headers").or_else(|| hwe.strip_suffix("-tools")).is_some_and(|series| {
                !series.is_empty() && series.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
        }),
        None => false,
    }
}

/// Kernel releases with an installed `linux-image-<release>` package (signed
/// or unsigned, once each; debug-symbol packages are not kernels).
fn installed_kernel_images(packages: &[String]) -> Vec<String> {
    let mut v: Vec<String> = packages
        .iter()
        .filter_map(|p| p.strip_prefix("linux-image-unsigned-").or_else(|| p.strip_prefix("linux-image-")))
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()) && !v.ends_with("-dbgsym"))
        .map(String::from)
        .collect();
    v.sort();
    v.dedup();
    v
}

/// UTF-8 names in `dir` (others can not be a kernel release we can act on).
fn dir_names(dir: &Path) -> Vec<String> {
    let Ok(rd) = fs::read_dir(dir) else { return Vec::new() };
    rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect()
}

/// Kernel check against injectable roots, the running release, the contents
/// of `/var/lib/dpkg/status` and an `apt-get -s purge` simulator.
fn kernel_findings(
    roots: &KernelRoots,
    running: &str,
    dpkg_status: &str,
    simulate: &dyn Fn(&[String]) -> Option<String>,
) -> CheckOutput {
    let packages = installed_packages(dpkg_status);
    let states = package_states(dpkg_status);
    let mut images = installed_kernel_images(&packages);
    if images.is_empty() || running.is_empty() {
        // Without the package database nothing can be judged safely.
        return CheckOutput::default();
    }
    // Keep the running kernel and the two newest *installed* ones: the set
    // Ubuntu's autoremove protects. Leftover module dirs do not count.
    images.sort_by(|a, b| version_key(a).cmp(&version_key(b)).then_with(|| a.cmp(b)));
    let newest = images.last().unwrap().clone();
    let mut keep: HashSet<&str> = images.iter().rev().take(2).map(|s| s.as_str()).collect();
    keep.insert(running);
    let kept_bases: HashSet<&str> = keep.iter().map(|v| kernel_base(v)).collect();

    let mut versions: HashSet<String> = images.iter().cloned().collect();
    if let Ok(rd) = fs::read_dir(roots.boot) {
        for e in rd.flatten() {
            let Ok(n) = e.file_name().into_string() else { continue };
            if let Some(v) = n.strip_prefix("vmlinuz-") {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    versions.insert(v.to_string());
                }
            }
        }
    }
    versions.extend(dir_names(roots.modules));
    let mut old: Vec<String> = versions.into_iter().filter(|v| !keep.contains(v.as_str())).collect();
    old.sort_by(|a, b| version_key(a).cmp(&version_key(b)).then_with(|| a.cmp(b)));

    let src_names = dir_names(roots.usr_src);
    let lib_names = dir_names(roots.usr_lib);
    let mut out = CheckOutput::default();
    let mut leftovers: Vec<(PathBuf, u64)> = Vec::new();
    for ver in &old {
        let ver = ver.as_str();
        let base = kernel_base(ver);
        let base_shared = kept_bases.contains(base);
        let mut paths = Vec::new();
        let mut bytes = 0;
        for f in ["vmlinuz", "initrd.img", "System.map", "config"] {
            let p = roots.boot.join(format!("{f}-{ver}"));
            if let Ok(md) = fs::metadata(&p) {
                bytes += file_bytes(&md);
                paths.push(p);
            }
        }
        let mut dirs = vec![
            roots.modules.join(ver),
            roots.usr_src.join(format!("linux-headers-{ver}")),
            roots.usr_lib.join(format!("linux-tools-{ver}")),
            roots.usr_lib.join("linux-tools").join(ver),
        ];
        if !base_shared && base != ver {
            let flavourless = |n: &&String, kind: &str| {
                n.strip_suffix(&format!("-{kind}-{base}"))
                    .is_some_and(|p| p.starts_with("linux-hwe-"))
            };
            dirs.push(roots.usr_src.join(format!("linux-headers-{base}")));
            dirs.push(roots.usr_lib.join(format!("linux-tools-{base}")));
            dirs.extend(src_names.iter().filter(|n| flavourless(n, "headers")).map(|n| roots.usr_src.join(n)));
            dirs.extend(lib_names.iter().filter(|n| flavourless(n, "tools")).map(|n| roots.usr_lib.join(n)));
        }
        for p in dirs {
            if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                bytes += scanner::du(&p).0;
                paths.push(p);
            }
        }
        let pkgs: Vec<String> = packages
            .iter()
            .filter(|p| kernel_pkg_matches(p, ver, base, base_shared))
            .cloned()
            .collect();
        if paths.is_empty() && pkgs.is_empty() {
            continue;
        }

        let manual = |why: String| (Action::Manual, why);
        let (action, detail) = if !pkgs.is_empty() {
            match simulate(&pkgs).map(|sim| apt_sim_removals(&sim)) {
                None => manual(format!(
                    "Kernel {ver} is not in use, but `apt-get -s purge` could not verify what \
                     purging its packages would remove. Review it with:\n  apt-get -s purge {}",
                    pkgs.join(" ")
                )),
                Some(removed) => {
                    let mut extra: Vec<String> =
                        removed.into_iter().filter(|r| !pkgs.contains(r)).collect();
                    extra.sort();
                    extra.dedup();
                    if !extra.is_empty() {
                        manual(format!(
                            "Kernel {ver} is not in use, but purging its packages would also \
                             change {} (e.g. remove the kernel metapackage that keeps future kernel \
                             updates coming). Not done automatically; review with:\n  \
                             apt-get -s purge {}",
                            extra.join(", "),
                            pkgs.join(" ")
                        ))
                    } else {
                        let list: Vec<String> = pkgs.iter().map(|p| shq(p)).collect();
                        (
                            Action::Shell {
                                command: format!(
                                    "sudo apt-get -o DPkg::Lock::Timeout=120 purge -y {}",
                                    list.join(" ")
                                ),
                            },
                            format!(
                                "Kernel {ver} is neither the running kernel ({running}) nor one \
                                 of the two newest installed ones (newest: {newest}), which \
                                 Ubuntu keeps as fallbacks. Purging exactly its packages removes \
                                 the image, initrd, modules, headers and tools and updates GRUB; \
                                 a dry run (apt-get -s) confirmed nothing else is removed."
                            ),
                        )
                    }
                }
            }
        } else if paths.iter().all(|p| p.starts_with(roots.modules))
            && !kernel_version_live(&states, ver)
            && version_key(ver) < version_key(&newest)
        {
            leftovers.extend(paths.into_iter().map(|p| (p, bytes)));
            continue;
        } else if paths.iter().all(|p| p.starts_with(roots.modules)) {
            // Being installed right now, or newer than every installed image
            // (e.g. a kernel installed outside dpkg): never touch it.
            continue;
        } else {
            manual(format!(
                "Kernel {ver} files were found but no matching dpkg package; it was \
                 probably installed by hand. Remove it the same way it was installed."
            ))
        };
        out.findings.push(Finding {
            id: format!("kernel:{ver}"),
            category: "Kernels".into(),
            title: format!("Inactive kernel {ver}"),
            risk: Risk::Moderate,
            bytes,
            detail,
            paths,
            action,
            needs_root: true,
        });
    }
    if !leftovers.is_empty() {
        let paths: Vec<PathBuf> = leftovers.iter().map(|l| l.0.clone()).collect();
        // Kernels removed without --purge leave dpkg records ("rc": config
        // files) that still own these dirs: purge them first so dpkg's
        // database stays consistent, then remove whatever is left.
        let rc = rc_kernel_packages(dpkg_status, &paths);
        let mut command = String::new();
        if !rc.is_empty() {
            command.push_str(&format!(
                "sudo dpkg --purge {}; ",
                rc.iter().map(|p| shq(p)).collect::<Vec<_>>().join(" ")
            ));
        }
        let per_dir: Vec<String> = paths
            .iter()
            .map(|p| leftover_rm_command(p.file_name().and_then(|n| n.to_str()).unwrap_or_default(), p))
            .collect();
        command.push_str(&per_dir.join("; "));
        out.findings.push(Finding {
            id: "kernel-leftovers".into(),
            category: "Kernels".into(),
            title: format!("Leftover module dirs of {} removed kernels", paths.len()),
            risk: Risk::Moderate,
            bytes: leftovers.iter().map(|l| l.1).sum(),
            detail: format!(
                "Directories under /lib/modules whose kernel packages are already \
                 removed; they hold files generated after install (DKMS modules, \
                 modules.* indexes) that apt does not track.{}",
                if rc.is_empty() {
                    String::new()
                } else {
                    format!(
                        " First purges the {} leftover dpkg records (removed, config kept) \
                         of those kernels so the package database stays consistent.",
                        rc.len()
                    )
                }
            ),
            action: Action::Shell { command },
            paths,
            needs_root: true,
        });
    }
    out
}

/// `sudo rm -rf -- <paths>` (all paths valid UTF-8, see `utf8_only`).
/// Packages in dpkg "rc" state (removed, config files kept) belonging to the
/// kernel versions of the given /lib/modules/<ver> dirs.
fn rc_kernel_packages(dpkg_status: &str, module_dirs: &[PathBuf]) -> Vec<String> {
    let versions: Vec<String> =
        module_dirs.iter().filter_map(|p| p.file_name()?.to_str().map(str::to_string)).collect();
    let mut out = Vec::new();
    for stanza in dpkg_status.split("\n\n") {
        let mut name = None;
        let mut rc = false;
        for l in stanza.lines() {
            if let Some(n) = l.strip_prefix("Package: ") {
                name = Some(n.trim());
            } else if let Some(st) = l.strip_prefix("Status: ") {
                rc = st.trim().ends_with("config-files");
            }
        }
        if let (Some(n), true) = (name, rc) {
            if n.starts_with("linux-") && versions.iter().any(|v| n.ends_with(&format!("-{v}"))) {
                out.push(n.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}


/// Keep only paths a shell command can name exactly (valid UTF-8).
fn utf8_only(files: Vec<(PathBuf, u64)>) -> Vec<(PathBuf, u64)> {
    files.into_iter().filter(|f| f.0.to_str().is_some()).collect()
}

/// 3. Disabled snap revisions.
fn check_snaps(ctx: &RuleContext) -> CheckOutput {
    let list = Command::new("snap")
        .args(["list", "--all"])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    // No snapd (or it failed): we can't tell disabled from pending revisions.
    let Some(list) = list else { return CheckOutput::default() };
    let home = &ctx.home;
    snap_findings_ext(
        &crate::sysdirs::get().snapd_state.join("snaps"),
        &crate::sysdirs::get().snap_mount,
        &list,
        &[PathBuf::from("/var/snap"), home.join("snap")],
    )
}

/// (name, revision) of rows marked `disabled` in `snap list --all` output.
/// Rows that don't line up with the header are skipped.
fn disabled_snap_revisions(list: &str) -> Vec<(String, String)> {
    let mut lines = list.lines();
    let Some(header) = lines.next() else { return Vec::new() };
    let cols: Vec<&str> = header.split_whitespace().collect();
    let col = |name: &str| cols.iter().position(|c| *c == name);
    let (Some(ni), Some(ri), Some(noi)) = (col("Name"), col("Rev"), col("Notes")) else {
        return Vec::new();
    };
    let valid_name = |n: &str| {
        !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    let valid_rev = |r: &str| {
        let d = r.strip_prefix('x').unwrap_or(r);
        !d.is_empty() && d.chars().all(|c| c.is_ascii_digit())
    };
    lines
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.len() != cols.len() || !t[noi].split(',').any(|n| n == "disabled") {
                return None;
            }
            (valid_name(t[ni]) && valid_rev(t[ri])).then(|| (t[ni].to_string(), t[ri].to_string()))
        })
        .collect()
}

/// Snap check: revisions `snap list --all` reports as disabled, sized from
/// their files in `snaps_dir`. `snap_root/<name>/current` is re-checked.
#[cfg(test)]
fn snap_findings(snaps_dir: &Path, snap_root: &Path, snap_list: &str) -> CheckOutput {
    snap_findings_ext(snaps_dir, snap_root, snap_list, &[])
}

/// `data_roots` hold per-revision data (/var/snap/<name>/<rev>, ~/snap/<name>/<rev>)
/// that `snap remove --revision` deletes along with the revision.
fn snap_findings_ext(snaps_dir: &Path, snap_root: &Path, snap_list: &str, data_roots: &[PathBuf]) -> CheckOutput {
    let mut immediate = 0u64;
    let mut data = 0u64;
    let mut data_dirs: Vec<String> = Vec::new();
    let mut cmds = Vec::new();
    let mut paths = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut bytes = 0;
    let mut reverted: Vec<(String, String, String)> = Vec::new();
    let num = |r: &str| r.parse::<u64>().ok();
    for (name, rev) in disabled_snap_revisions(snap_list) {
        if let Ok(cur) = fs::read_link(snap_root.join(&name).join("current")) {
            if cur.as_os_str() == rev.as_str() {
                continue; // never the active revision
            }
            // Newer than the active one: the user ran `snap revert`, and this
            // revision's data dir holds their most recent data.
            let cur = cur.to_string_lossy().into_owned();
            if let (Some(r), Some(c)) = (num(&rev), num(&cur)) {
                if r > c {
                    reverted.push((name, rev, cur));
                    continue;
                }
            }
        }
        let file = snaps_dir.join(format!("{name}_{rev}.snap"));
        if let Ok(md) = fs::symlink_metadata(&file) {
            if md.is_file() {
                bytes += file_bytes(&md);
                // A second link lives in snapd's download cache.
                if md.nlink() <= 1 {
                    immediate += file_bytes(&md);
                }
                paths.push(file);
            }
        }
        for root in data_roots {
            let dir = root.join(&name).join(&rev);
            if fs::symlink_metadata(&dir).map_or(false, |m| m.is_dir()) {
                let b = scanner::du(&dir).0;
                data += b;
                if b >= 1 << 20 {
                    data_dirs.push(format!("{} ({})", dir.display(), fmt_size(b)));
                }
            }
        }
        cmds.push(format!("sudo snap remove {} --revision={}", shq(&name), shq(&rev)));
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut out = CheckOutput::default();
    if !reverted.is_empty() {
        let list: Vec<String> = reverted.iter().map(|(n, r, c)| format!("{n} revision {r} (active: {c})")).collect();
        let bytes: u64 = reverted
            .iter()
            .map(|(n, r, _)| fs::metadata(snaps_dir.join(format!("{n}_{r}.snap"))).map_or(0, |m| file_bytes(&m)))
            .sum();
        out.findings.push(Finding {
            id: "snap-reverted".into(),
            category: "Snap".into(),
            title: format!("Snap revisions newer than the active one ({})", reverted.len()),
            risk: Risk::Caution,
            bytes,
            detail: format!(
                "{}. These snaps were reverted to an older revision, so the disabled newer \
                 revision's data folder holds your most recent data. Only remove one once you \
                 are sure you don't want to go back to it: sudo snap remove <name> --revision=<rev>",
                list.join(", ")
            ),
            paths: Vec::new(),
            action: Action::Manual,
            needs_root: true,
        });
    }
    if cmds.is_empty() {
        return out;
    }
    out.findings.push(Finding {
        id: "snap-revisions".into(),
        category: "Snap".into(),
        title: format!("Disabled snap revisions ({} in {})", cmds.len(), names.join(", ")),
        risk: Risk::Moderate,
        bytes: bytes + data,
        detail: format!(
            "snapd keeps superseded revisions of every snap (refresh.retain, default 2-3) \
             so it can roll back. Removing disabled revisions loses that rollback point and \
             that revision's saved data{}.\n\
             {} comes back immediately. The rest ({}) is also held by snapd's download \
             cache (/var/lib/snapd/cache): after this cleanup those cached copies show up \
             as \"Orphaned snapd download cache\" on the next analysis (visible when run \
             with sudo).\n\
             To keep fewer in future: sudo snap set system refresh.retain=2",
            if data_dirs.is_empty() { String::new() } else { format!(": {}", data_dirs.join(", ")) },
            fmt_size(immediate + data),
            fmt_size(bytes - immediate),
        ),
        paths,
        // Independent removals: one failing must not skip the others.
        action: Action::Shell { command: cmds.join("; ") },
        needs_root: true,
    });
    out
}

/// 4. Systemd journal above the retention target.
fn check_journal(ctx: &RuleContext) -> CheckOutput {
    // journald writes to persistent storage when it exists, else to the
    // volatile one; sysdirs lists persistent first.
    let dirs = &crate::sysdirs::get().journals;
    match dirs.len() {
        0 => CheckOutput::default(),
        _ => journal_findings(&dirs[0], ctx.journal_keep),
    }
}

/// Journal check against an injectable journal directory.
/// What `journalctl --vacuum-size=<keep>` frees: whole *archived* journal
/// files (named `…@….journal[~]`), oldest first, until all journal files
/// together use at most `keep`. Active files are never removed.
/// None when there are no readable journal files.
fn journal_vacuum_bytes(dir: &Path, keep: u64) -> Option<u64> {
    let mut files: Vec<(bool, std::time::SystemTime, u64)> = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    if let Ok(rd) = fs::read_dir(dir) {
        dirs.extend(rd.flatten().filter(|e| e.file_type().map_or(false, |t| t.is_dir())).map(|e| e.path()));
    }
    for d in dirs {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if !(n.ends_with(".journal") || n.ends_with(".journal~")) {
                continue;
            }
            let Ok(md) = e.metadata() else { continue };
            if md.is_file() {
                files.push((n.contains('@'), md.modified().unwrap_or(std::time::UNIX_EPOCH), file_bytes(&md)));
            }
        }
    }
    if files.is_empty() {
        return None;
    }
    let mut total: u64 = files.iter().map(|f| f.2).sum();
    let mut archived: Vec<&(bool, std::time::SystemTime, u64)> = files.iter().filter(|f| f.0).collect();
    archived.sort_by_key(|f| f.1);
    let mut freed = 0;
    for f in archived {
        if total <= keep {
            break;
        }
        total -= f.2;
        freed += f.2;
    }
    Some(freed)
}

fn journal_findings(dir: &Path, keep: u64) -> CheckOutput {
    if !dir.is_dir() {
        return CheckOutput::default();
    }
    let (size, _) = scanner::du(dir);
    if size <= keep {
        return CheckOutput::default();
    }
    // Replay journald's vacuum when the files are readable; otherwise
    // "size - keep" is a close lower bound.
    let reclaim = journal_vacuum_bytes(dir, keep).unwrap_or(size - keep);
    if reclaim == 0 {
        return CheckOutput::default();
    }
    let keep_mb = keep >> 20;
    // journalctl takes K/M/G: say exactly the keep size that was measured.
    let keep_arg = if keep % (1 << 20) == 0 { format!("{keep_mb}M") } else { format!("{}K", keep >> 10) };
    CheckOutput::one(Finding {
        id: "journal".into(),
        category: "Logs".into(),
        title: format!("systemd journal is {} (keep {})", fmt_size(size), fmt_size(keep)),
        risk: Risk::Moderate,
        bytes: reclaim,
        detail: format!(
            "Persistent journal logs in /var/log/journal. Vacuuming deletes the oldest \
             archived journal files until {keep_mb} MiB remain. To cap it permanently, set \
             SystemMaxUse={keep_mb}M in /etc/systemd/journald.conf."
        ),
        paths: vec![dir.to_path_buf()],
        // --directory: vacuum exactly the store that was measured.
        action: Action::Shell { command: format!("sudo journalctl --directory={} --vacuum-size={keep_arg}", shq(&dir.to_string_lossy())) },
        needs_root: true,
    })
}

/// logrotate's names: `x.gz` / `x.xz`, or `x.N` with a
/// small rotation number. `mysql-bin.000002` (a live MySQL binlog) and
/// `10.0.0.5` (rsyslog's per-host file) are not rotations.
fn is_rotated_log(name: &str) -> bool {
    if name.ends_with(".gz") || name.ends_with(".xz") {
        return true;
    }
    let Some((stem, ext)) = name.rsplit_once('.') else { return false };
    if !ext.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    // `x.log.20260914085904`: a date-stamped rotation (YYYYMMDD[hhmmss]).
    let dated = stem.ends_with(".log")
        && (ext.len() == 8 || ext.len() == 14)
        && ext[..2].eq("20")
        && (1..=12).contains(&ext[4..6].parse::<u32>().unwrap_or(0))
        && (1..=31).contains(&ext[6..8].parse::<u32>().unwrap_or(0));
    let small_number = (1..=3).contains(&ext.len());
    let stem_last = stem.rsplit('.').next().unwrap_or("");
    dated || (small_number && !(!stem_last.is_empty() && stem_last.chars().all(|c| c.is_ascii_digit())))
}

/// Old rotated logs (`syslog.1`, `kern.log.2.gz`, ...).
fn check_rotated_logs(_: &RuleContext) -> CheckOutput {
    rotated_log_findings(&crate::sysdirs::get().log)
}

/// Regular files below `root` that are rotated logs. Skips `journal/` (own
/// rule), `installer/` (the install record) and apt's `eipp.log.xz` (kept by
/// apt as its current solver log, not a rotation).
fn rotated_log_files(root: &Path) -> Vec<(PathBuf, u64)> {
    fn walk(dir: &Path, skip: &[PathBuf], acc: &mut Vec<(PathBuf, u64)>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        let entries: Vec<fs::DirEntry> = rd.flatten().collect();
        // A `*.index` file marks numbered files that belong together (MySQL
        // binlogs): those are data, never rotated logs.
        if entries.iter().any(|e| e.file_name().to_string_lossy().ends_with(".index")) {
            return;
        }
        for e in entries {
            let Ok(md) = e.metadata() else { continue };
            let p = e.path();
            if skip.contains(&p) {
                continue;
            }
            if md.is_dir() {
                walk(&p, skip, acc);
            } else if md.is_file() && is_rotated_log(&e.file_name().to_string_lossy()) {
                acc.push((p, file_bytes(&md)));
            }
        }
    }
    let skip = [root.join("journal"), root.join("installer"), root.join("apt/eipp.log.xz")];
    let mut files = Vec::new();
    walk(root, &skip, &mut files);
    utf8_only(files)
}

/// Rotated-log check against an injectable log root (`/var/log`). The
/// command deletes exactly the counted files.
fn rotated_log_findings(root: &Path) -> CheckOutput {
    let mut files = rotated_log_files(root);
    files.sort();
    let bytes: u64 = files.iter().map(|f| f.1).sum();
    if bytes == 0 {
        return CheckOutput::default();
    }
    let paths: Vec<PathBuf> = files.into_iter().map(|f| f.0).collect();
    CheckOutput::one(Finding {
        id: "rotated-logs".into(),
        category: "Logs".into(),
        title: format!("Rotated logs in {} ({} files)", root.display(), paths.len()),
        risk: Risk::Moderate,
        bytes,
        detail: "Compressed or numbered log archives left behind by logrotate. Current \
                 logs are untouched; you lose older history only."
            .into(),
        action: Action::Shell { command: sudo_delete_files(root, &paths) },
        paths,
        needs_root: true,
    })
}

/// 6b. Crash reports written by apport.
fn check_crash(_: &RuleContext) -> CheckOutput {
    crash_findings(&crate::sysdirs::get().crash)
}

/// Crash-report check against an injectable directory (`/var/crash`). Only
/// apport's own files count, and only in a real directory (not a symlink).
fn crash_findings(dir: &Path) -> CheckOutput {
    if !fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
        return CheckOutput::default();
    }
    let files = utf8_only(list_files(dir, |n| {
        !n.starts_with('.') && [".crash", ".upload", ".uploaded"].iter().any(|e| n.ends_with(e))
    }));
    let bytes: u64 = files.iter().map(|f| f.1).sum();
    if files.is_empty() {
        return CheckOutput::default();
    }
    let paths: Vec<PathBuf> = files.into_iter().map(|f| f.0).collect();
    CheckOutput::one(Finding {
        id: "crash".into(),
        category: "Crash dumps".into(),
        title: format!("Crash reports in {} ({} files)", dir.display(), paths.len()),
        risk: Risk::Safe,
        bytes,
        detail: "Core dumps and reports collected by apport. Once reported (or if you do \
                 not plan to), they serve no purpose."
            .into(),
        action: Action::Shell { command: sudo_delete_files(dir, &paths) },
        paths,
        needs_root: true,
    })
}

/// 5 & 6a. Per-user caches: thumbnails, pip, cargo, npm, trash.
fn check_user_caches(ctx: &RuleContext) -> CheckOutput {
    // Honour XDG_CACHE_HOME / XDG_DATA_HOME / CARGO_HOME / PIP_CACHE_DIR / npm_config_cache.
    let d = super::extra::Dirs::resolve(ctx);
    let specs: Vec<(&str, &str, &str, Vec<PathBuf>, Risk, &str)> = vec![
        (
            "thumbnails",
            "User cache",
            "Thumbnail cache",
            vec![d.cache.join("thumbnails")],
            Risk::Safe,
            "Image previews generated by the file manager; regenerated when needed.",
        ),
        (
            "pip-cache",
            "Python",
            "pip download cache",
            // pip's own sub-folders only (what `pip cache purge` clears), so a
            // PIP_CACHE_DIR shared with other data is never emptied wholesale.
            ["http", "http-v2", "wheels", "selfcheck"].iter().map(|s| d.pip_cache(ctx.is_root).join(s)).collect(),
            Risk::Safe,
            "Wheels and HTTP responses cached by pip. Equivalent: pip cache purge",
        ),
        (
            "cargo-registry",
            "Rust",
            "Cargo registry cache",
            vec![d.cargo.join("registry/cache"), d.cargo.join("registry/src")],
            Risk::Moderate,
            "Downloaded .crate archives and their extracted sources. Cargo re-downloads \
             what a build needs, so offline builds (--offline, vendored CI caches) break \
             until you are online again. Do not clear it while a cargo build is running.",
        ),
        (
            "cargo-git",
            "Rust",
            "Cargo git checkouts",
            vec![d.cargo.join("git/checkouts")],
            Risk::Safe,
            "Checkouts of git dependencies; re-created from the git db on the next build.",
        ),
        (
            "npm-cache",
            "Node",
            "npm cache",
            vec![d.npm_cache(ctx.is_root).join("_cacache")],
            Risk::Safe,
            "npm's content-addressable package cache. Equivalent: npm cache clean --force",
        ),
        (
            "trash",
            "User files",
            "Desktop Trash",
            vec![d.data.join("Trash/files"), d.data.join("Trash/info")],
            Risk::Moderate,
            "Files you moved to the Trash. Emptying it is permanent — have a look first.",
        ),
    ];
    let mut out = CheckOutput::default();
    for (id, cat, title, dirs, risk, detail) in specs {
        if let Some(f) = cache_dir_finding(ctx, id, cat, title, &dirs, risk, detail) {
            out.findings.push(f);
        }
    }
    out
}

// ---------------------------------------------------------------- docker

fn docker_socket() -> Option<PathBuf> {
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        return host.strip_prefix("unix://").map(PathBuf::from);
    }
    let mut candidates = vec![PathBuf::from("/var/run/docker.sock")];
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(rt).join("docker.sock"));
    }
    candidates.into_iter().find(|p| p.exists())
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let Some(nl) = rest.windows(2).position(|w| w == b"\r\n") else { break };
        let len_str = String::from_utf8_lossy(&rest[..nl]);
        let len = usize::from_str_radix(len_str.split(';').next().unwrap().trim(), 16).unwrap_or(0);
        if len == 0 || rest.len() < nl + 2 + len {
            break;
        }
        out.extend_from_slice(&rest[nl + 2..nl + 2 + len]);
        rest = &rest[(nl + 4 + len).min(rest.len())..];
    }
    out
}

/// Minimal HTTP GET over the Docker Engine unix socket.
fn docker_get(sock: &Path, path: &str) -> Result<serde_json::Value, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    write!(s, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n").map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    if !head.lines().next().unwrap_or("").contains(" 200") {
        return Err(head.lines().next().unwrap_or("").to_string());
    }
    let mut body = raw[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

/// From a `/system/df` response: (dangling image bytes, dangling image count,
/// builder cache bytes). Only what `docker image prune -f` / `docker builder
/// prune -f` actually delete is counted: unused dangling images minus layers
/// shared with other images, and cache records neither in use nor shared.
fn docker_reclaimable(df: &serde_json::Value) -> (u64, usize, u64) {
    let (mut img_bytes, mut img_count) = (0u64, 0usize);
    for img in df["Images"].as_array().into_iter().flatten() {
        let tags = img["RepoTags"].as_array();
        let dangling = tags.map_or(true, |t| {
            t.is_empty() || t.iter().all(|x| x.as_str() == Some("<none>:<none>"))
        });
        if dangling && img["Containers"].as_i64().unwrap_or(0) <= 0 {
            let size = img["Size"].as_i64().unwrap_or(0);
            let shared = img["SharedSize"].as_i64().unwrap_or(-1).max(0);
            img_bytes += (size - shared).max(0) as u64;
            img_count += 1;
        }
    }
    let build: u64 = df["BuildCache"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| !c["InUse"].as_bool().unwrap_or(true) && !c["Shared"].as_bool().unwrap_or(true))
        .map(|c| c["Size"].as_i64().unwrap_or(0).max(0) as u64)
        .sum();
    (img_bytes, img_count, build)
}

/// 5d. Dangling images and unused builder cache.
fn check_docker(_: &RuleContext) -> CheckOutput {
    let Some(sock) = docker_socket() else { return CheckOutput::default() };
    let df = match docker_get(&sock, "/system/df") {
        Ok(v) => v,
        Err(e) => {
            return CheckOutput::note(format!(
                "Docker socket {} is not accessible ({e}). Add yourself to the docker \
                 group or run with sudo to include Docker images and build cache.",
                sock.display()
            ))
        }
    };
    let mut out = CheckOutput::default();
    let (img_bytes, img_count, build) = docker_reclaimable(&df);
    if img_count > 0 {
        out.findings.push(Finding {
            id: "docker-dangling".into(),
            category: "Docker".into(),
            title: format!("Dangling Docker images ({img_count})"),
            risk: Risk::Safe,
            bytes: img_bytes,
            detail: "Untagged image layers no longer referenced by any tag or container, \
                     usually left over from rebuilding images."
                .into(),
            paths: Vec::new(),
            // -H: the daemon that was measured, not the CLI's current context.
            action: Action::Shell { command: format!("docker -H {} image prune -f", shq(&format!("unix://{}", sock.display()))) },
            needs_root: false,
        });
    }

    if build > 0 {
        out.findings.push(Finding {
            id: "docker-builder".into(),
            category: "Docker".into(),
            title: "Docker builder cache".into(),
            risk: Risk::Safe,
            bytes: build,
            detail: "BuildKit layer cache not used by a running build. Future builds are \
                     slower until the cache is warm again."
                .into(),
            paths: Vec::new(),
            // -H: the daemon that was measured, not the CLI's current context.
            action: Action::Shell { command: format!("docker -H {} builder prune -f", shq(&format!("unix://{}", sock.display()))) },
            needs_root: false,
        });
    }
    out
}

// ---------------------------------------------------------------- projects

/// A `node_modules` a package manager can restore: the project has a lockfile
/// (or the folder carries the package manager's install metadata), and it is
/// not the bundled code of an installed app (VS Code, Discord, Obsidian …
/// ship `resources/app/node_modules`, which nothing can reinstall).
fn is_restorable_node_modules(nm: &Path) -> bool {
    let Some(project) = nm.parent() else { return false };
    let s = project.to_string_lossy();
    if s.contains("/resources/app") || s.ends_with("/resources") {
        return false;
    }
    let asar_nearby = |d: &Path| {
        fs::read_dir(d).is_ok_and(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().ends_with(".asar")))
    };
    if asar_nearby(project) || project.parent().is_some_and(asar_nearby) {
        return false;
    }
    const LOCKS: &[&str] = &["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"];
    const INSTALLED: &[&str] = &[".package-lock.json", ".yarn-integrity", ".modules.yaml", ".yarn-state.yml"];
    LOCKS.iter().any(|l| project.join(l).is_file()) || INSTALLED.iter().any(|m| nm.join(m).is_file())
}

/// Project build artifacts under the dev roots: Rust `target/`, `node_modules/`
/// and `__pycache__/`. Reuses the main scan tree when it covers a dev root,
/// otherwise scans that root on its own.
pub fn run_artifact_check(ctx: &RuleContext, tree: Option<&Tree>, opts: &ScanOptions) -> CheckOutput {
    const MAX_PROJECT_FINDINGS: usize = 60;
    let mut artifacts: Vec<(Risk, &'static str, PathBuf, u64)> = Vec::new();
    let mut pycache: Vec<(PathBuf, u64)> = Vec::new();

    // Hidden directories hold tool and application data, not projects:
    // ~/.nvm/.../lib/node_modules is the global npm install, ~/.config/<app>/
    // node_modules belongs to that app, ~/.cargo and ~/.cache have their own
    // rules. ~/snap holds per-snap app data. None of it is safe build output.
    let skip: Vec<PathBuf> = vec![ctx.home.join("snap")];

    for root in &ctx.dev_roots {
        let Ok(root) = fs::canonicalize(root) else { continue };
        let owned;
        let (t, start) = match tree.and_then(|t| t.find(&root).map(|i| (t, i))) {
            Some((t, i)) if t.nodes[i].kind == NodeKind::Dir => (t, i),
            _ => {
                let o = ScanOptions { min_file_size: u64::MAX, ..opts.clone() };
                match scanner::scan(&root, &o, &Progress::default()) {
                    Ok(t) => {
                        owned = t;
                        (&owned, 0)
                    }
                    Err(_) => continue,
                }
            }
        };
        let skip_idx: HashSet<usize> = skip.iter().filter_map(|p| t.find(p)).collect();

        let mut stack = vec![start];
        while let Some(i) = stack.pop() {
            let node = &t.nodes[i];
            for &c in &node.children {
                let child = &t.nodes[c];
                if child.kind != NodeKind::Dir || skip_idx.contains(&c) {
                    continue;
                }
                if child.name.starts_with('.') {
                    continue;
                }
                match child.name.as_str() {
                    "node_modules" if node.markers & marker::PACKAGE_JSON != 0 => {
                        let nm = t.path_of(c);
                        if is_restorable_node_modules(&nm) {
                            artifacts.push((Risk::Caution, "node", nm, child.size));
                        }
                    }
                    "target"
                        if node.markers & marker::CARGO_TOML != 0
                            || child.markers & marker::CACHEDIR_TAG != 0 =>
                    {
                        artifacts.push((Risk::Caution, "rust", t.path_of(c), child.size));
                    }
                    "__pycache__" => pycache.push((t.path_of(c), child.size)),
                    // Never look inside a node_modules that isn't a project's
                    // (e.g. a global `npm -g --prefix` install): its nested
                    // node_modules are installed software, not build output.
                    "node_modules" => {}
                    _ => stack.push(c),
                }
            }
        }
    }

    // Overlapping dev roots (e.g. ~ and ~/src) reach the same directories more
    // than once: keep each path once, and never a path inside another candidate.
    let all: HashSet<PathBuf> =
        artifacts.iter().map(|a| a.2.clone()).chain(pycache.iter().map(|p| p.0.clone())).collect();
    let nested = |p: &Path| p.ancestors().skip(1).any(|a| all.contains(a));
    let mut seen = HashSet::new();
    artifacts.retain(|a| !nested(&a.2) && seen.insert(a.2.clone()));
    pycache.retain(|p| !nested(&p.0) && seen.insert(p.0.clone()));

    let mut out = CheckOutput::default();
    artifacts.sort_by(|a, b| b.3.cmp(&a.3));
    let total = artifacts.len();
    for (risk, kind, path, bytes) in artifacts.into_iter().take(MAX_PROJECT_FINDINGS) {
        let project = path.parent().unwrap_or(&path).to_path_buf();
        let shown = tilde(&project, &ctx.home);
        let (category, title, detail) = match kind {
            "rust" => (
                "Rust",
                format!("Cargo target/ in {shown}"),
                match project.join("Cargo.toml").to_str() {
                    Some(m) => format!(
                        "Build output of a Rust project. Rebuilt by the next `cargo build`.\n\
                         Equivalent: cargo clean --manifest-path {}",
                        shq(m)
                    ),
                    None => "Build output of a Rust project. Rebuilt by the next `cargo build`.\n\
                             Equivalent: `cargo clean` inside the project."
                        .to_string(),
                },
            ),
            _ => (
                "Node",
                format!("node_modules/ in {shown}"),
                "Installed npm dependencies. Restored with `npm ci` / `npm install` (needs \
                 network, and may resolve newer versions without a lockfile)."
                    .to_string(),
            ),
        };
        out.findings.push(Finding {
            id: format!("{kind}:{}", path.display()),
            category: category.into(),
            title,
            risk,
            bytes,
            detail,
            paths: vec![path.clone()],
            action: Action::Remove { paths: vec![path], keep_dir: false },
            needs_root: false,
        });
    }
    if total > MAX_PROJECT_FINDINGS {
        out.notes.push(format!(
            "{} smaller project artifact directories were not listed.",
            total - MAX_PROJECT_FINDINGS
        ));
    }

    let py_bytes: u64 = pycache.iter().map(|p| p.1).sum();
    if !pycache.is_empty() {
        let paths: Vec<PathBuf> = pycache.into_iter().map(|p| p.0).collect();
        out.findings.push(Finding {
            id: "pycache".into(),
            category: "Python".into(),
            title: format!("__pycache__ directories ({})", paths.len()),
            risk: Risk::Safe,
            bytes: py_bytes,
            detail: "Compiled Python bytecode (.pyc). Python regenerates it automatically \
                     the next time a module is imported."
                .into(),
            paths: paths.clone(),
            action: Action::Remove { paths, keep_dir: false },
            needs_root: false,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(version_key("6.8.0-138-generic") > version_key("6.8.0-100-generic"));
        assert!(version_key("6.10.0-1-generic") > version_key("6.8.0-138-generic"));
    }

    #[test]
    fn version_tokens() {
        let m = |p: &str| kernel_pkg_matches(p, "6.8.0-100-generic", "6.8.0-100", false);
        assert!(m("linux-image-6.8.0-100-generic"));
        assert!(m("linux-headers-6.8.0-100"));
        assert!(m("linux-hwe-6.8-tools-6.8.0-100"));
        assert!(!m("linux-image-6.8.0-1001-generic"));
        assert!(!m("linux-image-16.8.0-100-generic"));
        assert!(!m("linux-headers-6.8.0-10"));
        assert!(!m("linux-image-6.8.0-100-lowlatency"));
        assert!(!m("linux-image-6.8.0-100-generic-64k"));
        assert!(!m("nvidia-6.8.0-100-generic"));
        // Base shared with a kept kernel: flavour-less packages are off limits.
        assert!(!kernel_pkg_matches("linux-headers-6.8.0-100", "6.8.0-100-generic", "6.8.0-100", true));
        assert_eq!(kernel_base("6.8.0-100-generic"), "6.8.0-100");
        assert_eq!(kernel_base("6.8.0-100-generic-64k"), "6.8.0-100");
        assert_eq!(kernel_base("5.15.0-1034-azure"), "5.15.0-1034");
        assert_eq!(kernel_base("6.9.0"), "6.9.0");
    }

    #[test]
    fn rotated() {
        assert!(is_rotated_log("syslog.1"));
        assert!(is_rotated_log("kern.log.2.gz"));
        assert!(!is_rotated_log("syslog"));
        assert!(!is_rotated_log("auth.log"));
    }

    #[test]
    fn chunked() {
        assert_eq!(dechunk(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), b"Wikipedia");
    }

    // ================================================================ fixtures

    use crate::rules::Report;
    use crate::util::testutil::{alloc, pwned, sh, TempDir, HOSTILE};
    use std::os::unix::fs::symlink;

    /// Makes `sudo …` run as the current user, as in the pkexec script.
    const SHIM: &str = "sudo() { \"$@\"; }\n";
    /// Records argv (NUL separated, one line per call) instead of running.
    const ARGV_SHIM: &str = "sudo() { for a in \"$@\"; do printf '%s\\0' \"$a\"; done; printf '\\n'; }\n";

    fn argv_calls(out: &str) -> Vec<Vec<String>> {
        out.lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.split('\0').filter(|s| !s.is_empty()).map(String::from).collect())
            .collect()
    }

    fn shell_cmd(f: &Finding) -> &str {
        match &f.action {
            Action::Shell { command } => command,
            other => panic!("expected a shell action, got {other:?}"),
        }
    }

    // ================================================================ kernels

    fn base_of(ver: &str) -> &str {
        kernel_base(ver)
    }

    fn kernel_pkgs(ver: &str) -> Vec<String> {
        let mut v: Vec<String> = ["image", "modules", "modules-extra", "headers"]
            .iter()
            .map(|k| format!("linux-{k}-{ver}"))
            .collect();
        v.push(format!("linux-headers-{}", base_of(ver)));
        v
    }

    fn dpkg(vers: &[&str]) -> String {
        let mut pkgs: Vec<String> = vers.iter().flat_map(|v| kernel_pkgs(v)).collect();
        pkgs.sort();
        pkgs.dedup();
        pkgs.push("linux-generic".into());
        pkgs.iter()
            .map(|p| format!("Package: {p}\nStatus: install ok installed\nArchitecture: amd64\n"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Fake /boot, /lib/modules, /usr/src, /usr/lib with full kernels and module-only leftovers.
    fn kernel_tree(installed: &[&str], leftovers: &[&str]) -> TempDir {
        let d = TempDir::new("kernels");
        for dir in ["boot", "modules", "src", "lib"] {
            d.dir(dir);
        }
        for v in installed {
            for f in ["vmlinuz", "initrd.img", "System.map", "config"] {
                d.file(format!("boot/{f}-{v}"), 3000);
            }
            d.file(format!("modules/{v}/kernel/fs.ko"), 5000);
            d.file(format!("src/linux-headers-{v}/Makefile"), 100);
            d.file(format!("src/linux-headers-{}/Makefile", base_of(v)), 100);
        }
        for v in leftovers {
            d.file(format!("modules/{v}/updates/dkms/nvidia.ko"), 7000);
        }
        // Symlinks such as /boot/vmlinuz and /boot/vmlinuz.old are not kernels.
        if let Some(v) = installed.first() {
            symlink(format!("vmlinuz-{v}"), d.join("boot/vmlinuz")).unwrap();
            symlink(format!("vmlinuz-{v}"), d.join("boot/vmlinuz-latest-link")).unwrap();
        }
        d
    }

    /// Simulator answering like `apt-get -s purge`, removing exactly the request.
    fn exact_sim(pkgs: &[String]) -> Option<String> {
        let mut s = String::from("NOTE: This is only a simulation!\nReading package lists...\n");
        for p in pkgs {
            s.push_str(&format!("Purg {p} [6.8.0-1.1~22.04.1]\n"));
        }
        Some(s)
    }

    fn kernels_with(
        d: &TempDir,
        running: &str,
        status: &str,
        sim: &dyn Fn(&[String]) -> Option<String>,
    ) -> CheckOutput {
        let (boot, modules, src, lib) = (d.join("boot"), d.join("modules"), d.join("src"), d.join("lib"));
        let roots = KernelRoots { boot: &boot, modules: &modules, usr_src: &src, usr_lib: &lib };
        kernel_findings(&roots, running, status, sim)
    }

    fn kernels(d: &TempDir, running: &str, status: &str) -> CheckOutput {
        kernels_with(d, running, status, &exact_sim)
    }

    fn proposed(out: &CheckOutput) -> Vec<String> {
        let mut v: Vec<String> =
            out.findings.iter().filter_map(|f| f.id.strip_prefix("kernel:").map(String::from)).collect();
        v.sort_by_key(|s| version_key(s));
        v
    }

    const PURGE: &str = "sudo apt-get -o DPkg::Lock::Timeout=120 purge -y ";

    fn purged(f: &Finding) -> Vec<String> {
        let cmd = shell_cmd(f);
        let rest = cmd.strip_prefix(PURGE).expect(cmd);
        let mut v: Vec<String> = rest.split(' ').map(String::from).collect();
        v.sort();
        v
    }

    fn g(n: &str) -> String {
        format!("6.8.0-{n}-generic")
    }

    #[test]
    fn kernel_never_proposes_running_newest_or_fallback() {
        let vers = [g("100"), g("110"), g("120"), g("138")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let status = dpkg(&refs);
        for (running, want) in [
            (g("110"), vec![g("100")]),
            (g("138"), vec![g("100"), g("110")]),
            (g("100"), vec![g("110")]),
            (g("120"), vec![g("100"), g("110")]),
        ] {
            let out = kernels(&d, &running, &status);
            let got = proposed(&out);
            assert_eq!(got, want, "running {running}");
            assert!(!got.contains(&running) && !got.contains(&g("138")));
            for f in &out.findings {
                assert_eq!(f.risk, Risk::Moderate);
                assert!(f.needs_root);
                for p in purged(f) {
                    assert!(!p.contains(&running) && !p.contains("-138") && !p.contains("-120"), "{p}");
                }
            }
        }
    }

    #[test]
    fn kernel_version_ordering_is_numeric() {
        assert!(version_key("6.10.0-1-generic") > version_key("6.8.0-999-generic"));
        assert!(version_key("6.8.0-138-generic") > version_key("6.8.0-100-generic"));
        assert!(version_key("6.8.0-100-generic") > version_key("6.8.0-99-generic"));

        // As strings "6.8.0-99" > "6.8.0-138"; numerically 138 is newest.
        let vers = [g("9"), g("99"), g("100"), g("138")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        assert_eq!(proposed(&kernels(&d, &g("138"), &dpkg(&refs))), vec![g("9"), g("99")]);

        let vers = ["6.8.0-50-generic", "6.8.0-200-generic", "6.9.0-5-generic", "6.10.0-1-generic"];
        let d = kernel_tree(&vers, &[]);
        let out = kernels(&d, "6.10.0-1-generic", &dpkg(&vers));
        assert_eq!(proposed(&out), ["6.8.0-50-generic", "6.8.0-200-generic"]);
    }

    #[test]
    fn kernel_packages_never_cross_versions() {
        let vers = [g("10"), g("100"), g("1001"), g("1002")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let out = kernels(&d, &g("1002"), &dpkg(&refs));
        assert_eq!(proposed(&out), [g("10"), g("100")]);
        for f in &out.findings {
            let ver = f.id.strip_prefix("kernel:").unwrap();
            let mut want = kernel_pkgs(ver);
            want.sort();
            assert_eq!(purged(f), want, "{ver}");
            assert!(shell_cmd(f).starts_with(PURGE));
            // Files and dirs belong to this version only.
            for p in &f.paths {
                let name = p.file_name().unwrap().to_string_lossy();
                assert!(name.ends_with(ver) || name.ends_with(base_of(ver)), "{p:?}");
            }
            let expect: u64 = f.paths.iter().map(|p| scanner::du(p).0).sum();
            assert_eq!(f.bytes, expect);
        }
    }

    #[test]
    fn kernel_flavours_sharing_a_base_are_not_purged_together() {
        let vers = [g("100"), "6.8.0-100-lowlatency".to_string(), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let out = kernels(&d, "6.8.0-100-lowlatency", &dpkg(&refs));
        assert_eq!(proposed(&out), [g("100")]);
        let pk = purged(&out.findings[0]);
        assert_eq!(
            pk,
            [
                "linux-headers-6.8.0-100-generic",
                "linux-image-6.8.0-100-generic",
                "linux-modules-6.8.0-100-generic",
                "linux-modules-extra-6.8.0-100-generic",
            ]
        );
        assert!(!out.findings[0].paths.contains(&d.join("src/linux-headers-6.8.0-100")));
    }

    #[test]
    fn kernel_hwe_headers_and_tools_sized_and_purged() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let extra_dirs = [
            "src/linux-hwe-6.8-headers-6.8.0-100",
            "lib/linux-hwe-6.8-tools-6.8.0-100",
            "lib/linux-tools-6.8.0-100-generic",
            "src/linux-hwe-6.8-headers-6.8.0-110", // other version: untouched
        ];
        for x in extra_dirs {
            d.file(format!("{x}/payload"), 50_000);
        }
        let mut status = dpkg(&refs);
        for p in ["linux-hwe-6.8-headers-6.8.0-100", "linux-hwe-6.8-tools-6.8.0-100", "linux-tools-6.8.0-100-generic", "linux-tools-6.8.0-100", "linux-hwe-6.8-headers-6.8.0-110", "linux-tools-common"] {
            status.push_str(&format!("\nPackage: {p}\nStatus: install ok installed\n"));
        }
        let out = kernels(&d, &g("120"), &status);
        assert_eq!(proposed(&out), [g("100")]);
        let f = &out.findings[0];
        for x in &extra_dirs[..3] {
            assert!(f.paths.contains(&d.join(x)), "{x} missing from {:?}", f.paths);
        }
        assert!(!f.paths.contains(&d.join(extra_dirs[3])));
        assert_eq!(f.bytes, f.paths.iter().map(|p| scanner::du(p).0).sum::<u64>());
        let pk = purged(f);
        for p in ["linux-hwe-6.8-headers-6.8.0-100", "linux-hwe-6.8-tools-6.8.0-100", "linux-tools-6.8.0-100-generic", "linux-tools-6.8.0-100"] {
            assert!(pk.contains(&p.to_string()), "{p}");
        }
        assert!(!pk.iter().any(|p| p.contains("6.8.0-110") || p == "linux-tools-common"));
        assert!(!f.detail.contains("autoremove"), "autoremove is not equivalent");
    }

    #[test]
    fn kernel_leftover_modules_do_not_count_as_newest() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        // A newer, package-less leftover must not push 6.8.0-110 out of the kept set.
        let d = kernel_tree(&refs, &[&g("200"), &g("050")]);
        let out = kernels(&d, &g("120"), &dpkg(&refs));
        assert_eq!(proposed(&out), [g("100")]);
        // Only the older leftover: one newer than every installed image may be
        // a kernel that is being (or was hand-) installed.
        let left = out.findings.iter().find(|f| f.id == "kernel-leftovers").unwrap();
        assert_eq!(left.paths, [d.join(format!("modules/{}", g("050")))]);
    }

    #[test]
    fn kernel_being_installed_is_never_a_leftover() {
        // An unattended upgrade has unpacked 6.8.0-130's modules but not yet
        // its image: /lib/modules/6.8.0-130 exists with no /boot files.
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[&g("115"), &g("090")]);
        let mut status = dpkg(&refs);
        status.push_str(&format!("\nPackage: linux-modules-{}\nStatus: install ok unpacked\nArchitecture: amd64\n", g("115")));
        let out = kernels(&d, &g("120"), &status);
        let left = out.findings.iter().find(|f| f.id == "kernel-leftovers").unwrap();
        assert_eq!(left.paths, [d.join(format!("modules/{}", g("090")))]);
        // The command re-checks at run time before deleting.
        assert!(shell_cmd(left).contains("dpkg-query -W") && shell_cmd(left).contains("--one-file-system"));
    }

    #[test]
    fn debug_symbol_packages_are_not_kernels() {
        let pk: Vec<String> = ["linux-image-6.8.0-120-generic", "linux-image-unsigned-6.8.0-130-generic-dbgsym", "linux-image-unsigned-6.8.0-120-generic"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(installed_kernel_images(&pk), [g("120")]);
    }

    #[test]
    fn kernel_purge_is_manual_when_apt_would_remove_a_metapackage() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let greedy = |pkgs: &[String]| {
            let mut s = exact_sim(pkgs).unwrap();
            s.push_str("Remv linux-image-generic-hwe-22.04 [6.8.0.100.100~22.04.1]\n");
            s.push_str("Purg linux-generic-hwe-22.04:amd64 [6.8.0.100.100~22.04.1]\n");
            Some(s)
        };
        let out = kernels_with(&d, &g("120"), &dpkg(&refs), &greedy);
        let f = &out.findings[0];
        assert!(matches!(f.action, Action::Manual));
        assert!(f.detail.contains("linux-generic-hwe-22.04") && f.detail.contains("linux-image-generic-hwe-22.04"));
        // No simulation possible -> never an unchecked purge either.
        let out = kernels_with(&d, &g("120"), &dpkg(&refs), &|_: &[String]| None);
        assert!(matches!(out.findings[0].action, Action::Manual));
    }

    #[test]
    fn apt_simulation_parser() {
        let sim = "NOTE: This is only a simulation!\n      apt-get needs root privileges for real execution.\n\
                   Reading package lists...\nThe following packages will be REMOVED:\n  linux-image-6.8.0-100-generic*\n\
                   0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n\
                   Purg linux-image-6.8.0-100-generic [6.8.0-100.100~22.04.1]\n\
                   Remv linux-generic:amd64 [6.8.0.100.100]\n\
                   Inst something-else [1.0]\nConf something-else (1.0 Ubuntu:22.04/jammy [amd64])\n";
        assert_eq!(apt_sim_removals(sim), ["linux-image-6.8.0-100-generic", "linux-generic", "something-else (install)"]);
        assert!(apt_sim_removals("").is_empty());
    }

    #[test]
    fn kernel_leftover_module_dirs_grouped_into_one_finding() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[&g("40"), &g("45")]);
        let out = kernels(&d, &g("120"), &dpkg(&refs));
        assert_eq!(proposed(&out), [g("100")]);
        let left: Vec<&Finding> = out.findings.iter().filter(|f| f.id == "kernel-leftovers").collect();
        assert_eq!(left.len(), 1);
        let f = left[0];
        let want = [d.join(format!("modules/{}", g("40"))), d.join(format!("modules/{}", g("45")))];
        assert_eq!(f.paths, want);
        assert_eq!(f.bytes, want.iter().map(|p| scanner::du(p).0).sum::<u64>());
        // The command removes exactly those two directories.
        let (ok, _) = sh(&format!("{SHIM}{}", shell_cmd(f)), d.path());
        assert!(ok);
        assert!(!want[0].exists() && !want[1].exists());
        for v in &vers {
            assert!(d.join(format!("modules/{v}")).is_dir());
        }
    }

    #[test]
    fn kernel_nothing_without_dpkg_database() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        // Only /lib/modules visible (e.g. /boot not mounted) and dpkg unreadable.
        let d = kernel_tree(&[], &refs);
        assert!(kernels(&d, &g("120"), "").findings.is_empty());
        let d = kernel_tree(&refs, &[]);
        assert!(kernels(&d, &g("120"), "").findings.is_empty());
    }

    #[test]
    fn kernel_without_package_is_manual() {
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let out = kernels(&d, &g("120"), &dpkg(&[&g("110"), &g("120")]));
        assert_eq!(proposed(&out), [g("100")]);
        assert!(matches!(out.findings[0].action, Action::Manual));
        assert!(!out.findings[0].is_actionable());
    }

    #[test]
    fn kernel_nothing_proposed_with_one_or_two_kernels() {
        let (a, b) = (g("100"), g("138"));
        for (vers, running) in [
            (vec![a.clone()], a.clone()),
            (vec![a.clone()], "9.9.9-1-generic".to_string()),
            (vec![a.clone(), b.clone()], a.clone()),
            (vec![a.clone(), b.clone()], b.clone()),
            (vec![a.clone(), b.clone()], "5.15.0-1-generic".to_string()),
        ] {
            let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
            let d = kernel_tree(&refs, &[]);
            let out = kernels(&d, &running, &dpkg(&refs));
            assert!(out.findings.is_empty(), "{vers:?} running {running}");
        }
        // Unknown running kernel: never guess.
        let vers = [g("1"), g("2"), g("3"), g("4")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        assert!(kernels(&d, "", &dpkg(&refs)).findings.is_empty());
    }

    #[test]
    fn kernel_non_utf8_module_dir_is_ignored() {
        use std::os::unix::ffi::OsStrExt;
        let vers = [g("100"), g("110"), g("120")];
        let refs: Vec<&str> = vers.iter().map(|s| s.as_str()).collect();
        let d = kernel_tree(&refs, &[]);
        let bad = d.join(std::ffi::OsStr::from_bytes(b"6.8.0-5-gen\xe9ric"));
        d.file(bad.join("x.ko"), 10);
        let out = kernels(&d, &g("120"), &dpkg(&refs));
        assert!(!out.findings.iter().any(|f| f.id == "kernel-leftovers"));
        assert!(out.findings.iter().flat_map(|f| &f.paths).all(|p| p.to_str().is_some()));
    }

    #[test]
    fn dpkg_status_only_counts_installed_packages() {
        let status = "Package: a\nStatus: install ok installed\n\n\
                      Package: b\nStatus: deinstall ok config-files\n\n\
                      Package: c\nStatus: purge ok not-installed\n\n\
                      Package: d\nStatus: install ok half-installed\n\n\
                      Status: install ok installed\nPackage: e\n";
        assert_eq!(installed_packages(status), ["a", "e"]);
        assert!(installed_packages("").is_empty());
        let imgs = installed_kernel_images(&[
            "linux-image-6.8.0-100-generic".into(),
            "linux-image-unsigned-6.8.0-90-generic".into(),
            "linux-image-generic-hwe-22.04".into(),
            "linux-image-generic".into(),
            "linux-modules-6.8.0-80-generic".into(),
        ]);
        assert_eq!(imgs, ["6.8.0-100-generic", "6.8.0-90-generic"]);
    }

    // ================================================================ snaps

    const SNAP_LIST: &str = "\
Name            Version          Rev    Tracking         Publisher            Notes
blender         4.2.1            7740   latest/stable    blenderfoundation**  classic
code            1.92             165    latest/stable    vscode✓              disabled,classic
code            1.93             166    latest/stable    vscode✓              classic
core22          20240111         1122   latest/stable    canonical✓           base,disabled
core22          20240408         1380   latest/stable    canonical✓           base
firefox         128.0-2          4539   latest/stable/…  mozilla✓             disabled
firefox         129.0-1          4630   latest/stable/…  mozilla✓             -
local-app       0.1              x1     -                -                    disabled
broken row with too many columns here  1  disabled
";

    #[test]
    fn snap_list_parser_reads_disabled_rows_only() {
        let got = disabled_snap_revisions(SNAP_LIST);
        let want: Vec<(String, String)> = [("code", "165"), ("core22", "1122"), ("firefox", "4539"), ("local-app", "x1")]
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        assert_eq!(got, want);
        assert!(disabled_snap_revisions("").is_empty());
        assert!(disabled_snap_revisions("error: cannot communicate with server\n").is_empty());
    }

    fn snap_fixture() -> TempDir {
        let d = TempDir::new("snaps");
        for f in ["blender_7740", "blender_7803", "code_165", "code_166", "core22_1122", "core22_1380", "firefox_4539", "firefox_4630"] {
            d.file(format!("snaps/{f}.snap"), 4096);
        }
        for (n, cur) in [("blender", "7740"), ("code", "166"), ("core22", "1380"), ("firefox", "4630")] {
            d.dir(format!("snap/{n}"));
            symlink(cur, d.join(format!("snap/{n}/current"))).unwrap();
        }
        d
    }

    #[test]
    fn snap_proposes_only_listed_disabled_revisions() {
        let d = snap_fixture();
        let out = snap_findings(&d.join("snaps"), &d.join("snap"), SNAP_LIST);
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        let mut files: Vec<String> =
            f.paths.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
        files.sort();
        // blender_7803 is a pending (pre-downloaded) revision: not installed, not disabled.
        assert_eq!(files, ["code_165.snap", "core22_1122.snap", "firefox_4539.snap"]);
        assert_eq!(f.bytes, f.paths.iter().map(|p| alloc(p)).sum::<u64>());
        assert!(f.detail.contains("/var/lib/snapd/cache"));
        let cmd = shell_cmd(f);
        assert!(!cmd.contains("&&"), "removals must be independent: {cmd}");
        let (ok, out) = sh(&format!("{ARGV_SHIM}{cmd}"), d.path());
        assert!(ok);
        let calls = argv_calls(&out);
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            calls,
            [
                s(&["snap", "remove", "code", "--revision=165"]),
                s(&["snap", "remove", "core22", "--revision=1122"]),
                s(&["snap", "remove", "firefox", "--revision=4539"]),
                s(&["snap", "remove", "local-app", "--revision=x1"]),
            ]
        );
    }

    #[test]
    fn snap_one_failing_removal_does_not_skip_the_rest() {
        let d = snap_fixture();
        let out = snap_findings(&d.join("snaps"), &d.join("snap"), SNAP_LIST);
        // First removal fails; the others must still run.
        let shim = "n=0; sudo() { n=$((n+1)); echo \"$4\"; [ $n -ne 1 ]; }\n";
        let (_, stdout) = sh(&format!("{shim}{}", shell_cmd(&out.findings[0])), d.path());
        assert_eq!(stdout.lines().count(), 4, "{stdout}");
    }

    #[test]
    fn snap_current_revision_never_proposed_even_if_listed_disabled() {
        let d = snap_fixture();
        let list = "Name Version Rev Tracking Publisher Notes\ncode 1.93 166 latest/stable vscode disabled\n";
        assert!(snap_findings(&d.join("snaps"), &d.join("snap"), list).findings.is_empty());
    }

    #[test]
    fn snap_revision_newer_than_active_is_only_a_manual_step() {
        // blender was reverted to 7740; the disabled 7803 holds the newest data.
        let d = snap_fixture();
        let list = "Name Version Rev Tracking Publisher Notes\n\
                    blender 4.2 7803 latest/stable blenderfdn disabled\n\
                    code 1.92 165 latest/stable vscode disabled\n";
        let out = snap_findings(&d.join("snaps"), &d.join("snap"), list);
        let normal = out.findings.iter().find(|f| f.id == "snap-revisions").unwrap();
        assert_eq!(shell_cmd(normal), "sudo snap remove code --revision=165");
        let rev = out.findings.iter().find(|f| f.id == "snap-reverted").unwrap();
        assert!(!rev.is_actionable() && rev.risk == Risk::Caution && rev.detail.contains("blender revision 7803"));
    }

    #[test]
    fn snap_without_list_output_proposes_nothing() {
        let d = snap_fixture();
        assert!(snap_findings(&d.join("snaps"), &d.join("snap"), "").findings.is_empty());
    }

    #[test]
    fn snap_hostile_names_are_rejected() {
        let d = TempDir::new("snaps-hostile");
        let list = "Name Version Rev Tracking Publisher Notes\n\
                    $(touch${IFS}PWNED1) 1 1 - - disabled\n\
                    ok 1 `touch${IFS}PWNED2` - - disabled\n\
                    good;touch${IFS}PWNED3 1 1 - - disabled\n";
        assert!(disabled_snap_revisions(list).is_empty());
        assert!(snap_findings(&d.join("snaps"), &d.join("snap"), list).findings.is_empty());
        // Names that pass are shell-safe and still quoted through shq.
        assert_eq!(shq("gnome-42-2204"), "gnome-42-2204");
        assert!(!pwned(d.path()));
    }

    // ================================================================ journal

    #[test]
    fn leftover_kernels_purge_their_rc_dpkg_records_first() {
        let status = "Package: linux-modules-6.8.0-52-generic\nStatus: deinstall ok config-files\n\n\
                      Package: linux-image-6.8.0-52-generic\nStatus: deinstall ok config-files\n\n\
                      Package: linux-modules-6.8.0-520-generic\nStatus: deinstall ok config-files\n\n\
                      Package: linux-modules-6.8.0-138-generic\nStatus: install ok installed\n\n\
                      Package: libfoo-6.8.0-52-generic\nStatus: deinstall ok config-files\n";
        let dirs = [PathBuf::from("/lib/modules/6.8.0-52-generic")];
        // Exact version suffix only; installed and non-kernel packages excluded.
        assert_eq!(
            rc_kernel_packages(status, &dirs),
            vec!["linux-image-6.8.0-52-generic".to_string(), "linux-modules-6.8.0-52-generic".to_string()]
        );
        assert!(rc_kernel_packages(status, &[]).is_empty());
    }

    #[test]
    fn snap_reports_immediate_space_and_revision_data() {
        let d = TempDir::new("snap-imm");
        for (n, r) in [("firefox", "4630"), ("code", "166"), ("core22", "1380")] {
            fs::create_dir_all(d.join("snap").join(n)).unwrap();
            std::os::unix::fs::symlink(r, d.join("snap").join(n).join("current")).unwrap();
        }
        let lone = d.file("snaps/firefox_4539.snap", 3 << 20);
        let cached = d.file("snaps/code_165.snap", 2 << 20);
        fs::hard_link(&cached, d.join("cache-copy")).unwrap();
        d.file("snaps/core22_1122.snap", 1 << 20);
        d.file("vardata/firefox/4539/prefs.db", 2 << 20);
        let out = snap_findings_ext(&d.join("snaps"), &d.join("snap"), SNAP_LIST, &[d.join("vardata")]);
        let f = &out.findings[0];
        let data = scanner::du(&d.join("vardata/firefox/4539")).0;
        assert_eq!(f.bytes, alloc(&lone) + alloc(&cached) + alloc(&d.join("snaps/core22_1122.snap")) + data);
        // The detail names the per-revision data that removal deletes, and
        // separates what comes back now from what snapd's cache still holds.
        assert!(f.detail.contains("vardata/firefox/4539"), "{}", f.detail);
        assert!(f.detail.contains(&fmt_size(alloc(&cached))), "{}", f.detail);
    }

    #[test]
    fn journal_vacuum_removes_whole_archived_files_oldest_first() {
        let d = TempDir::new("journal");
        let old = d.file("journal/abc/system@0001-old.journal", 3 << 20);
        let newer = d.file("journal/abc/system@0002-new.journal", 2 << 20);
        let active = d.file("journal/abc/system.journal", 1 << 20);
        let t = |p: &Path, secs: u64| {
            let f = fs::File::options().write(true).open(p).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)).unwrap();
        };
        t(&old, 1_000);
        t(&newer, 2_000);
        t(&active, 3_000);
        let dir = d.join("journal");
        let (o, n) = (alloc(&old), alloc(&newer));
        // keep 4 MiB of 6: only the oldest archived file has to go (whole file).
        let f = &journal_findings(&dir, 4 << 20).findings[0];
        assert_eq!(f.bytes, o);
        assert_eq!(shell_cmd(f), format!("sudo journalctl --directory={} --vacuum-size=4M", dir.display()));
        // keep 1 MiB: both archived files go, the active one never does.
        assert_eq!(journal_findings(&dir, 1 << 20).findings[0].bytes, o + n);
        // Already under the keep size: nothing.
        assert!(journal_findings(&dir, 64 << 20).findings.is_empty());
        assert!(journal_findings(&d.join("nope"), 0).findings.is_empty());
    }

    #[test]
    fn journal_falls_back_to_size_minus_keep_without_readable_files() {
        let d = TempDir::new("journal-fallback");
        d.file("journal/abc/unknown.bin", 3 << 20);
        let dir = d.join("journal");
        let size = scanner::du(&dir).0;
        assert_eq!(journal_findings(&dir, 1 << 20).findings[0].bytes, size - (1 << 20));
    }


    // ================================================================ rotated logs

    const LOG_NAMES: &[(&str, bool)] = &[
        ("syslog.1", true),
        ("kern.log.2.gz", true),
        ("dmesg.0", true),
        ("foo.log", false),
        ("x.10", true),
        ("app.1.log", false),
        ("weird..1", true),
        (".hidden.1", true),
        ("file.gz", true),
        ("file.xz", true),
        ("file.bz2", false),
        ("2024-01-01.log", false),
        ("syslog", false),
        ("auth.log", false),
        ("1", false),
        ("trailing.", false),
        (".1", true),
        ("x.1a", false),
        ("x.GZ", false),
        ("apt.log.12.xz", true),
        ("sysstat.07", true),
        ("dpkg.log.1 ", false),
        ("space name.3", true),
        ("uni-ünï.4", true),
        ("mysql-bin.000002", false), // live MySQL binlog
        ("10.0.0.5", false),         // rsyslog per-host file
        ("syslog.1234", false),
        ("vncserver-x11.log.20260914085904", true),
        ("xrdp.log.20260914", true),
        ("app.log.99999999", false),
        ("mysql-bin.20260914", false), // not a .log stem
    ];

    #[test]
    fn rotated_log_predicate_table() {
        for (name, want) in LOG_NAMES {
            assert_eq!(is_rotated_log(name), *want, "{name:?}");
        }
    }

    #[test]
    fn rotated_log_command_deletes_exactly_the_counted_files() {
        use std::os::unix::ffi::OsStrExt;
        let d = TempDir::new("rotlogs");
        let root = d.dir("log");
        let mut all = Vec::new();
        for sub in ["", "apt/", "cups/deep/", "journal/", "journal/abc/", "installer/", "installer/x/"] {
            for (name, _) in LOG_NAMES {
                all.push(d.file(format!("log/{sub}{name}"), 100));
            }
        }
        for n in HOSTILE {
            all.push(d.file(format!("log/{n}.1"), 100));
        }
        let eipp = d.file("log/apt/eipp.log.xz", 100);
        let non_utf8 = d.join(std::ffi::OsStr::from_bytes(b"log/caf\xe9.log.1"));
        std::fs::write(&non_utf8, b"x").unwrap();
        d.dir("log/dir.1"); // directories never match
        let outside = d.file("outside.1", 100);
        symlink(&outside, root.join("link.1")).unwrap();
        symlink(&outside, root.join("link.gz")).unwrap();

        let counted: HashSet<PathBuf> = rotated_log_files(&root).into_iter().map(|f| f.0).collect();
        for p in &counted {
            assert!(is_rotated_log(&p.file_name().unwrap().to_string_lossy()));
            for skip in ["journal", "installer"] {
                assert!(!p.starts_with(root.join(skip)), "{p:?}");
            }
        }
        let per_dir = LOG_NAMES.iter().filter(|n| n.1).count();
        assert_eq!(counted.len(), 3 * per_dir + HOSTILE.len());
        assert!(!counted.contains(&eipp) && !counted.contains(&non_utf8));

        let out = rotated_log_findings(&root);
        let f = &out.findings[0];
        assert_eq!(f.paths.iter().cloned().collect::<HashSet<_>>(), counted);
        assert_eq!(f.bytes, counted.iter().map(|p| alloc(p)).sum::<u64>());
        assert!(shell_cmd(f).starts_with("sudo find "));
        let (ok, _) = sh(&format!("{SHIM}{}", shell_cmd(f)), &root);
        assert!(ok, "{}", shell_cmd(f));
        let deleted: HashSet<PathBuf> = all.iter().filter(|p| !p.exists()).cloned().collect();
        assert_eq!(deleted, counted);
        assert!(eipp.exists() && non_utf8.exists() && outside.exists() && root.join("dir.1").is_dir());
        assert!(fs::symlink_metadata(root.join("link.1")).is_ok(), "symlinks are not rotated logs");
        assert!(!pwned(&root) && !pwned(d.path()));
    }

    // ================================================================ crash, apt

    #[test]
    fn crash_command_removes_exactly_listed_reports() {
        let d = TempDir::new("crash");
        let dir = d.dir("crash");
        let mut targets = vec![d.file("crash/_usr_bin_foo.1000.crash", 5000)];
        targets.extend(HOSTILE.iter().map(|n| d.file(format!("crash/{n}.crash"), 10)));
        let lock = d.file("crash/.lock", 1);
        d.file("crash/sub/inner.crash", 10); // not a regular file directly inside
        let out = crash_findings(&dir);
        let f = &out.findings[0];
        assert_eq!(f.risk, Risk::Safe);
        assert_eq!(f.paths.len(), targets.len());
        let (ok, _) = sh(&format!("{SHIM}{}", shell_cmd(f)), &dir);
        assert!(ok);
        assert!(targets.iter().all(|p| !p.exists()));
        assert!(lock.exists() && d.join("crash/sub/inner.crash").exists());
        assert!(!pwned(&dir) && !pwned(d.path()));
        assert!(crash_findings(&d.join("empty-nope")).findings.is_empty());
        // Only apport's files, and never through a symlinked directory.
        let docs = d.dir("docs");
        d.file("docs/thesis.pdf", 5000);
        d.file("docs/notes.txt", 5000);
        assert!(crash_findings(&docs).findings.is_empty());
        d.file("real/x.crash", 5000);
        symlink(d.join("real"), d.join("linked")).unwrap();
        assert!(crash_findings(&d.join("linked")).findings.is_empty());
    }

    #[test]
    fn apt_counts_debs_and_partial_not_rebuilt_package_lists() {
        let d = TempDir::new("apt");
        let files = [
            d.file("apt/archives/a_1.0_amd64.deb", 2 << 20),
            d.file("apt/archives/partial/b_2.0_amd64.deb.part", 1 << 20),
            d.file("apt/pkgcache.bin", 1 << 20),
            d.file("apt/srcpkgcache.bin", 1 << 20),
        ];
        d.file("apt/archives/lock", 0);
        d.file("apt/other.txt", 1 << 20);
        let out = apt_findings(&d.join("apt"));
        let f = &out.findings[0];
        // pkgcache.bin/srcpkgcache.bin come straight back on the next apt run:
        // only the .deb archives and partial downloads are lasting savings.
        assert_eq!(f.bytes, files[..2].iter().map(|p| alloc(p)).sum::<u64>());
        assert_eq!(shell_cmd(f), "sudo apt-get clean");
        assert!(f.title.contains("1 .deb"));
        // paths are exactly the counted files, and the text mentions both kinds.
        let mut paths = f.paths.clone();
        paths.sort();
        let mut want = files.to_vec();
        want.sort();
        assert_eq!(paths, want);
        assert!(f.detail.contains(".deb") && f.detail.contains("pkgcache.bin"));
        // Only package-list caches: nothing lasting to reclaim, so no finding.
        let d2 = TempDir::new("apt-bins");
        d2.file("apt/pkgcache.bin", 2 << 20);
        assert!(apt_findings(&d2.join("apt")).findings.is_empty());
        assert!(apt_findings(&d.join("none")).findings.is_empty());
    }

    // ================================================================ artifacts

    fn ctx_for(home: &Path, roots: &[PathBuf]) -> RuleContext {
        RuleContext { home: home.to_path_buf(), dev_roots: roots.to_vec(), journal_keep: 0, is_root: false }
    }

    fn artifact_home() -> TempDir {
        let d = TempDir::new("artifacts");
        let big = 2 << 20;
        d.file("proj/Cargo.toml", 10);
        d.file("proj/target/debug/app", big);
        d.file("proj/src/target/x", big); // target without manifest: not an artifact
        d.file("notrust/target/big", big);
        d.file("tagged/target/CACHEDIR.TAG", 43);
        d.file("tagged/target/release/app", big);
        d.file("web/package.json", 10);
        d.file("web/package-lock.json", 10);
        d.file("web/node_modules/dep/index.js", big);
        // No lockfile: an installed app's bundled code, not restorable.
        d.file("apps/VSCode/resources/app/package.json", 10);
        d.file("apps/VSCode/resources/app/package-lock.json", 10);
        d.file("apps/VSCode/resources/app/node_modules/x/index.js", big);
        d.file("nolock/package.json", 10);
        d.file("nolock/node_modules/y/index.js", big);
        d.file("web/node_modules/dep/Cargo.toml", 10);
        d.file("web/node_modules/dep/target/x", big); // inside node_modules: not separate
        d.file("web/node_modules/dep/__pycache__/x.pyc", 10);
        d.file("nopkg/node_modules/big", big);
        d.file("py/a/__pycache__/m.pyc", 700_000);
        d.file("py/b/c/__pycache__/n.pyc", 700_000);
        d.file(".hidden/proj/Cargo.toml", 10);
        d.file(".hidden/proj/target/x", big);
        d.file(".nvm/lib/node_modules/x", big);
        d.file("snap/app/proj/Cargo.toml", 10);
        d.file("snap/app/proj/target/x", big);
        d.file("proj/target/__pycache__/x.pyc", 10); // inside target: not separate
        d
    }

    fn ids(out: &CheckOutput) -> Vec<String> {
        let mut v: Vec<String> = out.findings.iter().map(|f| f.id.clone()).collect();
        v.sort();
        v
    }

    #[test]
    fn artifacts_detected_only_with_project_markers() {
        let d = artifact_home();
        let home = d.path();
        let o = ScanOptions::default();
        let out = run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), None, &o);
        let want = [
            format!("node:{}", home.join("web/node_modules").display()),
            "pycache".to_string(),
            format!("rust:{}", home.join("proj/target").display()),
            format!("rust:{}", home.join("tagged/target").display()),
        ];
        assert_eq!(ids(&out), want);
        for f in &out.findings {
            let Action::Remove { paths, keep_dir } = &f.action else { panic!() };
            assert!(!keep_dir && !f.needs_root);
            assert_eq!(paths, &f.paths);
            if f.id == "pycache" {
                assert_eq!(f.risk, Risk::Safe);
                let mut p = paths.clone();
                p.sort();
                assert_eq!(p, [home.join("py/a/__pycache__"), home.join("py/b/c/__pycache__")]);
                assert_eq!(f.bytes, p.iter().map(|x| scanner::du(x).0).sum::<u64>());
            } else {
                assert_eq!(f.risk, Risk::Caution);
                assert_eq!(f.bytes, scanner::du(&paths[0]).0, "{}", f.id);
            }
        }
        // Same answer when reusing the main scan tree.
        let tree = scanner::scan(home, &o, &Progress::default()).unwrap();
        let out2 = run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), Some(&tree), &o);
        assert_eq!(ids(&out2), want);
        let bytes = |o: &CheckOutput| o.findings.iter().map(|f| f.bytes).sum::<u64>();
        assert_eq!(bytes(&out), bytes(&out2));
    }

    #[test]
    fn artifacts_not_double_counted_with_overlapping_dev_roots() {
        let d = artifact_home();
        let home = d.path();
        let roots = [home.to_path_buf(), home.join("proj"), home.join("py"), home.join("py/a")];
        let out = run_artifact_check(&ctx_for(home, &roots), None, &ScanOptions::default());
        let single = run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), None, &ScanOptions::default());
        assert_eq!(ids(&out), ids(&single), "raw output must not repeat a path");
        let py = out.findings.iter().find(|f| f.id == "pycache").unwrap();
        assert_eq!(py.paths.len(), 2);
        let py1 = single.findings.iter().find(|f| f.id == "pycache").unwrap();
        assert_eq!(py.bytes, py1.bytes);
        let all: Vec<&PathBuf> = out.findings.iter().flat_map(|f| &f.paths).collect();
        for p in &all {
            assert!(!all.iter().any(|q| q != p && p.starts_with(q)), "{p:?} nested in another finding");
        }
    }

    #[test]
    fn artifact_cap_and_one_mib_threshold() {
        let d = TempDir::new("artifact-cap");
        for i in 0..63 {
            d.file(format!("p{i:02}/Cargo.toml"), 1);
            d.file(format!("p{i:02}/target/x"), if i < 3 { 2 << 20 } else { 100 });
        }
        let home = d.path();
        let out = run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), None, &ScanOptions::default());
        assert_eq!(out.findings.len(), 60);
        assert_eq!(out.notes, ["3 smaller project artifact directories were not listed."]);
        // Largest kept first.
        for i in 0..3 {
            assert!(out.findings.iter().any(|f| f.paths[0] == home.join(format!("p{i:02}/target"))));
        }
        let mut r = Report::default();
        r.merge(out);
        assert_eq!(r.findings.len(), 3, "only the ≥ 1 MiB targets survive merge");
        assert!(r.findings.iter().all(|f| f.bytes >= 1 << 20));
    }

    // ================================================================ user caches

    #[test]
    fn user_caches_target_only_their_own_dirs() {
        let d = TempDir::new("usercache");
        let h = d.path();
        let mb = 1 << 20;
        for p in [
            ".cache/thumbnails/large/a.png",
            ".cache/pip/http/b",
            ".cargo/registry/cache/idx/c.crate",
            ".cargo/registry/src/idx/c/lib.rs",
            ".cargo/git/checkouts/repo/d",
            ".npm/_cacache/content/e",
            ".local/share/Trash/files/f",
            ".local/share/Trash/info/f.trashinfo",
            // Neighbours that must never be touched:
            ".cache/other/keep",
            ".cargo/registry/index/keep",
            ".cargo/bin/cargo",
            ".npm/_logs/keep",
            ".local/share/Trash/expunged/keep",
        ] {
            d.file(p, mb);
        }
        let out = check_user_caches(&ctx_for(h, &[]));
        let expect: Vec<(&str, Risk, Vec<&str>)> = vec![
            ("thumbnails", Risk::Safe, vec![".cache/thumbnails"]),
            ("pip-cache", Risk::Safe, vec![".cache/pip/http"]),
            ("cargo-registry", Risk::Moderate, vec![".cargo/registry/cache", ".cargo/registry/src"]),
            ("cargo-git", Risk::Safe, vec![".cargo/git/checkouts"]),
            ("npm-cache", Risk::Safe, vec![".npm/_cacache"]),
            ("trash", Risk::Moderate, vec![".local/share/Trash/files", ".local/share/Trash/info"]),
        ];
        assert_eq!(out.findings.len(), expect.len());
        for (id, risk, dirs) in expect {
            let f = out.findings.iter().find(|f| f.id == id).unwrap();
            let dirs: Vec<PathBuf> = dirs.iter().map(|x| h.join(x)).collect();
            assert_eq!(f.risk, risk, "{id}");
            assert_eq!(f.paths, dirs, "{id}");
            let Action::Remove { paths, keep_dir } = &f.action else { panic!("{id}") };
            assert!(*keep_dir, "{id}");
            assert_eq!(paths, &dirs);
            // The dirs are kept, so only their contents are reclaimable.
            let contents: u64 = dirs.iter().map(|x| scanner::du(x).0 - crate::util::testutil::alloc(x)).sum();
            assert_eq!(f.bytes, contents, "{id}");
            for p in paths {
                crate::cleanup::remove_path(p, *keep_dir, h).unwrap();
                assert!(p.is_dir() && fs::read_dir(p).unwrap().next().is_none(), "{p:?}");
            }
        }
        for keep in [".cache/other/keep", ".cargo/registry/index/keep", ".cargo/bin/cargo", ".npm/_logs/keep", ".local/share/Trash/expunged/keep"] {
            assert!(h.join(keep).exists(), "{keep}");
        }
        // Nothing left to reclaim -> no findings (except empty-dir blocks).
        let again = check_user_caches(&ctx_for(h, &[]));
        let mut r = Report::default();
        r.merge(again);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn user_caches_absent_dirs_produce_nothing() {
        let d = TempDir::new("usercache-empty");
        assert!(check_user_caches(&ctx_for(d.path(), &[])).findings.is_empty());
    }


    // ================================================================ docker

    #[test]
    fn docker_counts_only_what_prune_removes() {
        let df: serde_json::Value = serde_json::from_str(
            r#"{
              "Images": [
                {"RepoTags": ["<none>:<none>"], "Containers": 0, "Size": 500, "SharedSize": 200},
                {"RepoTags": [], "Containers": 0, "Size": 100, "SharedSize": -1},
                {"RepoTags": null, "Containers": 0, "Size": 50, "SharedSize": 0},
                {"RepoTags": ["<none>:<none>"], "Containers": 2, "Size": 9000, "SharedSize": 0},
                {"RepoTags": ["app:latest"], "Containers": 0, "Size": 7000, "SharedSize": 0}
              ],
              "BuildCache": [
                {"InUse": false, "Shared": false, "Size": 1000},
                {"InUse": false, "Shared": true,  "Size": 20000},
                {"InUse": true,  "Shared": false, "Size": 30000},
                {"InUse": true,  "Shared": true,  "Size": 40000},
                {"Size": 50000},
                {"InUse": false, "Shared": false, "Size": 3}
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(docker_reclaimable(&df), (300 + 100 + 50, 3, 1003));
        assert_eq!(docker_reclaimable(&serde_json::json!({})), (0, 0, 0));
    }

    // ================================================================ non-UTF-8

    #[test]
    fn non_utf8_project_targets_real_dir_not_lossy_decoy() {
        use std::os::unix::ffi::OsStrExt;
        let d = TempDir::new("nonutf8");
        let real = d.join(std::ffi::OsStr::from_bytes(b"caf\xe9"));
        d.file(real.join("Cargo.toml"), 10);
        d.file(real.join("target/debug/big"), 2 << 20);
        let decoy = d.join("caf\u{FFFD}");
        let decoy_file = d.file(decoy.join("target/precious"), 2 << 20);
        let home = d.path();
        for tree in [None, Some(scanner::scan(home, &ScanOptions::default(), &Progress::default()).unwrap())] {
            let out = run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), tree.as_ref(), &ScanOptions::default());
            assert_eq!(out.findings.len(), 1, "{:?}", out.findings);
            let f = &out.findings[0];
            assert_eq!(f.paths, [real.join("target")]);
            // No lossy path in any shell text.
            assert!(!f.command_text().contains('\u{FFFD}'), "{}", f.command_text());
            assert!(!f.detail.contains('\u{FFFD}'));
            assert!(f.is_actionable(), "user-owned removal runs in-process");
        }
        let f = &run_artifact_check(&ctx_for(home, &[home.to_path_buf()]), None, &ScanOptions::default()).findings[0];
        let Action::Remove { paths, keep_dir } = &f.action else { panic!() };
        for p in paths {
            crate::cleanup::remove_path(p, *keep_dir, home).unwrap();
        }
        assert!(!real.join("target").exists(), "real target removed");
        assert!(decoy_file.exists(), "decoy survives");
        // A root removal with such a path is never handed to a shell.
        let root_f = Finding { needs_root: true, ..f.clone() };
        assert!(!root_f.is_actionable());
    }

}
