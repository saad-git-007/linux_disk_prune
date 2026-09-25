//! System locations, discovered at runtime from the tools that own them
//! instead of being assumed. Each falls back to the stock Ubuntu path when the
//! tool is missing or says nothing, so the app works on any Ubuntu 22.04+.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct SysDirs {
    /// apt's cache dir (Dir::Cache), e.g. /var/cache/apt.
    pub apt_cache: PathBuf,
    /// Where downloaded .debs go (Dir::Cache::archives).
    pub apt_archives: PathBuf,
    /// dpkg's status database (Dir::State::status).
    pub dpkg_status: PathBuf,
    /// Where snaps are mounted (SNAPD_MOUNT), /snap on Ubuntu.
    pub snap_mount: PathBuf,
    /// snapd's state dir; holds snaps/ and cache/.
    pub snapd_state: PathBuf,
    /// Journal storage: persistent and/or volatile.
    pub journals: Vec<PathBuf>,
    /// apport's crash report dir.
    pub crash: PathBuf,
    /// System-wide Flatpak installations.
    pub flatpak_system: Vec<PathBuf>,
    pub boot: PathBuf,
    pub modules: PathBuf,
    pub usr_src: PathBuf,
    pub usr_lib: PathBuf,
    pub log: PathBuf,
    pub coredump: PathBuf,
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let o = Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Resolve apt's directory tree from `apt-config dump` output. apt joins
/// relative values onto their parent (Dir → Dir::Cache → Dir::Cache::archives).
pub fn parse_apt_config(dump: &str) -> (PathBuf, PathBuf, PathBuf) {
    let get = |key: &str| -> Option<String> {
        dump.lines().find_map(|l| {
            let rest = l.strip_prefix(key)?.strip_prefix(' ')?;
            Some(rest.trim().trim_end_matches(';').trim_matches('"').to_string())
        })
    };
    let join = |parent: &Path, v: Option<String>, default: &str| -> PathBuf {
        let v = v.filter(|s| !s.is_empty()).unwrap_or_else(|| default.to_string());
        if v.starts_with('/') { PathBuf::from(v) } else { parent.join(v) }
    };
    let root = join(Path::new("/"), get("Dir"), "/");
    let cache = join(&root, get("Dir::Cache"), "var/cache/apt/");
    let archives = join(&cache, get("Dir::Cache::archives"), "archives/");
    let state = join(&root, get("Dir::State"), "var/lib/apt/");
    let status = join(&state, get("Dir::State::status"), "/var/lib/dpkg/status");
    (cache, archives, status)
}

/// `snap debug paths` prints lines like SNAPD_MOUNT=/snap.
pub fn parse_snap_paths(out: &str) -> Option<PathBuf> {
    out.lines()
        .find_map(|l| l.strip_prefix("SNAPD_MOUNT="))
        .map(|v| PathBuf::from(v.trim()))
        .filter(|p| p.is_absolute())
}

/// `flatpak --installations` prints one path per line.
pub fn parse_flatpak_installations(out: &str) -> Vec<PathBuf> {
    out.lines().map(str::trim).filter(|l| l.starts_with('/')).map(PathBuf::from).collect()
}

impl SysDirs {
    fn discover() -> Self {
        let (apt_cache, apt_archives, dpkg_status) = parse_apt_config(&run("apt-config", &["dump"]).unwrap_or_default());
        let snap_mount = run("snap", &["debug", "paths"]).and_then(|o| parse_snap_paths(&o)).unwrap_or_else(|| "/snap".into());
        // journald stores logs persistently if /var/log/journal exists,
        // otherwise in the volatile /run/log/journal.
        let journals = ["/var/log/journal", "/run/log/journal"].iter().map(PathBuf::from).filter(|p| p.is_dir()).collect();
        let crash = std::env::var_os("APPORT_REPORT_DIR").map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| "/var/crash".into());
        let mut flatpak_system = run("flatpak", &["--installations"]).map(|o| parse_flatpak_installations(&o)).unwrap_or_default();
        if flatpak_system.is_empty() && Path::new("/var/lib/flatpak").is_dir() {
            flatpak_system.push("/var/lib/flatpak".into());
        }
        // On merged-/usr systems /lib is a symlink to /usr/lib: use the real path.
        let canon = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        SysDirs {
            apt_cache,
            apt_archives,
            dpkg_status,
            snap_mount,
            snapd_state: "/var/lib/snapd".into(),
            journals,
            crash,
            flatpak_system,
            boot: "/boot".into(),
            modules: canon("/lib/modules"),
            usr_src: "/usr/src".into(),
            usr_lib: "/usr/lib".into(),
            log: "/var/log".into(),
            coredump: "/var/lib/systemd/coredump".into(),
        }
    }
}

/// Discovered once per process.
pub fn get() -> &'static SysDirs {
    static DIRS: OnceLock<SysDirs> = OnceLock::new();
    DIRS.get_or_init(SysDirs::discover)
}

/// First existing regular file among the fonts fontconfig resolves for
/// `families`, then the given fallbacks.
pub fn find_font(families: &[&str], fallbacks: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = families
        .iter()
        .filter_map(|f| run("fc-match", &["-f", "%{file}", f]))
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| p.is_file())
        .collect();
    out.extend(fallbacks.iter().map(PathBuf::from).filter(|p| p.is_file()));
    out.dedup();
    out
}

/// A program on PATH.
pub fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_defaults_and_overrides() {
        let stock = "Dir \"/\";\nDir::Cache \"var/cache/apt\";\nDir::Cache::archives \"archives/\";\nDir::State \"var/lib/apt\";\nDir::State::status \"/var/lib/dpkg/status\";\n";
        assert_eq!(
            parse_apt_config(stock),
            ("/var/cache/apt".into(), "/var/cache/apt/archives/".into(), "/var/lib/dpkg/status".into())
        );
        // Relocated cache and absolute archives.
        let moved = "Dir \"/\";\nDir::Cache \"/srv/aptcache/\";\nDir::Cache::archives \"/mnt/debs\";\n";
        let (c, a, s) = parse_apt_config(moved);
        assert_eq!((c, a, s), ("/srv/aptcache/".into(), "/mnt/debs".into(), "/var/lib/dpkg/status".into()));
        // Chroot-style Dir prefix.
        let chroot = "Dir \"/target/\";\nDir::Cache \"var/cache/apt/\";\n";
        assert_eq!(parse_apt_config(chroot).1, PathBuf::from("/target/var/cache/apt/archives/"));
        // Nothing known: stock layout.
        assert_eq!(parse_apt_config("").0, PathBuf::from("/var/cache/apt/"));
    }

    #[test]
    fn snap_and_flatpak_parsers() {
        let snap = "SNAPD_MOUNT=/snap\nSNAPD_BIN=/snap/bin\nSNAPD_LIBEXEC=/usr/lib/snapd\n";
        assert_eq!(parse_snap_paths(snap), Some("/snap".into()));
        assert_eq!(parse_snap_paths("SNAPD_MOUNT=/var/lib/snapd/snap\n"), Some("/var/lib/snapd/snap".into()));
        assert_eq!(parse_snap_paths("garbage"), None);
        assert_eq!(
            parse_flatpak_installations("/var/lib/flatpak\n/opt/flatpak\n\nwarning: x\n"),
            vec![PathBuf::from("/var/lib/flatpak"), PathBuf::from("/opt/flatpak")]
        );
    }
}
