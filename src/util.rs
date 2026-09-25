//! Small shared helpers: size formatting/parsing, shell quoting, user detection.

use bytesize::ByteSize;
use std::path::{Path, PathBuf};

/// Human readable size using binary (IEC) units, e.g. `4.8 GiB`.
pub fn fmt_size(bytes: u64) -> String {
    ByteSize::b(bytes).display().iec().to_string()
}

/// Parse sizes such as `500M`, `1.5G`, `200MiB`, `4096` (binary multiples).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("invalid size: {s}"))?;
    let unit = unit.trim().to_ascii_uppercase();
    let mult: u64 = match unit.trim_end_matches("IB").trim_end_matches('B') {
        "" => 1,
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return Err(format!("unknown size unit in {s:?} (use K, M, G or T)")),
    };
    let bytes = n * mult as f64;
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return Err(format!("size too large: {s}"));
    }
    Ok(bytes as u64)
}

/// Remove ANSI colour sequences (`ESC [ … m`).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Quote a string for POSIX `sh` if needed.
pub fn shq(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+:=@%,".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

pub fn shq_path(p: &Path) -> String {
    shq(&p.to_string_lossy())
}

/// Replace the home directory prefix with `~` for display.
pub fn tilde(p: &Path, home: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".into(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

/// Effective UID, read from /proc so we need no libc binding.
pub fn euid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(u32::MAX)
}

pub fn is_root() -> bool {
    euid() == 0
}

/// Home directory of the *real* user. When launched through `sudo`, this is the
/// invoking user's home (from SUDO_USER), not /root.
pub fn real_user_home() -> PathBuf {
    if is_root() {
        if let Ok(user) = std::env::var("SUDO_USER") {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                for line in passwd.lines() {
                    let f: Vec<&str> = line.split(':').collect();
                    if f.len() >= 6 && f[0] == user {
                        return PathBuf::from(f[5]);
                    }
                }
            }
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Kernel release of the running kernel (same as `uname -r`).
pub fn running_kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Thousands separator for counts.
pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("500M").unwrap(), 500 << 20);
        assert_eq!(parse_size("1GiB").unwrap(), 1 << 30);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("5X").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(shq("/var/log"), "/var/log");
        assert_eq!(shq("a b"), "'a b'");
        assert_eq!(shq("it's"), r"'it'\''s'");
    }

    #[test]
    fn counts() {
        assert_eq!(fmt_count(1234567), "1,234,567");
        assert_eq!(fmt_count(12), "12");
    }
}

/// Fixture helpers shared by the unit tests. Everything lives in a unique
/// directory under `std::env::temp_dir()` and is removed on drop.
#[cfg(test)]
pub mod testutil {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!(
                "ldp-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            TempDir(fs::canonicalize(&p).unwrap())
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
        pub fn join(&self, rel: impl AsRef<Path>) -> PathBuf {
            self.0.join(rel)
        }
        /// Create a file (and its parents) holding `len` bytes of real data.
        pub fn file(&self, rel: impl AsRef<Path>, len: usize) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, vec![0xA5u8; len]).unwrap();
            p
        }
        pub fn dir(&self, rel: impl AsRef<Path>) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
    }

    fn make_writable(p: &Path) {
        let Ok(md) = fs::symlink_metadata(p) else { return };
        if md.is_dir() {
            let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
            if let Ok(rd) = fs::read_dir(p) {
                for e in rd.flatten() {
                    make_writable(&e.path());
                }
            }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            make_writable(&self.0);
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Blocks actually allocated to `p` (not following symlinks), in bytes.
    pub fn alloc(p: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(p).unwrap().blocks() * 512
    }

    /// Run `script` with `sh -c` in `cwd`; returns (success, stdout).
    pub fn sh(script: &str, cwd: &Path) -> (bool, String) {
        let o = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .current_dir(cwd)
            .output()
            .unwrap();
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned())
    }

    /// Names that try to break out of shell quoting.
    pub const HOSTILE: &[&str] = &[
        "a b",
        "it's",
        "q\"uote",
        "$(touch PWNED1)",
        "`touch PWNED2`",
        "new\nline",
        "-rf",
        "semi;touch PWNED3",
        "and&&touch PWNED4",
        "star*",
        "~tilde",
        "glob[1]",
        "back\\slash",
        "tab\there",
        "dollar$HOME",
        "ünïcödé 日本",
    ];

    /// True if any injected command left a marker behind.
    pub fn pwned(dir: &Path) -> bool {
        (1..=9).any(|i| dir.join(format!("PWNED{i}")).exists())
    }
}
