//! Executes cleanup actions — only ever after explicit confirmation in the UI.

use crate::rules::{Action, Finding};
use crate::util::fmt_size;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Paths that must never be removed, whatever a rule says.
const PROTECTED: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
    "/run", "/sbin", "/snap", "/srv", "/sys", "/tmp", "/usr", "/var",
];

fn check_removable(p: &Path, home: &Path) -> Result<(), String> {
    if !p.is_absolute() {
        return Err("refusing relative path".into());
    }
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("refusing path containing '..'".into());
    }
    if PROTECTED.iter().any(|x| p == Path::new(x)) || p == home {
        return Err("refusing protected path".into());
    }
    if home.starts_with(p) {
        return Err("refusing a folder that contains your home folder".into());
    }
    if p.components().count() < 3 {
        return Err("refusing top-level path".into());
    }
    Ok(())
}

/// Mount points from `/proc/self/mountinfo` text (5th field, with the kernel's
/// octal escapes such as `\040` for a space decoded).
pub(crate) fn parse_mountinfo(text: &str) -> Vec<PathBuf> {
    text.lines().filter_map(|l| l.split(' ').nth(4)).map(unescape_mount).collect()
}

fn unescape_mount(s: &str) -> PathBuf {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let oct = b.get(i + 1..i + 4).filter(|o| o.iter().all(|c| (b'0'..=b'7').contains(c)));
        match (b[i], oct) {
            (b'\\', Some(o)) => {
                out.push((o[0] - b'0') * 64 + (o[1] - b'0') * 8 + (o[2] - b'0'));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    PathBuf::from(OsString::from_vec(out))
}

/// Mount points that `p` contains (or is, when the directory itself would go).
fn mounts_inside<'a>(p: &Path, mounts: &'a [PathBuf], include_self: bool) -> Option<&'a PathBuf> {
    mounts.iter().find(|m| m.starts_with(p) && (include_self || m.as_path() != p))
}

/// First directory below `dir` (not following symlinks) that lives on another
/// device than `dev`: a mount point `/proc/self/mountinfo` did not list.
fn foreign_device(dir: &Path, dev: u64, dev_of: &dyn Fn(&fs::Metadata) -> u64) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let child = e.path();
            if let Ok(md) = fs::symlink_metadata(&child) {
                if md.is_dir() {
                    if dev_of(&md) != dev {
                        return Some(child);
                    }
                    stack.push(child);
                }
            }
        }
    }
    None
}

/// Delete everything below `dir` without following symlinks and without
/// entering a directory on another device than `dev`. Crossing stops the
/// whole removal before anything is deleted.
///
/// Sub-trees go through `std::fs::remove_dir_all`, which walks with directory
/// handles and `O_NOFOLLOW`: a directory swapped for a symlink mid-way (even
/// when this runs as root) cannot redirect the deletion elsewhere.
fn remove_contents(dir: &Path, dev: u64, dev_of: &dyn Fn(&fs::Metadata) -> u64) -> io::Result<()> {
    if let Some(m) = foreign_device(dir, dev, dev_of) {
        return Err(io::Error::new(
            io::ErrorKind::CrossesDevices,
            format!("refusing to cross into another filesystem at {}", m.display()),
        ));
    }
    let mut first_err = None;
    for entry in fs::read_dir(dir)? {
        let child = entry?.path();
        let res = match fs::symlink_metadata(&child) {
            Ok(md) if md.is_dir() => fs::remove_dir_all(&child),
            Ok(_) => fs::remove_file(&child),
            Err(e) => Err(e),
        };
        if let Err(e) = res {
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Remove directory `p` (or only its contents with `keep_dir`), refusing when
/// a mount point lies below it.
fn remove_dir_checked(
    p: &Path,
    keep_dir: bool,
    mounts: &[PathBuf],
    dev_of: &dyn Fn(&fs::Metadata) -> u64,
) -> io::Result<()> {
    if let Some(m) = mounts_inside(p, mounts, !keep_dir) {
        return Err(io::Error::other(format!(
            "refusing: {} is a mounted filesystem inside {}",
            m.display(),
            p.display()
        )));
    }
    let dev = dev_of(&fs::symlink_metadata(p)?);
    remove_contents(p, dev, dev_of)?;
    if !keep_dir {
        fs::remove_dir(p)?;
    }
    Ok(())
}

/// Delete `p` (never following symlinks: a symlink is unlinked, not its
/// target). With `keep_dir`, a directory is emptied but kept.
pub fn remove_path(p: &Path, keep_dir: bool, home: &Path) -> io::Result<()> {
    check_removable(p, home).map_err(io::Error::other)?;
    let md = match fs::symlink_metadata(p) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // The checks above look at the literal path: refuse when a parent is a
    // symlink, which would make it point somewhere else entirely.
    if let Some(parent) = p.parent() {
        if fs::canonicalize(parent)? != parent {
            return Err(io::Error::other(format!(
                "refusing: {} goes through a symlinked directory",
                p.display()
            )));
        }
    }
    if keep_dir && md.file_type().is_symlink() {
        // "Empty this folder" on a symlink: its contents live elsewhere.
        return Ok(());
    }
    if !md.is_dir() {
        return fs::remove_file(p);
    }
    // Without the mount table a bind mount of the same filesystem could not
    // be told apart from a folder: refuse rather than guess.
    let mounts = fs::read_to_string("/proc/self/mountinfo")
        .map(|t| parse_mountinfo(&t))
        .map_err(|e| io::Error::other(format!("refusing: cannot read the mount table ({e})")))?;
    remove_dir_checked(p, keep_dir, &mounts, &|md| md.dev())
}

/// Run the actions of the given findings, printing progress to stdout.
/// Returns the number of findings that completed without error.
pub fn execute(findings: &[Finding], home: &Path) -> usize {
    let mut ok = 0;
    for (i, f) in findings.iter().enumerate() {
        println!(
            "\n\x1b[1;36m[{}/{}] {}\x1b[0m  (~{})",
            i + 1,
            findings.len(),
            f.title,
            fmt_size(f.bytes)
        );
        let success = match &f.action {
            Action::Shell { command } => {
                println!("\x1b[33m$ {command}\x1b[0m");
                let _ = io::stdout().flush();
                // On stdin, not as an argument: one argument is capped at 128 KiB.
                let run = || -> io::Result<std::process::ExitStatus> {
                    let mut child = Command::new("sh").arg("-s").stdin(std::process::Stdio::piped()).spawn()?;
                    let mut stdin = child.stdin.take().expect("piped stdin");
                    stdin.write_all(format!("( {command} ) </dev/null\n").as_bytes())?;
                    drop(stdin);
                    child.wait()
                };
                match run() {
                    Ok(s) if s.success() => true,
                    Ok(s) => {
                        println!("\x1b[31mcommand exited with {s}\x1b[0m");
                        false
                    }
                    Err(e) => {
                        println!("\x1b[31mfailed to start: {e}\x1b[0m");
                        false
                    }
                }
            }
            Action::Remove { paths, keep_dir } => {
                let mut all = true;
                for p in paths {
                    match remove_path(p, *keep_dir, home) {
                        Ok(()) => println!("  removed {}", p.display()),
                        Err(e) => {
                            all = false;
                            println!("\x1b[31m  {}: {e}\x1b[0m", p.display());
                        }
                    }
                }
                all
            }
            Action::Manual => {
                println!("  (manual step — nothing executed)");
                false
            }
        };
        if success {
            ok += 1;
            println!("\x1b[32m  ✔ done\x1b[0m");
        }
    }
    ok
}

/// System trees that are owned by packages: never removed from the treemap,
/// even when permissions would allow it (use apt/snap/journalctl instead).
const SYSTEM_TREES: &[&str] = &[
    "/usr", "/etc", "/boot", "/var/lib", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/snap",
    "/proc", "/sys", "/dev", "/run",
];

/// Rules for paths the user marked by hand in the tree or treemap.
pub fn check_markable(p: &Path, scan_root: &Path, home: &Path) -> Result<(), String> {
    check_removable(p, home)?;
    if !p.starts_with(scan_root) || p == scan_root {
        return Err("only paths inside the scanned root can be removed".into());
    }
    if SYSTEM_TREES.iter().any(|s| p.starts_with(s)) {
        return Err("system tree managed by packages — use the Prune tab / apt instead".into());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RemoveMode {
    Trash,
    Permanent,
}

/// Disk space a successful removal gives back: trashed items still occupy
/// the disk until the Trash is emptied.
fn freed_bytes(mode: RemoveMode, size: u64) -> u64 {
    match mode {
        RemoveMode::Trash => 0,
        RemoveMode::Permanent => size,
    }
}

/// Remove hand-marked paths, either to the desktop trash (`gio trash`) or
/// permanently. No shell is involved: a file called `-rf` is just a file.
/// Progress lines go to `log`. Returns (items removed, bytes freed). Trashed
/// items free nothing until the Trash is emptied, so they add no bytes.
pub fn remove_marked(
    paths: &[(std::path::PathBuf, u64)],
    mode: RemoveMode,
    home: &Path,
    log: &mut dyn FnMut(String),
) -> (usize, u64) {
    let (mut ok, mut bytes) = (0, 0);
    for (p, size) in paths {
        let res = match mode {
            RemoveMode::Trash => Command::new("gio")
                .args(["trash", "--"])
                .arg(p)
                .output()
                .map_err(|e| io::Error::other(format!("gio not available: {e}")))
                .and_then(|o| {
                    if o.status.success() {
                        Ok(())
                    } else {
                        Err(io::Error::other(String::from_utf8_lossy(&o.stderr).trim().to_string()))
                    }
                }),
            RemoveMode::Permanent => remove_path(p, false, home),
        };
        match res {
            Ok(()) => {
                ok += 1;
                bytes += freed_bytes(mode, *size);
                let verb = if mode == RemoveMode::Trash { "trashed" } else { "deleted" };
                log(format!("✔ {verb} {} ({})", p.display(), fmt_size(*size)));
            }
            Err(e) => log(format!("✘ {}: {e}", p.display())),
        }
    }
    (ok, bytes)
}

/// Is `gio trash` usable on this system?
pub fn trash_available() -> bool {
    Command::new("gio")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    #[test]
    fn never_removes_a_folder_containing_home() {
        let home = Path::new("/mnt/data/users/u");
        assert!(check_removable(Path::new("/mnt/data/users"), home).is_err());
        assert!(check_removable(Path::new("/mnt/data"), home).is_err());
        assert!(check_removable(Path::new("/mnt/data/users/u/.cache/x"), home).is_ok());
    }

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn mark_rules() {
        let home = Path::new("/home/u");
        let root = Path::new("/");
        assert!(check_markable(Path::new("/usr/share/foo"), root, home).is_err());
        assert!(check_markable(Path::new("/var/lib/docker"), root, home).is_err());
        assert!(check_markable(Path::new("/home/u/Downloads/x.iso"), root, home).is_ok());
        assert!(check_markable(Path::new("/home/u/x"), Path::new("/home/u/src"), home).is_err());
    }

    #[test]
    fn guards() {
        let home = Path::new("/home/u");
        assert!(check_removable(Path::new("/"), home).is_err());
        assert!(check_removable(Path::new("/usr"), home).is_err());
        assert!(check_removable(Path::new("/home/u"), home).is_err());
        assert!(check_removable(Path::new("/home/u/../x"), home).is_err());
        assert!(check_removable(Path::new("relative/x"), home).is_err());
        assert!(check_removable(Path::new("/home/u/.cache/pip"), home).is_ok());
    }

    use crate::util::testutil::{alloc, TempDir};
    use std::os::unix::fs::symlink;

    #[test]
    fn removable_refuses_root_system_dirs_home_and_odd_paths() {
        let home = Path::new("/home/u");
        for p in [
            "/", "/usr", "/usr/", "/etc", "/boot", "/var", "/home", "/tmp", "/snap", "/root", "/opt",
            "/lib64", "/proc", "/sys", "/dev", "/run", "/srv", "/bin", "/sbin", "/lib",
            "/home/u", "/home/u/", "/home/u/.", "/data", "/mnt", "//usr",
            "/home/u/../x", "/home/u/a/../../..", "relative/x", "./x", "", "~/x",
        ] {
            assert!(check_removable(Path::new(p), home).is_err(), "{p:?} must be refused");
        }
        for p in ["/home/u/.cache/pip", "/home/u/x", "/var/log/syslog.1", "/mnt/data/x"] {
            assert!(check_removable(Path::new(p), home).is_ok(), "{p:?}");
        }
    }

    #[test]
    fn markable_refuses_scan_root_outside_and_system_trees() {
        let home = Path::new("/home/u");
        let root = Path::new("/");
        for p in [
            "/usr/lib/x", "/etc/fstab", "/boot/grub", "/var/lib/dpkg", "/var/lib/docker/x",
            "/snap/core/1", "/lib/modules/6.8", "/lib32/x", "/lib64/x", "/bin/x", "/sbin/x",
            "/proc/1", "/sys/kernel", "/dev/shm/x", "/run/user/1000/x",
        ] {
            assert!(check_markable(Path::new(p), root, home).is_err(), "{p:?} must be refused");
        }
        let src = Path::new("/home/u/src");
        assert!(check_markable(src, src, home).is_err(), "scan root itself");
        assert!(check_markable(Path::new("/home/u/src2/x"), src, home).is_err(), "sibling prefix");
        assert!(check_markable(Path::new("/home/u/other"), src, home).is_err(), "outside root");
        assert!(check_markable(Path::new("/home/u/src/../other"), src, home).is_err(), "'..' escape");
        assert!(check_markable(Path::new("/home/u"), root, home).is_err(), "$HOME");
        assert!(check_markable(Path::new("/home/u/src/proj/target"), src, home).is_ok());
        assert!(check_markable(Path::new("/var/log/big.log"), root, home).is_ok());
    }

    #[test]
    fn remove_path_deletes_symlink_to_dir_not_target() {
        let outside = TempDir::new("rm-outside");
        let precious = outside.file("precious/data.txt", 100);
        let d = TempDir::new("rm-link");
        let link = d.join("link");
        symlink(outside.join("precious"), &link).unwrap();
        remove_path(&link, false, Path::new("/home/nobody")).unwrap();
        assert!(fs::symlink_metadata(&link).is_err(), "link removed");
        assert!(precious.exists(), "target survives");

        // keep_dir on a symlink: still only the link goes, never the target's contents.
        symlink(outside.join("precious"), &link).unwrap();
        remove_path(&link, true, Path::new("/home/nobody")).unwrap();
        assert!(precious.exists());

        // A directory holding a symlink to the outside, removed whole or emptied.
        for keep_dir in [false, true] {
            d.dir("tree/sub");
            symlink(outside.join("precious"), d.join("tree/sub/escape")).unwrap();
            symlink(&precious, d.join("tree/file-link")).unwrap();
            remove_path(&d.join("tree"), keep_dir, Path::new("/home/nobody")).unwrap();
            assert_eq!(d.join("tree").exists(), keep_dir);
            assert!(precious.exists(), "keep_dir={keep_dir}: target survives");
            let _ = fs::remove_dir_all(d.join("tree"));
        }
    }

    #[test]
    fn remove_path_keep_dir_empties_but_keeps_dir() {
        let d = TempDir::new("rm-keep");
        let cache = d.dir("cache");
        d.file("cache/a", 10);
        d.file("cache/.hidden", 10);
        d.file("cache/sub/deeper/b", 10);
        d.file("sibling/c", 10);
        remove_path(&cache, true, Path::new("/home/nobody")).unwrap();
        assert!(cache.is_dir());
        assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
        assert!(d.join("sibling/c").exists());
        // Missing paths are not an error (already clean).
        remove_path(&d.join("gone"), true, Path::new("/home/nobody")).unwrap();
    }

    #[test]
    fn remove_path_refuses_home_and_protected() {
        let d = TempDir::new("rm-home");
        let f = d.file("h/file", 10);
        assert!(remove_path(&d.join("h"), false, &d.join("h")).is_err());
        assert!(remove_path(&d.join("h"), true, &d.join("h")).is_err());
        assert!(f.exists());
        assert!(remove_path(Path::new("/usr"), true, Path::new("/home/nobody")).is_err());
        assert!(remove_path(Path::new("relative"), false, Path::new("/home/nobody")).is_err());
    }

    #[test]
    fn remove_marked_permanent_deletes_and_reports_bytes() {
        let d = TempDir::new("marked");
        let a = d.file("a.bin", 2 << 20);
        let b = d.file("dir/b.bin", 1 << 20);
        let (sa, sb) = (alloc(&a), alloc(&d.join("dir")) + alloc(&b));
        let marks = vec![(a.clone(), sa), (d.join("dir"), sb), (PathBuf::from("/usr"), 999)];
        let mut log = Vec::new();
        let (n, bytes) =
            remove_marked(&marks, RemoveMode::Permanent, Path::new("/home/nobody"), &mut |l| log.push(l));
        assert_eq!((n, bytes), (2, sa + sb));
        assert!(!a.exists() && !d.join("dir").exists());
        assert!(Path::new("/usr").is_dir());
        assert_eq!(log.iter().filter(|l| l.starts_with('✔')).count(), 2);
        assert_eq!(log.iter().filter(|l| l.starts_with('✘')).count(), 1);
    }


    #[test]
    fn trash_frees_no_bytes() {
        assert_eq!(freed_bytes(RemoveMode::Trash, 123), 0);
        assert_eq!(freed_bytes(RemoveMode::Permanent, 123), 123);
    }

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
61 22 259:1 / /boot/efi rw,relatime shared:31 - vfat /dev/nvme0n1p1 rw
90 22 8:17 / /home/u/My\\040Drive rw,relatime shared:40 - ext4 /dev/sdb1 rw
91 22 8:18 / /home/u/tab\\011and\\134slash rw,relatime shared:41 - ext4 /dev/sdb2 rw
92 22 8:19 / /home/u/caf\\351 rw,relatime shared:42 - ext4 /dev/sdb3 rw
";

    #[test]
    fn mountinfo_parser_decodes_escapes() {
        use std::os::unix::ffi::OsStrExt;
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(m.len(), 6);
        assert_eq!(m[0], Path::new("/"));
        assert_eq!(m[2], Path::new("/boot/efi"));
        assert_eq!(m[3], Path::new("/home/u/My Drive"));
        assert_eq!(m[4], Path::new("/home/u/tab\tand\\slash"));
        assert_eq!(m[5].as_os_str().as_bytes(), b"/home/u/caf\xe9");
        assert_eq!(unescape_mount("/a\\04"), Path::new("/a\\04"), "incomplete escape kept literally");
        assert!(parse_mountinfo("").is_empty());
    }

    #[test]
    fn mounts_inside_is_strict_for_keep_dir() {
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(mounts_inside(Path::new("/home/u"), &m, false), Some(&m[3]));
        assert_eq!(mounts_inside(Path::new("/home/u/My Drive"), &m, false), None, "emptying a mount's own contents");
        assert_eq!(mounts_inside(Path::new("/home/u/My Drive"), &m, true), Some(&m[3]));
        assert_eq!(mounts_inside(Path::new("/home/u/My"), &m, true), None, "component-wise prefix");
        assert_eq!(mounts_inside(Path::new("/srv/data"), &m, true), None);
    }

    #[test]
    fn removal_refuses_dir_with_mount_point_below() {
        let d = TempDir::new("rm-mount");
        let f = d.file("tree/mnt/data.bin", 10);
        d.file("tree/other.bin", 10);
        let mounts = vec![PathBuf::from("/"), d.join("tree/mnt")];
        for keep_dir in [false, true] {
            let e = remove_dir_checked(&d.join("tree"), keep_dir, &mounts, &|md| md.dev()).unwrap_err();
            assert!(e.to_string().contains("mounted filesystem"), "{e}");
            assert!(f.exists() && d.join("tree/other.bin").exists(), "nothing deleted");
        }
    }

    #[test]
    fn removal_never_crosses_into_another_device() {
        let d = TempDir::new("rm-dev");
        let f = d.file("tree/zz-foreign/data.bin", 10);
        let foreign = fs::metadata(d.join("tree/zz-foreign")).unwrap().ino();
        // Pretend tree/zz-foreign is on another device without being in mountinfo.
        let dev_of = |md: &fs::Metadata| if md.ino() == foreign { md.dev() ^ 1 } else { md.dev() };
        let e = remove_dir_checked(&d.join("tree"), false, &[], &dev_of).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::CrossesDevices);
        assert!(f.exists(), "foreign filesystem untouched");
        assert!(d.join("tree").is_dir());
        // Same tree without the fake device boundary goes away completely.
        remove_dir_checked(&d.join("tree"), false, &[], &|md| md.dev()).unwrap();
        assert!(!d.join("tree").exists());
    }

    #[test]
    fn removal_refuses_symlinked_parent_component() {
        let d = TempDir::new("rm-symparent");
        let victim = d.file("real/dir/victim.bin", 10);
        d.file("real/dir2/other.bin", 10);
        symlink(d.join("real"), d.join("alias")).unwrap();
        for keep_dir in [false, true] {
            for p in [d.join("alias/dir/victim.bin"), d.join("alias/dir"), d.join("alias/dir2")] {
                let e = remove_path(&p, keep_dir, Path::new("/home/nobody")).unwrap_err();
                assert!(e.to_string().contains("symlink"), "{e}");
            }
        }
        assert!(victim.exists() && d.join("real/dir2/other.bin").exists());
        // The symlink itself (parent is real) is removable, and only the link goes.
        remove_path(&d.join("alias"), false, Path::new("/home/nobody")).unwrap();
        assert!(victim.exists());
    }

}
