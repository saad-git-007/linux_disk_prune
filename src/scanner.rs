//! Fast multi-threaded filesystem scanner.
//!
//! Like disktree, every directory is read with a single `readdir` pass and its
//! subdirectories are recursed in parallel on a rayon work-stealing pool. Sizes
//! are real disk usage (`st_blocks * 512`), hard links are counted once, and by
//! default the scan never crosses into other mounted filesystems.
//!
//! To keep memory bounded on multi-million-file trees, files smaller than
//! `min_file_size` are folded into a single `<N small files>` node per directory.

use rayon::prelude::*;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Marker files recorded per directory (used to recognise project roots).
pub mod marker {
    pub const CARGO_TOML: u8 = 1 << 0;
    pub const PACKAGE_JSON: u8 = 1 << 1;
    pub const CACHEDIR_TAG: u8 = 1 << 2;
}

/// Pseudo filesystems that are never worth walking.
const VIRTUAL_DIRS: &[&str] = &["/proc", "/sys"];

/// Live counters, readable from the UI thread while a scan runs.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub dirs: AtomicU64,
    pub bytes: AtomicU64,
    pub errors: AtomicU64,
    pub cancel: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub one_file_system: bool,
    pub min_file_size: u64,
    /// 0 = one thread per CPU.
    pub threads: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self { one_file_system: true, min_file_size: 1 << 20, threads: 0 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NodeKind {
    Dir,
    File,
    /// Several small files folded together.
    Aggregate,
    /// A mount point of another filesystem that was not entered.
    Mount,
}

#[derive(Debug)]
pub struct Node {
    /// Display name (lossy for names that are not valid UTF-8).
    pub name: String,
    /// The exact on-disk name when it is not valid UTF-8 (`name` is lossy then).
    pub raw: Option<Box<OsStr>>,
    pub kind: NodeKind,
    pub size: u64,
    pub files: u64,
    pub markers: u8,
    pub unreadable: bool,
    pub parent: Option<usize>,
    /// Sorted by size, largest first.
    pub children: Vec<usize>,
}

/// Arena-allocated result of a scan. Node 0 is the root.
pub struct Tree {
    pub root_path: PathBuf,
    pub nodes: Vec<Node>,
    pub dirs: u64,
    pub errors: u64,
    pub elapsed: Duration,
}

impl Node {
    /// Exact file name as on disk; use this, never `name`, to build paths.
    pub fn os_name(&self) -> &OsStr {
        self.raw.as_deref().unwrap_or(OsStr::new(&self.name))
    }
}

/// Split a file name into (display name, exact name if not valid UTF-8).
fn split_name(os: OsString) -> (String, Option<Box<OsStr>>) {
    match os.into_string() {
        Ok(s) => (s, None),
        Err(os) => (os.to_string_lossy().into_owned(), Some(os.into_boxed_os_str())),
    }
}

impl Tree {
    pub fn root(&self) -> &Node {
        &self.nodes[0]
    }

    pub fn path_of(&self, mut idx: usize) -> PathBuf {
        let mut parts = Vec::new();
        while let Some(p) = self.nodes[idx].parent {
            parts.push(self.nodes[idx].os_name());
            idx = p;
        }
        let mut path = self.root_path.clone();
        for part in parts.iter().rev() {
            path.push(part);
        }
        path
    }

    /// Locate the node for `path` (directory, large file or mount point), if it
    /// lies inside the scanned tree.
    pub fn find(&self, path: &Path) -> Option<usize> {
        let rel = path.strip_prefix(&self.root_path).ok()?;
        let mut idx = 0;
        for comp in rel.components() {
            let name = match comp {
                Component::Normal(name) => name,
                Component::CurDir => continue,
                // `..` would silently resolve to the wrong node.
                _ => return None,
            };
            // Exact byte comparison: a lossy match could pick a look-alike
            // sibling (`caf\xe9` vs a real `caf\u{FFFD}`).
            idx = *self.nodes[idx]
                .children
                .iter()
                .find(|&&c| self.nodes[c].kind != NodeKind::Aggregate && self.nodes[c].os_name() == name)?;
        }
        Some(idx)
    }

    pub fn depth_of(&self, mut idx: usize) -> usize {
        let mut d = 0;
        while let Some(p) = self.nodes[idx].parent {
            d += 1;
            idx = p;
        }
        d
    }
}

struct Tmp {
    name: String,
    raw: Option<Box<OsStr>>,
    kind: NodeKind,
    size: u64,
    files: u64,
    markers: u8,
    unreadable: bool,
    children: Vec<Tmp>,
}

struct Ctx<'a> {
    opts: &'a ScanOptions,
    progress: &'a Progress,
    root_dev: u64,
    /// Every multiply-linked file seen: ((dev, inode), exact path, bytes).
    /// Resolved after the scan so each inode is counted exactly once.
    links: Mutex<Vec<((u64, u64), PathBuf, u64)>>,
}

fn disk_bytes(md: &fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// Build a rayon pool with generous stacks: work stealing can nest recursion.
/// When the system can't give that many threads (memory limits), retry with
/// half as many rather than failing the scan.
fn pool(threads: usize) -> io::Result<rayon::ThreadPool> {
    let mut n = threads;
    loop {
        let built = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .stack_size(32 << 20)
            .thread_name(|i| format!("scan-{i}"))
            .build();
        match built {
            Ok(p) => return Ok(p),
            Err(_) if n > 1 => n /= 2,
            Err(e) => return Err(io::Error::other(e)),
        }
    }
}

/// Scan `root` and build the full size tree.
pub fn scan(root: &Path, opts: &ScanOptions, progress: &Progress) -> io::Result<Tree> {
    let start = Instant::now();
    let root = fs::canonicalize(root)?;
    let md = fs::metadata(&root)?;
    if !md.is_dir() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
    }
    let ctx = Ctx {
        opts,
        progress,
        root_dev: md.dev(),
        links: Mutex::new(Vec::new()),
    };
    let tmp = pool(opts.threads)?
        .install(|| scan_dir(&root, root.display().to_string(), disk_bytes(&md), &ctx));

    let mut nodes = Vec::with_capacity(progress.dirs.load(Relaxed) as usize * 2);
    flatten(tmp, None, &mut nodes);
    let mut tree = Tree {
        root_path: root,
        nodes,
        dirs: progress.dirs.load(Relaxed),
        errors: progress.errors.load(Relaxed),
        elapsed: start.elapsed(),
    };
    let links = std::mem::take(&mut *ctx.links.lock().unwrap());
    dedupe_hard_links(&mut tree, links);
    Ok(tree)
}

/// Count each multiply-linked inode once, crediting it to its
/// lexicographically smallest path. Deciding after the scan (instead of
/// "first thread to see it wins") makes per-directory sizes reproducible.
fn dedupe_hard_links(t: &mut Tree, mut links: Vec<((u64, u64), PathBuf, u64)>) {
    links.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut touched = HashSet::new();
    for i in 1..links.len() {
        let (key, path, size) = &links[i];
        if *key != links[i - 1].0 || *size == 0 {
            continue; // the first path of each inode keeps the bytes
        }
        let (Some(dir), Some(name)) = (path.parent().and_then(|p| t.find(p)), path.file_name()) else { continue };
        let kids = &t.nodes[dir].children;
        let holder = kids
            .iter()
            .copied()
            .find(|&c| t.nodes[c].kind == NodeKind::File && t.nodes[c].os_name() == name)
            .or_else(|| kids.iter().copied().find(|&c| t.nodes[c].kind == NodeKind::Aggregate));
        if let Some(h) = holder {
            t.nodes[h].size = t.nodes[h].size.saturating_sub(*size);
        }
        let mut cur = Some(dir);
        while let Some(c) = cur {
            t.nodes[c].size = t.nodes[c].size.saturating_sub(*size);
            touched.insert(c);
            cur = t.nodes[c].parent;
        }
    }
    // Sizes changed: restore largest-first order where it matters.
    for d in touched {
        let mut kids = std::mem::take(&mut t.nodes[d].children);
        kids.sort_by(|&a, &b| t.nodes[b].size.cmp(&t.nodes[a].size).then_with(|| t.nodes[a].name.cmp(&t.nodes[b].name)));
        t.nodes[d].children = kids;
    }
}

fn scan_dir(path: &Path, name: String, own_size: u64, ctx: &Ctx) -> Tmp {
    scan_dir_raw(path, (name, None), own_size, ctx)
}

fn scan_dir_raw(path: &Path, (name, raw): (String, Option<Box<OsStr>>), own_size: u64, ctx: &Ctx) -> Tmp {
    ctx.progress.dirs.fetch_add(1, Relaxed);
    let mut node = Tmp {
        name,
        raw,
        kind: NodeKind::Dir,
        size: own_size,
        files: 0,
        markers: 0,
        unreadable: false,
        children: Vec::new(),
    };
    if ctx.progress.cancel.load(Relaxed) {
        return node;
    }
    let rd = match fs::read_dir(path) {
        Ok(rd) => rd,
        Err(_) => {
            ctx.progress.errors.fetch_add(1, Relaxed);
            node.unreadable = true;
            return node;
        }
    };

    let mut subdirs = Vec::new();
    let (mut small_count, mut small_bytes) = (0u64, 0u64);
    for entry in rd {
        let Ok(entry) = entry else {
            ctx.progress.errors.fetch_add(1, Relaxed);
            continue;
        };
        // DirEntry::metadata does not follow symlinks.
        let Ok(md) = entry.metadata() else {
            ctx.progress.errors.fetch_add(1, Relaxed);
            continue;
        };
        let (name, raw) = split_name(entry.file_name());

        if md.is_dir() {
            let p = entry.path();
            if VIRTUAL_DIRS.iter().any(|v| p == Path::new(v)) {
                continue;
            }
            if ctx.opts.one_file_system && md.dev() != ctx.root_dev {
                node.children.push(Tmp {
                    name,
                    raw,
                    kind: NodeKind::Mount,
                    size: 0,
                    files: 0,
                    markers: 0,
                    unreadable: false,
                    children: Vec::new(),
                });
                continue;
            }
            subdirs.push((p, (name, raw), disk_bytes(&md)));
            continue;
        }

        let size = disk_bytes(&md);
        // Counted in full here; dedupe_hard_links() removes the extra copies.
        if md.nlink() > 1 && !md.is_symlink() {
            ctx.links.lock().unwrap().push(((md.dev(), md.ino()), entry.path(), size));
        }
        node.markers |= match name.as_str() {
            "Cargo.toml" => marker::CARGO_TOML,
            "package.json" => marker::PACKAGE_JSON,
            "CACHEDIR.TAG" => marker::CACHEDIR_TAG,
            _ => 0,
        };
        ctx.progress.files.fetch_add(1, Relaxed);
        ctx.progress.bytes.fetch_add(size, Relaxed);
        node.files += 1;
        node.size += size;
        if size >= ctx.opts.min_file_size {
            node.children.push(Tmp {
                name,
                raw,
                kind: NodeKind::File,
                size,
                files: 1,
                markers: 0,
                unreadable: false,
                children: Vec::new(),
            });
        } else {
            small_count += 1;
            small_bytes += size;
        }
    }
    if small_count > 0 {
        node.children.push(Tmp {
            name: format!("<{} small files>", small_count),
            raw: None,
            kind: NodeKind::Aggregate,
            size: small_bytes,
            files: small_count,
            markers: 0,
            unreadable: false,
            children: Vec::new(),
        });
    }

    let subs: Vec<Tmp> = subdirs
        .into_par_iter()
        .map(|(p, n, own)| scan_dir_raw(&p, n, own, ctx))
        .collect();
    for s in subs {
        node.size += s.size;
        node.files += s.files;
        node.children.push(s);
    }
    node
}

fn flatten(tmp: Tmp, parent: Option<usize>, nodes: &mut Vec<Node>) -> usize {
    let idx = nodes.len();
    nodes.push(Node {
        name: tmp.name,
        raw: tmp.raw,
        kind: tmp.kind,
        size: tmp.size,
        files: tmp.files,
        markers: tmp.markers,
        unreadable: tmp.unreadable,
        parent,
        children: Vec::new(),
    });
    let mut kids = tmp.children;
    kids.sort_unstable_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    let ids: Vec<usize> = kids.into_iter().map(|k| flatten(k, Some(idx), nodes)).collect();
    nodes[idx].children = ids;
    idx
}

/// Is the block device holding `path` a spinning disk?
/// Resolved through /sys/dev/block/MAJ:MIN; unknown devices count as SSD.
pub fn is_rotational(path: &Path) -> bool {
    let Ok(md) = fs::metadata(path) else { return false };
    let dev = md.dev();
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    let Ok(sys) = fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")) else { return false };
    // A partition has no queue/ of its own; its parent disk does.
    [sys.join("queue/rotational"), sys.join("../queue/rotational")]
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .map_or(false, |v| v.trim() == "1")
}

/// Scanner threads for this machine. Directory scanning is bound by metadata
/// I/O latency, not CPU: NVMe/SSD queues reward more requests in flight than
/// there are cores, while a spinning disk thrashes its head with too many.
pub fn auto_threads(path: &Path) -> usize {
    let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
    if is_rotational(path) {
        cpus.min(4)
    } else {
        (cpus * 2).clamp(4, 32)
    }
}

/// Total disk usage of `path` (no tree kept), measured like `scan`: the
/// directory's own blocks included, hard links counted once, symlinks not
/// followed. Stays on one filesystem. Returns (bytes, files). Missing paths
/// yield (0, 0).
pub fn du(path: &Path) -> (u64, u64) {
    let Ok(md) = fs::symlink_metadata(path) else { return (0, 0) };
    if !md.is_dir() {
        return (disk_bytes(&md), 1);
    }
    let seen = Mutex::new(HashSet::new());
    let (b, f) = du_dir(path, md.dev(), &seen);
    (disk_bytes(&md) + b, f)
}

fn du_dir(path: &Path, dev: u64, seen: &Mutex<HashSet<(u64, u64)>>) -> (u64, u64) {
    let Ok(rd) = fs::read_dir(path) else { return (0, 0) };
    let mut bytes = 0;
    let mut files = 0;
    let mut subdirs = Vec::new();
    for entry in rd.flatten() {
        let Ok(md) = entry.metadata() else { continue };
        if md.is_dir() {
            if md.dev() == dev {
                bytes += disk_bytes(&md);
                subdirs.push(entry.path());
            }
        } else {
            let first = md.nlink() <= 1 || md.is_symlink() || seen.lock().unwrap().insert((md.dev(), md.ino()));
            if first {
                bytes += disk_bytes(&md);
            }
            files += 1;
        }
    }
    let (b, f) = subdirs
        .par_iter()
        .map(|p| du_dir(p, dev, seen))
        .reduce(|| (0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    (bytes + b, files + f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_link_attribution_is_deterministic() {
        let d = TempDir::new("hl-det");
        let a = d.file("a/f.bin", 3 << 20);
        fs::create_dir_all(d.join("b")).unwrap();
        fs::hard_link(&a, d.join("b/f.bin")).unwrap();
        for threads in [1, 2, 8, 16] {
            for _ in 0..5 {
                let o = ScanOptions { one_file_system: true, min_file_size: 1 << 20, threads };
                let t = scan(d.path(), &o, &Progress::default()).unwrap();
                let (ia, ib) = (t.find(&d.join("a")).unwrap(), t.find(&d.join("b")).unwrap());
                // Credited to the smaller path ("a/f.bin"), counted once overall.
                assert!(t.nodes[ia].size >= 3 << 20, "threads={threads}");
                assert!(t.nodes[ib].size < 1 << 20, "threads={threads}");
                let sum: u64 = t.nodes[0].children.iter().map(|&c| t.nodes[c].size).sum();
                assert_eq!(t.root().size, sum + alloc(d.path()));
            }
        }
    }

    #[test]
    fn scans_temp_tree() {
        let dir = std::env::temp_dir().join(format!("ldp-test-{}", std::process::id()));
        let sub = dir.join("proj/target");
        fs::create_dir_all(&sub).unwrap();
        fs::write(dir.join("proj/Cargo.toml"), "[package]").unwrap();
        fs::write(sub.join("big.bin"), vec![1u8; 2 << 20]).unwrap();

        let progress = Progress::default();
        let tree = scan(&dir, &ScanOptions::default(), &progress).unwrap();
        let proj = tree.find(&dir.join("proj")).unwrap();
        assert!(tree.nodes[proj].markers & marker::CARGO_TOML != 0);
        let target = tree.find(&sub).unwrap();
        assert!(tree.nodes[target].size >= 2 << 20);
        assert_eq!(tree.path_of(target), fs::canonicalize(&sub).unwrap());
        assert!(tree.root().size >= tree.nodes[target].size);
        fs::remove_dir_all(&dir).unwrap();
    }

    // ------------------------------------------------------------ measurement

    use crate::util::testutil::{alloc, TempDir};
    use std::io::{Seek, SeekFrom, Write as _};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn opts(min: u64) -> ScanOptions {
        ScanOptions { one_file_system: true, min_file_size: min, threads: 2 }
    }

    fn scan_dir_tree(d: &TempDir, min: u64) -> Tree {
        scan(d.path(), &opts(min), &Progress::default()).unwrap()
    }

    /// Sum of allocated blocks of `p` and everything below it, each inode once.
    fn expected_usage(p: &Path) -> u64 {
        fn walk(p: &Path, seen: &mut HashSet<(u64, u64)>) -> u64 {
            let md = fs::symlink_metadata(p).unwrap();
            if !seen.insert((md.dev(), md.ino())) {
                return 0;
            }
            let mut n = md.blocks() * 512;
            if md.is_dir() {
                for e in fs::read_dir(p).unwrap().flatten() {
                    n += walk(&e.path(), seen);
                }
            }
            n
        }
        walk(p, &mut HashSet::new())
    }

    #[test]
    fn file_size_is_st_blocks_times_512() {
        let d = TempDir::new("blocks");
        let f = d.file("odd.bin", 5_000); // not a block multiple
        let t = scan_dir_tree(&d, 0);
        let i = t.find(&f).unwrap();
        assert_eq!(t.nodes[i].kind, NodeKind::File);
        assert_eq!(t.nodes[i].size, fs::metadata(&f).unwrap().blocks() * 512);
        assert_ne!(t.nodes[i].size, 5_000, "must be allocation, not apparent length");
        assert_eq!(t.root().size, expected_usage(d.path()));
    }

    #[test]
    fn sparse_file_counted_by_allocated_blocks() {
        let d = TempDir::new("sparse");
        let p = d.join("sparse.img");
        let mut f = fs::File::create(&p).unwrap();
        f.set_len(256 << 20).unwrap();
        f.seek(SeekFrom::Start(100 << 20)).unwrap();
        f.write_all(b"x").unwrap();
        drop(f);
        let allocated = alloc(&p);
        let t = scan_dir_tree(&d, 0);
        let i = t.find(&p).unwrap();
        assert_eq!(t.nodes[i].size, allocated);
        assert!(allocated < 256 << 20, "fixture fs does not support sparse files?");
        assert_eq!(du(&p).0, allocated);
    }

    #[test]
    fn hard_links_in_same_dir_counted_once() {
        let d = TempDir::new("hl-same");
        let a = d.file("a.bin", 2 << 20);
        fs::hard_link(&a, d.join("b.bin")).unwrap();
        let t = scan_dir_tree(&d, 0);
        assert_eq!(t.root().size, alloc(d.path()) + alloc(&a));
        assert_eq!(t.root().files, 2, "both names are still listed as files");
        assert_eq!(du(d.path()).0, t.root().size);
    }

    #[test]
    fn hard_links_across_dirs_counted_once() {
        let d = TempDir::new("hl-cross");
        let a = d.file("x/a.bin", 3 << 20);
        d.dir("y/z");
        fs::hard_link(&a, d.join("y/z/b.bin")).unwrap();
        let t = scan_dir_tree(&d, 0);
        let expect = alloc(d.path()) + alloc(&d.join("x")) + alloc(&d.join("y"))
            + alloc(&d.join("y/z")) + alloc(&a);
        assert_eq!(t.root().size, expect);
        let (x, y) = (t.find(&d.join("x")).unwrap(), t.find(&d.join("y")).unwrap());
        // Exactly one of the two directories carries the data.
        let data = (t.nodes[x].size - alloc(&d.join("x")))
            + (t.nodes[y].size - alloc(&d.join("y")) - alloc(&d.join("y/z")));
        assert_eq!(data, alloc(&a));
        assert_eq!(du(d.path()).0, expect);
    }

    #[test]
    fn symlinks_are_not_followed() {
        let outside = TempDir::new("sym-outside");
        let big = outside.file("big.bin", 4 << 20);
        let d = TempDir::new("sym");
        symlink(&big, d.join("link-to-file")).unwrap();
        symlink(outside.path(), d.join("link-to-dir")).unwrap();
        let t = scan_dir_tree(&d, 0);
        let expect =
            alloc(d.path()) + alloc(&d.join("link-to-file")) + alloc(&d.join("link-to-dir"));
        assert_eq!(t.root().size, expect);
        assert!(t.root().size < 1 << 20, "symlink target must not be counted");
        let l = t.find(&d.join("link-to-dir")).unwrap();
        assert_eq!(t.nodes[l].kind, NodeKind::File, "symlink to dir is a leaf");
        assert!(t.nodes[l].children.is_empty());
        assert_eq!(du(&d.join("link-to-file")).0, alloc(&d.join("link-to-file")));
        assert_eq!(du(d.path()).0, expect);
    }

    #[test]
    fn unreadable_dir_is_marked_and_scan_continues() {
        if crate::util::is_root() {
            eprintln!("skipped: root can read mode-000 directories");
            return;
        }
        let d = TempDir::new("unreadable");
        d.file("locked/secret.bin", 2 << 20);
        d.file("open/ok.bin", 2 << 20);
        fs::set_permissions(d.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
        let p = Progress::default();
        let t = scan(d.path(), &opts(0), &p).unwrap();
        let locked = t.find(&d.join("locked")).unwrap();
        assert!(t.nodes[locked].unreadable);
        assert!(t.nodes[locked].children.is_empty());
        assert!(t.errors >= 1);
        let open = t.find(&d.join("open/ok.bin")).unwrap();
        assert_eq!(t.nodes[open].size, alloc(&d.join("open/ok.bin")));
        assert!(!t.root().unreadable);
    }

    #[test]
    fn one_file_system_turns_foreign_devices_into_empty_mount_nodes() {
        // A real mount needs root; instead pretend the scan started on another
        // device, so every subdirectory looks like a foreign filesystem.
        let d = TempDir::new("mounts");
        d.file("sub/big.bin", 2 << 20);
        d.file("top.bin", 2 << 20);
        let dev = fs::metadata(d.path()).unwrap().dev();
        let run = |one_fs: bool, root_dev: u64| {
            let o = ScanOptions { one_file_system: one_fs, min_file_size: 0, threads: 1 };
            let progress = Progress::default();
            let ctx = Ctx { opts: &o, progress: &progress, root_dev, links: Mutex::default() };
            let tmp = scan_dir(d.path(), "root".into(), 0, &ctx);
            let mut nodes = Vec::new();
            flatten(tmp, None, &mut nodes);
            nodes
        };
        let foreign = run(true, dev.wrapping_add(1));
        let sub = foreign.iter().find(|n| n.name == "sub").unwrap();
        assert_eq!(sub.kind, NodeKind::Mount);
        assert_eq!((sub.size, sub.files), (0, 0));
        assert!(sub.children.is_empty());
        assert_eq!(foreign[0].size, alloc(&d.join("top.bin")), "mount contents not counted");

        let crossed = run(false, dev.wrapping_add(1));
        let sub = crossed.iter().find(|n| n.name == "sub").unwrap();
        assert_eq!(sub.kind, NodeKind::Dir, "-x descends into other filesystems");
        assert_eq!(sub.files, 1);

        let same = run(true, dev);
        assert_eq!(same.iter().find(|n| n.name == "sub").unwrap().kind, NodeKind::Dir);
    }

    #[test]
    fn small_files_aggregate_preserves_totals() {
        let d = TempDir::new("agg");
        let mut small = 0;
        for i in 0..7 {
            small += alloc(&d.file(format!("s{i}.txt"), 1000 + i * 3000));
        }
        let big = d.file("big.bin", 2 << 20);
        let t = scan_dir_tree(&d, 1 << 20);
        let root = t.root();
        assert_eq!(root.files, 8);
        let agg: Vec<&Node> =
            root.children.iter().map(|&c| &t.nodes[c]).filter(|n| n.kind == NodeKind::Aggregate).collect();
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].name, "<7 small files>");
        assert_eq!((agg[0].files, agg[0].size), (7, small));
        assert_eq!(root.size, alloc(d.path()) + small + alloc(&big));
        assert!(t.find(&d.join("s0.txt")).is_none(), "folded files are not addressable");
        assert!(t.find(&d.join("<7 small files>")).is_none(), "aggregate is not a path");
    }

    fn build_nested(d: &TempDir) {
        d.file("a/b/c/deep.bin", 1_500_000);
        d.file("a/b/small.txt", 10);
        d.file("a/x.bin", 2 << 20);
        d.file("my dir/with space.bin", 1 << 20);
        d.file("ünïcödé 日本/файл.bin", 1_200_000);
        d.file("quote'dir/\"q\".txt", 5);
        d.dir("empty");
        d.file("top.txt", 3);
    }

    #[test]
    fn parent_size_is_own_blocks_plus_children_at_every_node() {
        let d = TempDir::new("invariant");
        build_nested(&d);
        for min in [0, 1 << 20, u64::MAX] {
            let t = scan_dir_tree(&d, min);
            for (i, n) in t.nodes.iter().enumerate() {
                let kids: u64 = n.children.iter().map(|&c| t.nodes[c].size).sum();
                let kid_files: u64 = n.children.iter().map(|&c| t.nodes[c].files).sum();
                match n.kind {
                    NodeKind::Dir => {
                        assert_eq!(n.size, alloc(&t.path_of(i)) + kids, "{:?} min={min}", t.path_of(i));
                        assert_eq!(n.files, kid_files, "{:?}", t.path_of(i));
                    }
                    _ => assert!(n.children.is_empty()),
                }
                // Children sorted largest first.
                assert!(n.children.windows(2).all(|w| t.nodes[w[0]].size >= t.nodes[w[1]].size));
            }
            assert_eq!(t.root().size, expected_usage(d.path()));
        }
    }

    #[test]
    fn find_and_path_of_round_trip() {
        let d = TempDir::new("roundtrip");
        build_nested(&d);
        let t = scan_dir_tree(&d, 0);
        assert_eq!(t.find(d.path()), Some(0));
        assert_eq!(t.path_of(0), d.path());
        let mut checked = 0;
        for i in 0..t.nodes.len() {
            if t.nodes[i].kind == NodeKind::Aggregate {
                continue;
            }
            let p = t.path_of(i);
            assert!(fs::symlink_metadata(&p).is_ok(), "{p:?} must exist");
            assert_eq!(t.find(&p), Some(i), "{p:?}");
            checked += 1;
        }
        assert!(checked >= 14);
        for name in ["my dir/with space.bin", "ünïcödé 日本/файл.bin", "quote'dir/\"q\".txt"] {
            let i = t.find(&d.join(name)).unwrap();
            assert_eq!(t.path_of(i), d.join(name));
        }
        assert_eq!(t.find(&d.join("a/./b")), t.find(&d.join("a/b")));
        assert_eq!(t.find(&d.join("a/b/../x.bin")), None);
        // Skipping `..` would land on the existing a/b/c; the real a/c does not exist.
        assert_eq!(t.find(&d.join("a/b/../c")), None, "'..' must not resolve to a/b/c");
        assert_eq!(t.find(&d.join("missing")), None);
        assert_eq!(t.find(Path::new("/definitely/elsewhere")), None);
        assert_eq!(t.depth_of(t.find(&d.join("a/b/c/deep.bin")).unwrap()), 4);
    }

    #[test]
    fn du_matches_scan_root_size() {
        let d = TempDir::new("du");
        build_nested(&d);
        fs::hard_link(d.join("a/x.bin"), d.join("my dir/x-again.bin")).unwrap();
        symlink(d.join("a"), d.join("link")).unwrap();
        let t = scan_dir_tree(&d, 1 << 20);
        let (bytes, files) = du(d.path());
        assert_eq!(bytes, t.root().size);
        assert_eq!(files, t.root().files);
        // (a/ itself holds one side of the hard link, so compare a subtree without it.)
        let ab = t.find(&d.join("a/b")).unwrap();
        assert_eq!(du(&d.join("a/b")), (t.nodes[ab].size, t.nodes[ab].files));
        assert_eq!(du(&d.join("nope")), (0, 0));
    }


    #[test]
    fn non_utf8_names_round_trip_exactly() {
        use std::os::unix::ffi::OsStrExt;
        let d = TempDir::new("nonutf8-scan");
        let e9 = d.join(OsStr::from_bytes(b"caf\xe9"));
        let e8 = d.join(OsStr::from_bytes(b"caf\xe8"));
        let decoy = d.join("caf\u{FFFD}");
        for p in [&e9, &e8, &decoy] {
            d.file(p.join("big.bin"), 2 << 20);
        }
        let t = scan_dir_tree(&d, 0);
        let ids: Vec<usize> = [&e9, &e8, &decoy].iter().map(|p| t.find(p).unwrap()).collect();
        assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2], "look-alikes must stay distinct");
        for (i, p) in ids.iter().zip([&e9, &e8, &decoy]) {
            assert_eq!(&t.path_of(*i), p);
            assert_eq!(t.find(&p.join("big.bin")).map(|f| t.nodes[f].parent), Some(Some(*i)));
        }
        assert_eq!(t.nodes[ids[0]].name, "caf\u{FFFD}", "display name stays lossy");
        assert!(t.nodes[ids[2]].raw.is_none(), "valid UTF-8 keeps no raw copy");
    }

}
