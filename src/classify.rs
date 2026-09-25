//! Classifies tree nodes by the *kind* of data they hold, for treemap colours
//! (an idea borrowed from disktree), and flags space that can be had back.

use crate::scanner::{marker, NodeKind, Tree};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Code,
    Git,
    Build,
    Cache,
    Toolchain,
    Media,
    Documents,
    Containers,
    Logs,
    System,
    Other,
}

impl Kind {
    pub const LEGEND: [Kind; 10] = [
        Kind::Code,
        Kind::Git,
        Kind::Build,
        Kind::Cache,
        Kind::Toolchain,
        Kind::Media,
        Kind::Documents,
        Kind::Containers,
        Kind::Logs,
        Kind::System,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Kind::Code => "code",
            Kind::Git => "git",
            Kind::Build => "build output",
            Kind::Cache => "caches",
            Kind::Toolchain => "toolchains",
            Kind::Media => "media",
            Kind::Documents => "documents",
            Kind::Containers => "VMs & containers",
            Kind::Logs => "logs",
            Kind::System => "system",
            Kind::Other => "other",
        }
    }

    /// Base colour (r, g, b), muted; the UI lightens it with depth.
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Kind::Code => (70, 130, 200),
            Kind::Git => (196, 110, 80),
            Kind::Build => (150, 105, 190),
            Kind::Cache => (95, 165, 95),
            Kind::Toolchain => (60, 150, 150),
            Kind::Media => (190, 90, 150),
            Kind::Documents => (120, 135, 185),
            Kind::Containers => (60, 165, 200),
            Kind::Logs => (170, 145, 95),
            Kind::System => (95, 102, 125),
            Kind::Other => (105, 110, 120),
        }
    }
}

fn by_extension(name: &str) -> Option<Kind> {
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "raw" | "cr2" | "nef" | "mp4" | "mkv"
        | "mov" | "avi" | "webm" | "mp3" | "flac" | "wav" | "ogg" | "m4a" | "svg" | "psd" => {
            Kind::Media
        }
        "pdf" | "doc" | "docx" | "odt" | "xls" | "xlsx" | "ods" | "ppt" | "pptx" | "odp" | "txt"
        | "md" | "epub" => Kind::Documents,
        "iso" | "img" | "qcow2" | "vdi" | "vmdk" | "vhd" | "vhdx" | "ova" => Kind::Containers,
        "log" | "journal" | "gz" if name.contains("log") || ext == "journal" || ext == "log" => {
            Kind::Logs
        }
        "deb" | "snap" | "whl" | "crate" | "tgz" => Kind::Cache,
        "rs" | "py" | "js" | "ts" | "go" | "c" | "cpp" | "h" | "java" | "rb" => Kind::Code,
        _ => return None,
    })
}

fn by_dir_name(t: &Tree, idx: usize, name: &str) -> Option<Kind> {
    let parent = t.nodes[idx].parent.map(|p| &t.nodes[p]);
    let parent_marks = parent.map_or(0, |p| p.markers);
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        ".git" => Kind::Git,
        "node_modules" | "__pycache__" | ".pytest_cache" | ".mypy_cache" | ".next" | ".gradle"
        | ".tox" | "cmake-build-debug" => Kind::Build,
        "target" if parent_marks & marker::CARGO_TOML != 0
            || t.nodes[idx].markers & marker::CACHEDIR_TAG != 0 =>
        {
            Kind::Build
        }
        "build" | "dist" | "out" if parent_marks & (marker::CARGO_TOML | marker::PACKAGE_JSON) != 0 => {
            Kind::Build
        }
        ".cache" | "cache" | "caches" | "_cacache" | "thumbnails" | ".npm" | "archives" => {
            Kind::Cache
        }
        ".rustup" | ".cargo" | ".nvm" | ".pyenv" | ".sdkman" | "go" | ".vscode-server"
        | ".local" | "snap" | "flatpak" | "opt" => Kind::Toolchain,
        "pictures" | "videos" | "music" | "photos" | "movies" => Kind::Media,
        "documents" | "desktop" | "downloads" | "templates" | "public" => Kind::Documents,
        "docker" | "containers" | "virtualbox vms" | "libvirt" | "lxd" | ".docker" => {
            Kind::Containers
        }
        "log" | "logs" | "journal" | "crash" => Kind::Logs,
        "src" | "projects" | "code" | "repos" | "workspace" | "dev" | "git" => Kind::Code,
        _ => {
            if t.nodes[idx].markers & (marker::CARGO_TOML | marker::PACKAGE_JSON) != 0 {
                Kind::Code
            } else if lower.contains("cache") {
                Kind::Cache
            } else {
                return None;
            }
        }
    })
}

/// Kind of every node; unclassified nodes inherit their parent's kind.
pub fn classify(t: &Tree) -> Vec<Kind> {
    let mut kinds = vec![Kind::Other; t.nodes.len()];
    // System roots at the top of an absolute scan.
    for (i, n) in t.nodes.iter().enumerate() {
        let inherited = n.parent.map_or(Kind::Other, |p| kinds[p]);
        // Parents always precede children in the arena, so `inherited` is final.
        let own = match n.kind {
            NodeKind::Dir => {
                let path_kind = if n.parent == Some(0) && t.root_path == std::path::Path::new("/") {
                    match n.name.as_str() {
                        "usr" | "lib" | "lib32" | "lib64" | "bin" | "sbin" | "boot" | "etc" => {
                            Some(Kind::System)
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                path_kind.or_else(|| by_dir_name(t, i, &n.name))
            }
            NodeKind::File => by_extension(&n.name),
            _ => None,
        };
        // Build/cache/git override whatever is above; others only refine "Other"
        // or System/Toolchain containers.
        kinds[i] = match (own, inherited) {
            (Some(k), _) if matches!(k, Kind::Build | Kind::Cache | Kind::Git) => k,
            (_, k) if matches!(k, Kind::Build | Kind::Cache | Kind::Git) => k,
            (Some(k), _) => k,
            (None, k) => k,
        };
    }
    kinds
}
