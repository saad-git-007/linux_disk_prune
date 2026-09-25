//! Recommendation engine: data model shared by all rule sets.

pub mod extra;
pub mod ubuntu;

use crate::util::{shq, shq_path};
use serde::Serialize;
use std::path::PathBuf;

/// Findings smaller than this are not worth showing.
pub const MIN_FINDING_BYTES: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Risk {
    /// Pure caches: regenerated automatically, no data loss.
    Safe,
    /// System housekeeping: old logs, kernels, snap revisions.
    Moderate,
    /// Project build artifacts: rebuilding costs time.
    Caution,
}

impl Risk {
    pub const ALL: [Risk; 3] = [Risk::Safe, Risk::Moderate, Risk::Caution];

    pub fn label(self) -> &'static str {
        match self {
            Risk::Safe => "SAFE",
            Risk::Moderate => "MODERATE",
            Risk::Caution => "CAUTION",
        }
    }
}

/// What a cleanup would do. Nothing runs unless the user confirms it.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// A shell command, shown verbatim to the user (may contain `sudo`).
    Shell { command: String },
    /// Delete these paths. With `keep_dir`, only the directories' contents go.
    Remove { paths: Vec<PathBuf>, keep_dir: bool },
    /// Informational only; nothing to execute.
    Manual,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// Stable identifier (survives re-analysis, used for selection).
    pub id: String,
    pub category: String,
    pub title: String,
    pub risk: Risk,
    /// Bytes that the action is expected to free.
    pub bytes: u64,
    pub detail: String,
    /// Locations involved (for display and tree tagging).
    pub paths: Vec<PathBuf>,
    pub action: Action,
    pub needs_root: bool,
}

impl Finding {
    /// Exact shell equivalent of the action, suitable for copy & paste.
    pub fn command_text(&self) -> String {
        match &self.action {
            Action::Shell { command } => command.clone(),
            Action::Remove { paths, .. } if paths.iter().any(|p| p.to_str().is_none()) => {
                // A lossy rendering would name a different (look-alike) path.
                "(a path is not valid UTF-8 and has no exact shell form — it is removed \
                 in-process by this app)"
                    .into()
            }
            Action::Remove { paths, keep_dir } => {
                let sudo = if self.needs_root { "sudo " } else { "" };
                if *keep_dir {
                    paths
                        .iter()
                        .map(|p| format!("{sudo}find {} -mindepth 1 -delete", shq_path(p)))
                        .collect::<Vec<_>>()
                        .join(" && ")
                } else {
                    let list: Vec<String> = paths.iter().map(|p| shq_path(p)).collect();
                    format!("{sudo}rm -rf -- {}", list.join(" "))
                }
            }
            Action::Manual => "(no automatic command — see details)".into(),
        }
    }

    pub fn is_actionable(&self) -> bool {
        match &self.action {
            Action::Manual => false,
            // Root removals run as shell text, which can't name such a path.
            Action::Remove { paths, .. } if self.needs_root => paths.iter().all(|p| p.to_str().is_some()),
            _ => true,
        }
    }
}

/// Output of one check.
#[derive(Default)]
pub struct CheckOutput {
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

impl CheckOutput {
    pub fn one(f: Finding) -> Self {
        Self { findings: vec![f], notes: Vec::new() }
    }
    pub fn note(n: impl Into<String>) -> Self {
        Self { findings: Vec::new(), notes: vec![n.into()] }
    }
    pub fn extend(&mut self, other: CheckOutput) {
        self.findings.extend(other.findings);
        self.notes.extend(other.notes);
    }
}

#[derive(Default, Clone, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

impl Report {
    pub fn merge(&mut self, out: CheckOutput) {
        for f in out.findings {
            if f.bytes < MIN_FINDING_BYTES || self.findings.iter().any(|g| g.id == f.id) {
                continue;
            }
            self.findings.push(f);
        }
        for n in out.notes {
            if !self.notes.contains(&n) {
                self.notes.push(n);
            }
        }
        self.findings
            .sort_by(|a, b| a.risk.cmp(&b.risk).then(b.bytes.cmp(&a.bytes)));
    }

    pub fn total(&self, risk: Risk) -> u64 {
        self.findings.iter().filter(|f| f.risk == risk).map(|f| f.bytes).sum()
    }

    pub fn grand_total(&self) -> u64 {
        self.findings.iter().map(|f| f.bytes).sum()
    }
}

/// Shell command that runs `sudo rm -f` on an explicit list of files.
/// Callers must pass only valid UTF-8 paths (a lossy path would be another file).
pub fn sudo_rm_files(paths: &[PathBuf]) -> String {
    debug_assert!(paths.iter().all(|p| p.to_str().is_some()), "non-UTF-8 path in shell command");
    let list: Vec<String> = paths.iter().map(|p| shq(&p.to_string_lossy())).collect();
    format!("sudo rm -f -- {}", list.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testutil::{pwned, sh, TempDir, HOSTILE};
    use std::path::Path;

    fn f(id: &str, risk: Risk, bytes: u64) -> Finding {
        Finding {
            id: id.into(),
            category: "t".into(),
            title: id.into(),
            risk,
            bytes,
            detail: String::new(),
            paths: Vec::new(),
            action: Action::Manual,
            needs_root: false,
        }
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn merge_dedupes_ids_first_wins() {
        let mut r = Report::default();
        r.merge(CheckOutput { findings: vec![f("a", Risk::Safe, 5 * MIB), f("a", Risk::Caution, 9 * MIB)], notes: vec![] });
        r.merge(CheckOutput::one(f("a", Risk::Moderate, 7 * MIB)));
        assert_eq!(r.findings.len(), 1);
        assert_eq!((r.findings[0].risk, r.findings[0].bytes), (Risk::Safe, 5 * MIB));
    }

    #[test]
    fn merge_drops_findings_below_one_mib() {
        let mut r = Report::default();
        r.merge(CheckOutput {
            findings: vec![f("tiny", Risk::Safe, MIB - 1), f("exact", Risk::Safe, MIB), f("zero", Risk::Safe, 0)],
            notes: vec![],
        });
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["exact"]);
        // A dropped finding does not reserve its id.
        r.merge(CheckOutput::one(f("tiny", Risk::Safe, 2 * MIB)));
        assert!(r.findings.iter().any(|f| f.id == "tiny"));
    }

    #[test]
    fn merge_sorts_by_risk_then_size_desc() {
        let mut r = Report::default();
        r.merge(CheckOutput {
            findings: vec![
                f("c1", Risk::Caution, 100 * MIB),
                f("s1", Risk::Safe, 2 * MIB),
                f("m1", Risk::Moderate, 3 * MIB),
            ],
            notes: vec![],
        });
        r.merge(CheckOutput {
            findings: vec![f("s2", Risk::Safe, 50 * MIB), f("m2", Risk::Moderate, 30 * MIB)],
            notes: vec![],
        });
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["s2", "s1", "m2", "m1", "c1"]);
    }

    #[test]
    fn totals_per_tier() {
        let mut r = Report::default();
        r.merge(CheckOutput {
            findings: vec![
                f("s1", Risk::Safe, 2 * MIB),
                f("s2", Risk::Safe, 3 * MIB),
                f("m1", Risk::Moderate, 7 * MIB),
                f("c1", Risk::Caution, 11 * MIB),
                f("dropped", Risk::Caution, 10),
                f("s1", Risk::Safe, 1000 * MIB),
            ],
            notes: vec!["n".into(), "n".into()],
        });
        assert_eq!(r.total(Risk::Safe), 5 * MIB);
        assert_eq!(r.total(Risk::Moderate), 7 * MIB);
        assert_eq!(r.total(Risk::Caution), 11 * MIB);
        assert_eq!(r.grand_total(), 23 * MIB);
        assert_eq!(Risk::ALL.iter().map(|&k| r.total(k)).sum::<u64>(), r.grand_total());
        assert_eq!(r.notes, ["n"]);
    }

    // ------------------------------------------------------------ command safety

    /// Shim that makes `sudo …` run the command as the current user, exactly
    /// as the pkexec script does.
    const SHIM: &str = "sudo() { \"$@\"; }\n";

    fn remove_finding(paths: Vec<PathBuf>, keep_dir: bool, needs_root: bool) -> Finding {
        Finding {
            action: Action::Remove { paths: paths.clone(), keep_dir },
            paths,
            needs_root,
            ..f("rm", Risk::Safe, MIB)
        }
    }

    fn hostile_files(d: &TempDir) -> Vec<PathBuf> {
        HOSTILE.iter().map(|n| d.file(Path::new("t").join(n), 10)).collect()
    }

    fn assert_only_targets_gone(d: &TempDir, targets: &[PathBuf]) {
        for p in targets {
            assert!(!p.exists(), "{p:?} should have been deleted");
        }
        assert!(d.join("t/keep").exists(), "bystander deleted");
        assert!(d.join("t/star-bystander").exists(), "glob expanded");
        assert!(!pwned(d.path()) && !pwned(&d.join("t")), "injected command ran");
    }

    #[test]
    fn rm_command_quotes_hostile_paths() {
        for needs_root in [false, true] {
            let d = TempDir::new("cmd-rm");
            let targets = hostile_files(&d);
            d.file("t/keep", 1);
            d.file("t/star-bystander", 1);
            let cmd = remove_finding(targets.clone(), false, needs_root).command_text();
            assert_eq!(cmd.starts_with("sudo "), needs_root);
            let (ok, _) = sh(&format!("{SHIM}{cmd}"), &d.join("t"));
            assert!(ok, "{cmd}");
            assert_only_targets_gone(&d, &targets);
        }
    }

    #[test]
    fn keep_dir_command_empties_hostile_dirs_but_keeps_them() {
        let d = TempDir::new("cmd-find");
        let dirs: Vec<PathBuf> = HOSTILE.iter().map(|n| d.dir(Path::new("t").join(n))).collect();
        for dir in &dirs {
            d.file(dir.join("inner/file"), 10);
            d.file(dir.join(".hidden"), 10);
        }
        d.file("t/keep", 1);
        d.file("t/star-bystander", 1);
        let cmd = remove_finding(dirs.clone(), true, true).command_text();
        let (ok, _) = sh(&format!("{SHIM}{cmd}"), &d.join("t"));
        assert!(ok, "{cmd}");
        for dir in &dirs {
            assert!(dir.is_dir(), "{dir:?} itself must be kept");
            assert_eq!(fs_count(dir), 0, "{dir:?} must be empty");
        }
        assert!(d.join("t/keep").exists() && !pwned(&d.join("t")));
    }

    fn fs_count(p: &Path) -> usize {
        std::fs::read_dir(p).unwrap().count()
    }

    #[test]
    fn sudo_rm_files_quotes_hostile_paths() {
        let d = TempDir::new("cmd-sudo-rm");
        let targets = hostile_files(&d);
        d.file("t/keep", 1);
        d.file("t/star-bystander", 1);
        let cmd = sudo_rm_files(&targets);
        assert!(cmd.starts_with("sudo rm -f -- "));
        let (ok, _) = sh(&format!("{SHIM}{cmd}"), &d.join("t"));
        assert!(ok, "{cmd}");
        assert_only_targets_gone(&d, &targets);
    }

    #[test]
    fn generated_commands_pass_exact_argv() {
        // Print argv instead of running rm: sh must see exactly our paths.
        let d = TempDir::new("cmd-argv");
        let paths: Vec<PathBuf> = HOSTILE.iter().map(|n| d.join(n)).collect();
        let shim = "sudo() { shift 3; for a in \"$@\"; do printf '%s\\0' \"$a\"; done; }\n";
        let (ok, out) = sh(&format!("{shim}{}", sudo_rm_files(&paths)), d.path());
        assert!(ok);
        let got: Vec<&str> = out.split('\0').filter(|s| !s.is_empty()).collect();
        let want: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn manual_findings_are_not_actionable() {
        let m = f("m", Risk::Safe, MIB);
        assert!(!m.is_actionable());
        assert!(m.command_text().starts_with('('));
        let s = Finding { action: Action::Shell { command: "true".into() }, ..f("s", Risk::Safe, MIB) };
        assert!(s.is_actionable());
        assert_eq!(s.command_text(), "true");
    }
}
