//! Background work shared by the front-ends: the tree scan and the rule checks
//! run on their own threads and report back through a channel.

use crate::classify::Kind;
use crate::rules::ubuntu::{self, RuleContext};
use crate::rules::{CheckOutput, Report, Risk};
use crate::scanner::{self, Progress, ScanOptions, Tree};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc};
use std::time::Instant;

pub enum Event {
    TreeReady(Arc<Tree>),
    ScanFailed(String),
    Findings(CheckOutput),
}

enum Msg {
    Tree(u64, Result<Arc<Tree>, String>),
    Rules(u64, CheckOutput),
}

/// Called from worker threads when there is news (e.g. to wake the GUI).
pub type Notify = Arc<dyn Fn() + Send + Sync>;

pub struct Engine {
    pub root: PathBuf,
    pub opts: ScanOptions,
    pub ctx: RuleContext,
    pub progress: Arc<Progress>,
    pub scan_started: Instant,
    /// Rule groups still running (system checks, project artifacts).
    pub rules_pending: u8,
    scan_gen: u64,
    rules_gen: u64,
    tx: mpsc::Sender<Msg>,
    rx: mpsc::Receiver<Msg>,
    notify: Notify,
}

impl Engine {
    pub fn new(root: PathBuf, opts: ScanOptions, ctx: RuleContext, notify: Notify) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            root,
            opts,
            ctx,
            progress: Arc::new(Progress::default()),
            scan_started: Instant::now(),
            rules_pending: 0,
            scan_gen: 0,
            rules_gen: 0,
            tx,
            rx,
            notify,
        }
    }

    /// Scan the tree and run all rules. Results of earlier runs are discarded.
    pub fn start_scan(&mut self) {
        self.progress.cancel.store(true, Relaxed);
        self.progress = Arc::new(Progress::default());
        self.scan_gen += 1;
        self.rules_gen += 1;
        self.rules_pending = 2;
        self.scan_started = Instant::now();

        let (tx, progress, notify) = (self.tx.clone(), self.progress.clone(), self.notify.clone());
        let (root, opts, ctx) = (self.root.clone(), self.opts.clone(), self.ctx.clone());
        let (sg, rg) = (self.scan_gen, self.rules_gen);
        std::thread::Builder::new()
            .name("scan".into())
            .stack_size(64 << 20)
            .spawn(move || {
                let tree = scanner::scan(&root, &opts, &progress).map(Arc::new);
                let for_rules = tree.as_ref().ok().cloned();
                let _ = tx.send(Msg::Tree(sg, tree.map_err(|e| e.to_string())));
                notify();
                if progress.cancel.load(Relaxed) {
                    return;
                }
                let out = ubuntu::run_artifact_check(&ctx, for_rules.as_deref(), &opts);
                let _ = tx.send(Msg::Rules(rg, out));
                notify();
            })
            .expect("spawn scan thread");
        self.spawn_system_rules();
    }

    /// Re-run the rules against an existing tree.
    pub fn reanalyze(&mut self, tree: Arc<Tree>) {
        self.rules_gen += 1;
        self.rules_pending = 2;
        self.spawn_system_rules();
        let (tx, ctx, opts, rg, notify) =
            (self.tx.clone(), self.ctx.clone(), self.opts.clone(), self.rules_gen, self.notify.clone());
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let out = ubuntu::run_artifact_check(&ctx, Some(&tree), &opts);
                let _ = tx.send(Msg::Rules(rg, out));
                notify();
            })
            .expect("spawn analysis thread");
    }

    fn spawn_system_rules(&self) {
        let (tx, ctx, rg, notify) = (self.tx.clone(), self.ctx.clone(), self.rules_gen, self.notify.clone());
        std::thread::spawn(move || {
            let out = ubuntu::run_system_checks(&ctx);
            let _ = tx.send(Msg::Rules(rg, out));
            notify();
        });
    }

    pub fn cancel(&self) {
        self.progress.cancel.store(true, Relaxed);
    }

    /// Collect finished work, dropping results from superseded runs.
    pub fn poll(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Tree(g, res) if g == self.scan_gen => out.push(match res {
                    Ok(t) => Event::TreeReady(t),
                    Err(e) => Event::ScanFailed(e),
                }),
                Msg::Rules(g, o) if g == self.rules_gen => {
                    self.rules_pending = self.rules_pending.saturating_sub(1);
                    out.push(Event::Findings(o));
                }
                _ => {}
            }
        }
        out
    }
}

/// Which nodes can be had back (hatched) and which are exactly a finding.
/// Only space covered by a finding is hatched: a name that merely looks like
/// a cache or build dir (kind colouring) is no promise that it is safe.
pub fn overlays(t: &Tree, _kinds: &[Kind], report: &Report) -> (Vec<bool>, HashMap<usize, Risk>) {
    let mut reclaim = vec![false; t.nodes.len()];
    let mut nodes = HashMap::new();
    for f in &report.findings {
        for p in &f.paths {
            if let Some(i) = t.find(p) {
                reclaim[i] = true;
                nodes.entry(i).or_insert(f.risk);
            }
        }
    }
    // Parents precede children in the arena: one pass propagates down.
    for i in 1..t.nodes.len() {
        if let Some(p) = t.nodes[i].parent {
            if reclaim[p] {
                reclaim[i] = true;
            }
        }
    }
    (reclaim, nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify;
    use crate::rules::{Action, CheckOutput, Finding};
    use crate::scanner::{scan, ScanOptions};
    use crate::util::testutil::TempDir;

    #[test]
    fn reclaim_shading_comes_only_from_findings() {
        let d = TempDir::new("overlay");
        for f in ["mycache/a", "archives/b.tgz", "web/dist/c", "nopkg/node_modules/d", "proj/target/e", "x/f"] {
            d.file(f, 2 << 20);
        }
        d.file("proj/Cargo.toml", 1);
        let t = scan(d.path(), &ScanOptions { min_file_size: 0, ..Default::default() }, &Progress::default()).unwrap();
        let kinds = classify(&t);
        assert!(kinds.iter().any(|k| matches!(k, Kind::Cache | Kind::Build)), "fixture has cache/build-looking dirs");

        let (reclaim, nodes) = overlays(&t, &kinds, &Report::default());
        assert!(reclaim.iter().all(|r| !r), "no findings -> nothing hatched");
        assert!(nodes.is_empty());

        let target = d.join("proj/target");
        let mut report = Report::default();
        report.merge(CheckOutput::one(Finding {
            id: "rust:x".into(),
            category: "Rust".into(),
            title: "t".into(),
            risk: Risk::Caution,
            bytes: 2 << 20,
            detail: String::new(),
            paths: vec![target.clone()],
            action: Action::Remove { paths: vec![target.clone()], keep_dir: false },
            needs_root: false,
        }));
        let (reclaim, nodes) = overlays(&t, &kinds, &report);
        let ti = t.find(&target).unwrap();
        assert_eq!(nodes.get(&ti), Some(&Risk::Caution));
        assert_eq!(nodes.len(), 1);
        for i in 0..t.nodes.len() {
            let inside = t.path_of(i).starts_with(&target);
            assert_eq!(reclaim[i], inside, "{:?}", t.path_of(i));
        }
    }
}
