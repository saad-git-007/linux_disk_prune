//! Terminal UI: treemap, tree view, prune dashboard, review dialog.
//!
//! The treemap (colour = kind of data, hatching = space that can be had back,
//! amber = selection) and the mark → review → remove flow are modelled on
//! disktree by Tobi Lütke (https://github.com/tobi/disktree), translated from
//! its GPU canvas to terminal cells.

use crate::classify::{classify, Kind};
use crate::cleanup::{self, RemoveMode};
use crate::rules::ubuntu::{self, RuleContext};
use crate::rules::{CheckOutput, Finding, Report, Risk};
use crate::scanner::{self, NodeKind, Progress, ScanOptions, Tree};
use crate::util::{fmt_count, fmt_size, tilde};
use anyhow::Result;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Alignment, Constraint, Layout, Margin, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};
use ratatui::{Frame, Terminal};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, BufRead, Stdout, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------ theme

type Rgb = (u8, u8, u8);
const BG: Rgb = (13, 15, 23);
const PANEL: Rgb = (19, 22, 33);
const BORDER: Rgb = (50, 56, 82);
const FG: Rgb = (224, 227, 238);
const DIM: Rgb = (122, 128, 152);
const FAINT: Rgb = (64, 69, 92);
const ACCENT: Rgb = (122, 200, 255);
const AMBER: Rgb = (255, 186, 48);
const DANGER: Rgb = (236, 76, 90);
const SEL_BG: Rgb = (36, 41, 64);
const SAFE: Rgb = (86, 222, 128);
const MODERATE: Rgb = (255, 150, 80);
const CAUTION: Rgb = (255, 92, 138);

static TRUECOLOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub fn set_truecolor(on: bool) {
    let _ = TRUECOLOR.set(on);
}

/// Truecolor if the terminal advertises it (COLORTERM), otherwise 256 colours.
pub fn detect_truecolor() -> bool {
    let ct = std::env::var("COLORTERM").unwrap_or_default().to_ascii_lowercase();
    let term = std::env::var("TERM").unwrap_or_default();
    ct.contains("truecolor") || ct.contains("24bit") || term.contains("direct")
}

fn c(rgb: Rgb) -> Color {
    if *TRUECOLOR.get().unwrap_or(&true) {
        Color::Rgb(rgb.0, rgb.1, rgb.2)
    } else {
        Color::Indexed(to_256(rgb))
    }
}

/// Nearest xterm-256 colour: the 6x6x6 cube or the 24-step grey ramp.
fn to_256((r, g, b): Rgb) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let nearest = |v: u8| {
        (0..6).min_by_key(|&i| (LEVELS[i] - v as i32).abs()).unwrap()
    };
    let (qr, qg, qb) = (nearest(r), nearest(g), nearest(b));
    let dist = |x: i32, y: i32, z: i32| {
        (x - r as i32).pow(2) + (y - g as i32).pow(2) + (z - b as i32).pow(2)
    };
    let cube = dist(LEVELS[qr], LEVELS[qg], LEVELS[qb]);
    let avg = (r as i32 + g as i32 + b as i32) / 3;
    let gi = ((avg - 8).max(0) / 10).min(23);
    let gv = 8 + gi * 10;
    if dist(gv, gv, gv) < cube {
        232 + gi as u8
    } else {
        16 + (36 * qr + 6 * qg + qb) as u8
    }
}

fn mix(a: Rgb, b: Rgb, t: f64) -> Rgb {
    let t = t.clamp(0.0, 1.0);
    let l = |x: u8, y: u8| (x as f64 + (y as f64 - x as f64) * t).round() as u8;
    (l(a.0, b.0), l(a.1, b.1), l(a.2, b.2))
}

/// Signature gradient: teal → violet → pink.
fn grad(t: f64) -> Rgb {
    let stops = [(64, 224, 208), (130, 110, 255), (255, 94, 170)];
    if t < 0.5 {
        mix(stops[0], stops[1], t * 2.0)
    } else {
        mix(stops[1], stops[2], (t - 0.5) * 2.0)
    }
}

fn risk_rgb(r: Risk) -> Rgb {
    match r {
        Risk::Safe => SAFE,
        Risk::Moderate => MODERATE,
        Risk::Caution => CAUTION,
    }
}

fn st(fg: Rgb) -> Style {
    Style::new().fg(c(fg))
}

fn panel(title: &str, accent: Rgb) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(st(BORDER))
        .style(Style::new().bg(c(PANEL)).fg(c(FG)))
        .title(Line::from(vec![
            Span::styled(" ", st(accent)),
            Span::styled(title.to_string(), st(accent).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
        ]))
}

fn gradient_text(s: &str, bold: bool) -> Vec<Span<'static>> {
    let n = s.chars().count().max(2) as f64 - 1.0;
    s.chars()
        .enumerate()
        .map(|(i, ch)| {
            let mut style = st(grad(i as f64 / n));
            if bold {
                style = style.add_modifier(Modifier::BOLD);
            }
            Span::styled(ch.to_string(), style)
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max <= 1 {
        "…".chars().take(max).collect()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Truncate from the left, keeping the end of a path visible.
fn truncate_left(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let skip = n - max + 1;
        format!("…{}", s.chars().skip(skip).collect::<String>())
    }
}

/// Draw a horizontal bar with per-cell gradient and eighth-block precision.
fn draw_bar(buf: &mut Buffer, x: u16, y: u16, width: u16, frac: f64, color: impl Fn(f64) -> Rgb, empty: Rgb, bg: Rgb) {
    const EIGHTHS: [&str; 8] = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"];
    let total = frac.clamp(0.0, 1.0) * width as f64;
    for i in 0..width {
        let Some(cell) = buf.cell_mut((x + i, y)) else { continue };
        let t = if width > 1 { i as f64 / (width - 1) as f64 } else { 0.0 };
        let fill = (total - i as f64).clamp(0.0, 1.0);
        if fill >= 1.0 {
            cell.set_symbol("█").set_fg(c(color(t))).set_bg(c(bg));
        } else if fill > 0.0 {
            let e = ((fill * 8.0) as usize).min(7);
            cell.set_symbol(if e == 0 { "▏" } else { EIGHTHS[e] })
                .set_fg(c(color(t)))
                .set_bg(c(bg));
        } else {
            cell.set_symbol("·").set_fg(c(empty)).set_bg(c(bg));
        }
    }
}

// ------------------------------------------------------------------ state

pub struct Config {
    pub root: PathBuf,
    pub scan_opts: ScanOptions,
    pub rule_ctx: RuleContext,
    pub no_exec: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tab {
    Map,
    Tree,
    Prune,
}

enum Msg {
    Tree(u64, Result<Arc<Tree>, String>),
    Rules(u64, CheckOutput),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Modal {
    None,
    Review,
    About,
}

#[derive(Clone, Copy, Debug)]
enum Hit {
    Tab(Tab),
    About,
    Node(usize),
    Finding(usize),
    Button(Btn),
}

#[derive(Clone, Copy, Debug)]
enum Btn {
    Toggle,
    AllSafe,
    Clear,
    Review,
    Reanalyze,
    Run,
    RunPermanent,
    Cancel,
}

struct ExecRequest {
    findings: Vec<Finding>,
    marks: Vec<(PathBuf, u64)>,
    mode: RemoveMode,
}

struct Disk {
    mount: String,
    total: u64,
    avail: u64,
}

fn disk_info(root: &Path) -> Option<Disk> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    disks
        .list()
        .iter()
        .filter(|d| root.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .map(|d| Disk {
            mount: d.mount_point().display().to_string(),
            total: d.total_space(),
            avail: d.available_space(),
        })
}

struct App {
    /// A suggestion checked only because Review was opened on it: unchecked
    /// again if the review is cancelled.
    auto_checked: Option<String>,
    cfg: Config,
    tab: Tab,
    tx: mpsc::Sender<Msg>,
    rx: mpsc::Receiver<Msg>,
    scan_gen: u64,
    rules_gen: u64,
    progress: Arc<Progress>,
    scan_started: Instant,
    started: Instant,
    tree: Option<Arc<Tree>>,
    kinds: Vec<Kind>,
    /// Node lies inside something that can be had back (hatched in the map).
    reclaim: Vec<bool>,
    /// Nodes that are exactly the location of a finding.
    finding_nodes: HashMap<usize, Risk>,
    scan_error: Option<String>,
    expanded: Vec<bool>,
    sel: usize,
    focus: usize,
    tree_offset: usize,
    tree_page: usize,
    map_depth: usize,
    map_tiles: Vec<(usize, Rect)>,
    marked: BTreeSet<usize>,
    report: Report,
    rules_pending: u8,
    prune_cursor: usize,
    prune_offset: usize,
    prune_page: usize,
    checked: HashSet<String>,
    modal: Modal,
    hits: Vec<(Rect, Hit)>,
    status: Option<(String, Instant)>,
    disk: Option<Disk>,
    exec: Option<ExecRequest>,
    trash_ok: bool,
    quit: bool,
}

impl App {
    fn new(cfg: Config) -> Self {
        let (tx, rx) = mpsc::channel();
        let disk = disk_info(&cfg.root);
        Self {
            cfg,
            tab: Tab::Map,
            tx,
            rx,
            scan_gen: 0,
            rules_gen: 0,
            progress: Arc::new(Progress::default()),
            scan_started: Instant::now(),
            started: Instant::now(),
            tree: None,
            kinds: Vec::new(),
            reclaim: Vec::new(),
            finding_nodes: HashMap::new(),
            scan_error: None,
            expanded: Vec::new(),
            sel: 0,
            focus: 0,
            tree_offset: 0,
            tree_page: 10,
            map_depth: 2,
            map_tiles: Vec::new(),
            marked: BTreeSet::new(),
            report: Report::default(),
            rules_pending: 0,
            prune_cursor: 0,
            prune_offset: 0,
            prune_page: 10,
            checked: HashSet::new(),
            modal: Modal::None,
            auto_checked: None,
            hits: Vec::new(),
            status: None,
            disk,
            exec: None,
            trash_ok: cleanup::trash_available(),
            quit: false,
        }
    }

    fn flash(&mut self, msg: impl Into<String>) {
        self.status = Some((msg.into(), Instant::now()));
    }

    // ---------------------------------------------------------- background work

    fn start_scan(&mut self) {
        self.progress.cancel.store(true, Relaxed);
        self.progress = Arc::new(Progress::default());
        self.scan_gen += 1;
        self.rules_gen += 1;
        self.tree = None;
        self.scan_error = None;
        self.marked.clear();
        self.report = Report::default();
        self.rules_pending = 2;
        self.scan_started = Instant::now();
        self.disk = disk_info(&self.cfg.root);

        let (tx, progress) = (self.tx.clone(), self.progress.clone());
        let (root, opts, ctx) = (self.cfg.root.clone(), self.cfg.scan_opts.clone(), self.cfg.rule_ctx.clone());
        let (sg, rg) = (self.scan_gen, self.rules_gen);
        std::thread::Builder::new()
            .name("scan".into())
            .stack_size(64 << 20)
            .spawn(move || {
                let tree = scanner::scan(&root, &opts, &progress).map(Arc::new);
                let for_rules = tree.as_ref().ok().cloned();
                let _ = tx.send(Msg::Tree(sg, tree.map_err(|e| e.to_string())));
                if progress.cancel.load(Relaxed) {
                    return;
                }
                let out = ubuntu::run_artifact_check(&ctx, for_rules.as_deref(), &opts);
                let _ = tx.send(Msg::Rules(rg, out));
            })
            .expect("spawn scan thread");
        self.spawn_system_rules();
    }

    fn spawn_system_rules(&self) {
        let (tx, ctx, rg) = (self.tx.clone(), self.cfg.rule_ctx.clone(), self.rules_gen);
        std::thread::spawn(move || {
            let out = ubuntu::run_system_checks(&ctx);
            let _ = tx.send(Msg::Rules(rg, out));
        });
    }

    fn reanalyze(&mut self) {
        let Some(tree) = self.tree.clone() else {
            self.flash("Still scanning — analysis will finish with the scan");
            return;
        };
        self.rules_gen += 1;
        self.report = Report::default();
        self.rules_pending = 2;
        self.disk = disk_info(&self.cfg.root);
        self.spawn_system_rules();
        let (tx, ctx, opts, rg) =
            (self.tx.clone(), self.cfg.rule_ctx.clone(), self.cfg.scan_opts.clone(), self.rules_gen);
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                let out = ubuntu::run_artifact_check(&ctx, Some(&tree), &opts);
                let _ = tx.send(Msg::Rules(rg, out));
            })
            .expect("spawn analysis thread");
    }

    fn drain_messages(&mut self) -> bool {
        let mut any = false;
        while let Ok(msg) = self.rx.try_recv() {
            any = true;
            match msg {
                Msg::Tree(g, res) if g == self.scan_gen => match res {
                    Ok(t) => {
                        self.kinds = classify(&t);
                        self.expanded = vec![false; t.nodes.len()];
                        self.expanded[0] = true;
                        self.sel = t.nodes[0].children.first().copied().unwrap_or(0);
                        self.focus = 0;
                        self.tree_offset = 0;
                        self.tree = Some(t);
                        self.refresh_overlays();
                    }
                    Err(e) => self.scan_error = Some(e),
                },
                Msg::Rules(g, out) if g == self.rules_gen => {
                    let cur_id = self.report.findings.get(self.prune_cursor).map(|f| f.id.clone());
                    self.report.merge(out);
                    self.rules_pending = self.rules_pending.saturating_sub(1);
                    if let Some(id) = cur_id {
                        self.prune_cursor =
                            self.report.findings.iter().position(|f| f.id == id).unwrap_or(0);
                    }
                    let ids: HashSet<&String> = self.report.findings.iter().map(|f| &f.id).collect();
                    self.checked.retain(|id| ids.contains(id));
                    self.refresh_overlays();
                }
                _ => {}
            }
        }
        any
    }

    /// Recompute hatching and finding tags after the tree or report changed.
    /// Shared with the desktop app: only paths covered by a finding are hatched.
    fn refresh_overlays(&mut self) {
        let Some(t) = self.tree.clone() else { return };
        let (reclaim, nodes) = crate::engine::overlays(&t, &self.kinds, &self.report);
        self.reclaim = reclaim;
        self.finding_nodes = nodes;
    }

    // ---------------------------------------------------------- helpers

    fn visible_rows(&self, t: &Tree) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut stack = vec![(0usize, 0usize)];
        while let Some((i, d)) = stack.pop() {
            out.push((i, d));
            if self.expanded[i] {
                for &ch in t.nodes[i].children.iter().rev() {
                    stack.push((ch, d + 1));
                }
            }
        }
        out
    }

    fn reveal(&mut self, t: &Tree, idx: usize) {
        let mut p = t.nodes[idx].parent;
        while let Some(i) = p {
            self.expanded[i] = true;
            p = t.nodes[i].parent;
        }
    }

    fn is_ancestor(t: &Tree, anc: usize, mut idx: usize) -> bool {
        while let Some(p) = t.nodes[idx].parent {
            if p == anc {
                return true;
            }
            idx = p;
        }
        false
    }

    /// Marked directly or through a marked ancestor.
    fn marked_state(&self, t: &Tree, idx: usize) -> bool {
        let mut cur = Some(idx);
        while let Some(i) = cur {
            if self.marked.contains(&i) {
                return true;
            }
            cur = t.nodes[i].parent;
        }
        false
    }

    fn marked_bytes(&self, t: &Tree) -> u64 {
        self.marked.iter().map(|&i| t.nodes[i].size).sum()
    }

    fn checked_findings(&self) -> Vec<&Finding> {
        self.report.findings.iter().filter(|f| self.checked.contains(&f.id)).collect()
    }

    fn checked_bytes(&self) -> u64 {
        self.checked_findings().iter().map(|f| f.bytes).sum()
    }

    /// Make sure the map focus is a strict ancestor of the selection.
    fn sync_focus(&mut self) {
        let Some(t) = self.tree.clone() else { return };
        if self.sel == 0 {
            self.focus = 0;
            self.sel = t.nodes[0].children.first().copied().unwrap_or(0);
            return;
        }
        if !Self::is_ancestor(&t, self.focus, self.sel) {
            self.focus = t.nodes[self.sel].parent.unwrap_or(0);
        }
    }

    fn toggle_mark(&mut self) {
        let Some(t) = self.tree.clone() else { return };
        let idx = self.sel;
        if self.marked.remove(&idx) {
            self.flash(format!("Unmarked {}", t.nodes[idx].name));
            return;
        }
        let n = &t.nodes[idx];
        if matches!(n.kind, NodeKind::Aggregate | NodeKind::Mount) {
            self.flash("Grouped small files and mount points cannot be marked");
            return;
        }
        if self.marked_state(&t, idx) {
            self.flash("Already inside a marked directory — unmark that directory instead");
            return;
        }
        let path = t.path_of(idx);
        if let Err(e) = cleanup::check_markable(&path, &t.root_path, &self.cfg.rule_ctx.home) {
            self.flash(format!("Cannot mark {}: {e}", path.display()));
            return;
        }
        // Marking a directory absorbs marks already inside it.
        self.marked.retain(|&m| !Self::is_ancestor(&t, idx, m));
        self.marked.insert(idx);
        self.flash(format!("Marked {} ({}) — press c to review", n.name, fmt_size(n.size)));
    }

    fn open_review(&mut self) {
        if self.checked.is_empty() && self.marked.is_empty() {
            if self.tab == Tab::Prune {
                if let Some(f) = self.report.findings.get(self.prune_cursor) {
                    if f.is_actionable() {
                        self.checked.insert(f.id.clone());
                        self.auto_checked = Some(f.id.clone());
                    }
                }
            }
            if self.checked.is_empty() {
                self.flash("Nothing selected — check items in Prune (Space) or mark tiles (Space/x)");
                return;
            }
        }
        self.modal = Modal::Review;
    }

    fn cancel_review(&mut self) {
        if let Some(id) = self.auto_checked.take() {
            self.checked.remove(&id);
        }
        self.modal = Modal::None;
    }

    fn confirm_review(&mut self, mode: RemoveMode) {
        self.auto_checked = None;
        if self.cfg.no_exec {
            self.flash("Execution is disabled (--no-exec)");
            return;
        }
        let findings: Vec<Finding> = self.checked_findings().into_iter().cloned().collect();
        let marks = match &self.tree {
            Some(t) => self.marked.iter().map(|&i| (t.path_of(i), t.nodes[i].size)).collect(),
            None => Vec::new(),
        };
        self.modal = Modal::None;
        self.exec = Some(ExecRequest { findings, marks, mode });
    }

    // ---------------------------------------------------------- input

    fn on_key(&mut self, k: KeyEvent) {
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        match self.modal {
            Modal::About => {
                self.modal = Modal::None;
                return;
            }
            Modal::Review => {
                match k.code {
                    KeyCode::Char('y') | KeyCode::Enter => {
                        self.confirm_review(if self.trash_ok { RemoveMode::Trash } else { RemoveMode::Permanent })
                    }
                    KeyCode::Char('t') if self.trash_ok => self.confirm_review(RemoveMode::Trash),
                    KeyCode::Char('p') => self.confirm_review(RemoveMode::Permanent),
                    KeyCode::Char('!') => {
                        self.marked.clear();
                        self.checked.clear();
                        self.modal = Modal::None;
                        self.flash("Unmarked everything");
                    }
                    _ => self.cancel_review(),
                }
                return;
            }
            Modal::None => {}
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.modal = Modal::About,
            KeyCode::Char('1') => self.set_tab(Tab::Map),
            KeyCode::Char('2') => self.set_tab(Tab::Tree),
            KeyCode::Char('3') => self.set_tab(Tab::Prune),
            KeyCode::Tab if self.tab != Tab::Map => self.set_tab(match self.tab {
                Tab::Tree => Tab::Prune,
                _ => Tab::Map,
            }),
            KeyCode::BackTab => self.set_tab(match self.tab {
                Tab::Map => Tab::Prune,
                Tab::Tree => Tab::Map,
                Tab::Prune => Tab::Tree,
            }),
            KeyCode::Char('R') => {
                self.start_scan();
                self.flash("Rescanning…");
            }
            KeyCode::Char('c') => self.open_review(),
            _ => match self.tab {
                Tab::Map => self.map_key(k.code),
                Tab::Tree => self.tree_key(k.code),
                Tab::Prune => self.prune_key(k.code),
            },
        }
    }

    fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        if let Some(t) = self.tree.clone() {
            match tab {
                Tab::Map => self.sync_focus(),
                Tab::Tree => self.reveal(&t, self.sel),
                Tab::Prune => {}
            }
        }
    }

    fn map_key(&mut self, code: KeyCode) {
        let Some(t) = self.tree.clone() else { return };
        match code {
            KeyCode::Left | KeyCode::Char('h') => self.map_move(-1, 0),
            KeyCode::Right | KeyCode::Char('l') => self.map_move(1, 0),
            KeyCode::Up | KeyCode::Char('k') => self.map_move(0, -1),
            KeyCode::Down | KeyCode::Char('j') => self.map_move(0, 1),
            KeyCode::Tab => {
                if let Some(p) = t.nodes[self.sel].parent {
                    let sib = &t.nodes[p].children;
                    if let Some(pos) = sib.iter().position(|&s| s == self.sel) {
                        self.sel = sib[(pos + 1) % sib.len()];
                    }
                }
            }
            KeyCode::Enter => self.zoom_in(self.sel),
            KeyCode::Backspace | KeyCode::Esc => self.zoom_out(),
            KeyCode::Char(' ') | KeyCode::Char('x') => self.toggle_mark(),
            KeyCode::Char('[') => self.map_depth = (self.map_depth - 1).max(1),
            KeyCode::Char(']') => self.map_depth = (self.map_depth + 1).min(4),
            KeyCode::Char('t') => self.set_tab(Tab::Tree),
            _ => {}
        }
    }

    fn zoom_in(&mut self, idx: usize) {
        let Some(t) = self.tree.clone() else { return };
        let n = &t.nodes[idx];
        if n.kind == NodeKind::Dir && !n.children.is_empty() {
            self.focus = idx;
            self.sel = n.children[0];
        }
    }

    fn zoom_out(&mut self) {
        let Some(t) = self.tree.clone() else { return };
        if let Some(p) = t.nodes[self.focus].parent {
            self.sel = self.focus;
            self.focus = p;
        }
    }

    /// Spatial navigation between sibling tiles, like disktree's arrows.
    fn map_move(&mut self, dx: i32, dy: i32) {
        let Some(t) = self.tree.clone() else { return };
        let parent = t.nodes[self.sel].parent;
        let cur = self.map_tiles.iter().find(|(i, _)| *i == self.sel).map(|(_, r)| *r);
        let Some(cur) = cur else {
            if let Some((i, _)) = self.map_tiles.first() {
                self.sel = *i;
            }
            return;
        };
        let center = |r: &Rect| (r.x as f64 + r.width as f64 / 2.0, (r.y as f64 + r.height as f64 / 2.0) * 2.0);
        let (cx, cy) = center(&cur);
        let best = self
            .map_tiles
            .iter()
            .filter(|(i, _)| *i != self.sel && t.nodes[*i].parent == parent)
            .filter_map(|(i, r)| {
                let (x, y) = center(r);
                let (ddx, ddy) = (x - cx, y - cy);
                let along = ddx * dx as f64 + ddy * dy as f64;
                if along <= 0.5 {
                    return None;
                }
                let across = (ddx * dy as f64).abs() + (ddy * dx as f64).abs();
                Some((along + across * 2.0, *i))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((_, i)) = best {
            self.sel = i;
        }
    }

    fn tree_key(&mut self, code: KeyCode) {
        let Some(t) = self.tree.clone() else { return };
        let rows = self.visible_rows(&t);
        let pos = rows.iter().position(|r| r.0 == self.sel).unwrap_or(0);
        let last = rows.len().saturating_sub(1);
        let n = &t.nodes[self.sel];
        let goto = |p: usize| rows[p.min(last)].0;
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.sel = goto(pos.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.sel = goto(pos + 1),
            KeyCode::PageUp => self.sel = goto(pos.saturating_sub(self.tree_page)),
            KeyCode::PageDown => self.sel = goto(pos + self.tree_page),
            KeyCode::Home | KeyCode::Char('g') => self.sel = goto(0),
            KeyCode::End | KeyCode::Char('G') => self.sel = goto(last),
            KeyCode::Right | KeyCode::Char('l') => {
                if !n.children.is_empty() {
                    if self.expanded[self.sel] {
                        self.sel = n.children[0];
                    } else {
                        self.expanded[self.sel] = true;
                    }
                }
            }
            KeyCode::Enter => {
                if !n.children.is_empty() {
                    self.expanded[self.sel] = !self.expanded[self.sel];
                }
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                if self.expanded[self.sel] && self.sel != 0 {
                    self.expanded[self.sel] = false;
                } else if let Some(p) = n.parent {
                    self.sel = p;
                }
            }
            KeyCode::Char(' ') | KeyCode::Char('x') => self.toggle_mark(),
            KeyCode::Char('m') => {
                self.focus = if n.kind == NodeKind::Dir && !n.children.is_empty() {
                    self.sel
                } else {
                    n.parent.unwrap_or(0)
                };
                if self.focus == self.sel {
                    self.sel = n.children[0];
                }
                self.tab = Tab::Map;
            }
            _ => {}
        }
    }

    fn prune_key(&mut self, code: KeyCode) {
        let len = self.report.findings.len();
        if len == 0 {
            if code == KeyCode::Char('r') {
                self.reanalyze();
            }
            return;
        }
        let last = len - 1;
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.prune_cursor = self.prune_cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.prune_cursor = (self.prune_cursor + 1).min(last),
            KeyCode::PageUp => self.prune_cursor = self.prune_cursor.saturating_sub(self.prune_page),
            KeyCode::PageDown => self.prune_cursor = (self.prune_cursor + self.prune_page).min(last),
            KeyCode::Home | KeyCode::Char('g') => self.prune_cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.prune_cursor = last,
            KeyCode::Char(' ') | KeyCode::Char('x') => self.toggle_finding(self.prune_cursor),
            KeyCode::Char('a') => self.select_tier(Some(Risk::Safe)),
            KeyCode::Char('A') => self.select_tier(None),
            KeyCode::Char('n') => self.checked.clear(),
            KeyCode::Enter => self.open_review(),
            KeyCode::Char('r') => self.reanalyze(),
            KeyCode::Char('t') => self.show_finding_in_tree(),
            _ => {}
        }
    }

    fn toggle_finding(&mut self, idx: usize) {
        let Some(f) = self.report.findings.get(idx) else { return };
        if !f.is_actionable() {
            self.flash("Manual step only — see the details for what to do");
            return;
        }
        let id = f.id.clone();
        if !self.checked.remove(&id) {
            self.checked.insert(id);
        }
    }

    fn select_tier(&mut self, tier: Option<Risk>) {
        for f in &self.report.findings {
            if f.is_actionable() && tier.map_or(true, |t| f.risk == t) {
                self.checked.insert(f.id.clone());
            }
        }
    }

    fn show_finding_in_tree(&mut self) {
        let (Some(t), Some(f)) = (self.tree.clone(), self.report.findings.get(self.prune_cursor)) else {
            return;
        };
        if let Some(i) = f.paths.iter().find_map(|p| t.find(p)) {
            self.sel = i;
            self.reveal(&t, i);
            self.tab = Tab::Tree;
        } else {
            self.flash("That location is outside the scanned tree");
        }
    }

    fn on_mouse(&mut self, m: MouseEvent) {
        let hit = self
            .hits
            .iter()
            .rev()
            .find(|(r, _)| m.column >= r.x && m.column < r.x + r.width && m.row >= r.y && m.row < r.y + r.height)
            .map(|(_, h)| *h);
        match m.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if self.modal == Modal::About {
                    self.modal = Modal::None;
                    return;
                }
                let Some(hit) = hit else { return };
                if self.modal == Modal::Review && !matches!(hit, Hit::Button(_)) {
                    return;
                }
                self.on_hit(hit);
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                if self.modal != Modal::None {
                    return;
                }
                let up = m.kind == MouseEventKind::ScrollUp;
                match self.tab {
                    // Scroll zooms like disktree: in toward the pointer, out again.
                    Tab::Map => {
                        if up {
                            if let (Some(Hit::Node(i)), Some(t)) = (hit, self.tree.clone()) {
                                // Zoom into the child of the focus that contains the tile.
                                let mut top = i;
                                while t.nodes[top].parent != Some(self.focus) {
                                    match t.nodes[top].parent {
                                        Some(p) => top = p,
                                        None => return,
                                    }
                                }
                                self.zoom_in(top);
                            }
                        } else {
                            self.zoom_out();
                        }
                    }
                    Tab::Tree => {
                        for _ in 0..3 {
                            self.tree_key(if up { KeyCode::Up } else { KeyCode::Down });
                        }
                    }
                    Tab::Prune => {
                        for _ in 0..3 {
                            self.prune_key(if up { KeyCode::Up } else { KeyCode::Down });
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn on_hit(&mut self, hit: Hit) {
        match hit {
            Hit::Tab(t) => self.set_tab(t),
            Hit::About => self.modal = Modal::About,
            Hit::Node(i) => {
                if self.sel == i {
                    match self.tab {
                        Tab::Map => self.zoom_in(i),
                        _ => self.tree_key(KeyCode::Enter),
                    }
                } else {
                    self.sel = i;
                }
            }
            Hit::Finding(i) => {
                if self.tab != Tab::Prune {
                    self.prune_cursor = i;
                    self.tab = Tab::Prune;
                } else if self.prune_cursor == i {
                    self.toggle_finding(i);
                } else {
                    self.prune_cursor = i;
                }
            }
            Hit::Button(b) => match b {
                Btn::Toggle => self.toggle_finding(self.prune_cursor),
                Btn::AllSafe => self.select_tier(Some(Risk::Safe)),
                Btn::Clear => {
                    self.checked.clear();
                    self.marked.clear();
                }
                Btn::Review => self.open_review(),
                Btn::Reanalyze => self.reanalyze(),
                Btn::Run => {
                    self.confirm_review(if self.trash_ok { RemoveMode::Trash } else { RemoveMode::Permanent })
                }
                Btn::RunPermanent => self.confirm_review(RemoveMode::Permanent),
                Btn::Cancel => self.cancel_review(),
            },
        }
    }
}

// ------------------------------------------------------------------ terminal

type Term = Terminal<CrosstermBackend<Stdout>>;

fn setup_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let init = || -> io::Result<Term> {
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        let mut t = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        t.clear()?;
        Ok(t)
    };
    // Never leave the terminal raw / on the alternate screen after a failure.
    init().inspect_err(|_| restore_terminal())
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture, Show);
}

pub fn run(cfg: Config) -> Result<()> {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        anyhow::bail!("the terminal UI needs an interactive terminal (and no desktop display was found); use --summary or --json for a report");
    }
    // `kill`, a closed SSH session or a stray SIGINT must not leave the
    // terminal raw and on the alternate screen.
    if let Ok(mut signals) = signal_hook::iterator::Signals::new([signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP, signal_hook::consts::SIGINT, signal_hook::consts::SIGQUIT]) {
        std::thread::spawn(move || {
            if let Some(sig) = signals.forever().next() {
                restore_terminal();
                std::process::exit(128 + sig);
            }
        });
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev(info);
    }));
    let mut term = setup_terminal()?;
    let mut app = App::new(cfg);
    app.start_scan();
    let res = event_loop(&mut term, &mut app);
    app.progress.cancel.store(true, Relaxed);
    restore_terminal();
    res
}

/// Redraws only when something changed or an animation is running, so an
/// idle window costs next to no CPU (kind to laptop batteries).
fn event_loop(term: &mut Term, app: &mut App) -> Result<()> {
    let mut dirty = true;
    loop {
        let got_msgs = app.drain_messages();
        let animating = (app.tree.is_none() && app.scan_error.is_none())
            || app.rules_pending > 0
            || app.status.as_ref().is_some_and(|(_, at)| at.elapsed() < Duration::from_millis(4200));
        if dirty || got_msgs || animating {
            term.draw(|f| draw(f, app))?;
            dirty = false;
        }
        if app.quit {
            return Ok(());
        }
        if let Some(req) = app.exec.take() {
            run_cleanup(term, app, req)?;
            dirty = true;
            continue;
        }
        let timeout = Duration::from_millis(if animating { 80 } else { 500 });
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(k) if k.kind == KeyEventKind::Press => app.on_key(k),
                Event::Mouse(m) => app.on_mouse(m),
                _ => {}
            }
            dirty = true;
        }
    }
}

/// Leave the TUI, run the confirmed actions in the normal terminal (so sudo can
/// prompt), report what was freed, then come back.
fn run_cleanup(term: &mut Term, app: &mut App, req: ExecRequest) -> Result<()> {
    restore_terminal();
    let before = disk_info(&app.cfg.root).map(|d| d.avail);
    println!("\x1b[1;35m━━ linux_disk_prune · cleanup ━━\x1b[0m");
    let home = app.cfg.rule_ctx.home.clone();
    let done = cleanup::execute(&req.findings, &home);
    let mut removed = 0;
    if !req.marks.is_empty() {
        let verb = if req.mode == RemoveMode::Trash { "Moving to trash" } else { "Deleting permanently" };
        println!("\n\x1b[1;36m{verb}: {} marked item(s)\x1b[0m", req.marks.len());
        removed = cleanup::remove_marked(&req.marks, req.mode, &home, &mut |l| println!("  {l}")).0;
    }
    let after = disk_info(&app.cfg.root).map(|d| d.avail);
    println!(
        "\n\x1b[1m{} of {} cleanup action(s) and {} of {} marked item(s) completed.\x1b[0m",
        done,
        req.findings.len(),
        removed,
        req.marks.len()
    );
    if let (Some(b), Some(a)) = (before, after) {
        println!("\x1b[1;32mFree space gained on this filesystem: {}\x1b[0m", fmt_size(a.saturating_sub(b)));
        if req.mode == RemoveMode::Trash && removed > 0 {
            println!("\x1b[2m(trashed items still use space until the trash is emptied)\x1b[0m");
        }
    }
    print!("\nPress Enter to return to linux_disk_prune… ");
    let _ = io::stdout().flush();
    let _ = io::stdin().lock().read_line(&mut String::new());

    *term = setup_terminal()?;
    for f in &req.findings {
        app.checked.remove(&f.id);
    }
    if removed > 0 {
        app.start_scan();
        app.flash("Rescanning so the numbers match the disk…");
    } else {
        app.reanalyze();
        app.flash("Re-analyzing…");
    }
    Ok(())
}

// ------------------------------------------------------------------ drawing

fn draw(f: &mut Frame, app: &mut App) {
    app.hits.clear();
    let area = f.area();
    f.render_widget(Block::new().style(Style::new().bg(c(BG)).fg(c(FG))), area);
    // Below this the panels have no room; say so instead of drawing garbage.
    if area.height < 12 || area.width < 40 {
        let msg = format!("Terminal too small ({}x{}): need at least 40x12 · q quits", area.width, area.height);
        let line = Rect::new(area.x, area.y + area.height / 2, area.width, area.height.min(1));
        f.render_widget(Paragraph::new(truncate(&msg, area.width as usize)).style(st(MODERATE)), line);
        return;
    }
    let [header, tabs, gauge, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, header);
    draw_tabs(f, app, tabs);
    draw_disk_gauge(f, app, gauge);

    let tree = app.tree.clone();
    match (app.tab, tree) {
        (Tab::Prune, _) => draw_prune(f, app, body),
        (_, None) => draw_scanning(f, app, body),
        (tab, Some(t)) => {
            let side = body.width >= 104;
            let [main, panel_area] = if side {
                Layout::horizontal([Constraint::Min(40), Constraint::Length(40)]).areas(body)
            } else {
                [body, Rect::default()]
            };
            if tab == Tab::Map {
                draw_map(f, app, &t, main);
            } else {
                draw_tree(f, app, &t, main);
            }
            if side {
                draw_side_panel(f, app, &t, panel_area);
            }
        }
    }
    draw_footer(f, app, footer);

    match app.modal {
        Modal::Review => draw_review(f, app, area),
        Modal::About => draw_about(f, area),
        Modal::None => {}
    }
}

fn spinner(app: &App) -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    FRAMES[(app.started.elapsed().as_millis() / 80) as usize % FRAMES.len()]
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::styled(" ◆ ", st(AMBER))];
    spans.extend(gradient_text("linux_disk_prune", true));
    spans.push(Span::styled(concat!(" v", env!("CARGO_PKG_VERSION")), st(FAINT)));
    spans.push(Span::styled("  │  ", st(FAINT)));
    spans.push(Span::styled(app.cfg.root.display().to_string(), st(FG).add_modifier(Modifier::BOLD)));
    f.render_widget(Paragraph::new(Line::from(spans)), area);

    let right = match &app.tree {
        Some(t) => {
            let mut s = format!(
                "{} · {} files · {} dirs · {:.1}s",
                fmt_size(t.root().size),
                fmt_count(t.root().files),
                fmt_count(t.dirs),
                t.elapsed.as_secs_f64()
            );
            if t.errors > 0 {
                s.push_str(&format!(" · {} unreadable", fmt_count(t.errors)));
            }
            Line::from(vec![Span::styled(s, st(DIM)), Span::raw(" ")])
        }
        None => Line::from(vec![
            Span::styled(spinner(app), st(ACCENT)),
            Span::styled(
                format!(" scanning · {} files ", fmt_count(app.progress.files.load(Relaxed))),
                st(DIM),
            ),
        ]),
    };
    f.render_widget(Paragraph::new(right).alignment(Alignment::Right), area);
}

fn draw_tabs(f: &mut Frame, app: &mut App, area: Rect) {
    let safe = app.report.total(Risk::Safe);
    let prune_label = if app.report.findings.is_empty() {
        " 3 ♻ Prune ".to_string()
    } else {
        format!(" 3 ♻ Prune · {} safe ", fmt_size(safe))
    };
    let tabs = [
        (Tab::Map, " 1 ▦ Treemap ".to_string()),
        (Tab::Tree, " 2 ≡ Tree ".to_string()),
        (Tab::Prune, prune_label),
    ];
    let mut x = area.x + 1;
    let mut spans = vec![Span::raw(" ")];
    for (tab, label) in tabs {
        let w = label.chars().count() as u16;
        let style = if app.tab == tab {
            Style::new().bg(c(AMBER)).fg(c(BG)).add_modifier(Modifier::BOLD)
        } else {
            Style::new().bg(c(PANEL)).fg(c(DIM))
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
        app.hits.push((Rect::new(x, area.y, w, 1), Hit::Tab(tab)));
        x += w + 1;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    let about = " ? about ";
    let w = about.len() as u16;
    let r = Rect::new(area.right().saturating_sub(w + 1), area.y, w, 1);
    f.render_widget(Paragraph::new(Span::styled(about, st(DIM).bg(c(PANEL)))), r);
    app.hits.push((r, Hit::About));
}

fn draw_disk_gauge(f: &mut Frame, app: &App, area: Rect) {
    let Some(d) = &app.disk else { return };
    let used = d.total.saturating_sub(d.avail);
    let frac = if d.total > 0 { used as f64 / d.total as f64 } else { 0.0 };
    let label = format!(" disk {} ", truncate(&d.mount, 12));
    let bar_w = (area.width / 4).clamp(10, 36);
    let buf = f.buffer_mut();
    buf.set_string(area.x, area.y, &label, st(DIM));
    let bx = area.x + label.chars().count() as u16;
    draw_bar(buf, bx, area.y, bar_w, frac, |t| mix(SAFE, mix(AMBER, DANGER, (t - 0.5) * 2.0), t * 2.0), FAINT, BG);
    let mut spans = vec![
        Span::styled(format!(" {:.0}% used", frac * 100.0), st(FG).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" · {} free of {}", fmt_size(d.avail), fmt_size(d.total)), st(DIM)),
    ];
    let reclaim = app.report.grand_total();
    if reclaim > 0 {
        spans.push(Span::styled("  │  reclaimable ", st(FAINT)));
        spans.push(Span::styled(fmt_size(reclaim), st(SAFE).add_modifier(Modifier::BOLD)));
    }
    if app.rules_pending > 0 {
        spans.push(Span::styled(format!("  {} analyzing", spinner(app)), st(ACCENT)));
    }
    let rest = Rect::new(bx + bar_w, area.y, area.width.saturating_sub(bx + bar_w - area.x), 1);
    f.render_widget(Paragraph::new(Line::from(spans)), rest);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if let Some((msg, at)) = &app.status {
        if at.elapsed() < Duration::from_secs(4) {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(" ● ", st(AMBER)),
                    Span::styled(msg.clone(), st(FG)),
                ])),
                area,
            );
            return;
        }
    }
    let keys: &[(&str, &str)] = match app.tab {
        Tab::Map => &[("←↑↓→", "move"), ("⏎", "zoom in"), ("⌫", "out"), ("␣", "mark"), ("[ ]", "depth"), ("c", "review"), ("?", "help"), ("q", "quit")],
        Tab::Tree => &[("↑↓", "move"), ("→←", "open/close"), ("␣", "mark"), ("m", "treemap"), ("c", "review"), ("R", "rescan"), ("q", "quit")],
        Tab::Prune => &[("↑↓", "move"), ("␣", "select"), ("a", "all safe"), ("n", "none"), ("⏎", "review & clean"), ("t", "show in tree"), ("r", "re-analyze"), ("q", "quit")],
    };
    let mut spans = vec![Span::raw(" ")];
    for (k, label) in keys {
        spans.push(Span::styled(format!(" {k} "), Style::new().bg(c(BORDER)).fg(c(FG)).add_modifier(Modifier::BOLD)));
        spans.push(Span::styled(format!(" {label}  "), st(DIM)));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    let credit = Line::from(vec![
        Span::styled("inspired by ", st(FAINT)),
        Span::styled("disktree", st(DIM).add_modifier(Modifier::ITALIC)),
        Span::styled(" ♥ ", st(CAUTION)),
    ]);
    if area.width > 120 {
        f.render_widget(Paragraph::new(credit).alignment(Alignment::Right), area);
    }
}

fn draw_scanning(f: &mut Frame, app: &App, area: Rect) {
    let card = centered(area, 64, 13);
    f.render_widget(Clear, card);
    let block = panel("Scanning", ACCENT);
    let inner = block.inner(card);
    f.render_widget(block, card);

    if let Some(e) = &app.scan_error {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("Scan failed", st(DANGER).add_modifier(Modifier::BOLD))),
                Line::from(e.clone()),
            ])
            .wrap(Wrap { trim: true }),
            inner.inner(Margin::new(2, 1)),
        );
        return;
    }
    let p = &app.progress;
    let files = p.files.load(Relaxed);
    let secs = app.scan_started.elapsed().as_secs_f64().max(0.001);
    let lines = vec![
        Line::from(vec![Span::styled(format!("{} ", spinner(app)), st(ACCENT)), Span::styled(app.cfg.root.display().to_string(), st(FG).add_modifier(Modifier::BOLD))]),
        Line::raw(""),
        Line::from(vec![Span::styled(format!("{:>14}", fmt_size(p.bytes.load(Relaxed))), st(AMBER).add_modifier(Modifier::BOLD)), Span::styled("  measured", st(DIM))]),
        Line::from(vec![Span::styled(format!("{:>14}", fmt_count(files)), st(FG).add_modifier(Modifier::BOLD)), Span::styled("  files", st(DIM))]),
        Line::from(vec![Span::styled(format!("{:>14}", fmt_count(p.dirs.load(Relaxed))), st(FG).add_modifier(Modifier::BOLD)), Span::styled("  directories", st(DIM))]),
        Line::from(vec![Span::styled(format!("{:>14}", fmt_count((files as f64 / secs) as u64)), st(FG)), Span::styled("  files / second", st(DIM))]),
        Line::from(vec![Span::styled(format!("{:>14}", fmt_count(p.errors.load(Relaxed))), st(if p.errors.load(Relaxed) > 0 { MODERATE } else { DIM })), Span::styled("  unreadable", st(DIM))]),
    ];
    let inner = inner.inner(Margin::new(2, 1));
    f.render_widget(Paragraph::new(lines), inner);

    // A comet sweeping along the bottom edge.
    let y = inner.bottom().saturating_sub(1);
    let w = inner.width;
    let head = (app.started.elapsed().as_millis() / 30) as u16 % (w.max(1) + 16);
    let buf = f.buffer_mut();
    for i in 0..w {
        let dist = head as i32 - i as i32;
        let (sym, col) = if (0..16).contains(&dist) {
            let t = 1.0 - dist as f64 / 16.0;
            ("━", mix(PANEL, grad(i as f64 / w as f64), t))
        } else {
            ("━", mix(PANEL, FAINT, 0.5))
        };
        if let Some(cell) = buf.cell_mut((inner.x + i, y)) {
            cell.set_symbol(sym).set_fg(c(col));
        }
    }
    if !app.report.findings.is_empty() {
        let hint = Rect::new(card.x, card.bottom(), card.width, 1);
        f.render_widget(
            Paragraph::new(Span::styled(
                format!("♻ {} reclaimable found so far — see the Prune tab (3)", fmt_size(app.report.grand_total())),
                st(SAFE),
            ))
            .alignment(Alignment::Center),
            hint,
        );
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(area.x + (area.width - w) / 2, area.y + (area.height - h) / 2, w, h)
}

// ------------------------------------------------------------------ treemap

fn worst(row: &[f64], short: f64) -> f64 {
    let s: f64 = row.iter().sum();
    let mx = row.iter().cloned().fold(f64::MIN, f64::max);
    let mn = row.iter().cloned().fold(f64::MAX, f64::min);
    let (s2, w2) = (s * s, short * short);
    (w2 * mx / s2).max(s2 / (w2 * mn))
}

/// Squarified treemap layout (Bruls et al.). Cells are about twice as tall as
/// they are wide, so the layout runs in a space with doubled height.
fn squarify(sizes: &[f64], area: Rect) -> Vec<Rect> {
    let (x, y, w, h) = (area.x as f64, area.y as f64 * 2.0, area.width as f64, area.height as f64 * 2.0);
    let total: f64 = sizes.iter().sum();
    if total <= 0.0 || w <= 0.0 || h <= 0.0 {
        return vec![Rect::default(); sizes.len()];
    }
    let areas: Vec<f64> = sizes.iter().map(|s| s * w * h / total).collect();
    let mut out = Vec::with_capacity(areas.len());
    let (mut rx, mut ry, mut rw, mut rh) = (x, y, w, h);
    let mut i = 0;
    while i < areas.len() {
        let short = rw.min(rh).max(1e-9);
        let mut end = i + 1;
        let mut best = worst(&areas[i..end], short);
        while end < areas.len() {
            let wv = worst(&areas[i..=end], short);
            if wv > best {
                break;
            }
            best = wv;
            end += 1;
        }
        let row = &areas[i..end];
        let sum: f64 = row.iter().sum();
        if rw >= rh {
            let sw = sum / rh.max(1e-9);
            let mut yy = ry;
            for a in row {
                let hh = a / sw.max(1e-9);
                out.push((rx, yy, sw, hh));
                yy += hh;
            }
            rx += sw;
            rw = (rw - sw).max(0.0);
        } else {
            let sh = sum / rw.max(1e-9);
            let mut xx = rx;
            for a in row {
                let ww = a / sh.max(1e-9);
                out.push((xx, ry, ww, sh));
                xx += ww;
            }
            ry += sh;
            rh = (rh - sh).max(0.0);
        }
        i = end;
    }
    let (ax1, ay1) = (area.right() as f64, area.bottom() as f64);
    out.into_iter()
        .map(|(fx, fy, fw, fh)| {
            let x0 = fx.round().clamp(area.x as f64, ax1);
            let x1 = (fx + fw).round().clamp(area.x as f64, ax1);
            let y0 = (fy / 2.0).round().clamp(area.y as f64, ay1);
            let y1 = ((fy + fh) / 2.0).round().clamp(area.y as f64, ay1);
            Rect::new(x0 as u16, y0 as u16, (x1 - x0) as u16, (y1 - y0) as u16)
        })
        .collect()
}

fn tile_color(app: &App, idx: usize, depth: usize) -> Rgb {
    let base = app.kinds.get(idx).copied().unwrap_or(Kind::Other).rgb();
    // One muted level, lighter with depth.
    mix(BG, base, 0.42 + 0.14 * depth as f64)
}

fn draw_map(f: &mut Frame, app: &mut App, t: &Tree, area: Rect) {
    let focus_path = tilde(&t.path_of(app.focus), &app.cfg.rule_ctx.home);
    let title = format!("Treemap · {}", truncate_left(&focus_path, area.width.saturating_sub(40) as usize));
    let block = panel(&title, AMBER).title_bottom(Line::from(vec![
        Span::styled(format!(" {} ", fmt_size(t.nodes[app.focus].size)), st(AMBER).add_modifier(Modifier::BOLD)),
        Span::styled(format!("depth {} ", app.map_depth), st(DIM)),
    ]));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height < 3 || inner.width < 10 {
        return;
    }
    let [map_area, legend_area] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);

    app.map_tiles.clear();
    let mut tiles = Vec::new();
    layout_level(app, t, app.focus, map_area, 0, &mut tiles);
    let buf = f.buffer_mut();
    for &(idx, r, depth, nested) in &tiles {
        paint_tile(buf, app, t, idx, r, depth, nested);
    }
    // Selection: amber outline around the selected tile, or its nearest drawn ancestor.
    let mut s = Some(app.sel);
    while let Some(i) = s {
        if let Some(&(_, r, _, _)) = tiles.iter().find(|x| x.0 == i) {
            outline(buf, r, AMBER);
            let label = format!(" {} · {} ", t.nodes[i].name, fmt_size(t.nodes[i].size));
            let max = r.width.saturating_sub(4) as usize;
            if max >= 4 && r.height >= 2 {
                buf.set_string(r.x + 1, r.y, truncate(&label, max), Style::new().bg(c(AMBER)).fg(c(BG)).add_modifier(Modifier::BOLD));
            }
            break;
        }
        s = t.nodes[i].parent;
    }
    for &(idx, r, _, _) in &tiles {
        app.hits.push((r, Hit::Node(idx)));
        app.map_tiles.push((idx, r));
    }

    // Legend: colour = kind, hatch = reclaimable, red = marked.
    let mut spans = vec![Span::raw(" ")];
    for k in Kind::LEGEND {
        spans.push(Span::styled("■", st(mix(BG, k.rgb(), 0.85))));
        spans.push(Span::styled(format!(" {}  ", k.label()), st(DIM)));
    }
    spans.push(Span::styled("╱╱", st(SAFE)));
    spans.push(Span::styled(" reclaimable  ", st(DIM)));
    spans.push(Span::styled("■", st(DANGER)));
    spans.push(Span::styled(" marked", st(DIM)));
    f.render_widget(Paragraph::new(Line::from(spans)), legend_area);
}

/// Lay out children of `node` in `r`, recursing into large directories.
/// Emits (node, rect, depth, has_nested_children) in paint order.
fn layout_level(app: &App, t: &Tree, node: usize, r: Rect, depth: usize, out: &mut Vec<(usize, Rect, usize, bool)>) {
    const MAX_TILES: usize = 80;
    let kids: Vec<usize> = t.nodes[node]
        .children
        .iter()
        .copied()
        .filter(|&k| t.nodes[k].size > 0)
        .take(MAX_TILES)
        .collect();
    if kids.is_empty() {
        return;
    }
    let mut sizes: Vec<f64> = kids.iter().map(|&k| t.nodes[k].size as f64).collect();
    // Keep proportions honest when children were cut off.
    let rest = t.nodes[node].size as f64 - sizes.iter().sum::<f64>();
    let has_rest = rest > sizes.last().copied().unwrap_or(0.0) * 0.5;
    if has_rest {
        sizes.push(rest);
    }
    let rects = squarify(&sizes, r);
    for (&k, &kr) in kids.iter().zip(&rects) {
        if kr.width == 0 || kr.height == 0 {
            continue;
        }
        let n = &t.nodes[k];
        let nest = depth + 1 < app.map_depth
            && n.kind == NodeKind::Dir
            && !n.children.is_empty()
            && kr.width >= 12
            && kr.height >= 4;
        out.push((k, kr, depth, nest));
        if nest {
            // Leave a gutter on the right/bottom edges and a name band on top.
            let inner = Rect::new(kr.x, kr.y + 1, kr.width.saturating_sub(1), kr.height.saturating_sub(2));
            layout_level(app, t, k, inner, depth + 1, out);
        }
    }
}

fn paint_tile(buf: &mut Buffer, app: &App, t: &Tree, idx: usize, r: Rect, depth: usize, nested: bool) {
    let n = &t.nodes[idx];
    let marked = app.marked_state(t, idx);
    let mut bg = if marked { mix(BG, DANGER, 0.55 + 0.1 * depth as f64) } else { tile_color(app, idx, depth) };
    if matches!(n.kind, NodeKind::Aggregate | NodeKind::Mount) {
        bg = mix(BG, FAINT, 0.7);
    }
    let hatch = app.reclaim.get(idx).copied().unwrap_or(false) && !marked;
    let hatch_fg = mix(bg, (235, 245, 235), 0.28);
    // Right column and bottom row form a gutter so neighbours stay distinct.
    let gx = if r.width > 2 { 1 } else { 0 };
    let gy = if r.height > 2 { 1 } else { 0 };
    for y in r.y..r.bottom() {
        for x in r.x..r.right() {
            let Some(cell) = buf.cell_mut((x, y)) else { continue };
            if x >= r.right() - gx || y >= r.bottom() - gy {
                cell.set_symbol(" ").set_bg(c(BG));
            } else if hatch && (x as u32 + 2 * y as u32) % 4 == 0 {
                cell.set_symbol("╱").set_fg(c(hatch_fg)).set_bg(c(bg));
            } else {
                cell.set_symbol(" ").set_bg(c(bg));
            }
        }
    }
    let label_w = r.width.saturating_sub(gx + 1) as usize;
    if label_w < 2 || r.height == 0 {
        return;
    }
    let name_style = Style::new().fg(c(FG)).bg(c(bg)).add_modifier(Modifier::BOLD);
    let size_style = Style::new().fg(c(mix(bg, FG, 0.7))).bg(c(bg));
    let size = fmt_size(n.size);
    let icon = match n.kind {
        NodeKind::Dir => "",
        NodeKind::Mount => "⏏ ",
        _ => "",
    };
    let mark = if app.marked.contains(&idx) { "✖ " } else { "" };
    if nested {
        // Name band on the top row of an open directory.
        let band = mix(bg, BG, 0.35);
        for x in r.x..r.right() - gx {
            if let Some(cell) = buf.cell_mut((x, r.y)) {
                cell.set_symbol(" ").set_bg(c(band));
            }
        }
        let text = truncate(&format!("{mark}{icon}{} ", n.name), label_w.saturating_sub(size.len() + 1));
        buf.set_string(r.x + 1, r.y, &text, name_style.bg(c(band)));
        let sx = r.x + 1 + text.chars().count() as u16;
        if (sx as usize) + size.len() <= (r.right() - gx) as usize {
            buf.set_string(sx, r.y, &size, size_style.bg(c(band)));
        }
    } else {
        let text = truncate(&format!("{mark}{icon}{}", n.name), label_w);
        buf.set_string(r.x + 1, r.y, &text, name_style);
        if r.height >= 3 && size.len() <= label_w {
            buf.set_string(r.x + 1, r.y + 1, &size, size_style);
        }
    }
}

fn outline(buf: &mut Buffer, r: Rect, color: Rgb) {
    let (w, h) = (r.width.saturating_sub(if r.width > 2 { 1 } else { 0 }), r.height.saturating_sub(if r.height > 2 { 1 } else { 0 }));
    if w < 2 || h < 2 {
        for x in r.x..r.x + w.max(1) {
            if let Some(cell) = buf.cell_mut((x, r.y)) {
                cell.set_bg(c(color)).set_fg(c(BG));
            }
        }
        return;
    }
    let (x0, y0, x1, y1) = (r.x, r.y, r.x + w - 1, r.y + h - 1);
    let style = Style::new().fg(c(color)).add_modifier(Modifier::BOLD);
    for x in x0..=x1 {
        for (y, ch) in [(y0, "━"), (y1, "━")] {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_symbol(ch).set_style(style);
            }
        }
    }
    for y in y0..=y1 {
        for (x, ch) in [(x0, "┃"), (x1, "┃")] {
            if let Some(cell) = buf.cell_mut((x, y)) {
                cell.set_symbol(ch).set_style(style);
            }
        }
    }
    for (x, y, ch) in [(x0, y0, "┏"), (x1, y0, "┓"), (x0, y1, "┗"), (x1, y1, "┛")] {
        if let Some(cell) = buf.cell_mut((x, y)) {
            cell.set_symbol(ch).set_style(style);
        }
    }
}

// ------------------------------------------------------------------ tree

fn draw_tree(f: &mut Frame, app: &mut App, t: &Tree, area: Rect) {
    let block = panel("Tree", ACCENT);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows = app.visible_rows(t);
    let h = inner.height as usize;
    app.tree_page = h.saturating_sub(1).max(1);
    let pos = rows.iter().position(|r| r.0 == app.sel).unwrap_or(0);
    if pos < app.tree_offset {
        app.tree_offset = pos;
    } else if pos >= app.tree_offset + h {
        app.tree_offset = pos + 1 - h;
    }
    app.tree_offset = app.tree_offset.min(rows.len().saturating_sub(h));

    let root_size = t.root().size.max(1);
    let bar_w: u16 = 12;
    for (row_i, &(idx, depth)) in rows.iter().enumerate().skip(app.tree_offset).take(h) {
        let y = inner.y + (row_i - app.tree_offset) as u16;
        let row = Rect::new(inner.x, y, inner.width.saturating_sub(1), 1);
        let n = &t.nodes[idx];
        let selected = idx == app.sel;
        let row_bg = if selected { SEL_BG } else { PANEL };
        let parent_size = n.parent.map_or(root_size, |p| t.nodes[p].size.max(1));
        let frac = n.size as f64 / parent_size as f64;
        let marked = app.marked_state(t, idx);

        let buf = f.buffer_mut();
        buf.set_style(row, Style::new().bg(c(row_bg)));
        if selected {
            buf.set_string(row.x, y, "▌", st(AMBER).bg(c(row_bg)));
        }
        buf.set_string(row.x + 1, y, format!("{:>10}", fmt_size(n.size)), st(if selected { AMBER } else { FG }).bg(c(row_bg)).add_modifier(Modifier::BOLD));
        draw_bar(buf, row.x + 12, y, bar_w, frac, grad, FAINT, row_bg);
        buf.set_string(row.x + 13 + bar_w, y, format!("{:>5.1}%", frac * 100.0), st(DIM).bg(c(row_bg)));

        let kind_rgb = app.kinds.get(idx).copied().unwrap_or(Kind::Other).rgb();
        let arrow = if n.children.is_empty() {
            match n.kind {
                NodeKind::Dir => "  ",
                NodeKind::Mount => "⏏ ",
                NodeKind::Aggregate => "… ",
                NodeKind::File => "• ",
            }
        } else if app.expanded[idx] {
            "▾ "
        } else {
            "▸ "
        };
        let name_style = match (marked, n.kind) {
            (true, _) => st(DANGER).add_modifier(Modifier::BOLD | Modifier::CROSSED_OUT),
            (_, NodeKind::Dir) => st(mix(kind_rgb, FG, 0.45)).add_modifier(Modifier::BOLD),
            (_, NodeKind::File) => st(FG),
            _ => st(DIM).add_modifier(Modifier::ITALIC),
        };
        let mut spans = vec![
            Span::raw("  ".repeat(depth)),
            Span::styled(arrow, st(DIM)),
            Span::styled("■ ", st(mix(BG, kind_rgb, 0.9))),
            Span::styled(if n.kind == NodeKind::Dir && idx != 0 { format!("{}/", n.name) } else { n.name.clone() }, name_style),
        ];
        if n.unreadable {
            spans.push(Span::styled("  ⚠ permission denied", st(MODERATE)));
        }
        if n.kind == NodeKind::Mount {
            spans.push(Span::styled("  other filesystem (use -x)", st(FAINT)));
        }
        if let Some(risk) = app.finding_nodes.get(&idx) {
            spans.push(Span::styled(format!("  ♻ {}", risk.label()), st(risk_rgb(*risk)).add_modifier(Modifier::BOLD)));
        }
        if app.marked.contains(&idx) {
            spans.push(Span::styled("  ✖ marked", st(DANGER).add_modifier(Modifier::BOLD)));
        }
        let name_x = row.x + 21 + bar_w;
        let name_area = Rect::new(name_x, y, row.right().saturating_sub(name_x), 1);
        f.render_widget(Paragraph::new(Line::from(spans)).style(Style::new().bg(c(row_bg))), name_area);
        app.hits.push((row, Hit::Node(idx)));
    }

    let mut sb = ScrollbarState::new(rows.len().saturating_sub(h)).position(app.tree_offset);
    f.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(st(ACCENT))
            .track_style(st(FAINT)),
        area.inner(Margin::new(0, 1)),
        &mut sb,
    );
}

// ------------------------------------------------------------------ side panel

fn draw_side_panel(f: &mut Frame, app: &mut App, t: &Tree, area: Rect) {
    let marked_n = app.marked.len();
    let [sel_area, look_area, marks_area, disk_area] = Layout::vertical([
        Constraint::Length(9),
        Constraint::Min(4),
        Constraint::Length(if marked_n > 0 { (marked_n as u16).min(4) + 2 } else { 3 }),
        Constraint::Length(6),
    ])
    .areas(area);

    // Selection
    let n = &t.nodes[app.sel];
    let kind = app.kinds.get(app.sel).copied().unwrap_or(Kind::Other);
    let share = n.size as f64 * 100.0 / t.root().size.max(1) as f64;
    let path = tilde(&t.path_of(app.sel), &app.cfg.rule_ctx.home);
    let w = sel_area.width.saturating_sub(4) as usize;
    let mut lines = vec![
        Line::from(Span::styled(truncate(&n.name, w), st(FG).add_modifier(Modifier::BOLD))),
        Line::from(vec![
            Span::styled(fmt_size(n.size), st(AMBER).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {share:.1}% of scan"), st(DIM)),
        ]),
        Line::from(Span::styled(
            format!("{} files{}", fmt_count(n.files), if n.children.is_empty() { String::new() } else { format!(" · {} entries", n.children.len()) }),
            st(DIM),
        )),
        Line::from(vec![
            Span::styled("■ ", st(mix(BG, kind.rgb(), 0.9))),
            Span::styled(kind.label(), st(FG)),
            if app.reclaim.get(app.sel).copied().unwrap_or(false) {
                Span::styled("  ╱╱ can be had back", st(SAFE))
            } else {
                Span::raw("")
            },
        ]),
        Line::from(Span::styled(truncate_left(&path, w), st(FAINT))),
    ];
    if let Some(r) = app.finding_nodes.get(&app.sel) {
        lines.push(Line::from(Span::styled(format!("♻ {} cleanup suggestion — see Prune", r.label()), st(risk_rgb(*r)))));
    }
    f.render_widget(Paragraph::new(lines).block(panel("Selection", AMBER)), sel_area);

    // Top savings: the largest findings.
    let block = panel("Top savings", SAFE);
    let inner = block.inner(look_area);
    f.render_widget(block, look_area);
    let mut y = inner.y;
    let mut top: Vec<(usize, &Finding)> = app.report.findings.iter().enumerate().collect();
    top.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
    if top.is_empty() {
        let msg = if app.rules_pending > 0 { format!("{} analyzing…", spinner(app)) } else { "Nothing notable to reclaim.".into() };
        f.render_widget(Paragraph::new(Span::styled(msg, st(DIM))), inner);
    }
    for (i, fnd) in top.into_iter().take(inner.height as usize) {
        let row = Rect::new(inner.x, y, inner.width, 1);
        let check = if app.checked.contains(&fnd.id) { "✔" } else { "●" };
        let line = Line::from(vec![
            Span::styled(format!("{check} "), st(risk_rgb(fnd.risk))),
            Span::styled(format!("{:>9} ", fmt_size(fnd.bytes)), st(FG).add_modifier(Modifier::BOLD)),
            Span::styled(truncate(&fnd.title, inner.width.saturating_sub(13) as usize), st(DIM)),
        ]);
        f.render_widget(Paragraph::new(line), row);
        app.hits.push((row, Hit::Finding(i)));
        y += 1;
    }

    // Marked
    let mb = app.marked_bytes(t);
    let title = if marked_n > 0 { format!("Marked · {marked_n} · {}", fmt_size(mb)) } else { "Marked".into() };
    let block = panel(&title, DANGER);
    let inner = block.inner(marks_area);
    f.render_widget(block, marks_area);
    if marked_n == 0 {
        f.render_widget(Paragraph::new(Span::styled("Space / x marks a tile for removal", st(FAINT))), inner);
    } else {
        let lines: Vec<Line> = app
            .marked
            .iter()
            .take(inner.height as usize)
            .map(|&i| {
                Line::from(vec![
                    Span::styled("✖ ", st(DANGER)),
                    Span::styled(format!("{:>9} ", fmt_size(t.nodes[i].size)), st(FG)),
                    Span::styled(truncate_left(&tilde(&t.path_of(i), &app.cfg.rule_ctx.home), inner.width.saturating_sub(12) as usize), st(DIM)),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }

    // Disk: free now and after the marks / selections.
    let block = panel("Disk", ACCENT);
    let inner = block.inner(disk_area);
    f.render_widget(block, disk_area);
    if let Some(d) = &app.disk {
        let gain = mb + app.checked_bytes();
        let after = (d.avail + gain).min(d.total);
        let lines = vec![
            Line::from(vec![Span::styled("free now   ", st(DIM)), Span::styled(fmt_size(d.avail), st(FG).add_modifier(Modifier::BOLD))]),
            Line::from(vec![
                Span::styled("after      ", st(DIM)),
                Span::styled(fmt_size(after), st(SAFE).add_modifier(Modifier::BOLD)),
                Span::styled(if gain > 0 { format!("  +{}", fmt_size(gain)) } else { String::new() }, st(SAFE)),
            ]),
        ];
        f.render_widget(Paragraph::new(lines), inner);
        if inner.height >= 3 {
            let y = inner.y + 2;
            let buf = f.buffer_mut();
            let wbar = inner.width.saturating_sub(12);
            let now = 1.0 - d.avail as f64 / d.total.max(1) as f64;
            let aft = 1.0 - after as f64 / d.total.max(1) as f64;
            draw_bar(buf, inner.x, y, wbar, now, |t| if t <= aft { mix(ACCENT, AMBER, t) } else { DANGER }, FAINT, PANEL);
            let btn = " c review ";
            let bx = inner.right().saturating_sub(btn.len() as u16);
            buf.set_string(bx, y, btn, Style::new().bg(c(AMBER)).fg(c(BG)).add_modifier(Modifier::BOLD));
            app.hits.push((Rect::new(bx, y, btn.len() as u16, 1), Hit::Button(Btn::Review)));
        }
    }
}

// ------------------------------------------------------------------ prune

fn draw_prune(f: &mut Frame, app: &mut App, area: Rect) {
    let [cards, stack, body, buttons] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(area);

    // Summary cards.
    let card_areas = Layout::horizontal([Constraint::Ratio(1, 4); 4]).split(cards);
    let specs = [
        (Risk::Safe, "✔ SAFE TO FREE", "pure caches"),
        (Risk::Moderate, "◆ MODERATE", "logs · kernels · snaps"),
        (Risk::Caution, "▲ CAUTION", "project build output"),
    ];
    for (i, (risk, title, sub)) in specs.iter().enumerate() {
        let total = app.report.total(*risk);
        let count = app.report.findings.iter().filter(|f| f.risk == *risk).count();
        let block = panel(title, risk_rgb(*risk)).border_style(st(mix(PANEL, risk_rgb(*risk), 0.6)));
        let lines = vec![
            Line::from(Span::styled(fmt_size(total), st(risk_rgb(*risk)).add_modifier(Modifier::BOLD))).alignment(Alignment::Center),
            Line::from(Span::styled(format!("{count} items · {sub}"), st(DIM))).alignment(Alignment::Center),
        ];
        f.render_widget(Paragraph::new(lines).block(block), card_areas[i].inner(Margin::new(0, 0)));
    }
    let sel_bytes = app.checked_bytes();
    let block = panel("☑ SELECTED", AMBER).border_style(st(mix(PANEL, AMBER, 0.6)));
    f.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(fmt_size(sel_bytes), st(AMBER).add_modifier(Modifier::BOLD))).alignment(Alignment::Center),
            Line::from(Span::styled(format!("{} items · Enter to review", app.checked.len()), st(DIM))).alignment(Alignment::Center),
        ])
        .block(block),
        card_areas[3],
    );

    // Composition bar.
    let total = app.report.grand_total().max(1);
    let buf = f.buffer_mut();
    let w = stack.width.saturating_sub(2);
    let mut acc = 0u64;
    for r in Risk::ALL {
        let part = app.report.total(r);
        let start = (acc as f64 / total as f64 * w as f64).round() as u16;
        acc += part;
        let end = (acc as f64 / total as f64 * w as f64).round() as u16;
        for i in start..end {
            let t = (i - start) as f64 / (end - start).max(1) as f64;
            if let Some(cell) = buf.cell_mut((stack.x + 1 + i, stack.y)) {
                cell.set_symbol("▀").set_fg(c(mix(risk_rgb(r), mix(risk_rgb(r), BG, 0.45), t))).set_bg(c(BG));
            }
        }
    }

    // List + details.
    let wide = body.width >= 100;
    let [list_area, detail_area] = if wide {
        Layout::horizontal([Constraint::Percentage(56), Constraint::Percentage(44)]).areas(body)
    } else {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(body)
    };
    draw_prune_list(f, app, list_area);
    draw_prune_detail(f, app, detail_area);

    // Buttons.
    let btns: [(&str, Btn, Rgb); 5] = [
        (" ␣ select ", Btn::Toggle, BORDER),
        (" a all SAFE ", Btn::AllSafe, mix(PANEL, SAFE, 0.5)),
        (" n clear ", Btn::Clear, BORDER),
        (" ⏎ review & clean… ", Btn::Review, AMBER),
        (" r re-analyze ", Btn::Reanalyze, BORDER),
    ];
    if buttons.height == 0 || buttons.width < 4 {
        return;
    }
    let mut x = buttons.x + 1;
    for (label, btn, bg) in btns {
        let w = label.chars().count() as u16;
        if x + w > buttons.right() {
            break;
        }
        let fg = if bg == AMBER { BG } else { FG };
        f.buffer_mut().set_string(x, buttons.y, label, Style::new().bg(c(bg)).fg(c(fg)).add_modifier(Modifier::BOLD));
        app.hits.push((Rect::new(x, buttons.y, w, 1), Hit::Button(btn)));
        x += w + 2;
    }
}

fn draw_prune_list(f: &mut Frame, app: &mut App, area: Rect) {
    let block = panel("Reclaimable space", SAFE);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Rows: tier headers + findings.
    enum Row {
        Header(Risk),
        Item(usize),
        Note(String),
    }
    let mut rows = Vec::new();
    if app.rules_pending > 0 {
        rows.push(Row::Note(format!("{} analyzing… ({} check groups running)", spinner(app), app.rules_pending)));
    }
    for r in Risk::ALL {
        let items: Vec<usize> = (0..app.report.findings.len()).filter(|&i| app.report.findings[i].risk == r).collect();
        if items.is_empty() {
            continue;
        }
        rows.push(Row::Header(r));
        rows.extend(items.into_iter().map(Row::Item));
    }
    if app.report.findings.is_empty() && app.rules_pending == 0 {
        rows.push(Row::Note("Nothing significant to reclaim — this system is tidy.".into()));
    }
    for n in &app.report.notes {
        rows.push(Row::Note(format!("note: {n}")));
    }

    let h = inner.height as usize;
    app.prune_page = h.saturating_sub(2).max(1);
    let cursor_row = rows.iter().position(|r| matches!(r, Row::Item(i) if *i == app.prune_cursor)).unwrap_or(0);
    if cursor_row < app.prune_offset {
        app.prune_offset = cursor_row.saturating_sub(1);
    } else if cursor_row >= app.prune_offset + h {
        app.prune_offset = cursor_row + 1 - h;
    }
    let max_bytes = app.report.findings.iter().map(|f| f.bytes).max().unwrap_or(1).max(1);

    for (ri, row) in rows.iter().enumerate().skip(app.prune_offset).take(h) {
        let y = inner.y + (ri - app.prune_offset) as u16;
        let rect = Rect::new(inner.x, y, inner.width, 1);
        match row {
            Row::Header(r) => {
                let label = format!("━━ {} · {} ", r.label(), fmt_size(app.report.total(*r)));
                let fill = "━".repeat((inner.width as usize).saturating_sub(label.chars().count()));
                f.render_widget(
                    Paragraph::new(Line::from(vec![
                        Span::styled(label, st(risk_rgb(*r)).add_modifier(Modifier::BOLD)),
                        Span::styled(fill, st(mix(PANEL, risk_rgb(*r), 0.35))),
                    ])),
                    rect,
                );
            }
            Row::Note(n) => {
                f.render_widget(Paragraph::new(Span::styled(truncate(n, inner.width as usize), st(DIM).add_modifier(Modifier::ITALIC))), rect);
            }
            Row::Item(i) => {
                let fnd = &app.report.findings[*i];
                let selected = *i == app.prune_cursor;
                let bg = if selected { SEL_BG } else { PANEL };
                let checked = app.checked.contains(&fnd.id);
                let buf = f.buffer_mut();
                buf.set_style(rect, Style::new().bg(c(bg)));
                if selected {
                    buf.set_string(rect.x, y, "▌", st(AMBER).bg(c(bg)));
                }
                let (box_s, box_c) = if !fnd.is_actionable() {
                    ("[·]", FAINT)
                } else if checked {
                    ("[✔]", risk_rgb(fnd.risk))
                } else {
                    ("[ ]", DIM)
                };
                buf.set_string(rect.x + 1, y, box_s, st(box_c).bg(c(bg)).add_modifier(Modifier::BOLD));
                buf.set_string(rect.x + 5, y, format!("{:>10}", fmt_size(fnd.bytes)), st(if checked { risk_rgb(fnd.risk) } else { FG }).bg(c(bg)).add_modifier(Modifier::BOLD));
                let risk = fnd.risk;
                draw_bar(buf, rect.x + 16, y, 8, fnd.bytes as f64 / max_bytes as f64, |t| mix(risk_rgb(risk), mix(risk_rgb(risk), FG, 0.3), t), FAINT, bg);
                let sudo = if fnd.needs_root && !app.cfg.rule_ctx.is_root { " sudo" } else { "" };
                let title_w = (inner.width as usize).saturating_sub(27 + sudo.len());
                let line = Line::from(vec![
                    Span::styled(truncate(&fnd.title, title_w), st(FG)),
                    Span::styled(sudo, st(MODERATE)),
                ]);
                f.render_widget(Paragraph::new(line).style(Style::new().bg(c(bg))), Rect::new(rect.x + 26, y, rect.width.saturating_sub(26), 1));
                app.hits.push((rect, Hit::Finding(*i)));
            }
        }
    }
}

fn draw_prune_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(fnd) = app.report.findings.get(app.prune_cursor) else {
        f.render_widget(panel("Details", ACCENT), area);
        return;
    };
    let rc = risk_rgb(fnd.risk);
    let mut lines = vec![
        Line::from(Span::styled(fnd.title.clone(), st(FG).add_modifier(Modifier::BOLD))),
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!(" {} ", fnd.risk.label()), Style::new().bg(c(rc)).fg(c(BG)).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {}  ", fnd.category), st(DIM)),
            Span::styled(format!("frees ~{}", fmt_size(fnd.bytes)), st(rc).add_modifier(Modifier::BOLD)),
            Span::styled(if fnd.needs_root { "  · needs root" } else { "  · no root needed" }, st(DIM)),
        ]),
        Line::raw(""),
    ];
    for l in fnd.detail.lines() {
        lines.push(Line::from(Span::styled(l.to_string(), st(FG))));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled("COMMAND", st(ACCENT).add_modifier(Modifier::BOLD))));
    let cmd = fnd.command_text();
    let cmd = if cmd.len() > 600 { format!("{} …", &cmd[..cmd.floor_char_boundary(600)]) } else { cmd };
    lines.push(Line::from(vec![Span::styled("$ ", st(DIM)), Span::styled(cmd, st(AMBER))]));
    if !fnd.paths.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(format!("PATHS ({})", fnd.paths.len()), st(ACCENT).add_modifier(Modifier::BOLD))));
        for p in fnd.paths.iter().take(12) {
            lines.push(Line::from(Span::styled(format!("  {}", tilde(p, &app.cfg.rule_ctx.home)), st(DIM))));
        }
        if fnd.paths.len() > 12 {
            lines.push(Line::from(Span::styled(format!("  … and {} more", fnd.paths.len() - 12), st(FAINT))));
        }
    }
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(panel("Details", ACCENT)), area);
}

// ------------------------------------------------------------------ modals

fn draw_review(f: &mut Frame, app: &mut App, area: Rect) {
    let r = centered(area, area.width.saturating_sub(8).min(110), area.height.saturating_sub(4).min(32));
    f.render_widget(Clear, r);
    let block = panel("Review & clean", AMBER).border_type(BorderType::Thick).border_style(st(AMBER));
    let inner = block.inner(r).inner(Margin::new(2, 1));
    f.render_widget(block, r);

    let findings = app.checked_findings();
    let tree = app.tree.clone();
    let mut lines = Vec::new();
    let mut total = 0u64;
    if !findings.is_empty() {
        lines.push(Line::from(Span::styled(format!("RECOMMENDED CLEANUPS ({})", findings.len()), st(ACCENT).add_modifier(Modifier::BOLD))));
        for fnd in &findings {
            total += fnd.bytes;
            lines.push(Line::from(vec![
                Span::styled("● ", st(risk_rgb(fnd.risk))),
                Span::styled(format!("{:>10}  ", fmt_size(fnd.bytes)), st(FG).add_modifier(Modifier::BOLD)),
                Span::styled(fnd.title.clone(), st(FG)),
            ]));
            let cmd = fnd.command_text();
            lines.push(Line::from(Span::styled(format!("    $ {}", truncate(&cmd, inner.width.saturating_sub(8) as usize)), st(AMBER))));
        }
        lines.push(Line::raw(""));
    }
    if let (false, Some(t)) = (app.marked.is_empty(), &tree) {
        let how = if app.trash_ok { "moved to the trash (t) or deleted permanently (p)" } else { "deleted permanently" };
        lines.push(Line::from(Span::styled(format!("MARKED IN THE TREEMAP ({}) — {how}", app.marked.len()), st(DANGER).add_modifier(Modifier::BOLD))));
        for &i in &app.marked {
            total += t.nodes[i].size;
            lines.push(Line::from(vec![
                Span::styled("✖ ", st(DANGER)),
                Span::styled(format!("{:>10}  ", fmt_size(t.nodes[i].size)), st(FG).add_modifier(Modifier::BOLD)),
                Span::styled(tilde(&t.path_of(i), &app.cfg.rule_ctx.home), st(FG)),
            ]));
        }
        lines.push(Line::raw(""));
    }
    lines.push(Line::from(vec![
        Span::styled("Total to free: ", st(DIM)),
        Span::styled(fmt_size(total), st(SAFE).add_modifier(Modifier::BOLD)),
    ]));
    if findings.iter().any(|f| f.needs_root) && !app.cfg.rule_ctx.is_root {
        lines.push(Line::from(Span::styled("sudo will ask for your password in the terminal.", st(MODERATE))));
    }
    if app.cfg.no_exec {
        lines.push(Line::from(Span::styled("Execution is disabled (--no-exec). Copy the commands above instead.", st(DANGER))));
    }
    let [text, btn_row] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(inner);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text);

    let mut btns: Vec<(String, Btn, Rgb, Rgb)> = Vec::new();
    if !app.cfg.no_exec {
        let run = if !app.marked.is_empty() && app.trash_ok { " ⏎ run · marks to trash " } else { " ⏎ run now " };
        btns.push((run.into(), Btn::Run, AMBER, BG));
        if !app.marked.is_empty() {
            btns.push((" p delete marks permanently ".into(), Btn::RunPermanent, DANGER, BG));
        }
    }
    btns.push((" esc cancel ".into(), Btn::Cancel, BORDER, FG));
    let mut x = btn_row.x;
    for (label, b, bg, fg) in btns {
        let w = label.chars().count() as u16;
        f.buffer_mut().set_string(x, btn_row.y, &label, Style::new().bg(c(bg)).fg(c(fg)).add_modifier(Modifier::BOLD));
        app.hits.push((Rect::new(x, btn_row.y, w, 1), Hit::Button(b)));
        x += w + 2;
    }
}

fn draw_about(f: &mut Frame, area: Rect) {
    let r = centered(area, 78, 26);
    f.render_widget(Clear, r);
    let block = panel("About", ACCENT).border_type(BorderType::Double);
    let mut title = vec![Span::raw("  ◆ ")];
    title.extend(gradient_text("linux_disk_prune", true));
    title.push(Span::styled(concat!("  v", env!("CARGO_PKG_VERSION")), st(DIM)));
    let key = |k: &str, d: &str| {
        Line::from(vec![
            Span::styled(format!("  {k:>12}  "), st(AMBER).add_modifier(Modifier::BOLD)),
            Span::styled(d.to_string(), st(FG)),
        ])
    };
    let lines = vec![
        Line::raw(""),
        Line::from(title),
        Line::from(Span::styled("  Fast disk analyzer & safe cleanup assistant for Ubuntu 22.04", st(DIM))),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  ♥ Inspired by ", st(CAUTION)),
            Span::styled("disktree", st(FG).add_modifier(Modifier::BOLD)),
            Span::styled(" by Tobi Lütke — github.com/tobi/disktree", st(FG)),
        ]),
        Line::from(Span::styled("    The treemap (colour = kind of data, hatching = space you can", st(DIM))),
        Line::from(Span::styled("    have back, amber = selection), the mark → review → remove flow", st(DIM))),
        Line::from(Span::styled("    and the st_blocks / hardlinks-once measuring follow disktree.", st(DIM))),
        Line::raw(""),
        key("1 2 3", "treemap · tree · prune dashboard"),
        key("arrows / hjkl", "move (spatially in the treemap)"),
        key("enter / ⌫", "zoom into / out of a directory (or scroll wheel)"),
        key("space / x", "mark a tile, or select a prune suggestion"),
        key("[  ]", "treemap: draw fewer / more nested levels"),
        key("a  n", "prune: select all SAFE / clear selection"),
        key("c", "review everything marked and selected"),
        key("r  R", "re-analyze rules / rescan the disk"),
        key("q", "quit"),
        Line::raw(""),
        Line::from(Span::styled("  Read-only until you confirm. Nothing is deleted automatically.", st(SAFE))),
        Line::from(Span::styled("  MIT licensed · press any key to close", st(FAINT))),
    ];
    f.render_widget(Paragraph::new(lines).block(block), r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palette_256() {
        assert_eq!(to_256((0, 0, 0)), 16);
        assert_eq!(to_256((255, 255, 255)), 231);
        assert_eq!(to_256((255, 0, 0)), 196);
        assert!((232..=255).contains(&to_256((128, 128, 128))));
    }

    #[test]
    fn squarify_fills_area() {
        let area = Rect::new(0, 0, 80, 20);
        let rects = squarify(&[50.0, 25.0, 15.0, 10.0], area);
        let covered: u32 = rects.iter().map(|r| r.width as u32 * r.height as u32).sum();
        assert_eq!(covered, 80 * 20);
        assert!(rects[0].width as u32 * rects[0].height as u32 > rects[3].width as u32 * rects[3].height as u32);
    }
}
