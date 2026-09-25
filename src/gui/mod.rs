//! Native desktop GUI (eframe/egui), rendered on the GPU through wgpu —
//! Vulkan on Linux, with an OpenGL fallback.
//!
//! The treemap and the mark → review → remove flow follow disktree by Tobi
//! Lütke (https://github.com/tobi/disktree); the Prune dashboard adds the
//! Ubuntu 22.04 recommendation engine.

mod exec;
mod sunburst;
mod theme;
mod treemap;
mod views;

use crate::classify::{classify, Kind};
use crate::cleanup::{self, RemoveMode};
use crate::engine::{self, Engine, Event};
use crate::rules::ubuntu::RuleContext;
use crate::rules::{Finding, Report, Risk};
use crate::scanner::{NodeKind, ScanOptions, Tree};
use crate::util::{fmt_count, fmt_size, tilde};
use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, FontId, Frame, Id, Key, Layout, Margin, RichText,
    Sense, Stroke,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use theme::*;
use treemap::{Tile, Xform};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Renderer {
    Auto,
    Vulkan,
    Gl,
}

pub struct Config {
    pub root: PathBuf,
    pub scan_opts: ScanOptions,
    pub rule_ctx: RuleContext,
    pub no_exec: bool,
    pub renderer: Renderer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Treemap,
    Sunburst,
    Tree,
    Prune,
}

#[derive(Clone, Copy)]
enum Anim {
    /// Zooming into a tile that was at this rect.
    In(egui::Rect),
    /// Zooming out of this node (found in the new layout).
    Out(usize),
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
        .map(|d| Disk { mount: d.mount_point().display().to_string(), total: d.total_space(), avail: d.available_space() })
}

pub struct GuiApp {
    engine: Engine,
    no_exec: bool,
    renderer_info: String,
    /// Drawing happens on a real GPU (not a CPU rasterizer).
    renderer_gpu: bool,
    view: View,

    tree: Option<Arc<Tree>>,
    kinds: Vec<Kind>,
    reclaim: Vec<bool>,
    finding_nodes: HashMap<usize, Risk>,
    scan_error: Option<String>,
    report: Report,

    sel: usize,
    focus: usize,
    expanded: Vec<bool>,
    map_depth: usize,
    tiles: Vec<Tile>,
    anim: Option<(f64, Anim)>,
    scroll_acc: f32,
    menu_node: Option<usize>,
    tree_scroll_to_sel: bool,

    marked: BTreeSet<usize>,
    checked: HashSet<String>,
    prune_cursor: usize,

    review_open: bool,
    remove_mode: RemoveMode,
    trash_ok: bool,
    job: Option<exec::Job>,
    job_disk_before: Option<u64>,
    about_open: bool,
    path_input: String,

    disk: Option<Disk>,
    toast: Option<(String, f64)>,

    /// Ambient motion (aurora, pulses, marching stripes) enabled.
    motion: bool,
    /// Last time the user did anything; ambient motion rests after a while.
    last_active: f64,
    /// Clock for ambient motion; only advances while it runs, so nothing jumps.
    clock: f32,
    /// Bloom-in of the treemap / sweep of the sunburst.
    intro_start: Option<f64>,
    intro_pending: bool,
    sun_start: Option<f64>,
}

impl GuiApp {
    fn new(cc: &eframe::CreationContext<'_>, cfg: Config) -> Self {
        theme::install(&cc.egui_ctx);
        let (renderer_info, renderer_gpu) = renderer_info(cc);
        let ctx = cc.egui_ctx.clone();
        let notify: engine::Notify = Arc::new(move || ctx.request_repaint());
        let mut engine = Engine::new(cfg.root.clone(), cfg.scan_opts, cfg.rule_ctx, notify);
        engine.start_scan();
        Self {
            path_input: cfg.root.display().to_string(),
            disk: disk_info(&cfg.root),
            engine,
            no_exec: cfg.no_exec,
            renderer_info,
            renderer_gpu,
            view: View::Treemap,
            tree: None,
            kinds: Vec::new(),
            reclaim: Vec::new(),
            finding_nodes: HashMap::new(),
            scan_error: None,
            report: Report::default(),
            sel: 0,
            focus: 0,
            expanded: Vec::new(),
            map_depth: 3,
            tiles: Vec::new(),
            anim: None,
            scroll_acc: 0.0,
            menu_node: None,
            tree_scroll_to_sel: false,
            marked: BTreeSet::new(),
            checked: HashSet::new(),
            prune_cursor: 0,
            review_open: false,
            remove_mode: RemoveMode::Trash,
            trash_ok: cleanup::trash_available(),
            job: None,
            job_disk_before: None,
            about_open: false,
            toast: None,
            motion: true,
            last_active: 0.0,
            clock: 0.0,
            intro_start: None,
            intro_pending: false,
            sun_start: None,
        }
    }

    fn home(&self) -> &Path {
        &self.engine.ctx.home
    }

    fn toast(&mut self, ctx: &egui::Context, msg: impl Into<String>) {
        self.toast = Some((msg.into(), ctx.input(|i| i.time)));
    }

    // ------------------------------------------------------------ state

    fn rescan(&mut self, root: Option<PathBuf>) {
        if let Some(r) = root {
            self.engine.root = r;
            self.path_input = self.engine.root.display().to_string();
        }
        self.tree = None;
        self.scan_error = None;
        self.report = Report::default();
        self.marked.clear();
        self.tiles.clear();
        self.disk = disk_info(&self.engine.root);
        self.engine.start_scan();
    }

    fn reanalyze(&mut self) {
        if let Some(t) = self.tree.clone() {
            self.report = Report::default();
            self.disk = disk_info(&self.engine.root);
            self.engine.reanalyze(t);
        }
    }

    fn poll(&mut self) {
        for ev in self.engine.poll() {
            match ev {
                Event::TreeReady(t) => {
                    self.kinds = classify(&t);
                    self.expanded = vec![false; t.nodes.len()];
                    self.expanded[0] = true;
                    self.focus = 0;
                    self.sel = t.nodes[0].children.first().copied().unwrap_or(0);
                    self.anim = None;
                    self.intro_pending = true;
                    self.tree = Some(t);
                    self.refresh_overlays();
                }
                Event::ScanFailed(e) => self.scan_error = Some(e),
                Event::Findings(out) => {
                    let cur = self.report.findings.get(self.prune_cursor).map(|f| f.id.clone());
                    self.report.merge(out);
                    if let Some(id) = cur {
                        self.prune_cursor = self.report.findings.iter().position(|f| f.id == id).unwrap_or(0);
                    }
                    let ids: HashSet<&String> = self.report.findings.iter().map(|f| &f.id).collect();
                    self.checked.retain(|id| ids.contains(id));
                    self.refresh_overlays();
                }
            }
        }
        if let Some(job) = &mut self.job {
            if job.summary.is_none() {
                if let Ok(s) = job.done.try_recv() {
                    job.summary = Some(s);
                    self.disk = disk_info(&self.engine.root);
                }
            }
        }
    }

    fn refresh_overlays(&mut self) {
        if let Some(t) = &self.tree {
            let (r, n) = engine::overlays(t, &self.kinds, &self.report);
            self.reclaim = r;
            self.finding_nodes = n;
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

    fn marked_state(&self, idx: usize) -> bool {
        let Some(t) = &self.tree else { return false };
        let mut cur = Some(idx);
        while let Some(i) = cur {
            if self.marked.contains(&i) {
                return true;
            }
            cur = t.nodes[i].parent;
        }
        false
    }

    fn marked_bytes(&self) -> u64 {
        self.tree.as_ref().map_or(0, |t| self.marked.iter().map(|&i| t.nodes[i].size).sum())
    }

    fn checked_findings(&self) -> Vec<&Finding> {
        self.report.findings.iter().filter(|f| self.checked.contains(&f.id)).collect()
    }

    fn checked_bytes(&self) -> u64 {
        self.checked_findings().iter().map(|f| f.bytes).sum()
    }

    fn toggle_mark(&mut self, ctx: &egui::Context, idx: usize) {
        let Some(t) = self.tree.clone() else { return };
        if self.marked.remove(&idx) {
            self.toast(ctx, format!("Unmarked {}", t.nodes[idx].name));
            return;
        }
        let n = &t.nodes[idx];
        if idx == 0 || matches!(n.kind, NodeKind::Aggregate | NodeKind::Mount) {
            self.toast(ctx, "The scan root, grouped small files and mount points cannot be marked");
            return;
        }
        if self.marked_state(idx) {
            self.toast(ctx, "Already inside a marked directory — unmark that directory instead");
            return;
        }
        let path = t.path_of(idx);
        if let Err(e) = cleanup::check_markable(&path, &t.root_path, self.home()) {
            self.toast(ctx, format!("Can't mark {}: {e}", path.display()));
            return;
        }
        self.marked.retain(|&m| !Self::is_ancestor(&t, idx, m));
        self.marked.insert(idx);
        self.toast(ctx, format!("Marked {} · {}", n.name, fmt_size(n.size)));
    }

    fn select(&mut self, idx: usize) {
        self.sel = idx;
        if let Some(t) = self.tree.clone() {
            let mut p = t.nodes[idx].parent;
            while let Some(i) = p {
                self.expanded[i] = true;
                p = t.nodes[i].parent;
            }
            // Keep the treemap focus a strict ancestor of the selection.
            if idx != 0 && !Self::is_ancestor(&t, self.focus, idx) {
                self.focus = t.nodes[idx].parent.unwrap_or(0);
            }
        }
        self.tree_scroll_to_sel = true;
    }

    fn zoom_in(&mut self, time: f64, idx: usize) {
        let Some(t) = self.tree.clone() else { return };
        let n = &t.nodes[idx];
        if n.kind != NodeKind::Dir || n.children.is_empty() || idx == self.focus {
            return;
        }
        let from = self.tiles.iter().find(|x| x.node == idx).map(|x| x.rect);
        self.focus = idx;
        self.sel = n.children[0];
        self.anim = from.map(|r| (time, Anim::In(r)));
    }

    fn zoom_out(&mut self, time: f64) {
        let Some(t) = self.tree.clone() else { return };
        if let Some(p) = t.nodes[self.focus].parent {
            self.anim = Some((time, Anim::Out(self.focus)));
            self.sel = self.focus;
            self.focus = p;
        }
    }

    fn open_review(&mut self, ctx: &egui::Context) {
        if self.checked.is_empty() && self.marked.is_empty() {
            self.toast(ctx, "Nothing selected — tick suggestions in Prune, or mark tiles with Space / right-click");
            return;
        }
        self.remove_mode = if self.trash_ok { RemoveMode::Trash } else { RemoveMode::Permanent };
        self.review_open = true;
    }

    fn start_job(&mut self, ctx: &egui::Context) {
        let findings: Vec<Finding> = self.checked_findings().into_iter().cloned().collect();
        let marks: Vec<(PathBuf, u64)> = match &self.tree {
            Some(t) => self.marked.iter().map(|&i| (t.path_of(i), t.nodes[i].size)).collect(),
            None => Vec::new(),
        };
        let c = ctx.clone();
        self.job_disk_before = disk_info(&self.engine.root).map(|d| d.avail);
        self.job = Some(exec::start(
            findings,
            marks,
            self.remove_mode,
            self.engine.ctx.home.clone(),
            self.engine.ctx.is_root,
            Arc::new(move || c.request_repaint()),
        ));
        self.review_open = false;
    }

    fn finish_job(&mut self, ctx: &egui::Context) {
        if let Some(job) = self.job.take() {
            let freed = match (self.job_disk_before, disk_info(&self.engine.root)) {
                (Some(b), Some(a)) => a.avail.saturating_sub(b),
                _ => 0,
            };
            if let Some(s) = job.summary {
                self.toast(ctx, format!("Cleanup finished: {} ok, {} failed · {} freed on disk", s.ok + s.removed_marks, s.failed, fmt_size(freed)));
            }
            self.checked.clear();
            // Scan again so the numbers on screen match the disk.
            self.rescan(None);
        }
    }

    fn set_view(&mut self, v: View, ctx: &egui::Context) {
        if self.view != v {
            let now = ctx.input(|i| i.time);
            match v {
                View::Sunburst => self.sun_start = Some(now),
                View::Treemap => self.intro_start = Some(now),
                View::Tree => self.tree_scroll_to_sel = true,
                View::Prune => {}
            }
        }
        self.view = v;
    }

    /// Ambient motion runs while the window is in use; after a few quiet
    /// seconds it rests (and costs nothing) until the next input.
    fn ambient(&self, ctx: &egui::Context) -> bool {
        let (now, focused) = ctx.input(|i| (i.time, i.viewport().focused.unwrap_or(true)));
        self.motion && focused && now - self.last_active < 8.0
    }

    // ------------------------------------------------------------ keyboard

    fn keyboard(&mut self, ctx: &egui::Context) {
        if self.review_open || self.job.is_some() || self.about_open || ctx.egui_wants_keyboard_input() {
            return;
        }
        let time = ctx.input(|i| i.time);
        let pressed = |k: Key| ctx.input(|i| i.key_pressed(k));
        if pressed(Key::Num1) {
            self.set_view(View::Treemap, ctx);
        }
        if pressed(Key::Num2) {
            self.set_view(View::Sunburst, ctx);
        }
        if pressed(Key::Num3) {
            self.set_view(View::Tree, ctx);
        }
        if pressed(Key::Num4) {
            self.set_view(View::Prune, ctx);
        }
        if pressed(Key::C) {
            self.open_review(ctx);
        }
        if pressed(Key::F5) {
            self.rescan(None);
        }
        let Some(t) = self.tree.clone() else { return };
        match self.view {
            View::Sunburst => {
                if pressed(Key::Enter) {
                    self.zoom_in(time, self.sel);
                    self.sun_start = Some(time);
                }
                if pressed(Key::Backspace) || pressed(Key::Escape) {
                    self.zoom_out(time);
                    self.sun_start = Some(time);
                }
                if pressed(Key::Space) || pressed(Key::X) {
                    self.toggle_mark(ctx, self.sel);
                }
                if pressed(Key::OpenBracket) {
                    self.map_depth = (self.map_depth - 1).max(1);
                }
                if pressed(Key::CloseBracket) {
                    self.map_depth = (self.map_depth + 1).min(6);
                }
            }
            View::Treemap => {
                for (k, dx, dy) in [(Key::ArrowLeft, -1.0, 0.0), (Key::ArrowRight, 1.0, 0.0), (Key::ArrowUp, 0.0, -1.0), (Key::ArrowDown, 0.0, 1.0)] {
                    if pressed(k) {
                        self.map_move(&t, dx, dy);
                    }
                }
                if pressed(Key::Enter) {
                    self.zoom_in(time, self.sel);
                }
                if pressed(Key::Backspace) || pressed(Key::Escape) {
                    self.zoom_out(time);
                }
                if pressed(Key::Space) || pressed(Key::X) {
                    self.toggle_mark(ctx, self.sel);
                }
                if pressed(Key::OpenBracket) {
                    self.map_depth = (self.map_depth - 1).max(1);
                }
                if pressed(Key::CloseBracket) {
                    self.map_depth = (self.map_depth + 1).min(6);
                }
            }
            View::Tree => {
                let rows = views::visible_rows(&t, &self.expanded);
                let pos = rows.iter().position(|r| r.0 == self.sel).unwrap_or(0);
                let last = rows.len().saturating_sub(1);
                let go = |p: usize, me: &mut Self| {
                    me.sel = rows[p.min(last)].0;
                    me.tree_scroll_to_sel = true;
                };
                if pressed(Key::ArrowUp) {
                    go(pos.saturating_sub(1), self);
                }
                if pressed(Key::ArrowDown) {
                    go(pos + 1, self);
                }
                if pressed(Key::PageUp) {
                    go(pos.saturating_sub(20), self);
                }
                if pressed(Key::PageDown) {
                    go(pos + 20, self);
                }
                let n = &t.nodes[self.sel];
                if pressed(Key::ArrowRight) && !n.children.is_empty() {
                    if self.expanded[self.sel] {
                        self.select(n.children[0]);
                    } else {
                        self.expanded[self.sel] = true;
                    }
                }
                if pressed(Key::ArrowLeft) {
                    if self.expanded[self.sel] && self.sel != 0 {
                        self.expanded[self.sel] = false;
                    } else if let Some(p) = n.parent {
                        self.select(p);
                    }
                }
                if pressed(Key::Enter) && !n.children.is_empty() {
                    self.expanded[self.sel] = !self.expanded[self.sel];
                }
                if pressed(Key::Space) || pressed(Key::X) {
                    self.toggle_mark(ctx, self.sel);
                }
            }
            View::Prune => {
                let len = self.report.findings.len();
                if len > 0 {
                    if pressed(Key::ArrowUp) {
                        self.prune_cursor = self.prune_cursor.saturating_sub(1);
                    }
                    if pressed(Key::ArrowDown) {
                        self.prune_cursor = (self.prune_cursor + 1).min(len - 1);
                    }
                    if pressed(Key::Space) {
                        self.toggle_finding(self.prune_cursor);
                    }
                }
            }
        }
    }

    fn toggle_finding(&mut self, i: usize) {
        if let Some(f) = self.report.findings.get(i) {
            if f.is_actionable() && !self.checked.remove(&f.id) {
                self.checked.insert(f.id.clone());
            }
        }
    }

    /// Spatial navigation between sibling tiles.
    fn map_move(&mut self, t: &Tree, dx: f32, dy: f32) {
        let parent = t.nodes[self.sel].parent;
        let Some(cur) = self.tiles.iter().find(|x| x.node == self.sel).map(|x| x.rect.center()) else {
            if let Some(first) = self.tiles.first() {
                self.sel = first.node;
            }
            return;
        };
        let best = self
            .tiles
            .iter()
            .filter(|x| x.node != self.sel && t.nodes[x.node].parent == parent)
            .filter_map(|x| {
                let d = x.rect.center() - cur;
                let along = d.x * dx + d.y * dy;
                (along > 1.0).then(|| (along + (d.x * dy).abs() * 2.0 + (d.y * dx).abs() * 2.0, x.node))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((_, n)) = best {
            self.sel = n;
        }
    }

    // ------------------------------------------------------------ top & bottom bars

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Wordmark: a pulsing diamond and shimmering gradient text.
            let (logo, _) = ui.allocate_exact_size(vec2(168.0, 32.0), Sense::hover());
            let p = ui.painter_at(logo.expand(8.0));
            let dc = logo.left_center() + vec2(11.0, 0.0);
            let pulse = 0.75 + 0.25 * (self.clock * 2.0).sin();
            theme::radial_blob(&p, dc, 20.0, GLOW, 0.35 * pulse);
            let dia = [dc + vec2(0.0, -9.0), dc + vec2(9.0, 0.0), dc + vec2(0.0, 9.0), dc + vec2(-9.0, 0.0)];
            p.add(egui::Shape::convex_polygon(dia.to_vec(), theme::mix(GLOW, JELLY, 0.5 - 0.5 * (self.clock * 0.9).sin()), Stroke::new(1.0, theme::alpha(Color32::WHITE, 0.6))));
            theme::gradient_text(&p, logo.left_top() + vec2(28.0, 3.0), "Disk Prune", FontId::proportional(23.0), self.clock * 0.07);
            ui.add_space(10.0);
            self.tab_bar(ui);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(egui::Button::new(RichText::new("?").strong()).corner_radius(16)).on_hover_text("About & credits").clicked() {
                    self.about_open = true;
                }
                let n = self.marked.len() + self.checked.len();
                if glow_button(ui, &format!("Review & clean · {n}"), n > 0, self.clock).on_hover_text("Review everything marked and selected (C)").clicked() {
                    self.open_review(ui.ctx());
                }
                let motion_label = if self.motion { "✨ Motion" } else { "✨ Still" };
                if ui.add(egui::Button::new(RichText::new(motion_label).color(if self.motion { GLOW } else { DIM })).corner_radius(16))
                    .on_hover_text("Ambient animation (aurora, pulses, marching stripes). It rests by itself when you are idle.")
                    .clicked()
                {
                    self.motion = !self.motion;
                }
                if ui.add(egui::Button::new("⟳ Rescan").corner_radius(16)).on_hover_text("Scan again (F5)").clicked() {
                    self.rescan(None);
                }
                ui.menu_button("📂 Folder", |ui| {
                    ui.set_min_width(320.0);
                    ui.label(RichText::new("Scan a different folder").color(DIM));
                    let edit = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(300.0));
                    let go = ui.button("Scan").clicked() || (edit.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)));
                    ui.horizontal(|ui| {
                        if ui.button("/  whole disk").clicked() {
                            self.path_input = "/".into();
                            self.rescan(Some("/".into()));
                            ui.close();
                        }
                        if ui.button("~  home").clicked() {
                            let h = self.home().to_path_buf();
                            self.rescan(Some(h));
                            ui.close();
                        }
                    });
                    if go {
                        match std::fs::canonicalize(self.path_input.trim()) {
                            Ok(p) if p.is_dir() => {
                                self.rescan(Some(p));
                                ui.close();
                            }
                            _ => {
                                let msg = format!("Not a directory: {}", self.path_input);
                                self.toast(ui.ctx(), msg);
                            }
                        }
                    }
                });
            });
        });

        // Second row: breadcrumb trail + totals.
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            if let Some(t) = self.tree.clone() {
                let root = t.root_path.clone();
                // Crumbs above the scan root widen the scan (dimmer, like disktree).
                let ancestors: Vec<PathBuf> = root.ancestors().skip(1).map(Path::to_path_buf).collect();
                for a in ancestors.iter().rev() {
                    let label = if a == Path::new("/") { "/".to_string() } else { a.file_name().unwrap().to_string_lossy().into_owned() };
                    if ui.add(egui::Button::new(RichText::new(label).color(FAINT)).frame(false)).on_hover_text(format!("Scan {}", a.display())).clicked() {
                        self.rescan(Some(a.clone()));
                    }
                    ui.label(RichText::new("›").color(FAINT));
                }
                let mut chain = vec![self.focus];
                while let Some(p) = t.nodes[*chain.last().unwrap()].parent {
                    chain.push(p);
                }
                for (i, &node) in chain.iter().rev().enumerate() {
                    // Ancestors of the root are already shown as crumbs, so the root
                    // itself only needs its last component.
                    let name = if node == 0 {
                        root.file_name().map_or_else(|| "/".to_string(), |n| n.to_string_lossy().into_owned())
                    } else {
                        t.nodes[node].name.clone()
                    };
                    let last = i == chain.len() - 1;
                    let text = RichText::new(name).color(if last { FG } else { ACCENT }).strong();
                    if ui.add(egui::Button::new(text).frame(false)).clicked() {
                        self.focus = node;
                        self.select(if node == 0 { t.nodes[0].children.first().copied().unwrap_or(0) } else { node });
                        self.focus = node;
                        self.view = View::Treemap;
                    }
                    if !last {
                        ui.label(RichText::new("›").color(DIM));
                    }
                }
                ui.add_space(16.0);
                ui.label(RichText::new(format!(
                    "{} · {} files · {} dirs · scanned in {:.1}s{}",
                    fmt_size(t.root().size),
                    fmt_count(t.root().files),
                    fmt_count(t.dirs),
                    t.elapsed.as_secs_f64(),
                    if t.errors > 0 { format!(" · {} unreadable", fmt_count(t.errors)) } else { String::new() }
                )).color(DIM));
            } else {
                ui.add(egui::Spinner::new().size(14.0).color(ACCENT));
                ui.label(RichText::new(format!("Scanning {} …", self.engine.root.display())).color(DIM));
            }
        });
    }

    /// Segmented control with a gradient pill that slides between tabs.
    fn tab_bar(&mut self, ui: &mut egui::Ui) {
        let prune_label = if self.report.findings.is_empty() {
            "♻ Prune".to_string()
        } else {
            format!("♻ Prune · {} safe", fmt_size(self.report.total(Risk::Safe)))
        };
        let tabs = [
            (View::Treemap, "▦ Treemap".to_string()),
            (View::Sunburst, "◉ Sunburst".to_string()),
            (View::Tree, "☰ Tree".to_string()),
            (View::Prune, prune_label),
        ];
        let font = FontId::proportional(14.5);
        let widths: Vec<f32> = tabs.iter().map(|(_, l)| ui.painter().layout_no_wrap(l.clone(), font.clone(), FG).size().x + 30.0).collect();
        let total: f32 = widths.iter().sum::<f32>() + 8.0;
        let (bar, _) = ui.allocate_exact_size(vec2(total, 36.0), Sense::hover());
        let p = ui.painter_at(bar.expand(10.0));
        p.rect_filled(bar, 18.0, CARD);
        p.rect_stroke(bar, 18.0, Stroke::new(1.0, theme::alpha(BORDER, 0.8)), egui::StrokeKind::Inside);
        let mut x = bar.left() + 4.0;
        let mut rects = Vec::new();
        for w in &widths {
            rects.push(egui::Rect::from_min_size(pos2(x, bar.top() + 4.0), vec2(*w, 28.0)));
            x += w;
        }
        let active = tabs.iter().position(|(v, _)| *v == self.view).unwrap_or(0);
        let ctx = ui.ctx().clone();
        let px = ctx.animate_value_with_time(Id::new("tab_pill_x"), rects[active].left(), 0.28);
        let pw = ctx.animate_value_with_time(Id::new("tab_pill_w"), rects[active].width(), 0.28);
        let pill = egui::Rect::from_min_size(pos2(px, rects[active].top()), vec2(pw, 28.0));
        theme::radial_blob(&p, pill.center(), pw * 0.7, JELLY, 0.18);
        theme::gradient_pill(&p, pill, theme::mix(JELLY, GLOW, (self.clock * 0.5).sin() * 0.2 + 0.2), theme::mix(GLOW, JELLY, (self.clock * 0.5).cos() * 0.2 + 0.2));
        let mut clicked = None;
        for (i, ((v, label), r)) in tabs.iter().zip(&rects).enumerate() {
            let resp = ui.interact(*r, Id::new(("tab", i)), Sense::click());
            let on_pill = (r.center().x - pill.center().x).abs() < pw / 2.0;
            let color = if on_pill { BG } else if resp.hovered() { FG } else { DIM };
            p.text(r.center(), Align2::CENTER_CENTER, label, font.clone(), color);
            if resp.clicked() {
                clicked = Some(*v);
            }
        }
        if let Some(v) = clicked {
            self.set_view(v, &ctx);
        }
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            {
                {
                    let hint = match self.view {
                        View::Treemap => "click select · double-click / scroll ↑ zoom in · scroll ↓ / Backspace out · Space mark · right-click menu · [ ] depth",
                        View::Tree => "↑↓ move · → ← open/close · Space mark · right-click menu",
                        View::Sunburst => "click select · double-click / scroll ↑ zoom in · click the hub / Backspace out · Space mark · [ ] rings",
                        View::Prune => "tick suggestions · Review & clean runs them (root actions ask for your password once)",
                    };
                    ui.label(RichText::new(hint).color(FAINT));
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.hyperlink_to(RichText::new("inspired by disktree ♥").color(DIM).italics(), "https://github.com/tobi/disktree");
                ui.label(RichText::new("│").color(FAINT));
                if self.renderer_gpu {
                    ui.label(RichText::new(format!("⚡ {}", self.renderer_info)).color(SAFE))
                        .on_hover_text("Drawn on the GPU");
                } else {
                    ui.label(RichText::new(format!("⚙ {} · software", self.renderer_info)).color(MODERATE)).on_hover_text(
                        "This display is not driven by a GPU driver (for example a virtual X server used for \
                         remote desktop), so drawing happens on the CPU. On a normal Intel session the app \
                         renders with Vulkan on the integrated GPU.",
                    );
                }
                if self.engine.rules_pending > 0 {
                    ui.label(RichText::new("│").color(FAINT));
                    ui.label(RichText::new("analyzing…").color(ACCENT));
                    ui.add(egui::Spinner::new().size(12.0).color(ACCENT));
                }
            });
        });
    }

    // ------------------------------------------------------------ treemap view

    fn treemap_view(&mut self, ui: &mut egui::Ui) {
        let Some(t) = self.tree.clone() else { return };
        let full = ui.available_rect_before_wrap();
        let [map_rect, legend_rect] = {
            let legend_h = 24.0;
            [
                egui::Rect::from_min_max(full.min, pos2(full.max.x, full.max.y - legend_h)),
                egui::Rect::from_min_max(pos2(full.min.x, full.max.y - legend_h), full.max),
            ]
        };
        let resp = ui.allocate_rect(map_rect, Sense::click());
        let painter = ui.painter_at(map_rect);
        painter.rect_filled(map_rect, 12.0, theme::alpha(BG, 0.6));
        painter.rect_stroke(map_rect, 12.0, Stroke::new(1.0, theme::alpha(BORDER, 0.7)), egui::StrokeKind::Inside);

        self.tiles = treemap::layout(&t, self.focus, map_rect.shrink(6.0), self.map_depth);
        let time = ui.input(|i| i.time);
        if std::mem::take(&mut self.intro_pending) {
            self.intro_start = Some(time);
        }
        let intro = self.intro_start.map(|s| (time - s) as f32).filter(|a| *a < 1.4);
        if intro.is_some() {
            ui.ctx().request_repaint();
        } else {
            self.intro_start = None;
        }
        let ambient = self.ambient(ui.ctx());

        // Zoom animation: contents grow into place (or shrink back).
        const DUR: f64 = 0.24;
        let mut xf = Xform::identity();
        let inner = map_rect.shrink(6.0);
        if let Some((start, anim)) = self.anim {
            let raw = ((time - start) / DUR).clamp(0.0, 1.0) as f32;
            let e = 1.0 - (1.0 - raw).powi(3);
            match anim {
                Anim::In(from) => xf = Xform::new(inner, treemap::lerp_rect(from, inner, e)),
                Anim::Out(node) => {
                    if let Some(r) = self.tiles.iter().find(|x| x.node == node).map(|x| x.rect) {
                        xf = Xform::new(r, treemap::lerp_rect(inner, r, e));
                    }
                }
            }
            if raw >= 1.0 {
                self.anim = None;
            } else {
                ui.ctx().request_repaint();
            }
        }

        let pointer = resp.hover_pos();
        let hover = if self.anim.is_none() { pointer.and_then(|p| treemap::hit(&self.tiles, p)) } else { None };
        let marked_fn = |i: usize| self.marked_state(i);
        let pc = treemap::PaintCtx {
            tree: &t,
            kinds: &self.kinds,
            reclaim: &self.reclaim,
            is_marked: &marked_fn,
            sel: self.sel,
            hover,
            time: self.clock,
            ambient,
            intro,
        };
        treemap::paint(&painter, &pc, &self.tiles, xf);

        if t.nodes[self.focus].children.is_empty() {
            painter.text(map_rect.center(), Align2::CENTER_CENTER, "Empty directory", FontId::proportional(16.0), DIM);
        }

        // Interaction.
        if resp.clicked() {
            if let Some(h) = hover {
                self.sel = h;
            }
        }
        if resp.double_clicked() {
            if let Some(h) = hover {
                self.zoom_in(time, h);
            }
        }
        if resp.secondary_clicked() {
            self.menu_node = hover;
            if let Some(h) = hover {
                self.sel = h;
            }
        }
        if resp.hovered() {
            let dy = ui.input(|i| i.smooth_scroll_delta.y);
            self.scroll_acc += dy;
            if self.scroll_acc > 60.0 {
                self.scroll_acc = 0.0;
                // Zoom toward the pointer: into the focus child under it.
                if let Some(mut h) = hover {
                    while t.nodes[h].parent != Some(self.focus) {
                        match t.nodes[h].parent {
                            Some(p) => h = p,
                            None => break,
                        }
                    }
                    self.zoom_in(time, h);
                }
            } else if self.scroll_acc < -60.0 {
                self.scroll_acc = 0.0;
                self.zoom_out(time);
            }
            if let Some(h) = hover {
                self.node_tooltip(&resp, &t, h);
            }
        }
        let menu_node = self.menu_node;
        resp.context_menu(|ui| {
            if let Some(n) = menu_node {
                self.node_menu(ui, &t, n);
            }
        });

        // Legend.
        let lp = ui.painter_at(legend_rect);
        let mut x = legend_rect.left() + 6.0;
        let y = legend_rect.center().y;
        for k in Kind::LEGEND {
            theme::radial_blob(&lp, pos2(x + 5.0, y), 9.0, theme::kind(k), 0.35);
            lp.circle_filled(pos2(x + 5.0, y), 4.0, theme::kind(k));
            let g = lp.layout_no_wrap(k.label().to_string(), FontId::proportional(11.5), DIM);
            let w = g.size().x;
            lp.galley(pos2(x + 14.0, y - g.size().y / 2.0), g, DIM);
            x += w + 28.0;
        }
        let hatch_r = egui::Rect::from_center_size(pos2(x + 8.0, y), vec2(16.0, 10.0));
        lp.rect_filled(hatch_r, 2.0, theme::mix(BG, SAFE, 0.25));
        for i in 0..3 {
            let x0 = hatch_r.left() + i as f32 * 6.0;
            lp.with_clip_rect(hatch_r).line_segment([pos2(x0, hatch_r.bottom()), pos2(x0 + 10.0, hatch_r.top())], Stroke::new(1.3, SAFE));
        }
        lp.text(pos2(x + 20.0, y), Align2::LEFT_CENTER, "reclaimable", FontId::proportional(11.5), DIM);
        let x = x + 100.0;
        lp.rect_filled(egui::Rect::from_center_size(pos2(x + 5.0, y), vec2(10.0, 10.0)), 2.0, DANGER);
        lp.text(pos2(x + 14.0, y), Align2::LEFT_CENTER, "marked", FontId::proportional(11.5), DIM);
        lp.text(pos2(legend_rect.right() - 6.0, y), Align2::RIGHT_CENTER, format!("depth {}  ·  [ ]", self.map_depth), FontId::proportional(11.5), FAINT);
    }

    fn sunburst_view(&mut self, ui: &mut egui::Ui) {
        let Some(t) = self.tree.clone() else { return };
        let full = ui.available_rect_before_wrap();
        let resp = ui.allocate_rect(full, Sense::click());
        let painter = ui.painter_at(full);
        let time = ui.input(|i| i.time);
        let rings = (self.map_depth + 2).clamp(3, 8);
        let r_max = (full.width().min(full.height()) / 2.0 - 16.0).max(60.0);
        let g = sunburst::Geometry { center: full.center(), r_hub: r_max * 0.19, r_max, rings };
        let segs = sunburst::layout(&t, self.focus, rings);
        let sweep = match self.sun_start {
            Some(s) => {
                let v = ((time - s) as f32 / 0.9).clamp(0.0, 1.0);
                if v < 1.0 {
                    ui.ctx().request_repaint();
                } else {
                    self.sun_start = None;
                }
                v
            }
            None => 1.0,
        };
        let pointer = resp.hover_pos();
        let hit = if sweep >= 1.0 { pointer.and_then(|p| sunburst::hit(&segs, &g, p)) } else { None };
        let hover = match hit {
            Some(sunburst::Hit::Seg(n)) => Some(n),
            _ => None,
        };
        let hub_hover = matches!(hit, Some(sunburst::Hit::Hub));
        let marked_fn = |i: usize| self.marked_state(i);
        let ambient = self.ambient(ui.ctx());
        let pc = sunburst::PaintCtx {
            tree: &t,
            kinds: &self.kinds,
            reclaim: &self.reclaim,
            is_marked: &marked_fn,
            sel: self.sel,
            hover,
            time: self.clock,
            ambient,
            sweep,
        };
        sunburst::paint(&painter, &pc, &segs, &g, self.focus, hub_hover);

        // Legend in the corner.
        let mut y = full.top() + 10.0;
        for k in Kind::LEGEND {
            painter.circle_filled(pos2(full.left() + 16.0, y + 6.0), 4.5, theme::kind(k));
            painter.text(pos2(full.left() + 28.0, y + 6.0), Align2::LEFT_CENTER, k.label(), FontId::proportional(12.0), DIM);
            y += 20.0;
        }
        painter.text(pos2(full.left() + 12.0, y + 8.0), Align2::LEFT_CENTER, "lime rim = reclaimable", FontId::proportional(12.0), PLANKTON);
        painter.text(full.right_bottom() - vec2(10.0, 10.0), Align2::RIGHT_BOTTOM, format!("{rings} rings  ·  [ ]"), FontId::proportional(11.5), FAINT);

        if resp.clicked() {
            match hit {
                Some(sunburst::Hit::Hub) => {
                    self.zoom_out(time);
                    self.sun_start = Some(time);
                }
                Some(sunburst::Hit::Seg(n)) => self.sel = n,
                None => {}
            }
        }
        if resp.double_clicked() {
            if let Some(n) = hover {
                if t.nodes[n].kind == NodeKind::Dir && !t.nodes[n].children.is_empty() {
                    self.zoom_in(time, n);
                    self.sun_start = Some(time);
                }
            }
        }
        if resp.secondary_clicked() {
            self.menu_node = hover;
            if let Some(h) = hover {
                self.sel = h;
            }
        }
        if resp.hovered() {
            self.scroll_acc += ui.input(|i| i.smooth_scroll_delta.y);
            if self.scroll_acc > 60.0 {
                self.scroll_acc = 0.0;
                if let Some(n) = hover {
                    self.zoom_in(time, n);
                    self.sun_start = Some(time);
                }
            } else if self.scroll_acc < -60.0 {
                self.scroll_acc = 0.0;
                self.zoom_out(time);
                self.sun_start = Some(time);
            }
            if let Some(h) = hover {
                self.node_tooltip(&resp, &t, h);
            }
        }
        let menu_node = self.menu_node;
        resp.context_menu(|ui| {
            if let Some(n) = menu_node {
                self.node_menu(ui, &t, n);
            }
        });
    }

    fn node_tooltip(&self, resp: &egui::Response, t: &Tree, h: usize) {
        let n = &t.nodes[h];
        let share = n.size as f64 * 100.0 / t.root().size.max(1) as f64;
        let kind = self.kinds.get(h).copied().unwrap_or(Kind::Other);
        let path = tilde(&t.path_of(h), self.home());
        let reclaim = self.reclaim.get(h).copied().unwrap_or(false);
        resp.clone().on_hover_ui_at_pointer(|ui| {
            ui.label(RichText::new(&n.name).strong().size(15.0));
            ui.label(RichText::new(format!("{}  ·  {share:.1}% of scan  ·  {} files", fmt_size(n.size), fmt_count(n.files))).color(GLOW));
            ui.label(RichText::new(format!("● {}", kind.label())).color(theme::kind(kind)));
            if reclaim {
                ui.label(RichText::new("╱╱ space that can be had back").color(PLANKTON));
            }
            ui.label(RichText::new(path).color(DIM).small());
        });
    }

    /// Slow-drifting bioluminescent light behind the content.
    fn aurora(&self, p: &egui::Painter, r: egui::Rect) {
        let t = self.clock;
        let span = r.width().max(r.height());
        let blobs = [
            (JELLY, 0.11, 0.22, 0.30, 0.13, 0.9),
            (GLOW, 0.09, 0.78, 0.68, 0.10, 1.3),
            (ACCENT, 0.08, 0.50, 0.95, 0.07, 0.7),
        ];
        for (col, strength, fx, fy, speed, phase) in blobs {
            let c = pos2(
                r.left() + r.width() * (fx + 0.12 * (t * speed + phase).sin()),
                r.top() + r.height() * (fy + 0.10 * (t * speed * 1.3 + phase).cos()),
            );
            theme::radial_blob(p, c, span * 0.55, col, strength);
        }
    }

    fn toast_overlay(&mut self, ctx: &egui::Context) {
        let Some((msg, at)) = self.toast.clone() else { return };
        let age = (ctx.input(|i| i.time) - at) as f32;
        if age > 5.0 {
            self.toast = None;
            return;
        }
        let slide = theme::ease_out_back((age / 0.35).min(1.0));
        let fade = if age > 4.4 { 1.0 - (age - 4.4) / 0.6 } else { 1.0 };
        ctx.request_repaint();
        egui::Area::new(Id::new("toast"))
            .anchor(Align2::RIGHT_BOTTOM, vec2(-22.0 + (1.0 - slide) * 380.0, -52.0))
            .interactable(false)
            .show(ctx, |ui| {
                ui.set_opacity(fade.clamp(0.0, 1.0));
                Frame::new()
                    .fill(CARD)
                    .corner_radius(12)
                    .inner_margin(Margin::symmetric(16, 12))
                    .stroke(Stroke::new(1.0, theme::alpha(GLOW, 0.6)))
                    .shadow(egui::epaint::Shadow { offset: [0, 8], blur: 28, spread: 0, color: theme::alpha(GLOW, 0.22) })
                    .show(ui, |ui| {
                        ui.set_max_width(420.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("◆").color(GLOW));
                            ui.label(RichText::new(msg).color(FG));
                        });
                    });
            });
    }

    /// Context menu for a node (treemap and tree).
    fn node_menu(&mut self, ui: &mut egui::Ui, t: &Tree, n: usize) {
        let node = &t.nodes[n];
        let path = t.path_of(n);
        ui.label(RichText::new(&node.name).strong());
        ui.label(RichText::new(fmt_size(node.size)).color(AMBER));
        ui.separator();
        let time = ui.input(|i| i.time);
        if node.kind == NodeKind::Dir && !node.children.is_empty() && ui.button("🔍  Zoom into").clicked() {
            self.view = View::Treemap;
            self.zoom_in(time, n);
            ui.close();
        }
        let marked = self.marked.contains(&n);
        if ui.button(if marked { "↩  Unmark" } else { "✖  Mark for removal" }).clicked() {
            self.toggle_mark(ui.ctx(), n);
            ui.close();
        }
        let dir = if node.kind == NodeKind::Dir { path.clone() } else { path.parent().unwrap_or(&path).to_path_buf() };
        if ui.button("📂  Open in Files").clicked() {
            let _ = std::process::Command::new("xdg-open").arg(&dir).spawn();
            ui.close();
        }
        if ui.button("📋  Copy path").clicked() {
            ui.ctx().copy_text(path.display().to_string());
            ui.close();
        }
        if ui.button("☰  Show in tree").clicked() {
            self.select(n);
            self.view = View::Tree;
            ui.close();
        }
    }

    // ------------------------------------------------------------ dialogs

    fn review_dialog(&mut self, ctx: &egui::Context) {
        if !self.review_open {
            return;
        }
        let mut close = false;
        let mut run = false;
        let modal = egui::Modal::new(Id::new("review"))
            .frame(Frame::new().fill(CARD).corner_radius(14).inner_margin(Margin::same(20)).stroke(Stroke::new(1.5, AMBER)))
            .show(ctx, |ui| {
                ui.set_width(760.0_f32.min(ctx.content_rect().width() - 80.0));
                ui.heading(RichText::new("Review & clean").color(AMBER).strong());
                ui.label(RichText::new("Nothing has been changed yet. Untick anything you want to keep.").color(DIM));
                ui.add_space(8.0);
                let mut total = 0u64;
                egui::ScrollArea::vertical().max_height(ctx.content_rect().height() * 0.55).show(ui, |ui| {
                    let findings: Vec<Finding> = self.checked_findings().into_iter().cloned().collect();
                    if !findings.is_empty() {
                        ui.label(RichText::new(format!("RECOMMENDED CLEANUPS ({})", findings.len())).color(ACCENT).strong().small());
                        for f in &findings {
                            total += f.bytes;
                            ui.horizontal(|ui| {
                                if ui.small_button("✖").on_hover_text("Remove from this cleanup").clicked() {
                                    self.checked.remove(&f.id);
                                }
                                ui.label(RichText::new("●").color(theme::risk(f.risk)));
                                ui.label(RichText::new(format!("{:>10}", fmt_size(f.bytes))).monospace().strong());
                                ui.label(&f.title);
                                if f.needs_root && !self.engine.ctx.is_root {
                                    ui.label(RichText::new("admin").small().color(MODERATE));
                                }
                            });
                            let cmd = f.command_text();
                            let short = if cmd.len() > 220 { format!("{}…", &cmd[..cmd.floor_char_boundary(220)]) } else { cmd };
                            ui.label(RichText::new(format!("    $ {short}")).monospace().color(AMBER).size(12.0));
                        }
                        ui.add_space(8.0);
                    }
                    if let (false, Some(t)) = (self.marked.is_empty(), self.tree.clone()) {
                        ui.label(RichText::new(format!("MARKED BY YOU ({})", self.marked.len())).color(DANGER).strong().small());
                        for i in self.marked.clone() {
                            total += t.nodes[i].size;
                            ui.horizontal(|ui| {
                                if ui.small_button("✖").on_hover_text("Unmark").clicked() {
                                    self.marked.remove(&i);
                                }
                                ui.label(RichText::new(format!("{:>10}", fmt_size(t.nodes[i].size))).monospace().strong());
                                ui.label(tilde(&t.path_of(i), self.home()));
                            });
                        }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Marked items:");
                            ui.add_enabled_ui(self.trash_ok, |ui| {
                                ui.radio_value(&mut self.remove_mode, RemoveMode::Trash, "Move to Trash (recoverable)");
                            });
                            ui.radio_value(&mut self.remove_mode, RemoveMode::Permanent, RichText::new("Delete permanently").color(DANGER));
                        });
                    }
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Total to free").color(DIM));
                    ui.label(RichText::new(fmt_size(total)).size(22.0).strong().color(SAFE));
                });
                if self.checked_findings().iter().any(|f| f.needs_root) && !self.engine.ctx.is_root {
                    ui.label(RichText::new("🔒 Admin actions run together — Ubuntu asks for your password once.").color(MODERATE));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let empty = self.checked.is_empty() && self.marked.is_empty();
                    if self.no_exec {
                        ui.label(RichText::new("Execution is disabled (--no-exec). Copy the commands from the Prune view.").color(DANGER));
                    } else {
                        let label = if self.remove_mode == RemoveMode::Permanent && !self.marked.is_empty() { "Clean up & delete permanently" } else { "Clean up now" };
                        let fill = if self.remove_mode == RemoveMode::Permanent && !self.marked.is_empty() { DANGER } else { AMBER };
                        if ui.add_enabled(!empty, egui::Button::new(RichText::new(label).color(BG).strong().size(15.0)).fill(fill).corner_radius(18).min_size(vec2(200.0, 36.0))).clicked() {
                            run = true;
                        }
                    }
                    if ui.add(egui::Button::new("Cancel").corner_radius(18).min_size(vec2(100.0, 36.0))).clicked() {
                        close = true;
                    }
                });
            });
        if modal.should_close() || close {
            self.review_open = false;
        }
        if run {
            self.start_job(ctx);
        }
    }

    fn job_dialog(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.job else { return };
        let finished = job.summary.clone();
        let lines = job.lines.lock().unwrap().clone();
        let mut close = false;
        egui::Modal::new(Id::new("job"))
            .frame(Frame::new().fill(CARD).corner_radius(14).inner_margin(Margin::same(20)).stroke(Stroke::new(1.0, BORDER)))
            .show(ctx, |ui| {
                ui.set_width(820.0_f32.min(ctx.content_rect().width() - 80.0));
                ui.horizontal(|ui| {
                    if finished.is_none() {
                        ui.add(egui::Spinner::new().size(18.0).color(AMBER));
                        ui.heading(RichText::new("Cleaning up…").strong());
                    } else {
                        ui.heading(RichText::new("✔ Cleanup finished").strong().color(SAFE));
                    }
                });
                ui.add_space(6.0);
                Frame::new().fill(BG).corner_radius(8).inner_margin(Margin::same(10)).show(ui, |ui| {
                    egui::ScrollArea::vertical().max_height(380.0).stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                        for (kind, text) in &lines {
                            let rt = RichText::new(text).monospace().size(12.5);
                            ui.label(match kind {
                                exec::LineKind::Heading => rt.color(ACCENT).strong(),
                                exec::LineKind::Command => rt.color(AMBER),
                                exec::LineKind::Output => rt.color(DIM),
                                exec::LineKind::Ok => rt.color(SAFE),
                                exec::LineKind::Error => rt.color(DANGER),
                            });
                        }
                    });
                });
                if let Some(s) = &finished {
                    ui.add_space(8.0);
                    let freed = match (self.job_disk_before, &self.disk) {
                        (Some(b), Some(d)) => d.avail.saturating_sub(b),
                        _ => 0,
                    };
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{} completed · {} failed", s.ok + s.removed_marks, s.failed)).color(DIM));
                        ui.label(RichText::new(format!("{} freed on disk", fmt_size(freed))).strong().size(18.0).color(SAFE));
                    });
                    if self.remove_mode == RemoveMode::Trash && s.removed_marks > 0 {
                        ui.label(RichText::new("Trashed items still use space until the Trash is emptied.").color(DIM).small());
                    }
                    ui.add_space(6.0);
                    if ui.add(egui::Button::new(RichText::new("Done — rescan").color(BG).strong()).fill(AMBER).corner_radius(18).min_size(vec2(160.0, 34.0))).clicked() {
                        close = true;
                    }
                }
            });
        if close {
            self.finish_job(ctx);
        }
    }

    fn about_dialog(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }
        let info = self.renderer_info.clone();
        let threads = self.engine.opts.threads;
        let m = egui::Modal::new(Id::new("about"))
            .frame(Frame::new().fill(CARD).corner_radius(14).inner_margin(Margin::same(24)).stroke(Stroke::new(1.0, BORDER)))
            .show(ctx, |ui| {
                ui.set_width(560.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("◆").size(30.0).color(AMBER));
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Disk Prune").size(26.0).strong().color(grad(0.4)));
                        ui.label(RichText::new(format!("linux_disk_prune {} · Ubuntu 22.04 disk analyzer & cleanup assistant", env!("CARGO_PKG_VERSION"))).color(DIM));
                    });
                });
                ui.add_space(12.0);
                Frame::new().fill(theme::mix(CARD, CAUTION, 0.08)).corner_radius(10).inner_margin(Margin::same(12)).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("♥ Inspired by").color(CAUTION));
                        ui.hyperlink_to(RichText::new("disktree").strong(), "https://github.com/tobi/disktree");
                        ui.label("by Tobi Lütke (MIT).");
                    });
                    ui.label(RichText::new(
                        "The treemap — colour for the kind of data, a hatch for space that can be had back, \
                         one reserved highlight for the selection — the mark → review → remove flow, and \
                         measuring real disk usage with hard links counted once all follow disktree. This is \
                         an independent implementation with a sunburst view, the Abyssal theme and an \
                         Ubuntu-specific recommendation engine.",
                    ).color(DIM));
                });
                ui.add_space(10.0);
                egui::Grid::new("about_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                    ui.label(RichText::new("Renderer").color(DIM));
                    ui.label(RichText::new(&info).color(if self.renderer_gpu { SAFE } else { MODERATE }));
                    ui.end_row();
                    ui.label(RichText::new("Scanner").color(DIM));
                    ui.label(format!("{threads} threads (tuned for the disk type)"));
                    ui.end_row();
                    for (k, d) in [
                        ("1  2  3  4", "Treemap · Sunburst · Tree · Prune"),
                        ("Click / double-click", "select / zoom in"),
                        ("Scroll", "zoom toward the pointer, and back out"),
                        ("Arrows", "move between tiles"),
                        ("Enter / Backspace", "zoom in / out"),
                        ("Space, X", "mark or unmark"),
                        ("[  ]", "fewer / more nested levels"),
                        ("C", "review & clean"),
                        ("✨ Motion", "ambient animation on / off"),
                        ("F5", "rescan"),
                    ] {
                        ui.label(RichText::new(k).color(AMBER).monospace());
                        ui.label(d);
                        ui.end_row();
                    }
                });
                ui.add_space(10.0);
                ui.label(RichText::new("Read-only until you confirm. MIT licensed.").color(SAFE));
                if ui.button("Close").clicked() {
                    ui.close();
                }
            });
        if m.should_close() {
            self.about_open = false;
        }
    }
}

impl eframe::App for GuiApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        // Animate only while something is happening; idle costs nothing.
        if self.tree.is_none() && self.scan_error.is_none() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let (now, dt, busy) = ctx.input(|i| (i.time, i.stable_dt.min(0.1), !i.events.is_empty() || i.pointer.is_moving()));
        if busy || self.last_active == 0.0 {
            self.last_active = now;
        }
        let ambient = self.ambient(&ctx);
        if ambient {
            self.clock += dt;
            // ~30 fps is plenty for slow ambient motion.
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }
        self.keyboard(&ctx);

        egui::Panel::top("top")
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::symmetric(14, 10)))
            .show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("status")
            .frame(Frame::new().fill(PANEL).inner_margin(Margin::symmetric(14, 6)))
            .show(ui, |ui| self.status_bar(ui));
        if self.view != View::Prune {
            egui::Panel::right("side")
                .resizable(true)
                .default_size(360.0)
                .size_range(290.0..=560.0)
                .frame(Frame::new().fill(PANEL).inner_margin(Margin::same(12)))
                .show(ui, |ui| self.side_panel(ui));
        }
        egui::CentralPanel::no_frame()
            .frame(Frame::new().fill(BG).inner_margin(Margin::same(12)))
            .show(ui, |ui| {
                let bg = ui.max_rect().expand(12.0);
                self.aurora(&ui.painter_at(bg), bg);
                match (self.view, self.tree.is_some()) {
                    (View::Prune, _) => self.prune_view(ui),
                    (_, false) => self.scanning_view(ui),
                    (View::Treemap, true) => self.treemap_view(ui),
                    (View::Sunburst, true) => self.sunburst_view(ui),
                    (View::Tree, true) => self.tree_view(ui),
                }
            });
        self.toast_overlay(&ctx);

        self.review_dialog(&ctx);
        self.job_dialog(&ctx);
        self.about_dialog(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.engine.cancel();
    }
}

/// The main-action button: a jelly→cyan gradient pill that glows on hover.
fn glow_button(ui: &mut egui::Ui, text: &str, enabled: bool, clock: f32) -> egui::Response {
    let font = FontId::proportional(14.5);
    let g = ui.painter().layout_no_wrap(text.to_string(), font.clone(), BG);
    let size = vec2(g.size().x + 32.0, 32.0);
    let (r, resp) = ui.allocate_exact_size(size, if enabled { Sense::click() } else { Sense::hover() });
    let p = ui.painter();
    if enabled {
        let hov = ui.ctx().animate_bool_with_time(resp.id, resp.hovered(), 0.18);
        theme::radial_blob(p, r.center(), r.width() * (0.6 + 0.2 * hov), JELLY, 0.18 + 0.2 * hov);
        let shift = 0.15 * (clock * 1.5).sin();
        theme::gradient_pill(p, r, theme::mix(JELLY, GLOW, 0.1 + shift), theme::mix(GLOW, JELLY, 0.1 - shift));
        p.text(r.center(), Align2::CENTER_CENTER, text, font, BG);
    } else {
        p.rect_filled(r, 16.0, CARD);
        p.rect_stroke(r, 16.0, Stroke::new(1.0, theme::alpha(BORDER, 0.8)), egui::StrokeKind::Inside);
        p.text(r.center(), Align2::CENTER_CENTER, text, font, DIM);
    }
    resp
}

/// Human-readable renderer, e.g. "Vulkan · Intel(R) Xe Graphics (TGL GT2)".
/// The flag says whether drawing happens on a real GPU.
fn renderer_info(cc: &eframe::CreationContext<'_>) -> (String, bool) {
    if let Some(rs) = &cc.wgpu_render_state {
        let info = rs.adapter.get_info();
        let backend = match info.backend {
            eframe::wgpu::Backend::Vulkan => "Vulkan".to_string(),
            eframe::wgpu::Backend::Gl => "OpenGL (wgpu)".to_string(),
            b => format!("{b:?}"),
        };
        let gpu = info.device_type != eframe::wgpu::DeviceType::Cpu;
        return (format!("{backend} · {}", info.name), gpu);
    }
    if let Some(gl) = &cc.gl {
        use eframe::glow::HasContext;
        // SAFETY: plain string query on the live context eframe just created.
        let name = unsafe { gl.get_parameter_string(eframe::glow::RENDERER) };
        let gpu = !name.contains("llvmpipe") && !name.contains("softpipe") && !name.contains("SWR");
        return (format!("OpenGL · {name}"), gpu);
    }
    ("unknown renderer".into(), false)
}

fn native_options(renderer: eframe::Renderer, backends: eframe::wgpu::Backends, allow_software: bool) -> eframe::NativeOptions {
    use eframe::wgpu::DeviceType;
    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(c) = &mut wgpu_options.wgpu_setup {
        c.instance_descriptor.backends = backends;
        // Pick a GPU that can present to this window, integrated first: cool,
        // quiet and plenty for 2D. A CPU "GPU" (llvmpipe) is refused unless the
        // user forced Vulkan, so `auto` can fall back to OpenGL instead.
        c.native_adapter_selector = Some(Arc::new(move |adapters, surface| {
            let rank = |t: DeviceType| match t {
                DeviceType::IntegratedGpu => 0,
                DeviceType::DiscreteGpu => 1,
                DeviceType::VirtualGpu | DeviceType::Other => 2,
                DeviceType::Cpu => 3,
            };
            let mut usable: Vec<&eframe::wgpu::Adapter> =
                adapters.iter().filter(|a| surface.is_none_or(|s| a.is_surface_supported(s))).collect();
            usable.sort_by_key(|a| rank(a.get_info().device_type));
            match usable.first() {
                Some(a) if allow_software || a.get_info().device_type != DeviceType::Cpu => Ok((*a).clone()),
                _ => Err("no hardware GPU can present to this display".into()),
            }
        }));
    }
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Disk Prune")
            .with_app_id("linux-disk-prune")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 620.0])
            .with_icon(theme::icon()),
        renderer,
        wgpu_options,
        centered: true,
        ..Default::default()
    }
}

/// Start the desktop app.
///
/// `auto` tries Vulkan on a hardware GPU (the Iris Xe on an Intel laptop). If
/// no GPU can present to this display — e.g. a virtual X server used for
/// remote desktop, where only the CPU rasterizer is available — the app
/// re-launches itself with OpenGL (a process can only own one event loop).
pub fn run(cfg: Config) -> anyhow::Result<()> {
    use eframe::wgpu::Backends;
    let requested = cfg.renderer;
    let (renderer, backends, allow_software) = match requested {
        Renderer::Vulkan => (eframe::Renderer::Wgpu, Backends::VULKAN, true),
        Renderer::Gl => (eframe::Renderer::Glow, Backends::empty(), true),
        Renderer::Auto => (eframe::Renderer::Wgpu, Backends::VULKAN, false),
    };
    let result = eframe::run_native(
        "linux_disk_prune",
        native_options(renderer, backends, allow_software),
        Box::new(move |cc| Ok(Box::new(GuiApp::new(cc, cfg)))),
    );
    match result {
        Ok(()) => Ok(()),
        Err(e) if requested == Renderer::Auto => {
            eprintln!("Vulkan: {e} — falling back to OpenGL");
            relaunch_with_gl()
        }
        Err(e) => Err(anyhow::anyhow!("could not start the window: {e}")),
    }
}

fn relaunch_with_gl() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    let mut args: Vec<std::ffi::OsString> = Vec::new();
    let mut skip_next = false;
    for a in std::env::args_os().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        let s = a.to_string_lossy();
        if s == "--renderer" {
            skip_next = true;
            continue;
        }
        if s.starts_with("--renderer=") {
            continue;
        }
        args.push(a);
    }
    let err = std::process::Command::new(std::env::current_exe()?).args(args).args(["--renderer", "gl"]).exec();
    Err(anyhow::anyhow!("could not relaunch with OpenGL: {err}"))
}

/// Is there a display server to open a window on?
pub fn display_available() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some()
}

pub(crate) fn fmt_share(part: u64, whole: u64) -> String {
    format!("{:.1}%", part as f64 * 100.0 / whole.max(1) as f64)
}

