//! "Large items": every file or folder above a size you choose, as a mosaic,
//! a size histogram, a breakdown by kind and a ranked list.

use super::theme::{self, *};
use super::treemap::{self, squarify};
use super::GuiApp;
use crate::classify::Kind;
use crate::scanner::{NodeKind, Tree};
use crate::util::{fmt_count, fmt_size, tilde};
use eframe::egui::{self, pos2, vec2, Align2, Color32, FontId, Frame, Margin, Rect, RichText, Sense, Stroke, StrokeKind};

const MIB: u64 = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Show {
    Both,
    Files,
    Folders,
}

pub struct LargeState {
    /// Threshold as typed, in MB.
    pub input: String,
    pub min_mb: f64,
    pub show: Show,
    /// Leave out folders that only qualify because a sub-folder does.
    pub innermost: bool,
    pub name: String,
    /// (tree identity, settings) the cached result was computed for.
    key: Option<(usize, u64, Show, bool, String)>,
    results: Vec<usize>,
    /// When the result last changed (drives the grow-in animation).
    changed_at: f64,
}

impl Default for LargeState {
    fn default() -> Self {
        Self { input: "500".into(), min_mb: 500.0, show: Show::Both, innermost: true, name: String::new(), key: None, results: Vec::new(), changed_at: 0.0 }
    }
}

/// Parse "500", "1.5", "2G", "750 MB" into MB.
pub fn parse_mb(s: &str) -> Option<f64> {
    let s = s.trim().to_ascii_lowercase().replace(' ', "");
    let (num, mult) = if let Some(n) = s.strip_suffix("tb").or_else(|| s.strip_suffix('t')) {
        (n, 1024.0 * 1024.0)
    } else if let Some(n) = s.strip_suffix("gb").or_else(|| s.strip_suffix('g')) {
        (n, 1024.0)
    } else if let Some(n) = s.strip_suffix("mb").or_else(|| s.strip_suffix('m')) {
        (n, 1.0)
    } else if let Some(n) = s.strip_suffix("kb").or_else(|| s.strip_suffix('k')) {
        (n, 1.0 / 1024.0)
    } else {
        (s.as_str(), 1.0)
    };
    let v: f64 = num.parse().ok()?;
    (v.is_finite() && v >= 0.0).then_some(v * mult)
}

/// Nodes at least `min` bytes big, largest first. Folded small files and
/// unentered mount points are not items; the scan root is not listed.
pub fn large_items(t: &Tree, min: u64, show: Show, innermost: bool, name: &str) -> Vec<usize> {
    let needle = name.trim().to_lowercase();
    let mut out: Vec<usize> = (1..t.nodes.len())
        .filter(|&i| {
            let n = &t.nodes[i];
            if n.size < min.max(1) {
                return false;
            }
            let ok = match n.kind {
                NodeKind::File => show != Show::Folders,
                NodeKind::Dir => {
                    show != Show::Files
                        && !(innermost && n.children.iter().any(|&c| t.nodes[c].kind == NodeKind::Dir && t.nodes[c].size >= min.max(1)))
                }
                NodeKind::Aggregate | NodeKind::Mount => false,
            };
            ok && (needle.is_empty() || n.name.to_lowercase().contains(&needle))
        })
        .collect();
    out.sort_by(|&a, &b| t.nodes[b].size.cmp(&t.nodes[a].size).then(a.cmp(&b)));
    out
}

/// Histogram buckets as multiples of the threshold: 1–2×, 2–4×, 4–8×, 8–16×, ≥16×.
pub fn buckets(t: &Tree, items: &[usize], min: u64) -> [(u64, usize); 5] {
    let mut b = [(0u64, 0usize); 5];
    for &i in items {
        let ratio = t.nodes[i].size as f64 / min.max(1) as f64;
        let k = if ratio < 2.0 { 0 } else if ratio < 4.0 { 1 } else if ratio < 8.0 { 2 } else if ratio < 16.0 { 3 } else { 4 };
        b[k].0 += t.nodes[i].size;
        b[k].1 += 1;
    }
    b
}

impl GuiApp {
    fn large_refresh(&mut self, t: &Tree, now: f64) {
        let min = (self.large.min_mb * MIB as f64) as u64;
        let key = (t as *const Tree as usize, min, self.large.show, self.large.innermost, self.large.name.clone());
        if self.large.key.as_ref() != Some(&key) {
            self.large.results = large_items(t, min, self.large.show, self.large.innermost, &self.large.name);
            self.large.key = Some(key);
            self.large.changed_at = now;
        }
    }

    pub(super) fn large_view(&mut self, ui: &mut egui::Ui) {
        let Some(t) = self.tree.clone() else { return };
        let now = ui.input(|i| i.time);
        let ctx = ui.ctx().clone();

        // ---- controls
        Frame::new().fill(PANEL).corner_radius(12).inner_margin(Margin::symmetric(14, 10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Show items larger than").color(FG).size(15.0));
                let edit = egui::TextEdit::singleline(&mut self.large.input).desired_width(70.0).font(FontId::proportional(16.0));
                let r = ui.add(edit).on_hover_text("Size in MB. You can also type 2G or 1.5 GB.");
                let parsed = parse_mb(&self.large.input);
                if r.changed() {
                    if let Some(v) = parsed {
                        self.large.min_mb = v;
                    }
                }
                ui.label(RichText::new("MB").color(DIM).size(15.0));
                if parsed.is_none() {
                    ui.label(RichText::new("enter a number").color(DANGER).small());
                }
                ui.add_space(6.0);
                for (label, mb) in [("100 MB", 100.0), ("500 MB", 500.0), ("1 GB", 1024.0), ("5 GB", 5120.0)] {
                    let on = (self.large.min_mb - mb).abs() < 0.01;
                    if ui.add(egui::Button::new(RichText::new(label).color(if on { BG } else { FG })).fill(if on { GLOW } else { CARD }).corner_radius(12)).clicked() {
                        self.large.min_mb = mb;
                        self.large.input = format!("{mb}");
                    }
                }
                ui.add_space(10.0);
                for (s, label) in [(Show::Both, "Files & folders"), (Show::Files, "Files"), (Show::Folders, "Folders")] {
                    let on = self.large.show == s;
                    if ui.add(egui::Button::new(RichText::new(label).color(if on { BG } else { FG })).fill(if on { JELLY } else { CARD }).corner_radius(12)).clicked() {
                        self.large.show = s;
                    }
                }
                ui.add_space(6.0);
                ui.add_enabled(self.large.show != Show::Files, egui::Checkbox::new(&mut self.large.innermost, "innermost folders only"))
                    .on_hover_text("Hide a folder when one of its sub-folders is itself over the limit, so every folder listed is where the space really is.");
                ui.add_space(6.0);
                ui.add(egui::TextEdit::singleline(&mut self.large.name).hint_text("🔎 name contains…").desired_width(150.0));
            });
        });
        self.large_refresh(&t, now);
        let items = self.large.results.clone();
        let min = (self.large.min_mb * MIB as f64) as u64;
        let grow = theme::ease_out_cubic(((now - self.large.changed_at) / 0.7).clamp(0.0, 1.0) as f32);
        if grow < 1.0 {
            ctx.request_repaint();
        }
        ui.add_space(10.0);

        // ---- stats + charts
        // Folders listed together with a file inside them would count twice.
        let total: u64 = items
            .iter()
            .filter(|&&i| {
                let mut p = t.nodes[i].parent;
                while let Some(q) = p {
                    if self.large.results.binary_search_by(|&x| t.nodes[q].size.cmp(&t.nodes[x].size).then(x.cmp(&q))).is_ok() {
                        return false;
                    }
                    p = t.nodes[q].parent;
                }
                true
            })
            .map(|&i| t.nodes[i].size)
            .sum();
        let files = items.iter().filter(|&&i| t.nodes[i].kind == NodeKind::File).count();
        let (charts, _) = ui.allocate_exact_size(vec2(ui.available_width(), 150.0), Sense::hover());
        let p = ui.painter_at(charts.expand(10.0));
        let w = charts.width();
        let stat_r = Rect::from_min_size(charts.min, vec2((w * 0.27).max(220.0), charts.height()));
        let hist_r = Rect::from_min_max(pos2(stat_r.right() + 12.0, charts.top()), pos2(stat_r.right() + 12.0 + (w * 0.40), charts.bottom()));
        let kind_r = Rect::from_min_max(pos2(hist_r.right() + 12.0, charts.top()), charts.max);
        for (r, c) in [(stat_r, GLOW), (hist_r, JELLY), (kind_r, PLANKTON)] {
            theme::vgradient(&p, r.shrink(1.0), theme::mix(CARD, c, 0.10), CARD);
            p.rect_stroke(r, 14.0, Stroke::new(1.0, theme::alpha(c, 0.35)), StrokeKind::Inside);
        }
        // Stats.
        p.text(stat_r.left_top() + vec2(16.0, 18.0), Align2::LEFT_CENTER, format!("OVER {}", fmt_size(min)), FontId::proportional(11.5), GLOW);
        let shown = ctx.animate_value_with_time(egui::Id::new("large_total"), total as f32, 0.6);
        theme::gradient_text(&p, stat_r.left_top() + vec2(16.0, 32.0), &fmt_size(shown as u64), FontId::proportional(30.0), self.clock * 0.1);
        p.text(stat_r.left_top() + vec2(16.0, 84.0), Align2::LEFT_CENTER, format!("{} items · {} files · {} folders", fmt_count(items.len() as u64), fmt_count(files as u64), fmt_count((items.len() - files) as u64)), FontId::proportional(12.0), FG);
        p.text(stat_r.left_top() + vec2(16.0, 106.0), Align2::LEFT_CENTER, format!("{} of the scanned {}", super::fmt_share(total, t.root().size), fmt_size(t.root().size)), FontId::proportional(12.0), DIM);
        p.text(stat_r.left_top() + vec2(16.0, 126.0), Align2::LEFT_CENTER, "(nested items counted once)", FontId::proportional(10.5), FAINT);

        // Histogram.
        p.text(hist_r.left_top() + vec2(16.0, 18.0), Align2::LEFT_CENTER, "SIZE DISTRIBUTION", FontId::proportional(11.5), JELLY);
        let b = buckets(&t, &items, min);
        let maxc = b.iter().map(|x| x.1).max().unwrap_or(0).max(1);
        let labels = ["1–2×", "2–4×", "4–8×", "8–16×", "≥16×"];
        let area = Rect::from_min_max(hist_r.left_top() + vec2(16.0, 46.0), hist_r.right_bottom() - vec2(16.0, 24.0));
        let bw = area.width() / 5.0;
        for (k, &(bytes, count)) in b.iter().enumerate() {
            let h = area.height() * count as f32 / maxc as f32 * grow;
            let col = theme::grad(k as f32 / 5.0);
            let bar = Rect::from_min_max(pos2(area.left() + bw * k as f32 + 6.0, area.bottom() - h.max(2.0)), pos2(area.left() + bw * (k + 1) as f32 - 6.0, area.bottom()));
            theme::radial_blob(&p, bar.center_top(), bw * 0.45, col, 0.18);
            theme::vgradient(&p, bar, col, theme::mix(col, BG, 0.6));
            if count > 0 {
                p.text(bar.center_top() - vec2(0.0, 8.0), Align2::CENTER_CENTER, count.to_string(), FontId::proportional(12.0), FG);
            }
            let tip = ui.interact(bar.union(Rect::from_min_max(pos2(bar.left(), area.top()), bar.max)), egui::Id::new(("hist", k)), Sense::hover());
            tip.on_hover_text(format!("{} × threshold: {count} items, {}", labels[k], fmt_size(bytes)));
            p.text(pos2(bar.center().x, hist_r.bottom() - 12.0), Align2::CENTER_CENTER, labels[k], FontId::proportional(11.0), DIM);
        }

        // Kinds donut.
        p.text(kind_r.left_top() + vec2(16.0, 18.0), Align2::LEFT_CENTER, "WHAT IT IS", FontId::proportional(11.5), PLANKTON);
        let mut by_kind: Vec<(Kind, u64)> = Vec::new();
        for &i in &items {
            let k = self.kinds.get(i).copied().unwrap_or(Kind::Other);
            match by_kind.iter_mut().find(|x| x.0 == k) {
                Some(e) => e.1 += t.nodes[i].size,
                None => by_kind.push((k, t.nodes[i].size)),
            }
        }
        by_kind.sort_by(|a, b| b.1.cmp(&a.1));
        let ksum: u64 = by_kind.iter().map(|x| x.1).sum::<u64>().max(1);
        let dc = pos2(kind_r.left() + 66.0, kind_r.center().y + 8.0);
        let parts: Vec<(f32, Color32)> = by_kind.iter().map(|(k, s)| (*s as f32 / ksum as f32, theme::kind(*k))).collect();
        theme::radial_blob(&p, dc, 60.0, PLANKTON, 0.10);
        theme::donut(&p, dc, 28.0, 44.0, &parts, grow);
        p.text(dc, Align2::CENTER_CENTER, items.len().to_string(), FontId::proportional(15.0), FG);
        for (row, (k, s)) in by_kind.iter().take(5).enumerate() {
            let y = kind_r.top() + 40.0 + row as f32 * 20.0;
            let x = kind_r.left() + 126.0;
            p.circle_filled(pos2(x, y), 4.5, theme::kind(*k));
            p.with_clip_rect(kind_r.shrink(4.0)).text(pos2(x + 10.0, y), Align2::LEFT_CENTER, format!("{}  {}", k.label(), fmt_size(*s)), FontId::proportional(12.0), FG);
        }
        ui.add_space(10.0);

        // ---- mosaic (left) + ranked list (right)
        let avail = ui.available_rect_before_wrap();
        let split = avail.left() + avail.width() * 0.5;
        let map_r = Rect::from_min_max(avail.min, pos2(split - 6.0, avail.max.y));
        let list_r = Rect::from_min_max(pos2(split + 6.0, avail.top()), avail.max);
        if items.is_empty() {
            let p = ui.painter_at(avail);
            p.rect_filled(avail, 12.0, PANEL);
            p.text(avail.center(), Align2::CENTER_CENTER, format!("Nothing over {} here. Try a smaller size.", fmt_size(min)), FontId::proportional(15.0), DIM);
            ui.allocate_rect(avail, Sense::hover());
            return;
        }
        self.large_mosaic(ui, &t, &items, map_r, grow);
        ui.scope_builder(egui::UiBuilder::new().max_rect(list_r), |ui| {
            Frame::new().fill(PANEL).corner_radius(12).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_min_size(list_r.size() - vec2(20.0, 20.0));
                self.large_list(ui, &t, &items, grow);
            });
        });
        ui.allocate_rect(avail, Sense::hover());
    }

    /// Squarified mosaic of the (top 200) results, coloured by kind.
    fn large_mosaic(&mut self, ui: &mut egui::Ui, t: &Tree, items: &[usize], r: Rect, grow: f32) {
        let p = ui.painter_at(r);
        p.rect_filled(r, 12.0, PANEL);
        let shown: Vec<usize> = items.iter().copied().take(200).collect();
        let sizes: Vec<f32> = shown.iter().map(|&i| t.nodes[i].size as f32).collect();
        let area = r.shrink(8.0);
        let rects = squarify(&sizes, area);
        let hover = ui.input(|i| i.pointer.hover_pos());
        let resp = ui.interact(r, egui::Id::new("large_mosaic"), Sense::click());
        let mut hit = None;
        for (k, (&i, rect)) in shown.iter().zip(&rects).enumerate() {
            // Tiles bloom in from their centres, biggest first.
            let local = ((grow - k as f32 / shown.len() as f32 * 0.4) / 0.6).clamp(0.0, 1.0);
            let tr = Rect::from_center_size(rect.center(), rect.size() * theme::ease_out_back(local).max(0.0)).shrink(1.0);
            if tr.width() < 1.0 || tr.height() < 1.0 {
                continue;
            }
            let col = theme::kind(self.kinds.get(i).copied().unwrap_or(Kind::Other));
            let file = t.nodes[i].kind == NodeKind::File;
            let hov = hover.is_some_and(|h| rect.contains(h));
            if hov {
                hit = Some(i);
            }
            let (a, b) = if hov { (theme::mix(col, Color32::WHITE, 0.25), col) } else { (theme::mix(col, BG, 0.15), theme::mix(col, BG, 0.55)) };
            theme::vgradient(&p, tr, a, b);
            if !file {
                // Folders get the hatch the treemap uses for containers.
                p.rect_stroke(tr, 3.0, Stroke::new(1.0, theme::alpha(Color32::WHITE, 0.25)), StrokeKind::Inside);
            }
            if i == self.sel {
                theme::glow_rect(&p, tr, 3.0, GLOW, 0.9);
                p.rect_stroke(tr, 3.0, Stroke::new(2.0, GLOW), StrokeKind::Inside);
            }
            if tr.width() > 46.0 && tr.height() > 30.0 {
                let font = FontId::proportional(12.0);
                if let Some(name) = treemap::fit(&p, &format!("{}{}", if file { "" } else { "▸ " }, t.nodes[i].name), &font, tr.width() - 10.0) {
                    p.text(tr.left_top() + vec2(5.0, 5.0), Align2::LEFT_TOP, name, font, Color32::WHITE);
                    p.text(tr.left_top() + vec2(5.0, 20.0), Align2::LEFT_TOP, fmt_size(t.nodes[i].size), FontId::proportional(11.0), theme::alpha(Color32::WHITE, 0.75));
                }
            }
        }
        if let Some(i) = hit {
            let n = &t.nodes[i];
            resp.clone().on_hover_ui_at_pointer(|ui| {
                ui.label(RichText::new(&n.name).strong());
                ui.label(RichText::new(fmt_size(n.size)).color(GLOW));
                ui.label(RichText::new(tilde(&t.path_of(i), self.home())).small().color(DIM));
                ui.label(RichText::new("click select · double-click open · right-click menu").small().color(FAINT));
            });
            if resp.clicked() || resp.secondary_clicked() {
                self.sel = i;
                self.menu_node = Some(i);
            }
            if resp.double_clicked() {
                super::reveal(&t.path_of(i));
            }
        }
        if let Some(n) = self.menu_node {
            resp.context_menu(|ui| self.node_menu(ui, t, n));
        }
    }

    fn large_list(&mut self, ui: &mut egui::Ui, t: &Tree, items: &[usize], grow: f32) {
        let max = items.first().map(|&i| t.nodes[i].size).unwrap_or(1).max(1);
        let home = self.home().to_path_buf();
        egui::ScrollArea::vertical().id_salt("large_list").auto_shrink([false, false]).show_rows(ui, 40.0, items.len(), |ui, range| {
            for rank in range {
                let i = items[rank];
                let n = &t.nodes[i];
                let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
                let p = ui.painter_at(r);
                let col = theme::kind(self.kinds.get(i).copied().unwrap_or(Kind::Other));
                if i == self.sel {
                    p.rect_filled(r, 7.0, theme::mix(PANEL, GLOW, 0.13));
                    p.rect_filled(Rect::from_min_size(r.min, vec2(3.0, r.height())), 2.0, GLOW);
                } else if resp.hovered() {
                    p.rect_filled(r, 7.0, CARD);
                }
                p.text(pos2(r.left() + 30.0, r.top() + 13.0), Align2::RIGHT_CENTER, format!("{}", rank + 1), FontId::proportional(11.5), FAINT);
                let icon = if n.kind == NodeKind::File { "🗋" } else { "🗀" };
                p.text(pos2(r.left() + 42.0, r.top() + 13.0), Align2::CENTER_CENTER, icon, FontId::proportional(13.0), col);
                let name_r = Rect::from_min_max(pos2(r.left() + 54.0, r.top()), pos2(r.right() - 190.0, r.bottom()));
                p.with_clip_rect(name_r).text(pos2(name_r.left(), r.top() + 13.0), Align2::LEFT_CENTER, &n.name, FontId::proportional(13.5), FG);
                let parent = n.parent.map(|q| tilde(&t.path_of(q), &home)).unwrap_or_default();
                p.with_clip_rect(name_r).text(pos2(name_r.left(), r.top() + 30.0), Align2::LEFT_CENTER, parent, FontId::proportional(11.0), FAINT);
                let bar = Rect::from_min_size(pos2(r.right() - 180.0, r.top() + 10.0), vec2(90.0, 7.0));
                let frac = n.size as f32 / max as f32 * grow;
                p.rect_filled(bar, 3.5, theme::mix(PANEL, FAINT, 0.4));
                let fill = Rect::from_min_size(bar.min, vec2((bar.width() * frac).max(4.0), bar.height()));
                theme::gradient_pill(&p, fill, theme::mix(col, BG, 0.3), col);
                p.text(pos2(r.right() - 8.0, r.top() + 13.0), Align2::RIGHT_CENTER, fmt_size(n.size), FontId::proportional(14.0), FG);
                let mut tags = String::new();
                if let Some(risk) = self.finding_nodes.get(&i) {
                    tags = format!("♻ {} suggestion", risk.label());
                }
                if self.marked.contains(&i) {
                    tags = "✖ marked".into();
                }
                if !tags.is_empty() {
                    p.text(pos2(r.right() - 8.0, r.top() + 30.0), Align2::RIGHT_CENTER, tags, FontId::proportional(11.0), if self.marked.contains(&i) { DANGER } else { SAFE });
                }
                if resp.clicked() || resp.secondary_clicked() {
                    self.sel = i;
                }
                if resp.double_clicked() {
                    super::reveal(&t.path_of(i));
                }
                resp.on_hover_text("double-click to open in Files · right-click for more").context_menu(|ui| self.node_menu(ui, t, i));
            }
        });
    }

    pub(super) fn large_hint(&self) -> &'static str {
        "type a size in MB · click a tile or row to inspect · double-click opens in Files · right-click for Mark / Open / Copy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{scan, Progress, ScanOptions};
    use std::fs;

    fn write(p: &std::path::Path, mb: u64) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let data = vec![1u8; (mb * MIB) as usize];
        fs::write(p, data).unwrap();
    }

    #[test]
    fn parse_sizes() {
        assert_eq!(parse_mb("500"), Some(500.0));
        assert_eq!(parse_mb(" 1.5 GB"), Some(1536.0));
        assert_eq!(parse_mb("2g"), Some(2048.0));
        assert_eq!(parse_mb("750MB"), Some(750.0));
        assert_eq!(parse_mb("512k"), Some(0.5));
        assert_eq!(parse_mb("abc"), None);
        assert_eq!(parse_mb("-3"), None);
    }

    #[test]
    fn finds_files_and_innermost_folders_over_the_limit() {
        let d = std::env::temp_dir().join(format!("ldp-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        write(&d.join("a/big.bin"), 3);
        write(&d.join("a/small.bin"), 1);
        write(&d.join("b/c/one.bin"), 2);
        write(&d.join("b/c/two.bin"), 2);
        write(&d.join("b/tiny.txt"), 0);
        let opts = ScanOptions { min_file_size: 0, ..ScanOptions::default() };
        let t = scan(&d, &opts, &Progress::default()).unwrap();
        let name = |i: usize| t.nodes[i].name.clone();
        let names = |v: Vec<usize>| v.into_iter().map(name).collect::<Vec<_>>();

        // Files only, ≥ 2 MiB, largest first.
        let f = names(large_items(&t, 2 * MIB, Show::Files, true, ""));
        assert_eq!(f[0], "big.bin");
        assert_eq!(f.len(), 3);
        assert!(!f.contains(&"small.bin".to_string()));
        // Folders ≥ 3 MiB: innermost hides b (its child c qualifies); all shows both.
        let inner = names(large_items(&t, 3 * MIB, Show::Folders, true, ""));
        assert!(inner.contains(&"c".to_string()) && inner.contains(&"a".to_string()) && !inner.contains(&"b".to_string()));
        let all = names(large_items(&t, 3 * MIB, Show::Folders, false, ""));
        assert!(all.contains(&"b".to_string()) && all.contains(&"c".to_string()));
        // Root is never listed; name filter is case-insensitive.
        assert!(!large_items(&t, 1, Show::Both, false, "").contains(&0));
        assert_eq!(names(large_items(&t, 1, Show::Both, false, "BIG")), vec!["big.bin".to_string()]);
        // Histogram: 3 MiB file is in 1–2× of 2 MiB? no: 1.5× → bucket 0.
        let b = buckets(&t, &large_items(&t, 2 * MIB, Show::Files, true, ""), 2 * MIB);
        assert_eq!(b[0].1, 3);
        fs::remove_dir_all(&d).unwrap();
    }
}
