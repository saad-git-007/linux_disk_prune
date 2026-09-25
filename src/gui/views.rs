//! Tree view, Prune dashboard, side panel and the scanning screen.

use super::theme::{self, *};
use super::{fmt_share, GuiApp, View};
use crate::classify::Kind;
use crate::rules::{Finding, Risk};
use crate::scanner::{NodeKind, Tree};
use crate::util::{fmt_count, fmt_size, tilde};
use eframe::egui::{
    self, epaint, pos2, vec2, Align, Align2, Color32, FontId, Frame, Layout, Margin, Mesh, Rect,
    RichText, Sense, Stroke, StrokeKind,
};
use std::sync::atomic::Ordering::Relaxed;

const ROW_H: f32 = 24.0;

/// (node, depth) for every row currently visible in the tree view.
pub fn visible_rows(t: &Tree, expanded: &[bool]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut stack = vec![(0usize, 0usize)];
    while let Some((i, d)) = stack.pop() {
        out.push((i, d));
        if expanded[i] {
            for &c in t.nodes[i].children.iter().rev() {
                stack.push((c, d + 1));
            }
        }
    }
    out
}

/// Horizontal bar with a gradient fill (a GPU mesh with per-vertex colours).
fn gradient_bar(p: &egui::Painter, r: Rect, frac: f32, from: Color32, to: Color32, track: Color32) {
    p.rect_filled(r, r.height() / 2.0, track);
    let frac = frac.clamp(0.0, 1.0);
    if frac <= 0.0 {
        return;
    }
    let fr = Rect::from_min_size(r.min, vec2((r.width() * frac).max(r.height()), r.height()));
    let mut mesh = Mesh::default();
    let end = theme::mix(from, to, frac);
    mesh.colored_vertex(fr.left_top(), from);
    mesh.colored_vertex(fr.right_top(), end);
    mesh.colored_vertex(fr.right_bottom(), end);
    mesh.colored_vertex(fr.left_bottom(), from);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    p.with_clip_rect(fr).add(epaint::Shape::mesh(mesh));
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(CARD)
        .corner_radius(10)
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn section(ui: &mut egui::Ui, title: &str, color: Color32) {
    ui.label(RichText::new(title).small().strong().color(color));
}

impl GuiApp {
    // ------------------------------------------------------------ scanning

    pub(super) fn scanning_view(&mut self, ui: &mut egui::Ui) {
        let rect = ui.available_rect_before_wrap();
        let p = ui.painter_at(rect);
        let time = ui.input(|i| i.time) as f32;
        if let Some(e) = &self.scan_error {
            p.text(rect.center(), Align2::CENTER_CENTER, format!("Scan failed: {e}"), FontId::proportional(16.0), DANGER);
            return;
        }
        let pr = &self.engine.progress;
        let files = pr.files.load(Relaxed);
        let secs = self.engine.scan_started.elapsed().as_secs_f64().max(0.001);
        let r = (rect.height() * 0.34).min(rect.width() * 0.3).max(80.0);
        let c = rect.center() - vec2(0.0, 30.0);

        // Sonar: rings, a rotating sweep and blips for what has been found.
        theme::radial_blob(&p, c, r * 1.6, GLOW, 0.10);
        for i in 1..=4 {
            p.circle_stroke(c, r * i as f32 / 4.0, Stroke::new(1.0, theme::alpha(GLOW, 0.10 + 0.04 * i as f32)));
        }
        p.line_segment([c - vec2(r, 0.0), c + vec2(r, 0.0)], Stroke::new(1.0, theme::alpha(GLOW, 0.08)));
        p.line_segment([c - vec2(0.0, r), c + vec2(0.0, r)], Stroke::new(1.0, theme::alpha(GLOW, 0.08)));
        let head = time * 2.2;
        for k in 0..24 {
            let a1 = head - k as f32 * 0.035;
            let fade = 1.0 - k as f32 / 24.0;
            theme::ring_segment(&p, c, 0.0, r, a1 - 0.035, a1, theme::alpha(GLOW, 0.0), theme::alpha(GLOW, 0.35 * fade * fade));
        }
        p.line_segment([c, c + vec2(head.cos(), head.sin()) * r], Stroke::new(2.0, theme::alpha(GLOW, 0.9)));
        // Blips: deterministic pseudo-random positions; brighter right after the sweep passes.
        let blips = ((files as f64).sqrt() as usize / 4).clamp(6, 90);
        for i in 0..blips {
            let h = (i as u32).wrapping_mul(2654435761);
            let ang = (h % 6283) as f32 / 1000.0;
            let dist = r * (0.15 + 0.8 * ((h >> 13) % 1000) as f32 / 1000.0);
            let since = (head - ang).rem_euclid(std::f32::consts::TAU);
            let glow = (1.0 - since / 3.0).max(0.15);
            let col = [GLOW, JELLY, PLANKTON, ACCENT][i % 4];
            let pos = c + vec2(ang.cos(), ang.sin()) * dist;
            theme::radial_blob(&p, pos, 9.0, col, 0.5 * glow);
            p.circle_filled(pos, 2.2, theme::alpha(col, glow));
        }
        // Centre readout.
        let bytes = ui.ctx().animate_value_with_time(egui::Id::new("scan_bytes"), pr.bytes.load(Relaxed) as f32, 0.3);
        let big = fmt_size(bytes as u64);
        let w = p.layout_no_wrap(big.clone(), FontId::proportional(34.0), FG).size().x;
        p.circle_filled(c, r * 0.3, theme::alpha(BG, 0.85));
        p.circle_stroke(c, r * 0.3, Stroke::new(1.5, theme::alpha(GLOW, 0.5)));
        theme::gradient_text(&p, c + vec2(-w / 2.0, -22.0), &big, FontId::proportional(34.0), time * 0.1);
        p.text(c + vec2(0.0, 24.0), Align2::CENTER_CENTER, "measured", FontId::proportional(12.0), DIM);

        p.text(pos2(c.x, c.y + r + 34.0), Align2::CENTER_CENTER, format!("Scanning {}", self.engine.root.display()), FontId::proportional(17.0), FG);
        let stats = [
            (fmt_count(files), "files"),
            (fmt_count(pr.dirs.load(Relaxed)), "folders"),
            (fmt_count((files as f64 / secs) as u64), "files / s"),
            (fmt_count(pr.errors.load(Relaxed)), "unreadable"),
        ];
        for (i, (v, l)) in stats.iter().enumerate() {
            let x = c.x + (i as f32 - 1.5) * 150.0;
            p.text(pos2(x, c.y + r + 70.0), Align2::CENTER_CENTER, v, FontId::proportional(19.0), [GLOW, ACCENT, JELLY, DIM][i]);
            p.text(pos2(x, c.y + r + 92.0), Align2::CENTER_CENTER, *l, FontId::proportional(11.5), DIM);
        }
        if !self.report.findings.is_empty() {
            p.text(
                pos2(c.x, c.y + r + 124.0),
                Align2::CENTER_CENTER,
                format!("♻ {} reclaimable found so far — open Prune", fmt_size(self.report.grand_total())),
                FontId::proportional(14.0),
                PLANKTON,
            );
        }
        ui.ctx().request_repaint();
    }

    // ------------------------------------------------------------ tree view

    pub(super) fn tree_view(&mut self, ui: &mut egui::Ui) {
        let Some(t) = self.tree.clone() else { return };
        let rows = visible_rows(&t, &self.expanded);
        let root_size = t.root().size.max(1);
        let sel_pos = rows.iter().position(|r| r.0 == self.sel);

        let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
        if self.tree_scroll_to_sel {
            if let Some(pos) = sel_pos {
                let view_h = ui.available_height();
                let y = pos as f32 * ROW_H;
                let cur = ui.ctx().memory(|m| m.data.get_temp::<f32>(egui::Id::new("tree_off"))).unwrap_or(0.0);
                let off = if y < cur { y } else if y + ROW_H > cur + view_h { y + ROW_H - view_h } else { cur };
                area = area.vertical_scroll_offset(off.max(0.0));
            }
            self.tree_scroll_to_sel = false;
        }
        let mut clicked = None;
        let mut double = None;
        let mut toggle = None;
        let out = area.show_rows(ui, ROW_H, rows.len(), |ui, range| {
            for &(idx, depth) in &rows[range] {
                let n = &t.nodes[idx];
                let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
                let p = ui.painter_at(r);
                let selected = idx == self.sel;
                if selected {
                    theme::hgradient(&p, r, theme::alpha(GLOW, 0.2), theme::alpha(GLOW, 0.0));
                    p.rect_filled(Rect::from_min_size(r.min, vec2(3.0, r.height())), 2.0, GLOW);
                } else if resp.hovered() {
                    p.rect_filled(r, 6.0, CARD);
                }
                let parent_size = n.parent.map_or(root_size, |q| t.nodes[q].size.max(1));
                let frac = n.size as f32 / parent_size as f32;
                let y = r.center().y;
                p.text(pos2(r.left() + 96.0, y), Align2::RIGHT_CENTER, fmt_size(n.size), FontId::proportional(13.5), if selected { AMBER } else { FG });
                gradient_bar(&p, Rect::from_center_size(pos2(r.left() + 166.0, y), vec2(120.0, 8.0)), frac, grad(0.0), grad(0.62), theme::mix(PANEL, FAINT, 0.5));
                p.text(pos2(r.left() + 274.0, y), Align2::RIGHT_CENTER, fmt_share(n.size, parent_size), FontId::proportional(12.0), DIM);

                let x = r.left() + 290.0 + depth as f32 * 18.0;
                let arrow_r = Rect::from_center_size(pos2(x + 7.0, y), vec2(18.0, ROW_H));
                if !n.children.is_empty() {
                    p.text(arrow_r.center(), Align2::CENTER_CENTER, if self.expanded[idx] { "⏷" } else { "⏵" }, FontId::proportional(12.0), DIM);
                    if resp.clicked() && resp.interact_pointer_pos().is_some_and(|q| arrow_r.contains(q)) {
                        toggle = Some(idx);
                    }
                }
                let kind = self.kinds.get(idx).copied().unwrap_or(Kind::Other);
                p.rect_filled(Rect::from_center_size(pos2(x + 24.0, y), vec2(10.0, 10.0)), 2.0, theme::mix(BG, theme::kind(kind), 0.9));
                let marked = self.marked_state(idx);
                let (name, color) = match n.kind {
                    NodeKind::Dir if idx != 0 => (format!("{}/", n.name), theme::mix(theme::kind(kind), FG, 0.55)),
                    NodeKind::Aggregate | NodeKind::Mount => (n.name.clone(), DIM),
                    _ => (n.name.clone(), FG),
                };
                let color = if marked { DANGER } else { color };
                let g = p.layout_no_wrap(name, FontId::proportional(13.5), color);
                let mut tx = x + 34.0;
                let gw = g.size().x;
                p.galley(pos2(tx, y - g.size().y / 2.0), g, color);
                if marked {
                    p.line_segment([pos2(tx, y), pos2(tx + gw, y)], Stroke::new(1.0, DANGER));
                }
                tx += gw + 10.0;
                let mut tag = |text: &str, c: Color32| {
                    let g = p.layout_no_wrap(text.to_string(), FontId::proportional(11.0), c);
                    let tr = Rect::from_min_size(pos2(tx, y - 9.0), vec2(g.size().x + 12.0, 18.0));
                    p.rect_filled(tr, 9.0, theme::mix(PANEL, c, 0.18));
                    p.galley(pos2(tx + 6.0, y - g.size().y / 2.0), g, c);
                    tx += tr.width() + 6.0;
                };
                if let Some(risk) = self.finding_nodes.get(&idx) {
                    tag(&format!("♻ {}", risk.label()), theme::risk(*risk));
                }
                if self.marked.contains(&idx) {
                    tag("✖ marked", DANGER);
                }
                if n.unreadable {
                    tag("⚠ permission denied", MODERATE);
                }
                if n.kind == NodeKind::Mount {
                    tag("other filesystem", FAINT);
                }
                if resp.clicked() {
                    clicked = Some(idx);
                }
                if resp.double_clicked() {
                    double = Some(idx);
                }
                if resp.secondary_clicked() {
                    clicked = Some(idx);
                }
                resp.context_menu(|ui| self.node_menu(ui, &t, idx));
            }
        });
        ui.ctx().memory_mut(|m| m.data.insert_temp(egui::Id::new("tree_off"), out.state.offset.y));
        if let Some(i) = toggle {
            self.expanded[i] = !self.expanded[i];
        } else if let Some(i) = double {
            if !t.nodes[i].children.is_empty() {
                self.expanded[i] = !self.expanded[i];
            }
        }
        if let Some(i) = clicked {
            self.sel = i;
        }
    }

    // ------------------------------------------------------------ side panel

    pub(super) fn side_panel(&mut self, ui: &mut egui::Ui) {
        let Some(t) = self.tree.clone() else {
            card(ui, |ui| {
                ui.label(RichText::new("Waiting for the scan…").color(DIM));
            });
            return;
        };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 10.0;
            let n = &t.nodes[self.sel];
            let kind = self.kinds.get(self.sel).copied().unwrap_or(Kind::Other);

            // Selection
            card(ui, |ui| {
                section(ui, "SELECTION", AMBER);
                ui.label(RichText::new(&n.name).size(17.0).strong());
                let (sr, _) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::hover());
                let shown = ui.ctx().animate_value_with_time(egui::Id::new("sel_size"), n.size as f32, 0.35);
                theme::gradient_text(&ui.painter_at(sr), sr.min, &fmt_size(shown as u64), FontId::proportional(32.0), self.clock * 0.1);
                ui.label(RichText::new(format!("{} of scan · {} files", fmt_share(n.size, t.root().size), fmt_count(n.files))).color(DIM));
                ui.horizontal(|ui| {
                    ui.label(RichText::new("■").color(theme::kind(kind)));
                    ui.label(kind.label());
                    if self.reclaim.get(self.sel).copied().unwrap_or(false) {
                        ui.label(RichText::new("╱╱ can be had back").color(SAFE));
                    }
                });
                ui.label(RichText::new(tilde(&t.path_of(self.sel), self.home())).small().color(FAINT));
                if let Some(r) = self.finding_nodes.get(&self.sel) {
                    ui.label(RichText::new(format!("♻ {} cleanup suggestion in Prune", r.label())).color(theme::risk(*r)));
                }
                ui.horizontal(|ui| {
                    let marked = self.marked.contains(&self.sel);
                    let (label, fill) = if marked { ("↩ Unmark", CARD_HI) } else { ("✖ Mark for removal", theme::mix(CARD, DANGER, 0.35)) };
                    if ui.add(egui::Button::new(label).fill(fill).corner_radius(14)).clicked() {
                        let s = self.sel;
                        self.toggle_mark(ui.ctx(), s);
                    }
                    if ui.add(egui::Button::new("📂 Open").corner_radius(14)).on_hover_text("Show in Files").clicked() {
                        super::reveal(&t.path_of(self.sel));
                    }
                });
                // Largest inside, as mini bars.
                if !n.children.is_empty() {
                    ui.add_space(4.0);
                    section(ui, "LARGEST INSIDE", DIM);
                    for &c in n.children.iter().take(6) {
                        let ch = &t.nodes[c];
                        let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 20.0), Sense::click());
                        let p = ui.painter_at(r);
                        if resp.hovered() {
                            p.rect_filled(r, 4.0, CARD_HI);
                        }
                        let ck = self.kinds.get(c).copied().unwrap_or(Kind::Other);
                        gradient_bar(&p, Rect::from_min_size(pos2(r.left(), r.center().y - 3.0), vec2(70.0, 6.0)), ch.size as f32 / n.size.max(1) as f32, theme::mix(BG, theme::kind(ck), 0.9), theme::kind(ck), theme::mix(CARD, FAINT, 0.5));
                        p.text(pos2(r.left() + 78.0, r.center().y), Align2::LEFT_CENTER, &ch.name, FontId::proportional(12.5), FG);
                        p.text(pos2(r.right() - 2.0, r.center().y), Align2::RIGHT_CENTER, fmt_size(ch.size), FontId::proportional(12.0), DIM);
                        if resp.clicked() {
                            self.select(c);
                        }
                    }
                }
            });

            // Top savings: the largest suggestions
            card(ui, |ui| {
                section(ui, "TOP SAVINGS", SAFE);
                let mut top: Vec<(usize, &Finding)> = self.report.findings.iter().enumerate().collect();
                top.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
                if top.is_empty() {
                    ui.label(RichText::new(if self.engine.rules_pending > 0 { "Analyzing…" } else { "Nothing notable to reclaim." }).color(DIM));
                }
                let mut open = None;
                let top: Vec<(usize, Finding)> = top.into_iter().take(7).map(|(i, f)| (i, f.clone())).collect();
                for (i, f) in &top {
                    let (i, f) = (*i, f);
                    let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::click());
                    let p = ui.painter_at(r);
                    if resp.hovered() {
                        p.rect_filled(r, 4.0, CARD_HI);
                    }
                    theme::radial_blob(&p, pos2(r.left() + 6.0, r.center().y), 9.0, theme::risk(f.risk), 0.35);
                    p.circle_filled(pos2(r.left() + 6.0, r.center().y), 3.5, theme::risk(f.risk));
                    p.text(pos2(r.left() + 82.0, r.center().y), Align2::RIGHT_CENTER, fmt_size(f.bytes), FontId::proportional(12.5), FG);
                    p.with_clip_rect(r).text(pos2(r.left() + 92.0, r.center().y), Align2::LEFT_CENTER, &f.title, FontId::proportional(12.5), DIM);
                    let resp = resp.on_hover_text(&f.title);
                    if resp.clicked() {
                        open = Some(i);
                    }
                    resp.context_menu(|ui| self.finding_menu(ui, i));
                }
                if let Some(i) = open {
                    self.prune_cursor = i;
                    self.view = View::Prune;
                }
            });

            // Marked
            card(ui, |ui| {
                let mb = self.marked_bytes();
                section(ui, &format!("MARKED · {} · {}", self.marked.len(), fmt_size(mb)), DANGER);
                if self.marked.is_empty() {
                    ui.label(RichText::new("Space, or right-click → Mark, to queue a tile for removal.").color(FAINT).small());
                }
                for i in self.marked.clone().into_iter().take(6) {
                    ui.horizontal(|ui| {
                        if ui.small_button("✖").on_hover_text("Unmark").clicked() {
                            self.marked.remove(&i);
                        }
                        ui.label(RichText::new(fmt_size(t.nodes[i].size)).strong());
                        ui.label(RichText::new(tilde(&t.path_of(i), self.home())).color(DIM).small());
                    });
                }
            });

            // Disk
            card(ui, |ui| self.disk_card(ui));
        });
    }

    fn disk_card(&mut self, ui: &mut egui::Ui) {
        let Some(d) = &self.disk else { return };
        section(ui, &format!("DISK · {}", d.mount), ACCENT);
        let gain = self.marked_bytes() + self.checked_bytes();
        let after = (d.avail + gain).min(d.total);
        let used = 1.0 - d.avail as f32 / d.total.max(1) as f32;
        let used_after = 1.0 - after as f32 / d.total.max(1) as f32;
        let ctx = ui.ctx().clone();
        let used_a = ctx.animate_value_with_time(egui::Id::new("disk_used"), used, 0.8);
        let after_a = ctx.animate_value_with_time(egui::Id::new("disk_after"), used_after, 0.6);

        // 270° gauge: used (cyan → magenta → red when full), freed part in lime.
        let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 170.0), Sense::hover());
        let p = ui.painter_at(r);
        let c = pos2(r.center().x, r.top() + 92.0);
        let (r0, r1) = (58.0, 74.0);
        let start = std::f32::consts::PI * 0.75;
        let span = std::f32::consts::PI * 1.5;
        theme::ring_segment(&p, c, r0, r1, start, start + span, theme::alpha(FAINT, 0.35), theme::alpha(FAINT, 0.35));
        let steps = 40;
        for i in 0..steps {
            let t0 = i as f32 / steps as f32;
            let t1 = (i + 1) as f32 / steps as f32;
            if t0 >= used_a {
                break;
            }
            let col = if t0 < 0.5 { theme::mix(GLOW, JELLY, t0 * 2.0) } else { theme::mix(JELLY, DANGER, (t0 - 0.5) * 2.0) };
            theme::ring_segment(&p, c, r0, r1, start + span * t0, start + span * t1.min(used_a), theme::mix(col, BG, 0.3), col);
        }
        if gain > 0 {
            theme::ring_segment(&p, c, r0 - 3.0, r1 + 3.0, start + span * after_a, start + span * used_a, theme::alpha(PLANKTON, 0.55), PLANKTON);
        }
        let tip = start + span * used_a;
        theme::radial_blob(&p, c + vec2(tip.cos(), tip.sin()) * (r0 + r1) / 2.0, 16.0, Color32::WHITE, 0.4);
        p.text(c + vec2(0.0, -10.0), Align2::CENTER_CENTER, fmt_size(d.avail), FontId::proportional(20.0), FG);
        p.text(c + vec2(0.0, 12.0), Align2::CENTER_CENTER, "free now", FontId::proportional(11.0), DIM);
        if gain > 0 {
            p.text(c + vec2(0.0, 34.0), Align2::CENTER_CENTER, format!("→ {}", fmt_size(after)), FontId::proportional(14.0), PLANKTON);
        }
        p.text(pos2(c.x, r.bottom() - 6.0), Align2::CENTER_BOTTOM, format!("{:.0}% used of {}", used * 100.0, fmt_size(d.total)), FontId::proportional(11.0), DIM);

        let n = self.marked.len() + self.checked.len();
        let label = format!("Review & clean · {n} · {}", fmt_size(gain));
        ui.vertical_centered(|ui| {
            if super::glow_button(ui, &label, n > 0, self.clock).clicked() {
                self.open_review(ui.ctx());
            }
        });
    }

    // ------------------------------------------------------------ prune view

    pub(super) fn prune_view(&mut self, ui: &mut egui::Ui) {
        // Hero: animated donut of everything reclaimable + tier cards.
        let ctx = ui.ctx().clone();
        let total = self.report.grand_total();
        let appear = ctx.animate_bool_with_time(egui::Id::new("prune_appear"), !self.report.findings.is_empty(), 0.9);
        let hero_h = 186.0;
        let (hero, _) = ui.allocate_exact_size(vec2(ui.available_width(), hero_h), Sense::hover());
        let p = ui.painter_at(hero.expand(20.0));
        let hero_card = Rect::from_min_size(hero.min, vec2(360.0_f32.min(hero.width() * 0.34), hero_h));
        theme::vgradient(&p, hero_card.shrink(1.0), theme::alpha(theme::mix(CARD, JELLY, 0.14), 1.0), CARD);
        p.rect_stroke(hero_card, 16.0, Stroke::new(1.0, theme::alpha(JELLY, 0.45)), StrokeKind::Inside);
        let dc = pos2(hero_card.left() + 92.0, hero_card.center().y);
        let parts: Vec<(f32, Color32)> = Risk::ALL
            .iter()
            .map(|&r| (self.report.total(r) as f32 / total.max(1) as f32, theme::risk(r)))
            .collect();
        theme::radial_blob(&p, dc, 90.0, JELLY, 0.14);
        theme::donut(&p, dc, 50.0, 70.0, &parts, theme::ease_out_cubic(appear));
        let shown = ctx.animate_value_with_time(egui::Id::new("prune_total"), total as f32, 0.9);
        let big = fmt_size(shown as u64);
        let bw = p.layout_no_wrap(big.clone(), FontId::proportional(19.0), FG).size().x;
        theme::gradient_text(&p, dc + vec2(-bw / 2.0, -12.0), &big, FontId::proportional(19.0), self.clock * 0.1);
        p.text(dc + vec2(0.0, 18.0), Align2::CENTER_CENTER, "reclaimable", FontId::proportional(11.0), DIM);
        let tx = hero_card.left() + 180.0;
        p.text(pos2(tx, hero_card.top() + 30.0), Align2::LEFT_CENTER, "YOU CAN FREE", FontId::proportional(11.5), JELLY);
        let safe_shown = ctx.animate_value_with_time(egui::Id::new("prune_safe"), self.report.total(Risk::Safe) as f32, 0.9);
        theme::gradient_text(&p, pos2(tx, hero_card.top() + 44.0), &fmt_size(safe_shown as u64), FontId::proportional(30.0), 0.25 + self.clock * 0.1);
        p.text(pos2(tx, hero_card.top() + 92.0), Align2::LEFT_CENTER, "with zero risk", FontId::proportional(13.0), FG);
        p.text(pos2(tx, hero_card.top() + 112.0), Align2::LEFT_CENTER, "(caches only)", FontId::proportional(11.5), DIM);
        if let Some(d) = &self.disk {
            p.text(pos2(tx, hero_card.top() + 146.0), Align2::LEFT_CENTER, format!("{} free now", fmt_size(d.avail)), FontId::proportional(11.5), DIM);
        }

        // Tier cards in a 2 x 2 grid.
        let grid = Rect::from_min_max(pos2(hero_card.right() + 12.0, hero.top()), hero.max);
        let cw = (grid.width() - 12.0) / 2.0;
        let ch = (hero_h - 12.0) / 2.0;
        let specs = [
            (Some(Risk::Safe), "SAFE", "pure caches — no data loss"),
            (Some(Risk::Moderate), "MODERATE", "logs · kernels · snap revisions"),
            (Some(Risk::Caution), "CAUTION", "project build output"),
            (None, "SELECTED", "ready to review"),
        ];
        for (i, (risk, title, sub)) in specs.iter().enumerate() {
            let cell = Rect::from_min_size(grid.min + vec2((i % 2) as f32 * (cw + 12.0), (i / 2) as f32 * (ch + 12.0)), vec2(cw, ch));
            let (value, count, color) = match risk {
                Some(r) => (self.report.total(*r), self.report.findings.iter().filter(|f| f.risk == *r).count(), theme::risk(*r)),
                None => (self.checked_bytes(), self.checked.len(), GLOW),
            };
            theme::hgradient(&p, cell.shrink(1.0), theme::mix(CARD, color, 0.13), CARD);
            p.rect_stroke(cell, 14.0, Stroke::new(1.0, theme::alpha(color, 0.4)), StrokeKind::Inside);
            let shown = ctx.animate_value_with_time(egui::Id::new(("card", i)), value as f32, 0.8);
            p.text(cell.left_top() + vec2(16.0, 18.0), Align2::LEFT_CENTER, *title, FontId::proportional(11.5), color);
            p.text(cell.left_top() + vec2(16.0, 46.0), Align2::LEFT_CENTER, fmt_size(shown as u64), FontId::proportional(26.0), color);
            p.text(cell.left_top() + vec2(16.0, 72.0), Align2::LEFT_CENTER, format!("{count} items · {sub}"), FontId::proportional(11.0), DIM);
            // Mini donut: this tier's share.
            let frac = if total > 0 { value as f32 / total as f32 } else { 0.0 };
            let mc = pos2(cell.right() - 38.0, cell.center().y);
            theme::donut(&p, mc, 17.0, 24.0, &[(frac.min(1.0), color)], theme::ease_out_cubic(appear));
            p.text(mc, Align2::CENTER_CENTER, format!("{:.0}%", frac * 100.0), FontId::proportional(10.5), FG);
        }
        ui.add_space(10.0);

        // Composition bar with glowing segments.
        let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 10.0), Sense::hover());
        let p = ui.painter_at(r.expand(8.0));
        p.rect_filled(r, 5.0, CARD);
        let totalf = total.max(1) as f32;
        let mut x = r.left();
        for risk in Risk::ALL {
            let w = r.width() * self.report.total(risk) as f32 / totalf * appear;
            if w > 2.0 {
                let seg = Rect::from_min_size(pos2(x, r.top()), vec2(w, r.height()));
                theme::radial_blob(&p, seg.center(), (w * 0.5).min(60.0), theme::risk(risk), 0.25);
                theme::gradient_pill(&p, seg, theme::mix(theme::risk(risk), BG, 0.2), theme::risk(risk));
            }
            x += w;
        }
        ui.add_space(8.0);

        // Actions.
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new(RichText::new("✔ Select all SAFE").color(SAFE)).corner_radius(16)).clicked() {
                for f in &self.report.findings {
                    if f.risk == Risk::Safe && f.is_actionable() {
                        self.checked.insert(f.id.clone());
                    }
                }
            }
            if ui.add(egui::Button::new("Select all").corner_radius(16)).clicked() {
                for f in &self.report.findings {
                    if f.is_actionable() {
                        self.checked.insert(f.id.clone());
                    }
                }
            }
            if ui.add(egui::Button::new("Clear").corner_radius(16)).clicked() {
                self.checked.clear();
            }
            if ui.add(egui::Button::new("⟳ Re-analyze").corner_radius(16)).clicked() {
                self.reanalyze();
            }
            if self.engine.rules_pending > 0 {
                ui.add(egui::Spinner::new().color(ACCENT));
                ui.label(RichText::new("analyzing…").color(ACCENT));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let n = self.checked.len() + self.marked.len();
                let label = format!("Review & clean · {}", fmt_size(self.checked_bytes() + self.marked_bytes()));
                if super::glow_button(ui, &label, n > 0, self.clock).clicked() {
                    self.open_review(ui.ctx());
                }
            });
        });
        ui.add_space(6.0);

        // List + details.
        let avail = ui.available_rect_before_wrap();
        let split = avail.left() + avail.width() * 0.56;
        let list_r = Rect::from_min_max(avail.min, pos2(split - 6.0, avail.max.y));
        let detail_r = Rect::from_min_max(pos2(split + 6.0, avail.top()), avail.max);
        ui.scope_builder(egui::UiBuilder::new().max_rect(list_r), |ui| {
            Frame::new().fill(PANEL).corner_radius(12).inner_margin(Margin::same(10)).show(ui, |ui| {
                ui.set_min_size(list_r.size() - vec2(20.0, 20.0));
                egui::ScrollArea::vertical().id_salt("prune_list").auto_shrink([false, false]).show(ui, |ui| self.prune_list(ui));
            });
        });
        ui.scope_builder(egui::UiBuilder::new().max_rect(detail_r), |ui| {
            Frame::new().fill(PANEL).corner_radius(12).inner_margin(Margin::same(14)).show(ui, |ui| {
                ui.set_min_size(detail_r.size() - vec2(28.0, 28.0));
                egui::ScrollArea::vertical().id_salt("prune_detail").auto_shrink([false, false]).show(ui, |ui| self.prune_detail(ui));
            });
        });
        ui.allocate_rect(avail, Sense::hover());
    }

    fn prune_list(&mut self, ui: &mut egui::Ui) {
        if self.report.findings.is_empty() {
            ui.label(RichText::new(if self.engine.rules_pending > 0 { "Analyzing…" } else { "Nothing significant to reclaim — this system is tidy." }).color(DIM));
        }
        let max = self.report.findings.iter().map(|f| f.bytes).max().unwrap_or(1).max(1);
        let mut toggle = None;
        for risk in Risk::ALL {
            let items: Vec<usize> = (0..self.report.findings.len()).filter(|&i| self.report.findings[i].risk == risk).collect();
            if items.is_empty() {
                continue;
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(risk.label()).strong().color(theme::risk(risk)));
                ui.label(RichText::new(fmt_size(self.report.total(risk))).color(theme::risk(risk)));
                let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
                ui.painter().line_segment([r.left_center(), r.right_center()], Stroke::new(1.0, theme::mix(PANEL, theme::risk(risk), 0.4)));
            });
            for i in items {
                let f = self.report.findings[i].clone();
                let (r, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::click());
                let p = ui.painter_at(r);
                let selected = i == self.prune_cursor;
                let checked = self.checked.contains(&f.id);
                if selected {
                    p.rect_filled(r, 7.0, theme::mix(PANEL, AMBER, 0.13));
                    p.rect_filled(Rect::from_min_size(r.min, vec2(3.0, r.height())), 2.0, AMBER);
                } else if resp.hovered() {
                    p.rect_filled(r, 7.0, CARD);
                }
                let y = r.center().y;
                // Checkbox.
                let cb = Rect::from_center_size(pos2(r.left() + 18.0, y), vec2(16.0, 16.0));
                let rc = theme::risk(f.risk);
                if !f.is_actionable() {
                    p.rect_stroke(cb, 4.0, Stroke::new(1.0, FAINT), StrokeKind::Inside);
                } else if checked {
                    theme::radial_blob(&p, cb.center(), 16.0, rc, 0.35);
                    p.rect_filled(cb, 4.0, rc);
                    p.text(cb.center(), Align2::CENTER_CENTER, "✔", FontId::proportional(12.0), BG);
                } else {
                    p.rect_stroke(cb, 4.0, Stroke::new(1.5, DIM), StrokeKind::Inside);
                }
                p.text(pos2(r.left() + 110.0, y), Align2::RIGHT_CENTER, fmt_size(f.bytes), FontId::proportional(14.0), if checked { rc } else { FG });
                gradient_bar(&p, Rect::from_center_size(pos2(r.left() + 150.0, y), vec2(60.0, 6.0)), f.bytes as f32 / max as f32, theme::mix(PANEL, rc, 0.6), rc, theme::mix(PANEL, FAINT, 0.4));
                let right_pad = if f.needs_root && !self.engine.ctx.is_root { 64.0 } else { 8.0 };
                let tr = Rect::from_min_max(pos2(r.left() + 190.0, r.top()), pos2(r.right() - right_pad, r.bottom()));
                p.with_clip_rect(tr).text(pos2(tr.left(), y), Align2::LEFT_CENTER, &f.title, FontId::proportional(13.5), FG);
                if f.needs_root && !self.engine.ctx.is_root {
                    let br = Rect::from_center_size(pos2(r.right() - 34.0, y), vec2(52.0, 18.0));
                    p.rect_filled(br, 9.0, theme::mix(PANEL, MODERATE, 0.2));
                    p.text(br.center(), Align2::CENTER_CENTER, "admin", FontId::proportional(11.0), MODERATE);
                }
                if resp.clicked() {
                    if resp.interact_pointer_pos().is_some_and(|q| q.x < r.left() + 36.0) || selected {
                        toggle = Some(i);
                    }
                    self.prune_cursor = i;
                }
                if resp.secondary_clicked() {
                    self.prune_cursor = i;
                }
                if resp.double_clicked() {
                    if let Some(p0) = f.paths.first() {
                        super::reveal(p0);
                    }
                }
                resp.on_hover_text("right-click: open in Files, copy path or command").context_menu(|ui| self.finding_menu(ui, i));
            }
        }
        if let Some(i) = toggle {
            self.toggle_finding(i);
        }
        if !self.report.notes.is_empty() {
            ui.add_space(10.0);
            for n in &self.report.notes {
                ui.label(RichText::new(format!("Note: {n}")).small().color(DIM));
            }
        }
    }

    fn prune_detail(&mut self, ui: &mut egui::Ui) {
        let Some(f) = self.report.findings.get(self.prune_cursor).cloned() else {
            ui.label(RichText::new("Select a suggestion to see what it does.").color(DIM));
            return;
        };
        let rc = theme::risk(f.risk);
        ui.label(RichText::new(&f.title).size(18.0).strong());
        ui.horizontal(|ui| {
            Frame::new().fill(rc).corner_radius(8).inner_margin(Margin::symmetric(8, 2)).show(ui, |ui| {
                ui.label(RichText::new(f.risk.label()).color(BG).strong().small());
            });
            ui.label(RichText::new(&f.category).color(DIM));
            ui.label(RichText::new(format!("frees ~{}", fmt_size(f.bytes))).color(rc).strong());
            ui.label(RichText::new(if f.needs_root { "· needs admin" } else { "· no admin needed" }).color(DIM));
        });
        ui.add_space(8.0);
        ui.label(&f.detail);
        ui.add_space(10.0);
        section(ui, "EXACT COMMAND", ACCENT);
        let cmd = f.command_text();
        Frame::new().fill(BG).corner_radius(8).inner_margin(Margin::same(10)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(format!("$ {cmd}")).monospace().color(AMBER)).wrap());
        });
        ui.horizontal(|ui| {
            if ui.add(egui::Button::new("📋 Copy command").corner_radius(14)).clicked() {
                ui.ctx().copy_text(cmd.clone());
                self.toast(ui.ctx(), "Command copied to the clipboard");
            }
            let checked = self.checked.contains(&f.id);
            if f.is_actionable() && ui.add(egui::Button::new(if checked { "Deselect" } else { "✔ Select" }).corner_radius(14)).clicked() {
                let i = self.prune_cursor;
                self.toggle_finding(i);
            }
            if let Some(p0) = f.paths.first() {
                if ui.add(egui::Button::new("📂 Open in Files").corner_radius(14)).on_hover_text(p0.display().to_string()).clicked() {
                    super::reveal(p0);
                }
            }
            if let Some(t) = self.tree.clone() {
                if let Some(n) = f.paths.iter().find_map(|p| t.find(p)) {
                    if ui.add(egui::Button::new("▦ Show in treemap").corner_radius(14)).clicked() {
                        self.select(n);
                        self.view = View::Treemap;
                    }
                }
            }
        });
        if !f.paths.is_empty() {
            ui.add_space(10.0);
            section(ui, &format!("PATHS ({}) · click to open in Files", f.paths.len()), ACCENT);
            let home = self.home().to_path_buf();
            for p in f.paths.iter().take(40) {
                let resp = ui.add(egui::Label::new(RichText::new(format!("📂 {}", tilde(p, &home))).small().color(DIM)).sense(Sense::click()).truncate());
                let resp = if resp.hovered() {
                    ui.painter().line_segment([resp.rect.left_bottom(), resp.rect.right_bottom()], Stroke::new(1.0, ACCENT));
                    resp.on_hover_text(p.display().to_string())
                } else {
                    resp
                };
                if resp.clicked() {
                    super::reveal(p);
                }
                resp.context_menu(|ui| {
                    if ui.button("📂  Open in Files").clicked() {
                        super::reveal(p);
                        ui.close();
                    }
                    if p.is_file() && ui.button("🗋  Open file").clicked() {
                        let _ = std::process::Command::new("xdg-open").arg(p).spawn();
                        ui.close();
                    }
                    if ui.button("📋  Copy path").clicked() {
                        ui.ctx().copy_text(p.display().to_string());
                        ui.close();
                    }
                });
            }
            if f.paths.len() > 40 {
                ui.label(RichText::new(format!("… and {} more", f.paths.len() - 40)).small().color(FAINT));
            }
        }
    }
}
