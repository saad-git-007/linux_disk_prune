//! Sunburst: the directory hierarchy as concentric rings around the focus.
//! Each ring is one level deeper; a segment's angle is its share of the parent.
//! Enters with a clock-wipe while the rings grow outward.

use super::theme::{self, BG, CARD, DANGER, FAINT, FG, GLOW, PLANKTON};
use super::treemap::fit;
use crate::classify::Kind;
use crate::scanner::{NodeKind, Tree};
use crate::util::fmt_size;
use eframe::egui::{epaint, vec2, Align2, Color32, FontId, Painter, Pos2, Stroke};
use std::f32::consts::{PI, TAU};

/// Angles start at twelve o'clock.
const START: f32 = -PI / 2.0;
const MIN_SPAN: f32 = 0.006;

#[derive(Clone, Copy)]
pub struct Seg {
    pub node: usize,
    pub depth: usize,
    pub a0: f32,
    pub a1: f32,
}

pub struct Geometry {
    pub center: Pos2,
    pub r_hub: f32,
    pub r_max: f32,
    pub rings: usize,
}

impl Geometry {
    pub fn ring(&self, depth: usize) -> (f32, f32) {
        let w = (self.r_max - self.r_hub) / self.rings as f32;
        let r0 = self.r_hub + depth as f32 * w + 2.0;
        (r0, r0 + w - 3.0)
    }
}

pub fn layout(t: &Tree, focus: usize, rings: usize) -> Vec<Seg> {
    let mut out = Vec::new();
    rec(t, focus, 0.0, TAU, 0, rings, &mut out);
    out
}

fn rec(t: &Tree, node: usize, a0: f32, a1: f32, depth: usize, rings: usize, out: &mut Vec<Seg>) {
    if depth >= rings {
        return;
    }
    let total = t.nodes[node].size as f32;
    if total <= 0.0 {
        return;
    }
    let mut a = a0;
    for &c in &t.nodes[node].children {
        let span = (a1 - a0) * t.nodes[c].size as f32 / total;
        if span < MIN_SPAN {
            break; // children are sorted largest first
        }
        out.push(Seg { node: c, depth, a0: a, a1: a + span });
        if t.nodes[c].kind == NodeKind::Dir {
            rec(t, c, a, a + span, depth + 1, rings, out);
        }
        a += span;
    }
}

pub enum Hit {
    Hub,
    Seg(usize),
}

pub fn hit(segs: &[Seg], g: &Geometry, p: Pos2) -> Option<Hit> {
    let d = p - g.center;
    let dist = d.length();
    if dist < g.r_hub {
        return Some(Hit::Hub);
    }
    let ang = (d.y.atan2(d.x) - START).rem_euclid(TAU);
    segs.iter()
        .rev()
        .find(|s| {
            let (r0, r1) = g.ring(s.depth);
            dist >= r0 && dist <= r1 && ang >= s.a0 && ang < s.a1
        })
        .map(|s| Hit::Seg(s.node))
}

pub struct PaintCtx<'a> {
    pub tree: &'a Tree,
    pub kinds: &'a [Kind],
    pub reclaim: &'a [bool],
    pub is_marked: &'a dyn Fn(usize) -> bool,
    pub sel: usize,
    pub hover: Option<usize>,
    pub time: f32,
    pub ambient: bool,
    /// 0 → 1 intro progress.
    pub sweep: f32,
}

#[allow(clippy::too_many_arguments)]
pub fn paint(p: &Painter, pc: &PaintCtx, segs: &[Seg], g: &Geometry, focus: usize, hub_hover: bool) {
    let sweep = theme::ease_out_cubic(pc.sweep);
    // Soft light behind the whole wheel.
    theme::radial_blob(p, g.center, g.r_max * 1.15, theme::mix(BG, GLOW, 0.5), 0.10);

    for s in segs {
        let (r0, mut r1) = g.ring(s.depth);
        // Rings grow outward one after another.
        let grow = ((pc.sweep * 1.6) - s.depth as f32 * 0.14).clamp(0.0, 1.0);
        if grow <= 0.0 {
            continue;
        }
        r1 = r0 + (r1 - r0) * theme::ease_out_cubic(grow);
        let pad = 1.2 / ((r0 + r1) / 2.0);
        let (a0, a1) = (START + s.a0 * sweep + pad, START + s.a1 * sweep - pad);
        if a1 <= a0 {
            continue;
        }
        let n = &pc.tree.nodes[s.node];
        let d = s.depth as f32;
        let (mut inner, mut outer) = if (pc.is_marked)(s.node) {
            (theme::mix(BG, DANGER, 0.45), theme::mix(BG, DANGER, 0.85))
        } else if matches!(n.kind, NodeKind::Aggregate | NodeKind::Mount) {
            (theme::mix(BG, FAINT, 0.45), theme::mix(BG, FAINT, 0.75))
        } else {
            let k = theme::kind(pc.kinds.get(s.node).copied().unwrap_or(Kind::Other));
            (theme::mix(BG, k, 0.36 + 0.08 * d), theme::mix(BG, k, 0.78 + 0.05 * d))
        };
        if pc.hover == Some(s.node) {
            inner = theme::mix(inner, Color32::WHITE, 0.15);
            outer = theme::mix(outer, Color32::WHITE, 0.22);
        }
        theme::ring_segment(p, g.center, r0, r1, a0, a1, inner, outer);
        // Reclaimable space: a lime rim that shimmers along the arc.
        if pc.reclaim.get(s.node).copied().unwrap_or(false) {
            let shimmer = if pc.ambient { 0.55 + 0.45 * ((pc.time * 2.5) - (s.a0 * 3.0)).sin() } else { 0.8 };
            theme::ring_segment(p, g.center, r1 - 3.0, r1, a0, a1, theme::alpha(PLANKTON, 0.5 * shimmer), theme::alpha(PLANKTON, shimmer));
        }
        // Radial labels on segments with room for them.
        let mid = (a0 + a1) / 2.0;
        let rm = (r0 + r1) / 2.0;
        if (a1 - a0) * rm > 15.0 && grow >= 1.0 {
            let font = FontId::proportional(11.5);
            if let Some(name) = fit(p, &n.name, &font, r1 - r0 - 10.0) {
                let gal = p.layout_no_wrap(name, font, FG);
                let size = gal.size();
                let mut ang = mid;
                if mid.cos() < 0.0 {
                    ang += PI; // keep text upright on the left half
                }
                let dir = vec2(ang.cos(), ang.sin());
                let perp = vec2(-dir.y, dir.x);
                let c = g.center + vec2(mid.cos(), mid.sin()) * rm;
                let tl = c - dir * size.x / 2.0 - perp * size.y / 2.0;
                p.add(epaint::TextShape::new(tl, gal, FG).with_angle(ang));
            }
        }
    }

    // Selection: a pulsing halo around its segment.
    if let Some(s) = segs.iter().find(|s| s.node == pc.sel) {
        let (r0, r1) = g.ring(s.depth);
        let pulse = if pc.ambient { 0.65 + 0.35 * (pc.time * 3.4).sin() } else { 0.9 };
        let (a0, a1) = (START + s.a0 * sweep, START + s.a1 * sweep);
        theme::ring_segment(p, g.center, r1, r1 + 3.0, a0, a1, theme::alpha(GLOW, pulse), theme::alpha(GLOW, pulse));
        theme::ring_segment(p, g.center, r1 + 3.0, r1 + 10.0, a0, a1, theme::alpha(GLOW, 0.3 * pulse), theme::alpha(GLOW, 0.0));
        theme::ring_segment(p, g.center, r0 - 2.0, r0, a0, a1, theme::alpha(GLOW, 0.7 * pulse), theme::alpha(GLOW, 0.7 * pulse));
    }

    // Hub: the focus directory. Click it to go up.
    let n = &pc.tree.nodes[focus];
    theme::radial_blob(p, g.center, g.r_hub * 1.5, GLOW, if hub_hover { 0.35 } else { 0.2 });
    p.circle_filled(g.center, g.r_hub - 4.0, CARD);
    p.circle_stroke(g.center, g.r_hub - 4.0, Stroke::new(1.5, theme::alpha(GLOW, if hub_hover { 0.9 } else { 0.45 })));
    let name = if focus == 0 { pc.tree.root_path.display().to_string() } else { n.name.clone() };
    let name = fit(p, &name, &FontId::proportional(14.0), g.r_hub * 1.6).unwrap_or_default();
    p.text(g.center - vec2(0.0, 18.0), Align2::CENTER_CENTER, name, FontId::proportional(14.0), FG);
    let size = fmt_size(n.size);
    let w = p.layout_no_wrap(size.clone(), FontId::proportional(24.0), FG).size().x;
    theme::gradient_text(p, g.center + vec2(-w / 2.0, -6.0), &size, FontId::proportional(24.0), pc.time * 0.08);
    if n.parent.is_some() {
        p.text(g.center + vec2(0.0, 30.0), Align2::CENTER_CENTER, "↑ click to go up", FontId::proportional(11.0), theme::DIM);
    }
}
