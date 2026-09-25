//! Nested squarified treemap, painted with egui on the GPU.
//!
//! As in disktree: colour is the kind of data (lighter with depth), a diagonal
//! hatch marks space that can be had back and open directories carry a name
//! band. The Abyssal look adds glassy gradients, a bloom-in intro, marching
//! stripes and a breathing cyan selection.

use super::theme::{self, BG, DANGER, FAINT, FG, GLOW};
use crate::classify::Kind;
use crate::scanner::{NodeKind, Tree};
use crate::util::fmt_size;
use eframe::egui::{pos2, vec2, Align2, Color32, FontId, Painter, Pos2, Rect, Stroke};

pub const BAND_H: f32 = 18.0;
const GAP: f32 = 2.0;
const MAX_CHILDREN: usize = 160;

#[derive(Clone, Copy, Debug)]
pub struct Tile {
    pub node: usize,
    pub rect: Rect,
    pub depth: usize,
    /// Open directory with its children drawn inside.
    pub nested: bool,
}

fn worst(row: &[f32], short: f32) -> f32 {
    let s: f32 = row.iter().sum();
    let mx = row.iter().cloned().fold(f32::MIN, f32::max);
    let mn = row.iter().cloned().fold(f32::MAX, f32::min);
    let (s2, w2) = (s * s, short * short);
    (w2 * mx / s2).max(s2 / (w2 * mn))
}

/// Squarified layout (Bruls, Huizing & van Wijk) of `sizes` (sorted, > 0) in `area`.
pub fn squarify(sizes: &[f32], area: Rect) -> Vec<Rect> {
    let total: f32 = sizes.iter().sum();
    if total <= 0.0 || area.width() <= 0.0 || area.height() <= 0.0 {
        return vec![Rect::NOTHING; sizes.len()];
    }
    let scale = area.width() * area.height() / total;
    let areas: Vec<f32> = sizes.iter().map(|s| s * scale).collect();
    let mut out = Vec::with_capacity(areas.len());
    let mut r = area;
    let mut i = 0;
    while i < areas.len() {
        let short = r.width().min(r.height()).max(1e-3);
        let mut end = i + 1;
        let mut best = worst(&areas[i..end], short);
        while end < areas.len() {
            let w = worst(&areas[i..=end], short);
            if w > best {
                break;
            }
            best = w;
            end += 1;
        }
        let sum: f32 = areas[i..end].iter().sum();
        if r.width() >= r.height() {
            let w = sum / r.height().max(1e-3);
            let mut y = r.top();
            for a in &areas[i..end] {
                let h = a / w.max(1e-3);
                out.push(Rect::from_min_size(pos2(r.left(), y), vec2(w, h)));
                y += h;
            }
            r.min.x += w;
        } else {
            let h = sum / r.width().max(1e-3);
            let mut x = r.left();
            for a in &areas[i..end] {
                let w = a / h.max(1e-3);
                out.push(Rect::from_min_size(pos2(x, r.top()), vec2(w, h)));
                x += w;
            }
            r.min.y += h;
        }
        i = end;
    }
    out
}

/// Tiles for the children of `focus`, recursing into directories large enough
/// to show their contents, up to `max_depth` levels.
pub fn layout(t: &Tree, focus: usize, area: Rect, max_depth: usize) -> Vec<Tile> {
    let mut out = Vec::new();
    layout_into(t, focus, area, 0, max_depth, &mut out);
    out
}

fn layout_into(t: &Tree, node: usize, area: Rect, depth: usize, max_depth: usize, out: &mut Vec<Tile>) {
    let kids: Vec<usize> = t.nodes[node]
        .children
        .iter()
        .copied()
        .filter(|&k| t.nodes[k].size > 0)
        .take(MAX_CHILDREN)
        .collect();
    if kids.is_empty() {
        return;
    }
    let mut sizes: Vec<f32> = kids.iter().map(|&k| t.nodes[k].size as f32).collect();
    // Children cut off by MAX_CHILDREN still take their share of the area.
    let rest = t.nodes[node].size as f32 - sizes.iter().sum::<f32>();
    if rest > sizes.last().copied().unwrap_or(0.0) {
        sizes.push(rest);
    }
    for (&k, r) in kids.iter().zip(squarify(&sizes, area)) {
        let r = r.shrink(GAP / 2.0);
        if r.width() < 1.5 || r.height() < 1.5 {
            continue;
        }
        let n = &t.nodes[k];
        let nested = depth + 1 < max_depth
            && n.kind == NodeKind::Dir
            && !n.children.is_empty()
            && r.width() >= 56.0
            && r.height() >= 44.0;
        out.push(Tile { node: k, rect: r, depth, nested });
        if nested {
            let inner = Rect::from_min_max(r.min + vec2(3.0, BAND_H + 1.0), r.max - vec2(3.0, 3.0));
            layout_into(t, k, inner, depth + 1, max_depth, out);
        }
    }
}

/// Deepest tile under `p`.
pub fn hit(tiles: &[Tile], p: Pos2) -> Option<usize> {
    tiles.iter().rev().find(|t| t.rect.contains(p)).map(|t| t.node)
}

/// Linear map taking rect `from` onto rect `to`.
#[derive(Clone, Copy)]
pub struct Xform {
    from: Rect,
    to: Rect,
}

impl Xform {
    pub fn identity() -> Self {
        Self { from: Rect::from_min_size(Pos2::ZERO, vec2(1.0, 1.0)), to: Rect::from_min_size(Pos2::ZERO, vec2(1.0, 1.0)) }
    }
    pub fn new(from: Rect, to: Rect) -> Self {
        Self { from, to }
    }
    pub fn apply(&self, r: Rect) -> Rect {
        let sx = self.to.width() / self.from.width().max(1e-3);
        let sy = self.to.height() / self.from.height().max(1e-3);
        let p = |q: Pos2| pos2(self.to.min.x + (q.x - self.from.min.x) * sx, self.to.min.y + (q.y - self.from.min.y) * sy);
        Rect::from_min_max(p(r.min), p(r.max))
    }
}

pub fn lerp_rect(a: Rect, b: Rect, t: f32) -> Rect {
    Rect::from_min_max(a.min + (b.min - a.min) * t, a.max + (b.max - a.max) * t)
}

pub struct PaintCtx<'a> {
    pub tree: &'a Tree,
    pub kinds: &'a [Kind],
    pub reclaim: &'a [bool],
    pub is_marked: &'a dyn Fn(usize) -> bool,
    pub sel: usize,
    pub hover: Option<usize>,
    /// Seconds, for ambient motion.
    pub time: f32,
    /// Ambient animation is running (window in use and motion enabled).
    pub ambient: bool,
    /// Seconds since the bloom-in intro started, while it runs.
    pub intro: Option<f32>,
}

/// (top, bottom) of a tile's vertical gradient.
pub fn tile_colors(pc: &PaintCtx, node: usize, depth: usize) -> (Color32, Color32) {
    let n = &pc.tree.nodes[node];
    let d = depth as f32;
    if (pc.is_marked)(node) {
        return (theme::mix(BG, DANGER, 0.78), theme::mix(BG, DANGER, 0.42));
    }
    if matches!(n.kind, NodeKind::Aggregate | NodeKind::Mount) {
        return (theme::mix(BG, FAINT, 0.8), theme::mix(BG, FAINT, 0.5));
    }
    let k = theme::kind(pc.kinds.get(node).copied().unwrap_or(Kind::Other));
    (theme::mix(BG, k, 0.66 + 0.1 * d), theme::mix(BG, k, 0.34 + 0.1 * d))
}

/// Diagonal stripes clipped to `r`; `offset` makes them march.
fn stripes(p: &Painter, r: Rect, color: Color32, spacing: f32, width: f32, offset: f32) {
    let p = p.with_clip_rect(r);
    let h = r.height();
    let mut x = ((r.left() - h) / spacing).floor() * spacing + offset;
    while x < r.right() + spacing {
        p.line_segment([pos2(x, r.bottom()), pos2(x + h, r.top())], Stroke::new(width, color));
        x += spacing;
    }
}

/// Text fitted to `max_w` pixels (ellipsis when it does not fit).
pub fn fit(p: &Painter, text: &str, font: &FontId, max_w: f32) -> Option<String> {
    if max_w < 12.0 {
        return None;
    }
    let w = p.layout_no_wrap(text.to_string(), font.clone(), FG).size().x;
    if w <= max_w {
        return Some(text.to_string());
    }
    let n = text.chars().count();
    let keep = ((max_w / w) * n as f32) as usize;
    if keep < 3 {
        return None;
    }
    Some(format!("{}…", text.chars().take(keep - 1).collect::<String>()))
}

/// Glowing HUD brackets on the corners of `r`.
fn brackets(p: &Painter, r: Rect, color: Color32, len: f32) {
    let len = len.min(r.width() / 3.0).min(r.height() / 3.0);
    let s = Stroke::new(2.4, color);
    for (c, dx, dy) in [
        (r.left_top(), 1.0, 1.0),
        (r.right_top(), -1.0, 1.0),
        (r.left_bottom(), 1.0, -1.0),
        (r.right_bottom(), -1.0, -1.0),
    ] {
        p.line_segment([c, c + vec2(len * dx, 0.0)], s);
        p.line_segment([c, c + vec2(0.0, len * dy)], s);
    }
}

pub fn paint(p: &Painter, pc: &PaintCtx, tiles: &[Tile], xf: Xform) {
    let name_font = FontId::proportional(12.5);
    let size_font = FontId::proportional(11.0);
    let drift = if pc.ambient { (pc.time * 9.0).rem_euclid(9.0) } else { 0.0 };
    for (i, tile) in tiles.iter().enumerate() {
        let mut r = xf.apply(tile.rect);
        // Bloom-in: tiles pop into place, parents first, with a light stagger.
        let mut fade = 1.0;
        if let Some(age) = pc.intro {
            let delay = (i as f32 * 0.004).min(0.35) + tile.depth as f32 * 0.12;
            let t = ((age - delay) / 0.45).clamp(0.0, 1.0);
            if t <= 0.0 {
                continue;
            }
            r = Rect::from_center_size(r.center(), r.size() * theme::ease_out_back(t).max(0.0));
            fade = t;
        }
        if !p.clip_rect().intersects(r) || r.width() < 1.0 || r.height() < 1.0 {
            continue;
        }
        let n = &pc.tree.nodes[tile.node];
        let hovered = pc.hover == Some(tile.node);
        let (mut top, mut bottom) = tile_colors(pc, tile.node, tile.depth);
        if hovered {
            top = theme::mix(top, Color32::WHITE, 0.16);
            bottom = theme::mix(bottom, Color32::WHITE, 0.1);
        }
        p.rect_filled(r, 3.0, theme::alpha(bottom, fade));
        theme::vgradient(p, r.shrink(1.0), theme::alpha(top, fade), theme::alpha(bottom, fade));
        // Glass: a thin highlight along the top edge.
        if r.width() > 8.0 {
            p.line_segment(
                [pos2(r.left() + 3.0, r.top() + 1.0), pos2(r.right() - 3.0, r.top() + 1.0)],
                Stroke::new(1.0, theme::alpha(Color32::WHITE, 0.22 * fade)),
            );
        }
        let marked = (pc.is_marked)(tile.node);
        if marked && !tile.nested {
            stripes(p, r.shrink(1.0), theme::alpha(BG, 0.35 * fade), 14.0, 5.0, drift * 1.6);
        } else if pc.reclaim.get(tile.node).copied().unwrap_or(false) && !tile.nested {
            stripes(p, r.shrink(1.0), theme::alpha(theme::PLANKTON, 0.42 * fade), 8.0, 1.3, drift);
        }
        let text_p = p.with_clip_rect(r.shrink(1.0));
        let text_col = theme::alpha(FG, fade);
        if tile.nested {
            let band = Rect::from_min_size(r.min, vec2(r.width(), BAND_H));
            theme::hgradient(&text_p, band.shrink2(vec2(1.0, 0.5)), theme::alpha(BG, 0.62 * fade), theme::alpha(BG, 0.18 * fade));
            let size = fmt_size(n.size);
            let size_w = text_p.layout_no_wrap(size.clone(), size_font.clone(), FG).size().x;
            if let Some(name) = fit(&text_p, &n.name, &name_font, r.width() - size_w - 18.0) {
                text_p.text(band.left_center() + vec2(6.0, 0.0), Align2::LEFT_CENTER, name, name_font.clone(), text_col);
                text_p.text(band.right_center() - vec2(6.0, 0.0), Align2::RIGHT_CENTER, size, size_font.clone(), theme::alpha(theme::mix(top, FG, 0.75), fade));
            }
        } else if r.width() > 34.0 && r.height() > 17.0 {
            let prefix = match (marked, n.kind) {
                (true, _) => "✖ ",
                (_, NodeKind::Mount) => "⏏ ",
                _ => "",
            };
            if let Some(name) = fit(&text_p, &format!("{prefix}{}", n.name), &name_font, r.width() - 10.0) {
                text_p.text(r.min + vec2(6.0, 4.0), Align2::LEFT_TOP, name, name_font.clone(), text_col);
                if r.height() > 34.0 {
                    text_p.text(r.min + vec2(6.0, 19.0), Align2::LEFT_TOP, fmt_size(n.size), size_font.clone(), theme::alpha(theme::mix(top, FG, 0.75), fade));
                }
            }
        }
        if hovered && pc.sel != tile.node {
            theme::glow_rect(p, r, 3.0, theme::alpha(Color32::WHITE, 0.9), 0.45);
        }
    }
    // Selection last so it is never covered: a breathing glow with HUD brackets.
    let mut s = Some(pc.sel);
    while let Some(i) = s {
        if let Some(tile) = tiles.iter().find(|t| t.node == i) {
            let r = xf.apply(tile.rect);
            let pulse = if pc.ambient { 0.7 + 0.3 * (pc.time * 3.4).sin() } else { 0.9 };
            theme::glow_rect(p, r.expand(1.0), 4.0, GLOW, pulse);
            brackets(p, r.expand(4.0), theme::alpha(GLOW, 0.6 + 0.4 * pulse), 12.0);
            break;
        }
        s = pc.tree.nodes[i].parent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_area_and_keeps_order() {
        let area = Rect::from_min_size(Pos2::ZERO, vec2(400.0, 300.0));
        let rects = squarify(&[50.0, 25.0, 15.0, 10.0], area);
        let covered: f32 = rects.iter().map(|r| r.area()).sum();
        assert!((covered - area.area()).abs() < 1.0);
        assert!(rects[0].area() > rects[3].area());
        assert!(rects.iter().all(|r| area.expand(0.01).contains_rect(*r)));
    }

    #[test]
    fn xform_maps_corners() {
        let a = Rect::from_min_size(Pos2::ZERO, vec2(100.0, 100.0));
        let b = Rect::from_min_size(pos2(10.0, 20.0), vec2(50.0, 25.0));
        let x = Xform::new(a, b);
        assert_eq!(x.apply(a), b);
    }
}
