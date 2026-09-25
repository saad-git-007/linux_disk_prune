//! "Abyssal" theme: deep-sea bioluminescence. Ink-violet depths, glowing
//! cyan, jellyfish magenta and plankton lime. Plus the drawing primitives the
//! views share: gradients, glows, pills, rings and the window icon.

use crate::classify::Kind;
use crate::rules::Risk;
use eframe::egui::{
    self, epaint, pos2, vec2, Color32, CornerRadius, FontFamily, FontId, Mesh, Painter, Pos2, Rect, Stroke,
    StrokeKind, TextStyle,
};
use std::f32::consts::TAU;

// Depths
pub const BG: Color32 = Color32::from_rgb(7, 6, 17);
pub const PANEL: Color32 = Color32::from_rgb(14, 12, 30);
pub const CARD: Color32 = Color32::from_rgb(22, 19, 44);
pub const CARD_HI: Color32 = Color32::from_rgb(34, 30, 64);
pub const BORDER: Color32 = Color32::from_rgb(52, 46, 98);
// Ink
pub const FG: Color32 = Color32::from_rgb(238, 235, 255);
pub const DIM: Color32 = Color32::from_rgb(152, 144, 200);
pub const FAINT: Color32 = Color32::from_rgb(82, 76, 128);
// Light
pub const GLOW: Color32 = Color32::from_rgb(0, 242, 222); // bioluminescent cyan: selection
pub const JELLY: Color32 = Color32::from_rgb(255, 72, 214); // magenta: main action
pub const PLANKTON: Color32 = Color32::from_rgb(160, 255, 110); // lime: what can be had back
pub const ACCENT: Color32 = Color32::from_rgb(138, 150, 255); // periwinkle: links, headers
pub const DANGER: Color32 = Color32::from_rgb(255, 60, 108);
pub const SAFE: Color32 = PLANKTON;
pub const MODERATE: Color32 = Color32::from_rgb(255, 178, 64);
pub const CAUTION: Color32 = Color32::from_rgb(255, 92, 150);
/// Kept for places that talk about "the main action".
pub const AMBER: Color32 = GLOW;

pub fn risk(r: Risk) -> Color32 {
    match r {
        Risk::Safe => SAFE,
        Risk::Moderate => MODERATE,
        Risk::Caution => CAUTION,
    }
}

/// Jewel tones that glow on the dark background.
pub fn kind(k: Kind) -> Color32 {
    match k {
        Kind::Code => Color32::from_rgb(92, 124, 255),
        Kind::Git => Color32::from_rgb(255, 118, 72),
        Kind::Build => Color32::from_rgb(176, 92, 255),
        Kind::Cache => Color32::from_rgb(64, 226, 160),
        Kind::Toolchain => Color32::from_rgb(0, 186, 232),
        Kind::Media => Color32::from_rgb(255, 84, 196),
        Kind::Documents => Color32::from_rgb(150, 164, 255),
        Kind::Containers => Color32::from_rgb(255, 206, 84),
        Kind::Logs => Color32::from_rgb(212, 178, 124),
        Kind::System => Color32::from_rgb(112, 108, 170),
        Kind::Other => Color32::from_rgb(120, 114, 156),
    }
}

pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

/// Colour with alpha (0..1).
pub fn alpha(c: Color32, a: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), (a.clamp(0.0, 1.0) * 255.0) as u8)
}

/// Signature gradient: cyan → periwinkle → magenta.
pub fn grad(t: f32) -> Color32 {
    let t = t.rem_euclid(1.0);
    let stops = [GLOW, ACCENT, JELLY, GLOW];
    let x = t * 3.0;
    let i = (x.floor() as usize).min(2);
    mix(stops[i], stops[i + 1], x - i as f32)
}

pub fn ease_out_cubic(t: f32) -> f32 {
    1.0 - (1.0 - t.clamp(0.0, 1.0)).powi(3)
}

pub fn ease_out_back(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    let (c1, c3) = (1.4, 2.4);
    1.0 + c3 * (t - 1.0).powi(3) + c1 * (t - 1.0).powi(2)
}

// ------------------------------------------------------------------ primitives

/// Soft radial light: opaque-ish centre fading to nothing.
pub fn radial_blob(p: &Painter, center: Pos2, radius: f32, color: Color32, strength: f32) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(center, alpha(color, strength));
    let n = 48;
    for i in 0..=n {
        let a = i as f32 / n as f32 * TAU;
        mesh.colored_vertex(center + vec2(a.cos(), a.sin()) * radius, alpha(color, 0.0));
    }
    // Mid ring for a smoother falloff.
    let base = mesh.vertices.len() as u32;
    for i in 0..=n {
        let a = i as f32 / n as f32 * TAU;
        mesh.colored_vertex(center + vec2(a.cos(), a.sin()) * radius * 0.45, alpha(color, strength * 0.55));
    }
    for i in 0..n as u32 {
        mesh.add_triangle(0, base + i, base + i + 1);
        mesh.add_triangle(base + i, 1 + i, 1 + i + 1);
        mesh.add_triangle(base + i, 1 + i + 1, base + i + 1);
    }
    p.add(epaint::Shape::mesh(mesh));
}

/// Layered outer glow around a rounded rect.
pub fn glow_rect(p: &Painter, r: Rect, radius: f32, color: Color32, intensity: f32) {
    for (i, w) in [(1, 2.0), (2, 5.0), (3, 9.0)] {
        let a = intensity * 0.32 / i as f32;
        p.rect_stroke(r.expand(w * 0.5), radius + w * 0.5, Stroke::new(w, alpha(color, a)), StrokeKind::Outside);
    }
    p.rect_stroke(r, radius, Stroke::new(1.6, alpha(color, intensity.min(1.0))), StrokeKind::Outside);
}

/// Four-corner gradient quad.
pub fn quad(p: &Painter, r: Rect, tl: Color32, tr: Color32, br: Color32, bl: Color32) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(r.left_top(), tl);
    mesh.colored_vertex(r.right_top(), tr);
    mesh.colored_vertex(r.right_bottom(), br);
    mesh.colored_vertex(r.left_bottom(), bl);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    p.add(epaint::Shape::mesh(mesh));
}

pub fn vgradient(p: &Painter, r: Rect, top: Color32, bottom: Color32) {
    quad(p, r, top, top, bottom, bottom);
}

pub fn hgradient(p: &Painter, r: Rect, left: Color32, right: Color32) {
    quad(p, r, left, right, right, left);
}

/// A stadium ("pill") filled with a horizontal gradient.
pub fn gradient_pill(p: &Painter, r: Rect, left: Color32, right: Color32) {
    let rad = r.height() / 2.0;
    let n = 40;
    let mut mesh = Mesh::default();
    for i in 0..=n {
        let t = i as f32 / n as f32;
        let x = r.left() + r.width() * t;
        let dx = (x - r.left()).min(r.right() - x);
        let h = if dx >= rad { rad } else { (rad * rad - (rad - dx).powi(2)).max(0.0).sqrt() };
        let c = mix(left, right, t);
        let cy = r.center().y;
        mesh.colored_vertex(pos2(x, cy - h), c);
        mesh.colored_vertex(pos2(x, cy + h), c);
    }
    for i in 0..n as u32 {
        let a = i * 2;
        mesh.add_triangle(a, a + 1, a + 2);
        mesh.add_triangle(a + 1, a + 3, a + 2);
    }
    p.add(epaint::Shape::mesh(mesh));
}

/// An annular sector (ring segment) with a radial colour gradient.
#[allow(clippy::too_many_arguments)]
pub fn ring_segment(p: &Painter, c: Pos2, r0: f32, r1: f32, a0: f32, a1: f32, inner: Color32, outer: Color32) {
    if a1 <= a0 || r1 <= r0 {
        return;
    }
    let steps = (((a1 - a0) / TAU) * 160.0).ceil().max(2.0) as usize;
    let mut mesh = Mesh::default();
    for i in 0..=steps {
        let a = a0 + (a1 - a0) * i as f32 / steps as f32;
        let d = vec2(a.cos(), a.sin());
        mesh.colored_vertex(c + d * r0, inner);
        mesh.colored_vertex(c + d * r1, outer);
    }
    for i in 0..steps as u32 {
        let k = i * 2;
        mesh.add_triangle(k, k + 1, k + 2);
        mesh.add_triangle(k + 1, k + 3, k + 2);
    }
    p.add(epaint::Shape::mesh(mesh));
}

/// Donut chart: `parts` are (fraction, colour); `sweep` animates 0→1.
pub fn donut(p: &Painter, c: Pos2, r0: f32, r1: f32, parts: &[(f32, Color32)], sweep: f32) {
    ring_segment(p, c, r0, r1, 0.0, TAU, alpha(FAINT, 0.35), alpha(FAINT, 0.35));
    let mut a = -TAU / 4.0;
    for &(f, col) in parts {
        let span = f * TAU * sweep;
        if span > 0.002 {
            ring_segment(p, c, r0, r1, a + 0.012, a + span - 0.012, mix(col, BG, 0.25), col);
        }
        a += span;
    }
}

/// Gradient text drawn glyph by glyph (for the wordmark and big numbers).
pub fn gradient_text(p: &Painter, pos: Pos2, text: &str, font: FontId, phase: f32) -> Rect {
    let mut x = pos.x;
    let n = text.chars().count().max(1) as f32;
    let mut h: f32 = 0.0;
    for (i, ch) in text.chars().enumerate() {
        let col = grad(phase + i as f32 / n * 0.6);
        let g = p.layout_no_wrap(ch.to_string(), font.clone(), col);
        let w = g.size().x;
        h = h.max(g.size().y);
        p.galley(pos2(x, pos.y), g, col);
        x += w;
    }
    Rect::from_min_max(pos, pos2(x, pos.y + h))
}

// ------------------------------------------------------------------ egui style

/// Add system fonts as fallbacks so symbols missing from egui's bundled fonts
/// (◆ ▦ ↑ → …) still render. DejaVu ships with every Ubuntu desktop.
fn install_fonts(ctx: &egui::Context) {
    const CANDIDATES: [&str; 2] = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf",
    ];
    let mut fonts = egui::FontDefinitions::default();
    let mut added = false;
    for (i, path) in CANDIDATES.iter().enumerate() {
        if let Ok(bytes) = std::fs::read(path) {
            let name = format!("fallback{i}");
            fonts.font_data.insert(name.clone(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
            for fam in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts.families.entry(fam).or_default().push(name.clone());
            }
            added = true;
        }
    }
    if added {
        ctx.set_fonts(fonts);
    }
}

pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_theme(egui::ThemePreference::Dark);
    let mut v = egui::Visuals::dark();
    v.panel_fill = PANEL;
    v.window_fill = CARD;
    v.extreme_bg_color = BG;
    v.faint_bg_color = CARD;
    v.window_stroke = Stroke::new(1.0, BORDER);
    v.window_corner_radius = CornerRadius::same(14);
    v.menu_corner_radius = CornerRadius::same(10);
    v.override_text_color = Some(FG);
    v.hyperlink_color = GLOW;
    v.selection.bg_fill = mix(GLOW, BG, 0.6);
    v.selection.stroke = Stroke::new(1.0, GLOW);
    v.window_shadow = epaint::Shadow { offset: [0, 10], blur: 40, spread: 0, color: alpha(JELLY, 0.18) };
    v.popup_shadow = epaint::Shadow { offset: [0, 6], blur: 24, spread: 0, color: alpha(GLOW, 0.14) };
    let w = &mut v.widgets;
    for (st, fill) in [
        (&mut w.noninteractive, CARD),
        (&mut w.inactive, CARD_HI),
        (&mut w.hovered, mix(CARD_HI, GLOW, 0.16)),
        (&mut w.active, mix(CARD_HI, GLOW, 0.3)),
        (&mut w.open, CARD_HI),
    ] {
        st.bg_fill = fill;
        st.weak_bg_fill = fill;
        st.corner_radius = CornerRadius::same(8);
    }
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.inactive.bg_stroke = Stroke::new(1.0, alpha(BORDER, 0.6));
    w.hovered.bg_stroke = Stroke::new(1.0, alpha(GLOW, 0.7));
    w.active.bg_stroke = Stroke::new(1.0, GLOW);
    ctx.set_visuals_of(egui::Theme::Dark, v);

    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.text_styles.insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        s.text_styles.insert(TextStyle::Button, FontId::new(14.0, FontFamily::Proportional));
        s.text_styles.insert(TextStyle::Small, FontId::new(11.5, FontFamily::Proportional));
        s.text_styles.insert(TextStyle::Heading, FontId::new(21.0, FontFamily::Proportional));
        s.text_styles.insert(TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace));
    });
}

/// The window icon: a glowing mosaic on the abyss, drawn at start-up.
pub fn icon() -> egui::IconData {
    const N: u32 = 64;
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    let tiles: [(u32, u32, u32, u32, Color32); 6] = [
        (4, 4, 36, 60, kind(Kind::Code)),
        (39, 4, 60, 28, kind(Kind::Cache)),
        (39, 31, 49, 60, kind(Kind::Build)),
        (52, 31, 60, 45, kind(Kind::Media)),
        (52, 48, 60, 60, kind(Kind::Toolchain)),
        (7, 7, 33, 20, GLOW),
    ];
    for y in 0..N {
        for x in 0..N {
            let i = ((y * N + x) * 4) as usize;
            // Background: radial glow from the top-left into the abyss.
            let d = (((x as f32 - 16.0).powi(2) + (y as f32 - 12.0).powi(2)).sqrt() / 70.0).min(1.0);
            let mut c = mix(Color32::from_rgb(40, 24, 80), BG, d);
            let mut a = 255;
            let (dx, dy) = (x.min(N - 1 - x), y.min(N - 1 - y));
            if dx < 6 && dy < 6 && (6 - dx) * (6 - dx) + (6 - dy) * (6 - dy) > 36 {
                a = 0;
            }
            for &(x0, y0, x1, y1, col) in &tiles {
                if x >= x0 && x <= x1 && y >= y0 && y <= y1 {
                    // Glassy vertical sheen.
                    c = mix(col, Color32::WHITE, 0.25 * (1.0 - (y - y0) as f32 / (y1 - y0) as f32));
                }
            }
            if (39..=60).contains(&x) && (4..=28).contains(&y) && (x + y) % 6 < 2 {
                c = mix(c, PLANKTON, 0.6);
            }
            rgba[i..i + 4].copy_from_slice(&[c.r(), c.g(), c.b(), a]);
        }
    }
    egui::IconData { rgba, width: N, height: N }
}
