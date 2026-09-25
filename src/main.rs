//! linux_disk_prune — fast terminal disk analyzer and safe cleanup assistant
//! for Ubuntu 22.04 LTS.
//!
//! Inspired by disktree by Tobi Lütke (https://github.com/tobi/disktree): the
//! parallel scanner and expandable size tree follow its design; the Ubuntu
//! recommendation engine and prune dashboard are new.

mod classify;
mod cleanup;
mod engine;
mod gui;
mod rules;
mod scanner;
mod ui;
mod util;

use anyhow::{Context, Result};
use clap::Parser;
use rules::ubuntu::{self, RuleContext};
use rules::{Report, Risk};
use scanner::{NodeKind, Progress, ScanOptions, Tree};
use std::path::PathBuf;
use util::{fmt_count, fmt_size, parse_size, tilde};

pub const CREDITS: &str = "Inspired by disktree by Tobi Lütke — https://github.com/tobi/disktree";

#[derive(Parser, Debug)]
#[command(
    name = "linux_disk_prune",
    version,
    about = "Fast disk analyzer and safe cleanup assistant for Ubuntu 22.04 (desktop GPU app + terminal UI)",
    long_about = "Scans a directory tree in parallel, visualises where the space goes, and \
                  finds reclaimable space in known Ubuntu bloat locations (APT cache, old \
                  kernels, snap revisions, journal, developer caches, build artifacts).\n\n\
                  Read-only by default: nothing is deleted unless you select items in the \
                  Prune panel and confirm.",
    after_help = CREDITS
)]
struct Args {
    /// Directory to scan for the tree view
    #[arg(default_value = "/")]
    path: PathBuf,

    /// Print a non-interactive report instead of starting the TUI
    #[arg(short, long)]
    summary: bool,

    /// Print the report as JSON (implies --summary)
    #[arg(long)]
    json: bool,

    /// Skip the tree scan; only run the cleanup rules (summary mode)
    #[arg(long)]
    rules_only: bool,

    /// Number of largest directories listed in the summary
    #[arg(long, default_value_t = 15)]
    top: usize,

    /// Maximum depth of directories considered in the summary
    #[arg(long, default_value_t = 3)]
    depth: usize,

    /// Descend into other mounted filesystems
    #[arg(short = 'x', long)]
    cross_filesystems: bool,

    /// Files smaller than this are grouped as "<N small files>" in the tree
    #[arg(long, default_value = "1M", value_parser = parse_size)]
    min_file_size: u64,

    /// Journal size to keep when suggesting `journalctl --vacuum-size`
    #[arg(long, default_value = "500M", value_parser = parse_size)]
    journal_keep: u64,

    /// Home directory for user caches (default: the invoking user's home, even under sudo)
    #[arg(long)]
    home: Option<PathBuf>,

    /// Where to look for project build artifacts (repeatable; default: home)
    #[arg(long = "dev-root")]
    dev_roots: Vec<PathBuf>,

    /// Disable cleanup execution (pure viewer)
    #[arg(long)]
    no_exec: bool,

    /// Use the terminal UI instead of the desktop window (automatic without a display)
    #[arg(long)]
    tui: bool,

    /// GPU renderer for the desktop window: auto (Vulkan, falling back to OpenGL), vulkan or gl
    #[arg(long, default_value = "auto", value_parser = ["auto", "vulkan", "gl"])]
    renderer: String,

    /// Scanner threads (0 = auto: 2x CPUs on SSD/NVMe, at most 4 on spinning disks)
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// Colour depth: auto, truecolor or 256 (use 256 inside screen/tmux without truecolor)
    #[arg(long, default_value = "auto", value_parser = ["auto", "truecolor", "256"])]
    color: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Absolute paths only: findings and their commands must not depend on the
    // directory they are run from.
    let absolute = |p: &PathBuf| std::fs::canonicalize(p).unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(p));
    let home = args.home.as_ref().map(absolute).unwrap_or_else(util::real_user_home);
    let rule_ctx = RuleContext {
        dev_roots: if args.dev_roots.is_empty() { vec![home.clone()] } else { args.dev_roots.iter().map(absolute).collect() },
        home,
        // journalctl takes whole MiB; never ask it to vacuum down to 0.
        journal_keep: args.journal_keep.max(1 << 20),
        is_root: util::is_root(),
    };
    let root = std::fs::canonicalize(&args.path)
        .with_context(|| format!("cannot access {}", args.path.display()))?;
    let scan_opts = ScanOptions {
        one_file_system: !args.cross_filesystems,
        min_file_size: args.min_file_size,
        threads: if args.threads == 0 { scanner::auto_threads(&root) } else { args.threads },
    };
    ui::set_truecolor(match args.color.as_str() {
        "truecolor" => true,
        "256" => false,
        _ => ui::detect_truecolor(),
    });

    if args.summary || args.json {
        return summary(&args, root, &scan_opts, &rule_ctx);
    }
    if !args.tui && gui::display_available() {
        let renderer = match args.renderer.as_str() {
            "vulkan" => gui::Renderer::Vulkan,
            "gl" => gui::Renderer::Gl,
            _ => gui::Renderer::Auto,
        };
        return gui::run(gui::Config { root, scan_opts, rule_ctx, no_exec: args.no_exec, renderer });
    }
    ui::run(ui::Config { root, scan_opts, rule_ctx, no_exec: args.no_exec })
}

fn summary(args: &Args, root: PathBuf, opts: &ScanOptions, ctx: &RuleContext) -> Result<()> {
    let tree = if args.rules_only {
        None
    } else {
        if !args.json {
            eprintln!("Scanning {} …", root.display());
        }
        Some(scanner::scan(&root, opts, &Progress::default())?)
    };
    let mut report = Report::default();
    let (sys, art) = rayon::join(
        || ubuntu::run_system_checks(ctx),
        || ubuntu::run_artifact_check(ctx, tree.as_ref(), opts),
    );
    report.merge(sys);
    report.merge(art);

    if args.json {
        let largest: Vec<_> = tree
            .as_ref()
            .map(|t| {
                largest_dirs(t, args.top, args.depth)
                    .into_iter()
                    .map(|i| {
                        let p = t.path_of(i);
                        serde_json::json!({"path": p.to_string_lossy(), "lossy": p.to_str().is_none(), "bytes": t.nodes[i].size})
                    })
                    .collect()
            })
            .unwrap_or_default();
        let json = serde_json::json!({
            "root": root.to_string_lossy(),
            "total_bytes": tree.as_ref().map(|t| t.root().size),
            "largest_dirs": largest,
            "reclaimable": {
                "safe": report.total(Risk::Safe),
                "moderate": report.total(Risk::Moderate),
                "caution": report.total(Risk::Caution),
            },
            "findings": report.findings.iter().map(|f| serde_json::json!({
                "id": f.id, "category": f.category, "title": f.title, "risk": f.risk,
                "bytes": f.bytes, "command": f.command_text(), "needs_root": f.needs_root,
                "detail": f.detail,
                // JSON strings must be UTF-8: non-UTF-8 paths are shown lossily
                // and flagged; the app itself always acts on the exact bytes.
                "paths": f.paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                "lossy_paths": f.paths.iter().any(|p| p.to_str().is_none()),
            })).collect::<Vec<_>>(),
            "notes": report.notes,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    let bold = |s: &str| format!("\x1b[1m{s}\x1b[0m");
    let tier_color = |r: Risk| match r {
        Risk::Safe => "\x1b[1;32m",
        Risk::Moderate => "\x1b[1;33m",
        Risk::Caution => "\x1b[1;31m",
    };
    println!("{}", bold(&format!("linux_disk_prune {} — Ubuntu disk report", env!("CARGO_PKG_VERSION"))));
    println!("\x1b[2m{CREDITS}\x1b[0m\n");

    if let Some(t) = &tree {
        println!(
            "Scanned {}: {} in {} files, {} dirs ({:.1}s{})",
            root.display(),
            bold(&fmt_size(t.root().size)),
            fmt_count(t.root().files),
            fmt_count(t.dirs),
            t.elapsed.as_secs_f64(),
            if t.errors > 0 { format!(", {} unreadable", fmt_count(t.errors)) } else { String::new() }
        );
        println!("\n{}", bold("LARGEST DIRECTORIES"));
        let total = t.root().size.max(1);
        for i in largest_dirs(t, args.top, args.depth) {
            let n = &t.nodes[i];
            let pct = n.size as f64 * 100.0 / total as f64;
            let bar = "█".repeat((pct / 5.0).round() as usize);
            println!(
                "  {:>11}  {:>5.1}%  \x1b[36m{:<20}\x1b[0m {}",
                fmt_size(n.size),
                pct,
                bar,
                tilde(&t.path_of(i), &ctx.home)
            );
        }
    }

    println!("\n{}", bold("RECLAIMABLE SPACE"));
    for r in Risk::ALL {
        println!("  {}{:<9}\x1b[0m {:>11}", tier_color(r), r.label(), fmt_size(report.total(r)));
    }
    println!("  {:<9} {:>11}", "TOTAL", bold(&fmt_size(report.grand_total())));

    for r in Risk::ALL {
        let items: Vec<_> = report.findings.iter().filter(|f| f.risk == r).collect();
        if items.is_empty() {
            continue;
        }
        println!("\n{}── {} ──\x1b[0m", tier_color(r), r.label());
        for f in items {
            println!("  {:>11}  {}", fmt_size(f.bytes), bold(&f.title));
            let cmd = f.command_text();
            let cmd = if cmd.len() > 300 { format!("{} …", &cmd[..cmd.floor_char_boundary(300)]) } else { cmd };
            println!("               \x1b[33m$ {cmd}\x1b[0m");
        }
    }
    for n in &report.notes {
        println!("\n\x1b[2mnote: {n}\x1b[0m");
    }
    println!(
        "\nNothing was deleted. Run the commands above yourself, or start the interactive \
         mode (without --summary) to select and clean items."
    );
    Ok(())
}

/// Largest directories up to `max_depth` below the root.
fn largest_dirs(t: &Tree, n: usize, max_depth: usize) -> Vec<usize> {
    let mut all: Vec<usize> = (1..t.nodes.len())
        .filter(|&i| t.nodes[i].kind == NodeKind::Dir && t.depth_of(i) <= max_depth)
        .collect();
    all.sort_by(|&a, &b| t.nodes[b].size.cmp(&t.nodes[a].size));
    all.truncate(n);
    all
}
