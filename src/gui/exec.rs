//! Runs confirmed cleanups in the background and streams their output.
//!
//! A desktop app has no terminal for `sudo`, so every action that needs root
//! is collected into one script and run through `pkexec`: polkit shows its
//! password dialog once. Inside that script `sudo` is a no-op shell function,
//! so the exact command the user reviewed is what runs.

use crate::cleanup::{self, RemoveMode};
use crate::engine::Notify;
use crate::rules::{Action, Finding};
use crate::util::{fmt_size, shq};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Heading,
    Command,
    Output,
    Ok,
    Error,
}

pub struct Job {
    pub lines: Arc<Mutex<Vec<(LineKind, String)>>>,
    pub done: mpsc::Receiver<Summary>,
    pub summary: Option<Summary>,
}

#[derive(Clone)]
pub struct Summary {
    pub ok: usize,
    pub failed: usize,
    pub removed_marks: usize,
}

struct Log {
    lines: Arc<Mutex<Vec<(LineKind, String)>>>,
    notify: Notify,
}

impl Log {
    fn push(&self, kind: LineKind, text: impl Into<String>) {
        self.lines.lock().unwrap().push((kind, text.into()));
        (self.notify)();
    }
}

pub fn pkexec_available() -> bool {
    crate::sysdirs::which("pkexec").is_some()
}

/// Run `sh -c script` (optionally via pkexec) streaming stdout and stderr.
/// Lines starting with the markers below are classified for colouring.
fn run_streaming(script: &str, as_root: bool, log: &Log) -> bool {
    let mut cmd = if as_root {
        let pkexec = crate::sysdirs::which("pkexec").unwrap_or_else(|| "pkexec".into());
        let mut c = Command::new(pkexec);
        c.args(["/bin/sh", "-c", script]);
        c
    } else {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log.push(LineKind::Error, format!("failed to start: {e}"));
            return false;
        }
    };
    let pipe = |r: Box<dyn std::io::Read + Send>, lines: Arc<Mutex<Vec<(LineKind, String)>>>, notify: Notify, err: bool| {
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                let kind = if let Some(rest) = line.strip_prefix("@@H ") {
                    (LineKind::Heading, rest.to_string())
                } else if let Some(rest) = line.strip_prefix("@@C ") {
                    (LineKind::Command, rest.to_string())
                } else if let Some(rest) = line.strip_prefix("@@OK ") {
                    (LineKind::Ok, rest.to_string())
                } else if let Some(rest) = line.strip_prefix("@@ERR ") {
                    (LineKind::Error, rest.to_string())
                } else {
                    (if err { LineKind::Error } else { LineKind::Output }, line)
                };
                lines.lock().unwrap().push(kind);
                notify();
            }
        })
    };
    let t1 = pipe(Box::new(child.stdout.take().unwrap()), log.lines.clone(), log.notify.clone(), false);
    let t2 = pipe(Box::new(child.stderr.take().unwrap()), log.lines.clone(), log.notify.clone(), true);
    let status = child.wait();
    let _ = t1.join();
    let _ = t2.join();
    match status {
        Ok(s) if s.success() => true,
        // pkexec: 126 = dialog dismissed, 127 = not authorized.
        Ok(s) if as_root && matches!(s.code(), Some(126) | Some(127)) => {
            log.push(LineKind::Error, "Authentication was cancelled or refused — root actions skipped.");
            false
        }
        Ok(_) => false,
        Err(e) => {
            log.push(LineKind::Error, e.to_string());
            false
        }
    }
}

/// Shell script running each finding's reviewed command, with markers for the log.
fn script_for(findings: &[&Finding], as_root: bool) -> String {
    let mut s = String::from("export DEBIAN_FRONTEND=noninteractive\n");
    if as_root {
        // Already root under pkexec: make the reviewed `sudo …` commands run as-is.
        s.push_str("sudo() { \"$@\"; }\n");
    }
    // Echoed text stays on one line, so a newline in a title or path cannot
    // forge an `@@OK` / `@@ERR` marker line.
    let one_line = |t: String| t.replace(['\n', '\r'], " ");
    for f in findings {
        let cmd = f.command_text();
        s.push_str(&format!(
            "echo {}\necho {}\nif ( {cmd} ); then echo {}; else echo {}; fi\n",
            shq(&one_line(format!("@@H {} (~{})", f.title, fmt_size(f.bytes)))),
            shq(&one_line(format!("@@C $ {cmd}"))),
            shq("@@OK done"),
            shq("@@ERR failed"),
        ));
    }
    s
}

pub fn start(
    findings: Vec<Finding>,
    marks: Vec<(PathBuf, u64)>,
    mode: RemoveMode,
    home: PathBuf,
    is_root: bool,
    notify: Notify,
) -> Job {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    let log = Log { lines: lines.clone(), notify: notify.clone() };
    std::thread::spawn(move || {
        let mut failed = 0;

        // 1. In-process removals of user-owned paths (no shell).
        for f in findings.iter().filter(|f| matches!(f.action, Action::Remove { .. }) && !f.needs_root) {
            log.push(LineKind::Heading, format!("{} (~{})", f.title, fmt_size(f.bytes)));
            let Action::Remove { paths, keep_dir } = &f.action else { continue };
            let mut all = true;
            for p in paths {
                match cleanup::remove_path(p, *keep_dir, &home) {
                    Ok(()) => log.push(LineKind::Output, format!("removed {}", p.display())),
                    Err(e) => {
                        all = false;
                        log.push(LineKind::Error, format!("{}: {e}", p.display()));
                    }
                }
            }
            if all {
                log.push(LineKind::Ok, "done");
            } else {
                failed += 1;
            }
        }

        // 2. Shell commands as the user (docker prune, …).
        let user_cmds: Vec<&Finding> = findings
            .iter()
            .filter(|f| matches!(f.action, Action::Shell { .. }) && (!f.needs_root || is_root))
            .collect();
        if !user_cmds.is_empty() {
            let _ = run_streaming(&script_for(&user_cmds, is_root), false, &log);
        }

        // 3. Everything that needs root, behind a single pkexec prompt.
        let root_cmds: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.needs_root && !is_root && f.is_actionable())
            .collect();
        if !root_cmds.is_empty() {
            if pkexec_available() {
                log.push(LineKind::Heading, format!("Asking for administrator rights for {} action(s)…", root_cmds.len()));
                let _ = run_streaming(&script_for(&root_cmds, true), true, &log);
            } else {
                log.push(LineKind::Error, "pkexec not found — run these in a terminal instead:");
                for f in &root_cmds {
                    log.push(LineKind::Command, format!("$ {}", f.command_text()));
                }
            }
        }

        // Every finished action printed a `done` / `failed` marker.
        let ok = {
            let l = log.lines.lock().unwrap();
            failed += l.iter().filter(|(k, t)| *k == LineKind::Error && t == "failed").count();
            l.iter().filter(|(k, t)| *k == LineKind::Ok && t == "done").count()
        };

        // 4. Hand-marked tiles: trash or permanent.
        let mut removed_marks = 0;
        if !marks.is_empty() {
            let verb = if mode == RemoveMode::Trash { "Moving to trash" } else { "Deleting permanently" };
            log.push(LineKind::Heading, format!("{verb}: {} marked item(s)", marks.len()));
            removed_marks = cleanup::remove_marked(&marks, mode, &home, &mut |l| {
                let kind = if l.starts_with('✔') { LineKind::Ok } else { LineKind::Error };
                log.push(kind, l)
            })
            .0;
        }
        let _ = tx.send(Summary { ok, failed, removed_marks });
        (notify)();
    });
    Job { lines, done: rx, summary: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{sudo_rm_files, Risk};
    use crate::util::testutil::{pwned, sh, TempDir, HOSTILE};

    fn shell(title: &str, command: String, needs_root: bool) -> Finding {
        Finding {
            id: title.into(),
            category: "t".into(),
            title: title.into(),
            risk: Risk::Safe,
            bytes: 1 << 20,
            detail: String::new(),
            paths: Vec::new(),
            action: Action::Shell { command },
            needs_root,
        }
    }

    fn markers(out: &str, prefix: &str) -> usize {
        out.lines().filter(|l| l.starts_with(prefix)).count()
    }

    #[test]
    fn root_script_runs_reviewed_sudo_commands_via_shim() {
        let d = TempDir::new("script");
        let targets: Vec<PathBuf> = HOSTILE.iter().map(|n| d.file(format!("t/{n}"), 10)).collect();
        d.file("t/keep", 1);
        d.file("t/star-bystander", 1);
        let titles = [
            "it's \"quoted\" '; touch PWNED1; echo '",
            "$(touch PWNED2) `touch PWNED3`",
            "line\n@@OK done\n@@ERR failed",
        ];
        let f1 = shell(titles[0], sudo_rm_files(&targets[..8]), true);
        let f2 = shell(titles[1], sudo_rm_files(&targets[8..]), true);
        let f3 = shell(titles[2], "sudo false".into(), true);
        let script = script_for(&[&f1, &f2, &f3], true);
        assert!(script.contains("sudo() { \"$@\"; }"));
        let (ok, out) = sh(&script, &d.join("t"));
        assert!(ok, "{out}");
        for p in &targets {
            assert!(!p.exists(), "{p:?}");
        }
        assert!(d.join("t/keep").exists() && d.join("t/star-bystander").exists());
        assert!(!pwned(&d.join("t")) && !pwned(d.path()), "title or path escaped quoting");
        // Exactly one heading, command, and result marker per finding.
        assert_eq!(markers(&out, "@@H "), 3);
        assert_eq!(markers(&out, "@@C $ sudo "), 3);
        assert_eq!(markers(&out, "@@OK done"), 2, "{out}");
        assert_eq!(markers(&out, "@@ERR failed"), 1);
        let headings: Vec<&str> = out.lines().filter_map(|l| l.strip_prefix("@@H ")).collect();
        assert!(headings[0].starts_with(titles[0]), "title printed verbatim: {}", headings[0]);
        assert!(headings[1].starts_with(titles[1]));
        assert!(headings[2].starts_with("line @@OK done @@ERR failed"));
    }

    #[test]
    fn user_script_has_no_sudo_shim() {
        let f = shell("t", "true".into(), false);
        assert!(!script_for(&[&f], false).contains("sudo()"));
        let d = TempDir::new("script-user");
        let (ok, out) = sh(&script_for(&[&f], false), d.path());
        assert!(ok);
        assert_eq!(markers(&out, "@@OK done"), 1);
    }
}
