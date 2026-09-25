#!/usr/bin/env python3
"""Functional test harness for linux_disk_prune (Python stdlib only).

Complements tests/blackbox/run_blackbox_tests.py (which covers du-accuracy on a
mixed tree, artifact/cache detection, command quoting and basic robustness).
This harness covers what that suite does not:

  A  CLI surface: every flag/combination from --help, exit codes, stderr,
     JSON schema/type stability, summary sanity (totals, ordering, --top, --depth)
  B  scanner vs GNU du on tricky trees: deep nesting (< and > PATH_MAX),
     100k small files, multi-link hard links, r--/--x dirs, FIFOs/sockets,
     fallocate, U+FFFD collisions, concurrent writers/deleters, mounts
     (unshare -rm), /dev and /proc
  C  TUI in a pseudo-terminal (own tiny VT100 emulator): render, keys, panels,
     Prune list, review/cancel, real deletion (Trash + permanent) of a marked
     fixture item, guards (scan root, home, symlinked parent, mount points),
     resize, TERM/--color variants, terminal restore
  D  robustness: signals, /proc hidden, unreadable PATH/home, empty dir, file
     PATH, symlink PATH, huge thread counts
  E  performance on /usr and / (read-only), compared with du -sx

Usage:
  python3 tests/functional/run_functional_tests.py --binary PATH [--workdir DIR]
          [--only A,B,C,D,E] [--skip-perf] [--keep]

SAFETY: every deletion happens in fixture directories created under --workdir,
with HOME/XDG_* pointing at a fixture home.  The desktop display is never used
(DISPLAY/WAYLAND_DISPLAY are removed from the environment).  Findings from the
recommendation engine are never executed: sessions that touch the Prune list
run with --no-exec, and deletion sessions verify that the review lists only
marked fixture paths before confirming.
"""
import argparse, codecs, fcntl, json, os, re, select, shutil, signal, socket, stat, struct
import subprocess, sys, termios, threading, time, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BIN = os.path.join(HERE, "..", "..", "target", "release", "linux_disk_prune")
MiB = 1 << 20
RESULTS = []
BIN = None
WORK = None


# ----------------------------------------------------------------- recording
def rec(test, ok, expected="", actual="", note="", info=False):
    status = "INFO" if info else ("PASS" if ok else "FAIL")
    RESULTS.append((test, status, str(expected), str(actual), str(note)))
    print(f"[{status}] {test}: expected={str(expected)[:160]} actual={str(actual)[:200]} {str(note)[:200]}", flush=True)
    return ok


def clean_env(home=None, extra=None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "CARGO_HOME",
                        "PIP_CACHE_DIR", "npm_config_cache", "XDG_RUNTIME_DIR", "COLORTERM")}
    if home:
        env.update(HOME=home, XDG_DATA_HOME=os.path.join(home, ".local", "share"),
                   XDG_CACHE_HOME=os.path.join(home, ".cache"),
                   XDG_CONFIG_HOME=os.path.join(home, ".config"), GIO_USE_VFS="local")
    env.setdefault("TERM", "xterm-256color")
    if extra:
        env.update(extra)
    return env


def fake_home(name="home"):
    h = os.path.join(WORK, name)
    for d in (".local/share", ".cache", ".config"):
        os.makedirs(os.path.join(h, d), exist_ok=True)
    return h


def run(args, home=None, cwd=None, timeout=600, env=None, prefix=()):
    env = env or clean_env(home or fake_home())
    os.sync()  # delayed allocation: st_blocks settles after writeback
    t0 = time.time()
    p = subprocess.run(list(prefix) + [BIN] + args, cwd=cwd, env=env, capture_output=True,
                       timeout=timeout, stdin=subprocess.DEVNULL)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), time.time() - t0


def run_json(args, **kw):
    rc, out, err, wall = run(["--json"] + args, **kw)
    try:
        d = json.loads(out)
    except Exception:
        d = None
    return rc, d, err, wall


def du(path, x=True, extra=()):
    os.sync()
    cmd = ["du", "-s", "-B1"] + (["-x"] if x else []) + list(extra) + [path]
    p = subprocess.run(cmd, capture_output=True)
    return int(p.stdout.split()[0])


def du_ns(script_setup, path, x=True):
    """du inside an unshare -rm namespace after running script_setup."""
    p = subprocess.run(["unshare", "-rm", "sh", "-c", f"{script_setup} && du -s -B1 {'-x' if x else ''} '{path}'"],
                       capture_output=True)
    return int(p.stdout.split()[0])


def write_file(path, nbytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        left = nbytes
        while left > 0:
            n = min(left, MiB)
            f.write(os.urandom(n))
            left -= n


def snapshot(root):
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (stat.S_IFMT(st.st_mode), st.st_size if not stat.S_ISDIR(st.st_mode) else 0)
    return out


def unshare_ok():
    try:
        return subprocess.run(["unshare", "-rm", "true"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def nuke(root):
    """rm -rf a fixture tree (GNU rm copes with >PATH_MAX depth; shutil does not)."""
    assert os.path.abspath(root).startswith(WORK), root
    chmod_tree_writable(root)
    subprocess.run(["rm", "-rf", "--one-file-system", "--", root])


def chmod_tree_writable(root):
    subprocess.run(["chmod", "-R", "u+rwx", root], capture_output=True)


SCHEMA_TOP = {"root": str, "total_bytes": (int, type(None)), "largest_dirs": list, "reclaimable": dict,
              "findings": list, "notes": list, "scan_errors": (int, type(None))}
SCHEMA_FINDING = {"id": str, "category": str, "title": str, "risk": str, "bytes": int, "command": str,
                  "needs_root": bool, "detail": str, "paths": list, "lossy_paths": bool}


def schema_problems(d):
    probs = []
    if not isinstance(d, dict):
        return ["not an object"]
    if set(d) != set(SCHEMA_TOP):
        probs.append(f"top keys {sorted(d)}")
    for k, t in SCHEMA_TOP.items():
        if k in d and not isinstance(d[k], t):
            probs.append(f"{k} type {type(d[k]).__name__}")
    for x in d.get("largest_dirs", []):
        if set(x) != {"path", "lossy", "bytes"} or not isinstance(x.get("path"), str) \
                or not isinstance(x.get("lossy"), bool) or not isinstance(x.get("bytes"), int) or isinstance(x.get("bytes"), bool):
            probs.append(f"largest_dirs item {x}")
    r = d.get("reclaimable", {})
    if set(r) != {"safe", "moderate", "caution"} or not all(isinstance(v, int) and v >= 0 for v in r.values()):
        probs.append(f"reclaimable {r}")
    for f in d.get("findings", []):
        if set(f) != set(SCHEMA_FINDING):
            probs.append(f"finding keys {sorted(f)}")
        for k, t in SCHEMA_FINDING.items():
            if k in f and (not isinstance(f[k], t) or (t is int and isinstance(f[k], bool))):
                probs.append(f"finding.{k} type {type(f[k]).__name__}")
        if f.get("risk") not in ("SAFE", "MODERATE", "CAUTION"):
            probs.append(f"risk {f.get('risk')}")
        if not all(isinstance(p, str) for p in f.get("paths", [])):
            probs.append("paths not str")
        if isinstance(f.get("bytes"), int) and f["bytes"] < 0:
            probs.append("negative bytes")
    if not all(isinstance(n, str) for n in d.get("notes", [])):
        probs.append("notes not str")
    return probs


# ============================================================ VT100 emulator
class Screen:
    """Just enough of a VT100/xterm to read what ratatui/crossterm draws."""

    def __init__(self, rows, cols):
        self.dec = codecs.getincrementaldecoder("utf-8")("replace")
        self.raw = bytearray()
        self.state, self.buf = "n", ""
        self.alt = self.mouse = self.hidden = False
        self.saved = (0, 0)
        self.reply = None          # callback answering terminal queries (DSR)
        self.answer_dsr = True
        self.resize(rows, cols)

    def resize(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.x = self.y = 0

    def text(self):
        return "\n".join("".join(r) for r in self.grid)

    def feed(self, data):
        self.raw += data
        for ch in self.dec.decode(data):
            self._ch(ch)

    def _nl(self):
        self.y += 1
        if self.y >= self.rows:
            self.grid.pop(0)
            self.grid.append([" "] * self.cols)
            self.y = self.rows - 1

    def _ch(self, ch):
        s = self.state
        if s == "n":
            if ch == "\x1b":
                self.state = "e"
            elif ch == "\r":
                self.x = 0
            elif ch == "\n":
                self._nl()
            elif ch == "\b":
                self.x = max(0, self.x - 1)
            elif ord(ch) < 32 or ch == "\x7f":
                pass
            else:
                if unicodedata.combining(ch):
                    return
                w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
                if self.x + w > self.cols:
                    self.x = 0
                    self._nl()
                self.grid[self.y][self.x] = ch
                if w == 2 and self.x + 1 < self.cols:
                    self.grid[self.y][self.x + 1] = ""
                self.x += w
        elif s == "e":
            self.state = "n"
            if ch == "[":
                self.state, self.buf = "c", ""
            elif ch == "]":
                self.state = "o"
            elif ch in "()*+":
                self.state = "g"
            elif ch == "7":
                self.saved = (self.x, self.y)
            elif ch == "8":
                self.x, self.y = self.saved
        elif s == "g":
            self.state = "n"
        elif s == "o":
            if ch == "\x07":
                self.state = "n"
            elif ch == "\x1b":
                self.state = "oe"
        elif s == "oe":
            self.state = "n"
        elif s == "c":
            if "\x40" <= ch <= "\x7e":
                self._csi(self.buf, ch)
                self.state = "n"
            else:
                self.buf += ch

    def _csi(self, buf, fin):
        priv = buf.startswith("?")
        ps = [int(p) if p.isdigit() else 0 for p in buf.lstrip("?>=").split(";")] if buf.lstrip("?>=") else []
        p0 = ps[0] if ps else 0
        n = max(p0, 1)
        if priv and fin in "hl":
            on = fin == "h"
            for p in ps:
                if p in (1049, 1047, 47):
                    self.alt = on
                    if on:
                        self.grid = [[" "] * self.cols for _ in range(self.rows)]
                elif p in (1000, 1002, 1003, 1006, 1015):
                    self.mouse = on
                elif p == 25:
                    self.hidden = not on
            return
        if fin == "n" and p0 == 6 and not priv:
            if self.reply and self.answer_dsr:
                self.reply(f"\x1b[{self.y + 1};{self.x + 1}R".encode())
            return
        if fin in "Hf":
            self.y = min(max((ps[0] if ps else 1) - 1, 0), self.rows - 1)
            self.x = min(max((ps[1] if len(ps) > 1 else 1) - 1, 0), self.cols - 1)
        elif fin == "A":
            self.y = max(0, self.y - n)
        elif fin == "B":
            self.y = min(self.rows - 1, self.y + n)
        elif fin == "C":
            self.x = min(self.cols - 1, self.x + n)
        elif fin == "D":
            self.x = max(0, self.x - n)
        elif fin == "G":
            self.x = min(self.cols - 1, n - 1)
        elif fin == "d":
            self.y = min(self.rows - 1, n - 1)
        elif fin == "J":
            if p0 in (2, 3):
                self.grid = [[" "] * self.cols for _ in range(self.rows)]
            elif p0 == 0:
                self.grid[self.y][self.x:] = [" "] * (self.cols - self.x)
                for r in range(self.y + 1, self.rows):
                    self.grid[r] = [" "] * self.cols
        elif fin == "K":
            if p0 == 0:
                self.grid[self.y][self.x:] = [" "] * (self.cols - self.x)
            elif p0 == 2:
                self.grid[self.y] = [" "] * self.cols
            elif p0 == 1:
                self.grid[self.y][:self.x + 1] = [" "] * (self.x + 1)
        elif fin == "X":
            for i in range(self.x, min(self.cols, self.x + n)):
                self.grid[self.y][i] = " "


KEY = {"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D", "enter": "\r",
       "bs": "\x7f", "esc": "\x1b", "tab": "\t", "backtab": "\x1b[Z", "home": "\x1b[H", "end": "\x1b[F",
       "pgdn": "\x1b[6~", "pgup": "\x1b[5~", "f5": "\x1b[15~", "ctrl_c": "\x03"}


class Tui:
    def __init__(self, args, home, rows=40, cols=130, env_extra=None, prefix=(), cwd=None, env=None, answer_dsr=True):
        self.screen = Screen(rows, cols)
        self.screen.answer_dsr = answer_dsr
        self.lock = threading.Lock()
        self.m, self.s = os.openpty()
        self._winsz(rows, cols)
        self.cooked = termios.tcgetattr(self.s)
        env = env or clean_env(home, env_extra)

        def pre():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.p = subprocess.Popen(list(prefix) + [BIN] + args, stdin=self.s, stdout=self.s, stderr=self.s,
                                  env=env, cwd=cwd, preexec_fn=pre, close_fds=True)
        self.done = False
        self.screen.reply = lambda b: os.write(self.m, b)
        self.t = threading.Thread(target=self._reader, daemon=True)
        self.t.start()

    def _winsz(self, rows, cols):
        fcntl.ioctl(self.m, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def _reader(self):
        while True:
            try:
                r, _, _ = select.select([self.m], [], [], 0.1)
                if r:
                    data = os.read(self.m, 65536)
                    if not data:
                        break
                    with self.lock:
                        self.screen.feed(data)
                elif self.p.poll() is not None and self.done:
                    break
            except OSError:
                break

    def resize(self, rows, cols):
        with self.lock:
            self.screen.resize(rows, cols)
        self._winsz(rows, cols)  # kernel sends SIGWINCH to the foreground group

    def send(self, keys, pause=0.25):
        for k in (keys if isinstance(keys, list) else [keys]):
            os.write(self.m, KEY.get(k, k).encode())
            time.sleep(pause)

    def text(self):
        with self.lock:
            return self.screen.text()

    def flat(self):
        """Screen rows concatenated without separators: undoes soft line wraps."""
        with self.lock:
            return "".join("".join(r) for r in self.screen.grid)

    def raw(self):
        with self.lock:
            return bytes(self.screen.raw)

    def wait(self, pat, timeout=30, absent=False):
        rx = re.compile(pat)
        end = time.time() + timeout
        while time.time() < end:
            hit = rx.search(self.text())
            if bool(hit) != absent:
                return True
            if self.p.poll() is not None:
                time.sleep(0.2)
                hit = rx.search(self.text())
                return bool(hit) != absent
            time.sleep(0.1)
        return False

    def wait_raw(self, pat, timeout=30):
        rx = re.compile(pat)
        end = time.time() + timeout
        while time.time() < end:
            if rx.search(self.raw()):
                return True
            time.sleep(0.1)
        return False

    def selected_line(self):
        """The Tree/Prune row carrying the selection bar (panel border + '▌')."""
        return next((l for l in self.text().splitlines() if re.search(r"│▌", l)), "")

    def termios_cooked(self):
        a = termios.tcgetattr(self.s)
        return bool(a[3] & termios.ICANON) and bool(a[3] & termios.ECHO)

    def wait_exit(self, timeout=10):
        try:
            return self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def close(self):
        self.done = True
        if self.p.poll() is None:
            self.p.kill()
            self.p.wait()
        time.sleep(0.2)
        for fd in (self.m, self.s):
            try:
                os.close(fd)
            except OSError:
                pass


def scan_done_re():
    return r"\d+ files · \d+ dirs · [\d.]+s"


# ============================================================ A: CLI surface
def test_cli():
    root = os.path.join(WORK, "cli")
    home = fake_home("cli_home")
    # distinct sizes so ordering is unambiguous; depth up to 4
    layout = {"a/big.bin": 9, "a/a1/f.bin": 5, "a/a1/a2/f.bin": 3, "a/a1/a2/a3/f.bin": 2,
              "b/f.bin": 7, "b/b1/f.bin": 4, "c/f.bin": 6, "d/f.bin": 1, "e/e1/e2/f.bin": 8}
    for rel, mb in layout.items():
        write_file(os.path.join(root, rel), mb * MiB + 1234)
    os.makedirs(os.path.join(root, "empty"), exist_ok=True)

    rc, out, err, _ = run(["--help"])
    rec("A.--help rc/content", rc == 0 and "--min-file-size" in out and "--renderer" in out, "rc=0 + options", rc)
    rc, out, err, _ = run(["-h"])
    rec("A.-h short help", rc == 0 and "Usage:" in out, "rc=0", rc)
    rc, out, err, _ = run(["-V"])
    rec("A.-V version", rc == 0 and re.match(r"linux_disk_prune \d+\.\d+\.\d+", out), "linux_disk_prune X.Y.Z", out.strip())
    rc, out, err, _ = run(["--bogus-flag"])
    rec("A.unknown flag rc=2 + message", rc == 2 and "unexpected argument" in err, "rc=2", rc, err.strip()[:80])
    rc, out, err, _ = run([root, root])
    rec("A.two PATH arguments rejected", rc == 2, "rc=2", rc, err.strip()[:80])

    # ---------------- JSON schema, stability, stdout/stderr split
    rc, d, err, _ = run_json(["--home", home, root])
    rec("A.json rc=0 + parses", rc == 0 and d is not None, "rc=0", rc, err[:120])
    if d is None:
        return
    rec("A.json schema: all keys typed", not schema_problems(d), "no problems", schema_problems(d)[:5])
    rec("A.json writes nothing to stderr", err.strip() == "", "''", err.strip()[:120])
    rc2, d2, _, _ = run_json(["--home", home, "--rules-only", root])
    rec("A.json --rules-only: total_bytes null, largest_dirs []", d2 and d2["total_bytes"] is None and d2["largest_dirs"] == [],
        "null/[]", (d2 or {}).get("total_bytes"))
    rec("A.json --rules-only: same key set", d2 and set(d2) == set(d), sorted(d), sorted(d2 or {}))
    rec("A.json --rules-only schema", d2 is not None and not schema_problems(d2), "ok", schema_problems(d2 or {})[:3])
    tiers = {"safe": 0, "moderate": 0, "caution": 0}
    for f in d["findings"]:
        tiers[f["risk"].lower()] += f["bytes"]
    rec("A.json reclaimable == sum(findings by risk)", tiers == d["reclaimable"], d["reclaimable"], tiers)
    ids = [f["id"] for f in d["findings"]]
    rec("A.json finding ids unique", len(ids) == len(set(ids)), "unique", [i for i in ids if ids.count(i) > 1][:5])
    rec("A.json finding paths absolute", all(p.startswith("/") for f in d["findings"] for p in f["paths"]), "abs", "")
    rec("A.json lossy flags false on UTF-8 tree", not any(x["lossy"] for x in d["largest_dirs"]), False, "")

    # ---------------- --top / --depth honoured, exact expected set
    def expected_dirs(depth):
        exp = []
        for dp, dns, fns in os.walk(root):
            rel = os.path.relpath(dp, root)
            if rel == ".":
                continue
            if rel.count(os.sep) + 1 <= depth:
                exp.append((du(dp), dp))
        return sorted(exp, reverse=True)
    for top, depth in [(3, 1), (5, 2), (100, 3), (100, 10), (1, 4), (0, 3), (10, 0)]:
        rc, dd, err, _ = run_json(["--home", home, "--top", str(top), "--depth", str(depth), root])
        got = [(x["bytes"], x["path"]) for x in dd["largest_dirs"]] if dd else None
        exp = expected_dirs(depth)[:top]
        rec(f"A.--top {top} --depth {depth}: exact list vs du", got == exp, [(b, os.path.relpath(p, root)) for b, p in exp][:6],
            [(b, os.path.relpath(p, root)) for b, p in got][:6] if got else got)
    rc, dd, err, _ = run_json(["--home", home, "--top", "1000000000", "--depth", "1000000000", root])
    rec("A.--top/--depth huge values", rc == 0 and dd and len(dd["largest_dirs"]) == 12, "12 dirs", rc if not dd else len(dd["largest_dirs"]))
    rc, dd, err, _ = run_json(["--home", home, "--top", "18446744073709551616", root])
    rec("A.--top overflow rejected cleanly", rc == 2 and "panicked" not in err, "rc=2", rc, err.strip()[:80])

    # ---------------- summary text sanity
    rc, out, err, _ = run(["-s", "--home", home, "--top", "4", "--depth", "2", root])
    rec("A.summary rc=0, 'Scanning' on stderr only", rc == 0 and "Scanning" in err and "Scanning" not in out, "stderr", err.strip()[:60])
    plain = re.sub(r"\x1b\[[0-9;]*m", "", out)
    sec = plain.split("LARGEST DIRECTORIES", 1)[-1].split("RECLAIMABLE SPACE", 1)[0]
    rows = [l for l in sec.splitlines() if re.match(r"\s+[\d.]+ \w?i?B\s+[\d.]+%", l)]
    rec("A.summary: --top 4 rows", len(rows) == 4, 4, len(rows))
    rc, dj, _, _ = run_json(["--home", home, "--top", "4", "--depth", "2", root])
    txt_paths = [l.split()[-1] for l in rows]
    rec("A.summary: same order as JSON", txt_paths == [x["path"] for x in dj["largest_dirs"]], [os.path.basename(x["path"]) for x in dj["largest_dirs"]],
        [os.path.basename(p) for p in txt_paths])
    pcts = [float(re.search(r"([\d.]+)%", l).group(1)) for l in rows]
    exp_p = [round(x["bytes"] * 100 / dj["total_bytes"], 1) for x in dj["largest_dirs"]]
    rec("A.summary: percentages = bytes/total", all(abs(a - b) <= 0.1 for a, b in zip(pcts, exp_p)), exp_p, pcts)
    m = re.search(r"Scanned .*?: ([\d.]+ \w+) in ([\d,]+) files, ([\d,]+) dirs", plain)
    nfiles = sum(len(f) for _, _, f in os.walk(root))
    ndirs = sum(1 for _ in os.walk(root))
    rec("A.summary: file/dir counts", m and int(m.group(2).replace(",", "")) == nfiles and int(m.group(3).replace(",", "")) == ndirs,
        f"{nfiles} files, {ndirs} dirs", m.groups() if m else plain[:100])
    tot = re.search(r"TOTAL\s+([\d.]+ \w+)", plain)
    rec("A.summary: RECLAIMABLE TOTAL present", bool(tot), "TOTAL line", tot.group(1) if tot else None)
    rec("A.summary ends with 'Nothing was deleted'", "Nothing was deleted" in plain, "present", "")
    rec("A.summary piped to a file still contains ANSI escapes (no isatty / NO_COLOR check)", "\x1b[" not in out, "no escapes when stdout is not a TTY",
        "escapes present" if "\x1b[" in out else "clean")
    rc, out2, _, _ = run(["-s", "--home", home, root], env=clean_env(home, {"NO_COLOR": "1"}))
    rec("A.summary honours NO_COLOR", "\x1b[" not in out2, "no escapes", "escapes present" if "\x1b[" in out2 else "clean")
    rc, out, err, _ = run(["-s", "--rules-only", "--home", home, root])
    rec("A.summary --rules-only: no LARGEST section, no scan", rc == 0 and "LARGEST" not in out and "Scanning" not in err, "no tree", rc)

    # ---------------- flag combos
    rc, dj2, err, _ = run_json(["-s", "--home", home, root])
    rec("A.--json + -s -> JSON", dj2 is not None, "JSON", rc)
    rc, dj3, err, _ = run_json(["--tui", "--home", home, root])
    rec("A.--json + --tui -> JSON (non-interactive wins)", dj3 is not None, "JSON", rc, err[:80])
    rc, out, err, _ = run(["--rules-only", "--home", home, root])
    rec("A.--rules-only alone behaves as summary (help: 'summary mode')", rc == 0 and "RECLAIMABLE" in out, "report printed, rc=0",
        f"rc={rc}", err.strip()[:120])
    rc, dnx, err, _ = run_json(["--no-exec", "--home", home, root])
    rec("A.--json --no-exec accepted", rc == 0 and dnx is not None, "rc=0", rc)
    for col in ("auto", "truecolor", "256"):
        rc, dd, err, _ = run_json(["--color", col, "--home", home, root])
        rec(f"A.--color {col} with --json", rc == 0 and dd is not None, "rc=0", rc)
    rc, _, err, _ = run(["--color", "16", root])
    rec("A.--color 16 rejected", rc == 2 and "possible values" in err, "rc=2", rc)
    for r in ("auto", "vulkan", "gl"):
        rc, dd, err, _ = run_json(["--renderer", r, "--home", home, root])
        rec(f"A.--renderer {r} + --json (no display)", rc == 0 and dd is not None, "rc=0", rc)
    for r in ("auto", "vulkan", "gl"):
        rc, out, err, _ = run(["--renderer", r, "--home", home, root], timeout=30)
        rec(f"A.--renderer {r} without display and without tty: clean error", rc != 0 and "panicked" not in err and err.strip() != "",
            "rc!=0, message", f"rc={rc}", err.strip()[:120], info=True)
    rc, out, err, _ = run(["--tui", "--home", home, root], timeout=30)
    rec("A.--tui with stdin/stdout not a terminal: understandable error", rc != 0 and re.search(r"terminal|tty", err, re.I) is not None,
        "error mentioning terminal/tty", f"rc={rc}", err.strip()[:120])

    # ---------------- -x / --cross-filesystems accepted
    rc, dx, err, _ = run_json(["-x", "--home", home, root])
    rec("A.-x same result on single-fs tree", dx and dx["total_bytes"] == d["total_bytes"], d["total_bytes"], (dx or {}).get("total_bytes"))
    rc, dx, err, _ = run_json(["--cross-filesystems", "--home", home, root])
    rec("A.--cross-filesystems long form", rc == 0 and dx is not None, "rc=0", rc)

    # ---------------- --min-file-size parsing
    good = {"0": 0, "1": 1, "4096": 4096, "1K": 1024, "1k": 1024, "1KB": 1024, "1KiB": 1024, "1kib": 1024, "1.5M": 1572864,
            ".5M": 524288, "2G": 2 << 30, "1T": 1 << 40, " 5 M ": 5 * MiB, "10B": 10}
    for v in good:
        rc, dd, err, _ = run_json(["--min-file-size", v, "--home", home, root])
        rec(f"A.--min-file-size {v!r} accepted", rc == 0 and dd is not None and dd["total_bytes"] == d["total_bytes"], "rc=0, same total", rc, err.strip()[:80])
    for v in ["", "abc", "1.5.5M", "1e3", "5X", "10P", "M", "--", "1 M B", "0x10", "nan", "inf", "-5"]:
        rc, dd, err, _ = run(["--json", f"--min-file-size={v}", "--home", home, root])[:3] + (None,)
        rec(f"A.--min-file-size {v!r} rejected rc=2", rc == 2 and "panicked" not in err, "rc=2", rc, err.strip()[:90])
    rc, dd, err, _ = run(["--json", "--min-file-size=99999999999999999999T", "--home", home, root])[:3] + (None,)
    rec("A.--min-file-size absurd (1e20 T) rejected instead of saturating", rc == 2, "rc=2 (value overflows u64)", f"rc={rc}")
    rc, dd, err, _ = run(["--json", "--min-file-size=0.0001", "--home", home, root])[:3] + (None,)
    rec("A.--min-file-size 0.0001 (fraction of a byte)", True, "accepted/rejected?", f"rc={rc}", info=True)
    # min-file-size effect is only visible in the TUI tree; check it via summary file count (unchanged)
    # ---------------- --journal-keep parsing and clamp
    for v, ok in [("500M", True), ("0", True), ("100", True), ("1.5G", True), ("1T", True), ("10P", False), ("x", False), ("", False)]:
        rc, dd, err, _ = run_json(["--rules-only", "--journal-keep", v, "--home", home, root])
        rec(f"A.--journal-keep {v!r} {'accepted' if ok else 'rejected'}", (rc == 0 and dd is not None) if ok else rc == 2, "rc=0" if ok else "rc=2", rc)
        if ok and dd:
            j = [f for f in dd["findings"] if f["id"] == "journal"]
            if j:
                km = re.search(r"--vacuum-size=(\d+)M", j[0]["command"])
                keep = {"500M": 500, "0": 1, "100": 1, "1.5G": 1536, "1T": 1 << 20}[v]
                rec(f"A.--journal-keep {v!r} -> vacuum-size", km and int(km.group(1)) == keep, f"{keep}M (clamped to >= 1 MiB)", j[0]["command"])
            else:
                rec(f"A.--journal-keep {v!r}: no journal finding", True, "", "journal below keep or unreadable", info=True)
    rc, dd, err, _ = run_json(["--rules-only", "--journal-keep", "1536K", "--home", home, root])
    j = [f for f in (dd or {}).get("findings", []) if f["id"] == "journal"]
    if j:
        rec("A.--journal-keep 1536K: title/command keep agree with bytes basis", "1.5" in j[0]["title"] or "2 MiB" in j[0]["title"],
            "keep shown as 1.5 MiB or rounded up to 2 MiB (bytes are computed for 1.5 MiB)", j[0]["title"] + " | " + j[0]["command"], info=True)

    # ---------------- --home / --dev-root
    cwd = os.path.join(WORK, "cli_cwd")
    os.makedirs(cwd, exist_ok=True)
    rc, dd, err, _ = run_json(["--home", os.path.relpath(home, cwd), "--dev-root", os.path.relpath(root, cwd), "cli-rel-does-not-matter"], cwd=cwd)
    rec("A.nonexistent relative PATH -> rc!=0 'cannot access'", rc != 0 and "cannot access" in err, "rc!=0", rc, err.strip()[:100])
    rc, dd, err, _ = run_json(["--home", os.path.relpath(home, cwd), "--dev-root", os.path.relpath(root, cwd), os.path.relpath(root, cwd)], cwd=cwd)
    rec("A.relative --home/--dev-root/PATH", rc == 0 and dd and dd["root"] == os.path.realpath(root), os.path.realpath(root), (dd or {}).get("root"))
    rc, dd, err, _ = run_json(["--home", "no/such/home", "--dev-root", "no/such/dev", root], cwd=cwd)
    rec("A.nonexistent relative --home/--dev-root: rc=0, findings paths absolute", rc == 0 and dd and all(p.startswith("/") for f in dd["findings"] for p in f["paths"]),
        "rc=0", rc, err.strip()[:80])
    rc, dd, err, _ = run_json(["--home", home, "--dev-root", root, "--dev-root", home, "--dev-root", root, root])
    rec("A.repeated --dev-root (duplicates) no duplicate findings", rc == 0 and dd and len({f["id"] for f in dd["findings"]}) == len(dd["findings"]), "unique ids", rc)
    # --threads
    for t in ("0", "1", "3", "64", "512"):
        rc, dd, err, _ = run_json(["--threads", t, "--home", home, root])
        rec(f"A.--threads {t}", rc == 0 and dd and dd["total_bytes"] == d["total_bytes"], d["total_bytes"], (dd or {}).get("total_bytes"), err.strip()[:80])
    env = clean_env(home)
    p = subprocess.run(["sh", "-c", f"ulimit -v 4000000; exec '{BIN}' --json --threads 1000000 --home '{home}' '{root}'"], capture_output=True, env=env, timeout=120)
    e = p.stderr.decode(errors="replace")
    rec("A.--threads 1000000 (4 GB address-space limit): clean failure or clamp", "panicked" not in e and (p.returncode == 0 or e.strip()),
        "no panic", f"rc={p.returncode}", e.strip()[:120])
    rec("A.--threads 1000000: clamped to a sane maximum instead of failing", p.returncode == 0, "rc=0 (clamp threads)", f"rc={p.returncode}", e.strip()[:80])
    for v in ("-1", "abc", "1.5"):
        rc, _, err, _ = run(["--json", f"--threads={v}", root])
        rec(f"A.--threads {v} rejected", rc == 2, "rc=2", rc)


# ============================================================ B: scanner vs du
def test_scanner():
    home = fake_home("scan_home")
    base = os.path.join(WORK, "scan")
    os.makedirs(base, exist_ok=True)

    def total(path, extra=(), **kw):
        rc, d, err, _ = run_json(["--home", home] + list(extra) + [path], **kw)
        return rc, (d["total_bytes"] if d else None), d, err

    # ---- deep nesting < PATH_MAX (1500 levels of 'a')
    def mk_deep(root, levels, name):
        os.makedirs(root, exist_ok=True)
        fd = os.open(root, os.O_RDONLY)
        for i in range(levels):
            os.mkdir(name, dir_fd=fd)
            if i % 100 == 0:
                f = os.open(f"f{i}", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
                os.write(f, b"x" * 5000)
                os.close(f)
            nfd = os.open(name, os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = nfd
        f = os.open("leaf.bin", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
        os.write(f, os.urandom(2 * MiB))
        os.close(f)
        os.close(fd)
    d1 = os.path.join(base, "deep1500")
    mk_deep(d1, 1500, "a")
    rc, t, d, err = total(d1)
    rec("B.deep 1500 levels (path < PATH_MAX) total == du", rc == 0 and t == du(d1), du(d1), t, err.strip()[:80])
    rc, dd, err, _ = run_json(["--home", home, "--depth", "2000", "--top", "5", d1])
    rec("B.deep 1500: deepest dirs reported with --depth 2000", rc == 0 and dd and dd["largest_dirs"] and dd["largest_dirs"][0]["bytes"] == du(os.path.join(d1, "a")),
        du(os.path.join(d1, "a")), dd["largest_dirs"][0]["bytes"] if dd and dd["largest_dirs"] else None)
    d2 = os.path.join(base, "deep3000")
    mk_deep(d2, 3000, "dddddddddd")
    rc, t, d, err = total(d2)
    rec("B.deep 3000 levels (path ~33 KB > PATH_MAX) total == du", rc == 0 and t == du(d2), du(d2), t,
        "scanner uses full-path read_dir -> ENAMETOOLONG below ~370 levels")
    rc, out, err, _ = run(["-s", "--home", home, d2])
    m = re.search(r"\(([\d.]+)s, ([\d,]+) unreadable\)", out)
    rec("B.deep 3000: incompleteness surfaced in summary", bool(m), "'N unreadable'", m.group(0) if m else "none")
    rec("B.deep 3000: JSON exposes scan errors/incompleteness", d is not None and any(k for k in d if "error" in k or "unreadable" in k),
        "a field such as 'errors'/'unreadable'", sorted(d) if d else None)

    # ---- 100k small files
    many = os.path.join(base, "many")
    for i in range(100):
        dd_ = os.path.join(many, f"d{i:03}")
        os.makedirs(dd_, exist_ok=True)
        for j in range(1000):
            with open(os.path.join(dd_, f"f{j}"), "wb") as f:
                f.write(b"y" * ((i * 1000 + j) % 3000 + 1))
    rc, t, d, err = total(many)
    rec("B.100k small files total == du", rc == 0 and t == du(many), du(many), t)
    rc, out, err, _ = run(["-s", "--home", home, many])
    m = re.search(r"in ([\d,]+) files, ([\d,]+) dirs", out)
    rec("B.100k small files: summary counts", m and m.group(1) == "100,000" and m.group(2) == "101", "100,000 files, 101 dirs", m.groups() if m else None)
    for mfs in ("0", "1"):
        rc, t2, d, err = total(many, ["--min-file-size", mfs])
        rec(f"B.100k files with --min-file-size {mfs} (no folding) total == du", t2 == du(many), du(many), t2)

    # ---- hard links: 3 links in 3 dirs + one link outside the scan root + hard-linked small files
    hl = os.path.join(base, "hl")
    outside = os.path.join(base, "hl_outside")
    write_file(os.path.join(hl, "z/orig.bin"), 3 * MiB)
    for dname in ("a", "m"):
        os.makedirs(os.path.join(hl, dname), exist_ok=True)
        os.link(os.path.join(hl, "z/orig.bin"), os.path.join(hl, dname, "link.bin"))
    write_file(os.path.join(outside, "big.bin"), 2 * MiB)
    os.makedirs(os.path.join(hl, "o"), exist_ok=True)
    os.link(os.path.join(outside, "big.bin"), os.path.join(hl, "o", "only_link_inside.bin"))
    os.makedirs(os.path.join(hl, "s1"), exist_ok=True)
    os.makedirs(os.path.join(hl, "s2"), exist_ok=True)
    for j in range(50):
        with open(os.path.join(hl, "s1", f"small{j}"), "wb") as f:
            f.write(b"q" * 3000)
        os.link(os.path.join(hl, "s1", f"small{j}"), os.path.join(hl, "s2", f"small{j}"))
    rc, t, d, err = total(hl)
    rec("B.hard links (3-way, outside link, small-file links) total == du", t == du(hl), du(hl), t)
    rc, dd, err, _ = run_json(["--home", home, "--top", "20", "--depth", "1", hl])
    got = {os.path.basename(x["path"]): x["bytes"] for x in dd["largest_dirs"]} if dd else {}
    own = os.lstat(hl).st_blocks * 512
    rec("B.hard links: root == own + sum(children)", dd and dd["total_bytes"] == own + sum(got.values()), dd["total_bytes"] if dd else None, own + sum(got.values()))
    rec("B.hard links: 3-way inode credited once, to lexicographically smallest path (a/)",
        got.get("a", 0) >= 3 * MiB and got.get("m", 0) < MiB and got.get("z", 0) < MiB, "a>=3MiB, m,z small", {k: got.get(k) for k in "amz"})
    rec("B.hard links: link whose twin is outside root counted fully (like du)", got.get("o", 0) >= 2 * MiB, ">=2MiB", got.get("o"))
    rec("B.hard links: small-file links deduped (s1 full, s2 ~own blocks)", got.get("s2", 0) == os.lstat(os.path.join(hl, "s2")).st_blocks * 512,
        os.lstat(os.path.join(hl, "s2")).st_blocks * 512, got.get("s2"))
    # ---- odd file types
    odd = os.path.join(base, "odd")
    os.makedirs(odd, exist_ok=True)
    os.mkfifo(os.path.join(odd, "fifo"))
    sk = socket.socket(socket.AF_UNIX)
    cwd0 = os.getcwd()
    os.chdir(odd)  # AF_UNIX paths are limited to 108 bytes
    try:
        sk.bind("sock")
    finally:
        os.chdir(cwd0)
    os.symlink("loop2", os.path.join(odd, "loop1"))
    os.symlink("loop1", os.path.join(odd, "loop2"))
    os.symlink(odd, os.path.join(odd, "self_dir_link"))
    os.symlink("/nonexistent/x", os.path.join(odd, "dangling"))
    subprocess.run(["fallocate", "-l", str(5 * MiB), os.path.join(odd, "prealloc.bin")])
    with open(os.path.join(odd, "sparse_tail.bin"), "wb") as f:
        f.seek(50 * MiB)
        f.write(os.urandom(64 * 1024))
    write_file(os.path.join(odd, "sub/data.bin"), MiB)
    try:
        rc, t, d, err = total(odd, timeout=60)
        rec("B.FIFO/socket/symlink loops/fallocate/sparse: no hang, total == du", t == du(odd), du(odd), t, err.strip()[:80])
    except subprocess.TimeoutExpired:
        rec("B.FIFO/socket/symlink loops: no hang", False, "finish", "TIMEOUT")
    sk.close()
    # ---- permission variants
    perm = os.path.join(base, "perm")
    write_file(os.path.join(perm, "r_only/inner/f.bin"), MiB)      # r-- : names listable, not stat-able
    write_file(os.path.join(perm, "x_only/inner/f.bin"), MiB)      # --x : not listable
    write_file(os.path.join(perm, "ok/f.bin"), MiB)
    write_file(os.path.join(perm, "ok/deeper/locked/f.bin"), MiB)
    os.chmod(os.path.join(perm, "r_only"), 0o444)
    os.chmod(os.path.join(perm, "x_only"), 0o111)
    os.chmod(os.path.join(perm, "ok/deeper/locked"), 0o000)
    try:
        rc, t, d, err = total(perm)
        rec("B.r--/--x/000 dirs: total == du (du cannot read them either)", rc == 0 and t == du(perm), du(perm), t)
        rc, out, err, _ = run(["-s", "--home", home, perm])
        m = re.search(r"([\d,]+) unreadable", out)
        rec("B.r--/--x/000 dirs: unreadable count reported", bool(m), ">=3 unreadable", m.group(0) if m else "none", info=bool(m))
    finally:
        chmod_tree_writable(perm)
    # ---- U+FFFD collision in largest_dirs
    col = os.path.join(base, "collide").encode()
    os.makedirs(col, exist_ok=True)
    bad = col + b"/caf\xe9"
    good = col + "/caf�".encode()
    for p, n in ((bad, 3), (good, 1)):
        os.makedirs(p, exist_ok=True)
        with open(p + b"/f.bin", "wb") as f:
            f.write(os.urandom(n * MiB))
    rc, dd, err, _ = run_json(["--home", home, "--depth", "1", col.decode()])
    ent = [(x["bytes"], x["lossy"]) for x in dd["largest_dirs"]] if dd else []
    rec("B.non-UTF8 vs literal U+FFFD twin: both listed, sizes distinct, only one lossy",
        len(ent) == 2 and sorted(e[1] for e in ent) == [False, True] and ent[0][0] == du(bad.decode("utf-8", "surrogateescape")),
        "2 entries, lossy=[True(3MiB),False(1MiB)]", ent)
    # ---- mounts via unshare
    if unshare_ok():
        mt = os.path.join(base, "mt")
        write_file(os.path.join(mt, "local/a.bin"), 2 * MiB)
        src = os.path.join(base, "bindsrc")
        write_file(os.path.join(src, "b.bin"), 3 * MiB)
        for d_ in ("tmp", "bind", "tmp_nested_parent"):
            os.makedirs(os.path.join(mt, d_), exist_ok=True)
        setup = (f"mount -t tmpfs none '{mt}/tmp' && head -c 4000000 /dev/urandom > '{mt}/tmp/t.bin' && mkdir '{mt}/tmp/inner' && "
                 f"mount -t tmpfs none '{mt}/tmp/inner' && head -c 1000000 /dev/urandom > '{mt}/tmp/inner/i.bin' && "
                 f"mount --bind '{src}' '{mt}/bind'")
        for x in (False, True):
            script = f"{setup} && du -s -B1 {'' if x else '-x'} '{mt}' && exec \"$0\" \"$@\""
            p = subprocess.run(["unshare", "-rm", "sh", "-c", script, BIN, "--json", "--home", home] + (["-x"] if x else []) + [mt],
                               capture_output=True, env=clean_env(home), timeout=120)
            outp = p.stdout.decode()
            first, _, js = outp.partition("\n")
            try:
                dj = json.loads(js)
                tb = dj["total_bytes"]
            except Exception:
                dj, tb = None, None
            ref = int(first.split()[0]) if first.strip() else None
            rec(f"B.mounts (tmpfs, nested tmpfs, same-fs bind) {'-x' if x else 'default'}: total == du{' ' if x else ' -x'}",
                tb == ref, ref, tb, p.stderr.decode()[:80])
            if dj and not x:
                listed = [os.path.basename(e["path"]) for e in dj["largest_dirs"]]
                rec("B.mounts default: tmpfs mount point not descended/listed", "tmp" not in listed, "tmp absent", listed)
        # scan root itself is a mount point
        script = f"mount -t tmpfs none '{mt}/tmp' && head -c 3000000 /dev/urandom > '{mt}/tmp/r.bin' && du -s -B1 -x '{mt}/tmp' && exec \"$0\" \"$@\""
        p = subprocess.run(["unshare", "-rm", "sh", "-c", script, BIN, "--json", "--home", home, f"{mt}/tmp"], capture_output=True, env=clean_env(home))
        first, _, js = p.stdout.decode().partition("\n")
        try:
            tb = json.loads(js)["total_bytes"]
        except Exception:
            tb = None
        rec("B.scan root is itself a mount point", first.strip() and tb == int(first.split()[0]), first.split()[0] if first.strip() else None, tb)
    else:
        rec("B.mounts", True, "", "unshare -rm unavailable: skipped", info=True)
    # ---- /dev and /proc (read-only)
    for path, to in (("/dev", 60), ("/proc", 120), ("/sys/kernel", 120)):
        try:
            t0 = time.time()
            rc, t, d, err = total(path, timeout=to)
            ref = du(path)
            rec(f"B.{path}: completes, rc=0", rc == 0 and t is not None, "rc=0", f"rc={rc} {time.time() - t0:.1f}s", err.strip()[:80])
            rec(f"B.{path}: total vs du -sx", t == ref, ref, t, info=path != "/dev")
        except subprocess.TimeoutExpired:
            rec(f"B.{path}: completes", False, f"<{to}s", "TIMEOUT")

    # ---- writer appending during scan
    grow = os.path.join(many, "d000", "growing.bin")
    stop = threading.Event()

    def writer():
        with open(grow, "ab") as f:
            while not stop.is_set():
                f.write(os.urandom(256 * 1024))
                f.flush()
    before = du(many)
    th = threading.Thread(target=writer)
    th.start()
    try:
        ok = True
        vals = []
        for _ in range(3):
            rc, t, d, err = total(many)
            vals.append(t)
            ok &= rc == 0 and t is not None
    finally:
        stop.set()
        th.join()
    after = du(many)
    rec("B.writer appending during scan: rc=0, before <= total <= after", ok and all(before <= v <= after for v in vals), f"[{before},{after}]", vals)
    os.unlink(grow)
    # ---- deleter during scan
    dele = os.path.join(base, "deleting")
    for i in range(40):
        os.makedirs(os.path.join(dele, f"d{i}"), exist_ok=True)
        for j in range(500):
            with open(os.path.join(dele, f"d{i}", f"f{j}"), "wb") as f:
                f.write(b"z" * 5000)
    before = du(dele)
    p = subprocess.Popen([BIN, "-s", "--home", home, dele], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(home))
    shutil.rmtree(dele, ignore_errors=True)
    out, err = p.communicate(timeout=120)
    out = out.decode(errors="replace")
    rec("B.files deleted during scan: rc=0 or clean error, no panic", b"panicked" not in err and (p.returncode == 0 or err.strip()), "no panic",
        f"rc={p.returncode}", err.decode(errors="replace").strip()[:100])
    m = re.search(r"Scanned .*", out)
    rec("B.files deleted during scan: summary line", True, "", m.group(0)[-80:] if m else err.decode(errors="replace").strip()[:100], info=True)


# ============================================================ C: TUI in a pty
def build_tui_tree(root, victim="victim_big"):
    write_file(os.path.join(root, victim, "data.bin"), 6 * MiB)
    write_file(os.path.join(root, victim, "sub", "more.bin"), 1 * MiB)
    write_file(os.path.join(root, "keep_mid", "data.bin"), 4 * MiB)
    write_file(os.path.join(root, "keep_small", "data.bin"), 2 * MiB)
    with open(os.path.join(root, "note.txt"), "w") as f:
        f.write("keep me\n")


def tui_home(name):
    h = fake_home(name)
    write_file(os.path.join(h, ".cache", "pip", "http", "blob.bin"), 2 * MiB)  # a SAFE fixture finding
    return h


def test_tui():
    trash_ok = shutil.which("gio") is not None

    # ---------- C1 render, navigation, panels, restore (read-only session, --no-exec)
    root = os.path.join(WORK, "tui", "nav")
    build_tui_tree(root)
    home = tui_home("tui_home_nav")
    t = Tui(["--tui", "--no-exec", "--home", home, root], home, rows=40, cols=130)
    try:
        rec("C1.renders header + tabs", t.wait(r"linux_disk_prune") and t.wait(r"1 ▦ Treemap"), "header/tabs", t.text()[:200])
        rec("C1.scan completes (header shows files · dirs)", t.wait(scan_done_re(), 30), "N files · N dirs", t.text().splitlines()[0][-60:])
        rec("C1.alternate screen + mouse capture enabled", t.screen.alt and t.screen.mouse, "alt+mouse", (t.screen.alt, t.screen.mouse))
        rec("C1.terminal in raw mode while running", not t.termios_cooked(), "raw", "cooked" if t.termios_cooked() else "raw")
        rec("C1.treemap shows fixture tiles", t.wait("victim_big", 10) and "keep_mid" in t.text(), "tiles", "")
        t.send("2")
        rec("C1.'2' -> Tree panel with rows", t.wait(r"victim_big/", 5) and "keep_small/" in t.text(), "tree rows", "")
        rec("C1.tree: largest child selected first", "victim_big" in t.selected_line(), "victim_big", t.selected_line().strip()[:80])
        t.send("j")
        rec("C1.'j' moves selection down", "keep_mid" in t.selected_line(), "keep_mid", t.selected_line().strip()[:80])
        t.send("down")
        rec("C1.Down arrow moves selection", "keep_small" in t.selected_line(), "keep_small", t.selected_line().strip()[:80])
        t.send("k")
        t.send("up")
        rec("C1.'k'/Up move back", "victim_big" in t.selected_line(), "victim_big", t.selected_line().strip()[:80])
        t.send("l")
        rec("C1.'l' expands directory", t.wait(r"data\.bin", 3), "child rows visible", "")
        t.send("l")
        rec("C1.second 'l' enters first child", "data.bin" in t.selected_line(), "data.bin", t.selected_line().strip()[:80])
        t.send("h")
        rec("C1.'h' goes to parent", "victim_big" in t.selected_line(), "victim_big", t.selected_line().strip()[:80])
        t.send(["h"])
        t.send("end")
        last = t.selected_line()
        t.send("home")
        rec("C1.End/Home jump", "note" in last or "small files" in last or last != t.selected_line(), "moved", (last.strip()[:40], t.selected_line().strip()[:40]))
        t.send(["pgdn", "pgup", "G", "g"])
        rec("C1.PageDown/PageUp/G/g no crash", t.p.poll() is None, "alive", t.p.poll())
        t.send("m")
        rec("C1.'m' from tree jumps to treemap", t.wait(r"←↑↓→", 3), "map footer", "")
        t.send(["right", "left", "down", "up", "tab", "enter", "bs", "esc", "[", "[", "]", "]", "]", "]", "]"])
        rec("C1.treemap keys (arrows, tab, enter, bs, esc, [ ]) no crash", t.p.poll() is None and t.wait("Treemap", 2), "alive", t.p.poll())
        t.send("t")
        rec("C1.'t' in treemap -> Tree", t.wait(r"open/close", 3), "tree footer", "")
        t.send("tab")
        rec("C1.Tab from Tree -> Prune", t.wait(r"all safe", 3), "prune footer", "")
        t.send("tab")
        rec("C1.Tab from Prune -> Treemap", t.wait(r"zoom in", 3), "map footer", "")
        t.send("backtab")
        rec("C1.BackTab from Treemap -> Prune", t.wait(r"all safe", 3), "prune footer", "")
        t.send("backtab")
        rec("C1.BackTab from Prune -> Tree", t.wait(r"open/close", 3), "tree footer", "")
        t.send("1")
        rec("C1.'1' -> Treemap", t.wait(r"zoom in", 3), "map footer", "")
        t.send("?")
        rec("C1.'?' opens About", t.wait(r"About", 3) and t.wait("disktree", 3), "About modal", "")
        t.send("x")
        rec("C1.any key closes About", t.wait(r"zoom in", 3), "closed", "")
        t.send("4")
        rec("C1.README key '4' (sunburst) in TUI: harmless", t.p.poll() is None, "alive", "", info=True)
        t.send("f5")
        rec("C1.README key F5 rescans in TUI", t.wait(r"Rescanning", 2), "'Rescanning…' flash", "no reaction (TUI only maps 'R')", "README Keys line is GUI-centric; TUI footer documents lowercase keys", info=True)
        t.send("R")
        rec("C1.'R' rescans", t.wait(r"Rescanning", 3) and t.wait(scan_done_re(), 30), "flash + rescan", "")
        t.send("2")
        t.send("C")
        rec("C1.README key 'C' (uppercase) opens Review in TUI", t.wait(r"Review & clean|Nothing selected", 2), "review/nothing-selected flash", "no reaction (TUI maps only 'c')", "README Keys line is GUI-centric; TUI footer documents lowercase keys", info=True)
        t.send("esc")
        t.send("X")
        rec("C1.README key 'X' (uppercase) marks in TUI", t.wait(r"● (Marked|Cannot mark)", 2), "mark flash", "no reaction (TUI maps only 'x'/Space)", "README Keys line is GUI-centric; TUI footer documents lowercase keys", info=True)
        # ---- Prune list (no-exec session): wait for fixture finding
        t.send("3")
        rec("C1.Prune tab lists fixture pip cache finding", t.wait(r"pip download cache", 60), "pip download cache", "")
        rec("C1.analysis finishes", t.wait(r"analyzing", 90, absent=True), "no spinner", "")
        # move the cursor onto the pip finding
        found = False
        t.send("g")
        for _ in range(60):
            sel = next((l for l in t.text().splitlines() if "pip download cache" in l), "")
            det = t.text()
            if re.search(r"\.cache/pip", det) and "▌" in sel:
                found = True
                break
            t.send("j", 0.1)
        # simpler criterion: the detail pane names the pip path when cursor is on it
        found = found or bool(re.search(r"~/\.cache/pip|\.cache/pip", t.text()))
        rec("C1.cursor reaches the pip finding (detail pane shows its path)", found, "detail shows .cache/pip", "")
        t.send(" ")
        rec("C1.Space checks a finding ([✔])", t.wait(r"\[✔\]", 3), "[✔]", "")
        t.send("c")
        rec("C1.'c' opens Review with RECOMMENDED CLEANUPS (1)", t.wait(r"RECOMMENDED CLEANUPS \(1\)", 3), "review", "")
        rec("C1.review warns execution disabled (--no-exec)", "Execution is disabled" in t.text(), "warning", "")
        t.send("y")
        rec("C1.'y' under --no-exec refuses", t.wait(r"Execution is disabled \(--no-exec\)", 3) and os.path.exists(os.path.join(home, ".cache/pip/http/blob.bin")),
            "flash + cache intact", "")
        t.send("c")
        t.wait(r"Review & clean", 3)
        t.send("esc", 0.6)
        rec("C1.Esc cancels Review", t.wait(r"Review & clean", 3, absent=True), "closed", "")
        t.send("n")
        rec("C1.'n' clears selection", t.wait(r"\[✔\]", 3, absent=True), "no [✔]", "")
        t.send("a")
        n_all = t.text().count("[✔]")
        t.send("n")
        rec("C1.'a' selects all SAFE, 'n' clears", n_all >= 1 and "[✔]" not in t.text(), ">=1 then 0", n_all)
        # cancel must undo the implicit selection made by Enter-with-nothing-checked
        t.send("enter")
        opened = t.wait(r"RECOMMENDED CLEANUPS \(1\)", 3)
        t.send("esc", 0.6)
        t.wait(r"Review & clean", 3, absent=True)
        still = "[✔]" in t.text()
        rec("C1.Enter (nothing checked) then Esc: implicit selection is undone", opened and not still,
            "cancel leaves nothing checked", "finding stays checked after cancel" if still else "ok")
        t.send("n")
        t.send("t")
        rec("C1.'t' in Prune shows finding in tree / flashes", t.p.poll() is None, "alive", "")
        t.send("3")
        t.send("r")
        rec("C1.'r' re-analyzes", t.wait(r"analyzing", 5) or t.wait("Prune", 1), "analyzing", "")
        t.wait(r"analyzing", 90, absent=True)
        # ---- resize
        t.resize(24, 80)
        time.sleep(1)
        t.send("2")
        rec("C1.resize to 80x24 redraws", t.wait(r"victim_big", 5) and all(len(l) <= 80 for l in t.text().splitlines()), "fits 80 cols", "")
        t.resize(60, 220)
        time.sleep(1)
        t.send("1")
        rec("C1.resize to 220x60 redraws with side panel", t.wait(r"victim_big", 5), "redrawn", "")
        t.resize(40, 130)
        time.sleep(0.5)
        t.send("q")
        rc = t.wait_exit(10)
        raw = t.raw()
        rec("C1.'q' quits rc=0", rc == 0, 0, rc)
        rec("C1.terminal restored: alt screen left, mouse off, cursor shown", raw.rfind(b"\x1b[?1049l") > raw.rfind(b"\x1b[?1049h") and b"?1000l" in raw and raw.rfind(b"\x1b[?25h") > 0,
            "1049l,1000l,25h", "")
        rec("C1.terminal restored: cooked mode (ICANON+ECHO)", t.termios_cooked(), "cooked", "raw")
        rec("C1.no panic text", b"panicked" not in raw, "none", "")
    finally:
        t.close()

    # ---------- C1c tiny terminal sizes, one session per tab (a panic ends the session)
    for tab in ("1", "2", "3"):
        dead = []
        for r_, c_ in ((8, 30), (6, 80), (5, 20), (5, 120), (3, 10), (2, 200), (1, 1)):
            t = Tui(["--tui", "--no-exec", "--home", home, root], home)
            try:
                t.wait(scan_done_re(), 30)
                t.send(tab)
                if tab == "3":
                    t.wait("pip download cache", 60)
                t.resize(r_, c_)
                time.sleep(0.8)
                t.send(["j", "?"], 0.4)
                t.send("x", 0.4)
                if t.p.poll() is not None:
                    raw = t.raw().decode(errors="replace")
                    i = raw.find("panicked")
                    dead.append(f"{r_}x{c_}: " + (raw[i:i + 150].replace("\r\n", " ") if i >= 0 else f"rc={t.p.poll()}"))
            finally:
                t.close()
        rec(f"C1c.tab {tab}: tiny terminal sizes (8x30,6x80,5x20,5x120,3x10,2x200,1x1) do not panic", not dead, "no panic", dead[:2])

    # ---------- C1b terminal that never answers the cursor-position query (CSI 6n)
    t = Tui(["--tui", "--no-exec", "--home", home, root], home, answer_dsr=False)
    try:
        rc = t.wait_exit(15)
        rec("C1b.no DSR answer: exits with an error message", rc not in (None, 0) and "cursor position" in t.text(), "rc!=0 + message", rc)
        rec("C1b.no DSR answer: terminal restored after the startup error (cooked, alt screen left)",
            t.termios_cooked() and t.raw().rfind(b"?1049l") > t.raw().rfind(b"?1049h"), "cooked + ?1049l",
            f"cooked={t.termios_cooked()} left_alt={t.raw().rfind(b'?1049l') > t.raw().rfind(b'?1049h')}")
    finally:
        t.close()

    # ---------- C2 Ctrl-C quits
    t = Tui(["--tui", "--no-exec", "--home", home, root], home)
    try:
        t.wait(scan_done_re(), 30)
        t.send("ctrl_c")
        rc = t.wait_exit(10)
        rec("C2.Ctrl-C quits cleanly rc=0 + cooked", rc == 0 and t.termios_cooked(), "rc=0 cooked", (rc, t.termios_cooked()))
    finally:
        t.close()

    # ---------- C3 TERM / --color variants
    variants = [({"TERM": "xterm-256color"}, [], "256"), ({"TERM": "screen"}, [], "256"), ({"TERM": "dumb"}, [], "256"),
                ({"TERM": "xterm-256color", "COLORTERM": "truecolor"}, [], "true"),
                ({"TERM": "screen", "COLORTERM": "truecolor"}, ["--color", "256"], "256"),
                ({"TERM": "xterm"}, ["--color", "truecolor"], "true"), ({"TERM": "xterm-direct"}, [], "true")]
    for envx, extra, want in variants:
        t = Tui(["--tui", "--no-exec", "--home", home] + extra + [root], home, env_extra=envx)
        try:
            ok = t.wait(scan_done_re(), 30)
            raw = t.raw()
            has_true = re.search(rb"\x1b\[[0-9;]*38;2;\d+;\d+;\d+", raw) is not None
            has_256 = re.search(rb"\x1b\[[0-9;]*38;5;\d+", raw) is not None
            good = (has_true and not has_256) if want == "true" else (has_256 and not has_true)
            t.send("q")
            rc = t.wait_exit(10)
            rec(f"C3.{envx} {extra}: renders, {want}-colour, quits", ok and good and rc == 0, f"{want} colours, rc=0",
                f"render={ok} truecolor={has_true} 256={has_256} rc={rc}")
        finally:
            t.close()

    # ---------- C4 mark -> review -> cancel -> permanent delete
    def mark_delete_session(root, home, mode_key, label, env_extra=None, expect_trash=False):
        build_tui_tree(root)
        before = snapshot(root)
        t = Tui(["--tui", "--home", home, root], home, env_extra=env_extra)
        try:
            t.wait(scan_done_re(), 30)
            t.send("2")
            t.wait("victim_big/", 5)
            rec(f"{label}.victim selected", "victim_big" in t.selected_line(), "victim_big", t.selected_line().strip()[:60])
            t.send(" ")
            rec(f"{label}.Space marks (flash + ✖ marked)", t.wait(r"Marked victim_big", 3) and t.wait(r"✖ marked", 3), "marked", "")
            t.send("c")
            ok = t.wait(r"MARKED IN THE TREEMAP \(1\)", 3)
            scr = t.text()
            safe = ok and "RECOMMENDED CLEANUPS" not in scr and "victim_big" in scr
            rec(f"{label}.review lists only the marked item", safe, "1 marked, no findings", scr[scr.find("Review"):][:120] if ok else "no review")
            t.send("esc", 0.6)
            t.wait(r"Review & clean", 3, absent=True)
            time.sleep(0.5)
            rec(f"{label}.cancel leaves disk untouched", snapshot(root) == before, "unchanged", "changed")
            if not safe:
                return t
            t.send("c")
            t.wait(r"MARKED IN THE TREEMAP \(1\)", 3)
            if "RECOMMENDED CLEANUPS" in t.text():   # never execute findings
                rec(f"{label}.abort: findings present in review", False, "", "")
                return t
            t.send(mode_key)
            rec(f"{label}.cleanup output + prompt", t.wait(r"Press Enter to return", 20), "prompt", t.text()[-300:])
            txt = t.flat()
            after = snapshot(root)
            gone = {k for k in before if k not in after}
            rec(f"{label}.only the marked item is gone", gone == {k for k in before if k == "victim_big" or k.startswith("victim_big/")} and not os.path.exists(os.path.join(root, "victim_big")),
                "victim_big/**", sorted(gone)[:6])
            rec(f"{label}.siblings intact", all(after.get(k) == v for k, v in before.items() if not k.startswith("victim_big")), "intact", "")
            rec(f"{label}.log line", ("trashed" if expect_trash else "deleted") in txt and "1 of 1 marked item(s) completed" in txt,
                "trashed/deleted + 1 of 1", re.findall(r"(✔.*|✘.*|\d+ of \d+ marked.*)", txt)[:3])
            t.send("enter")
            rec(f"{label}.returns to TUI and rescans", t.wait(r"Rescanning|scanning", 5) or t.wait(scan_done_re(), 20), "back in TUI", "")
            t.wait(scan_done_re(), 30)
            t.send("2")
            rec(f"{label}.rescanned tree no longer shows victim", t.wait("keep_mid/", 5) and "victim_big" not in t.text(), "absent", "")
            return t
        except Exception as e:
            rec(f"{label}.exception", False, "", repr(e))
            return t

    home_p = tui_home("tui_home_perm")
    t = mark_delete_session(os.path.join(WORK, "tui", "perm"), home_p, "p", "C4.permanent")
    t.send("q")
    t.wait_exit(10)
    t.close()
    rec("C4.permanent: fake home untouched (pip cache kept)", os.path.exists(os.path.join(home_p, ".cache/pip/http/blob.bin")), "kept", "")

    if trash_ok:
        home_t = tui_home("tui_home_trash")
        t = mark_delete_session(os.path.join(WORK, "tui", "trash"), home_t, "t", "C5.trash", expect_trash=True)
        t.send("q")
        t.wait_exit(10)
        t.close()
        tf = os.path.join(home_t, ".local/share/Trash/files/victim_big")
        rec("C5.trash: item landed in the fixture home's Trash with data", os.path.isfile(os.path.join(tf, "data.bin")) and
            os.path.getsize(os.path.join(tf, "data.bin")) == 6 * MiB, tf, os.listdir(os.path.dirname(tf)) if os.path.isdir(os.path.dirname(tf)) else "no Trash")
        rec("C5.trash: .trashinfo written", os.path.exists(os.path.join(home_t, ".local/share/Trash/info/victim_big.trashinfo")), "exists", "")
        # default action (Enter) is Trash when gio exists
        home_t2 = tui_home("tui_home_trash2")
        t = mark_delete_session(os.path.join(WORK, "tui", "trash2"), home_t2, "enter", "C5b.trash-default(Enter)", expect_trash=True)
        t.send("q")
        t.wait_exit(10)
        t.close()
        rec("C5b.Enter defaults to Trash", os.path.isdir(os.path.join(home_t2, ".local/share/Trash/files/victim_big")), "in Trash", "")
    # without gio on PATH: review says 'deleted permanently' and Enter deletes permanently
    nogio = os.path.join(WORK, "nogio_bin")
    os.makedirs(nogio, exist_ok=True)
    for tool in ("sh", "apt-config", "dpkg-query", "snap", "journalctl", "uname", "find", "du"):
        w = shutil.which(tool)
        if w and not os.path.exists(os.path.join(nogio, tool)):
            os.symlink(w, os.path.join(nogio, tool))
    home_n = tui_home("tui_home_nogio")
    rootn = os.path.join(WORK, "tui", "nogio")
    build_tui_tree(rootn)
    t = Tui(["--tui", "--home", home_n, rootn], home_n, env_extra={"PATH": nogio})
    try:
        t.wait(scan_done_re(), 30)
        t.send(["2", " ", "c"])
        rec("C6.no gio: review says 'deleted permanently' and offers no trash", t.wait(r"MARKED IN THE TREEMAP \(1\) — deleted permanently", 3), "text", "")
        t.send("t")
        rec("C6.no gio: 't' does not act (closes review)", t.wait(r"Review & clean", 3, absent=True) and os.path.isdir(os.path.join(rootn, "victim_big")), "kept", "")
    finally:
        t.send("q")
        t.wait_exit(10)
        t.close()

    # ---------- C7 guards
    g = os.path.join(WORK, "tui", "guard")
    ghome = os.path.join(g, "home")
    write_file(os.path.join(ghome, "stuff.bin"), 9 * MiB)
    for d in (".local/share", ".cache", ".config"):
        os.makedirs(os.path.join(ghome, d), exist_ok=True)
    write_file(os.path.join(g, "par", "inner", "precious.bin"), 5 * MiB)
    write_file(os.path.join(g, "par", "side.bin"), 2 * MiB)
    write_file(os.path.join(g, "zz", "x.bin"), MiB)
    t = Tui(["--tui", "--home", ghome, g], ghome, cols=320)
    try:
        t.wait(scan_done_re(), 30)
        t.send("2")
        t.wait("home/", 5)
        t.send("g")
        t.send(" ")
        rec("C7.guard: scan root cannot be marked", t.wait(r"Cannot mark .*(only paths inside the scanned root|contains your home folder)", 3), "Cannot mark", t.text().splitlines()[-1][:120])
        t.send("j")
        rec("C7.home selected", "home/" in t.selected_line(), "home/", t.selected_line().strip()[:60])
        t.send(" ")
        rec("C7.guard: $HOME cannot be marked", t.wait(r"Cannot mark .*refusing protected path", 3), "refusing protected path", t.text().splitlines()[-1][:120])
        # symlinked parent (TOCTOU): mark par/inner, swap par for a symlink, confirm
        t.send("j")
        rec("C7.par selected", "par/" in t.selected_line(), "par/", t.selected_line().strip()[:60])
        t.send(["l", "l"])
        rec("C7.inner selected", "inner/" in t.selected_line(), "inner/", t.selected_line().strip()[:60])
        t.send(" ")
        t.wait(r"Marked inner", 3)
        os.rename(os.path.join(g, "par"), os.path.join(g, "par_real"))
        os.symlink("par_real", os.path.join(g, "par"))
        t.send("c")
        ok = t.wait(r"MARKED IN THE TREEMAP \(1\)", 3) and "RECOMMENDED" not in t.text()
        if ok:
            t.send("p")
            t.wait(r"Press Enter to return", 20)
            txt = t.flat()
            rec("C7.guard: symlinked parent refused", "symlinked directory" in txt and os.path.exists(os.path.join(g, "par_real/inner/precious.bin")),
                "refused, data kept", re.findall(r"✘.{0,400}", txt)[:1])
            t.send("enter")
        else:
            rec("C7.guard: symlinked parent", False, "review", "review did not open")
        rec("C7.home contents intact", os.path.exists(os.path.join(ghome, "stuff.bin")), "kept", "")
    finally:
        t.send("q")
        t.wait_exit(10)
        t.close()

    # ---------- C8 mount guards (user+mount namespace)
    if not unshare_ok():
        rec("C8.mount guards", True, "", "unshare -rm unavailable: skipped", info=True)
        return
    mroot = os.path.join(WORK, "tui", "mnt")
    src = os.path.join(WORK, "tui", "mnt_src")
    write_file(os.path.join(src, "precious.bin"), 3 * MiB)
    write_file(os.path.join(mroot, "cont", "local.bin"), 4 * MiB)
    os.makedirs(os.path.join(mroot, "cont", "tm"), exist_ok=True)
    os.makedirs(os.path.join(mroot, "cont", "bm"), exist_ok=True)
    write_file(os.path.join(mroot, "other", "o.bin"), MiB)
    mhome = tui_home("tui_home_mnt")

    def ns_tui(setup, args):
        return Tui(args, mhome, cols=320, prefix=["unshare", "-rm", "sh", "-c", setup + ' && exec "$0" "$@"'])

    # (a) tmpfs mount point node is not markable; the directory containing it is refused
    setup = f"mount -t tmpfs none '{mroot}/cont/tm' && head -c 2000000 /dev/urandom > '{mroot}/cont/tm/t.bin'"
    t = ns_tui(setup, ["--tui", "--home", mhome, mroot])
    try:
        t.wait(scan_done_re(), 30)
        t.send(["2", "l"])
        rec("C8a.tree shows mount point as other filesystem", t.wait(r"other filesystem \(use -x\)", 5), "⏏ … other filesystem", "")
        # cont: children local.bin (4MiB), then empty dir bm and tm mount (0)
        for _ in range(6):
            if "tm" in t.selected_line() and "other filesystem" in t.selected_line():
                break
            t.send("j")
        t.send(" ")
        rec("C8a.mount point node cannot be marked", t.wait(r"mount points cannot be marked", 3), "flash", t.text().splitlines()[-1][:100])
        t.send("g")
        t.send("j")
        rec("C8a.cont selected", "cont/" in t.selected_line(), "cont/", t.selected_line().strip()[:60])
        t.send([" ", "c"])
        ok = t.wait(r"MARKED IN THE TREEMAP \(1\)", 3) and "RECOMMENDED" not in t.text()
        if ok:
            t.send("p")
            t.wait(r"Press Enter to return", 20)
            txt = t.flat()
            rec("C8a.dir containing a tmpfs mount refused, nothing deleted", "mounted filesystem" in txt and os.path.exists(os.path.join(mroot, "cont/local.bin")),
                "refused + local.bin kept", re.findall(r"✘.*", txt)[:1])
            t.send("enter")
        else:
            rec("C8a.review", False, "review", "did not open")
    finally:
        t.send("q")
        t.wait_exit(10)
        t.close()

    # (b) same-filesystem bind mount (same st_dev!) inside the marked dir: only mountinfo protects it
    for hide_proc in (False, True):
        setup = f"mount --bind '{src}' '{mroot}/cont/bm'" + (" && mount -t tmpfs none /proc" if hide_proc else "")
        label = "C8c.bind+/proc hidden" if hide_proc else "C8b.bind mount"
        t = ns_tui(setup, ["--tui", "--home", mhome, mroot])
        try:
            t.wait(scan_done_re(), 30)
            t.send(["2", "g", "j"])
            if "cont/" not in t.selected_line():
                t.send("j")
            t.send([" ", "c"])
            ok = t.wait(r"MARKED IN THE TREEMAP \(1\)", 3) and "RECOMMENDED" not in t.text() and "cont" in t.text()
            if ok:
                t.send("p")
                t.wait(r"Press Enter to return", 20)
                txt = t.flat()
                kept = os.path.exists(os.path.join(src, "precious.bin"))
                rec(f"{label}: data behind a same-device bind mount survives", kept, "precious.bin kept (refuse)",
                    ("kept" if kept else "DELETED through the bind mount") + " | " + " ".join(re.findall(r"✘.*|✔.*", txt))[:160])
                t.send("enter")
            else:
                rec(f"{label}: review", False, "review", "did not open", t.selected_line())
        finally:
            t.send("q")
            t.wait_exit(10)
            t.close()
        # restore fixture for the next variant
        write_file(os.path.join(src, "precious.bin"), 3 * MiB)
        write_file(os.path.join(mroot, "cont", "local.bin"), 4 * MiB)
        for d in ("tm", "bm"):
            os.makedirs(os.path.join(mroot, "cont", d), exist_ok=True)

    # (d) with -x the tmpfs mount is a normal dir: marking the mount point itself must be refused on delete
    setup = f"mount -t tmpfs none '{mroot}/cont/tm' && head -c 6000000 /dev/urandom > '{mroot}/cont/tm/t.bin'"
    t = ns_tui(setup, ["--tui", "-x", "--home", mhome, mroot])
    try:
        t.wait(scan_done_re(), 30)
        t.send(["2", "g", "j"])
        if "cont/" not in t.selected_line():
            t.send("j")
        t.send("l")
        t.send("l")
        for _ in range(5):
            if "tm/" in t.selected_line():
                break
            t.send("j")
        rec("C8d.-x: tm mount shown as a directory", "tm/" in t.selected_line(), "tm/", t.selected_line().strip()[:60])
        t.send([" ", "c"])
        ok = t.wait(r"MARKED IN THE TREEMAP \(1\)", 3) and "RECOMMENDED" not in t.text()
        if ok:
            t.send("p")
            t.wait(r"Press Enter to return", 20)
            txt = t.flat()
            rec("C8d.-x: deleting a mount point itself is refused", "mounted filesystem" in txt, "refused", re.findall(r"✘.*|✔.*", txt)[:1])
            t.send("enter")
        else:
            rec("C8d.review", False, "review", "did not open")
    finally:
        t.send("q")
        t.wait_exit(10)
        t.close()


# ============================================================ D: robustness
def test_robust():
    home = fake_home("rob_home")
    base = os.path.join(WORK, "rob")
    os.makedirs(base, exist_ok=True)
    # signals during a long scan (JSON mode: never partial output)
    for sig in (signal.SIGINT, signal.SIGTERM):
        p = subprocess.Popen([BIN, "--json", "--home", home, "/usr"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env(home))
        time.sleep(0.4)
        t0 = time.time()
        p.send_signal(sig)
        try:
            out, err = p.communicate(timeout=10)
            dt = time.time() - t0
            rec(f"D.{sig.name} during --json scan: exits promptly, no partial JSON", dt < 3 and (out.strip() == b"" or json.loads(out) is not None),
                "<3s, empty stdout", f"{dt:.2f}s rc={p.returncode} out={len(out)}B")
        except subprocess.TimeoutExpired:
            p.kill()
            rec(f"D.{sig.name} during scan", False, "exit", "hung")
    # SIGTERM / SIGHUP to the TUI: terminal state
    root = os.path.join(WORK, "rob", "tui")
    build_tui_tree(root)
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        t = Tui(["--tui", "--no-exec", "--home", home, root], home)
        try:
            t.wait(scan_done_re(), 30)
            os.kill(t.p.pid, sig)
            rc = t.wait_exit(5)
            rec(f"D.{sig.name} to running TUI: terminal restored (cooked, alt screen left)", rc is not None and t.termios_cooked(),
                "cooked + ?1049l", f"rc={rc} cooked={t.termios_cooked()} left_alt={t.raw().rfind(b'?1049l') > t.raw().rfind(b'?1049h')}")
        finally:
            t.close()
    # /proc hidden entirely
    if unshare_ok():
        os.sync()
        p = subprocess.run(["unshare", "-rm", "sh", "-c", 'mount -t tmpfs none /proc && exec "$0" "$@"', BIN, "--json", "--home", home, root],
                           capture_output=True, env=clean_env(home), timeout=120)
        try:
            dj = json.loads(p.stdout)
        except Exception:
            dj = None
        rec("D./proc hidden: --json still works and matches du", p.returncode == 0 and dj and dj["total_bytes"] == du(root), du(root),
            (dj or {}).get("total_bytes"), p.stderr.decode()[:80])
        t = Tui(["--tui", "--no-exec", "--home", home, root], home, prefix=["unshare", "-rm", "sh", "-c", 'mount -t tmpfs none /proc && exec "$0" "$@"'])
        try:
            ok = t.wait(scan_done_re(), 30)
            t.send("q")
            rc = t.wait_exit(10)
            rec("D./proc hidden: TUI runs and quits", ok and rc == 0, "rc=0", rc)
        finally:
            t.close()
    # PATH variants
    empty = os.path.join(base, "empty")
    os.makedirs(empty, exist_ok=True)
    rc, d, err, _ = run_json(["--home", home, empty])
    rec("D.empty dir: total == du, no largest_dirs", rc == 0 and d and d["total_bytes"] == du(empty) and d["largest_dirs"] == [], du(empty), (d or {}).get("total_bytes"))
    rc, out, err, _ = run(["-s", "--home", home, empty])
    rec("D.empty dir summary", rc == 0 and "0 files" in out, "0 files", rc)
    f = os.path.join(base, "single.bin")
    write_file(f, 2 * MiB)
    rc, out, err, _ = run(["--json", "--home", home, f])
    rec("D.single file PATH: clean rc!=0", rc != 0 and "panicked" not in err, "rc!=0", rc, err.strip()[:80])
    rec("D.single file PATH: error names the path", f in err, "message contains the path", err.strip()[:120])
    unr = os.path.join(base, "unreadable_root")
    write_file(os.path.join(unr, "x.bin"), MiB)
    os.chmod(unr, 0)
    try:
        rc, d, err, _ = run_json(["--home", home, unr])
        rec("D.unreadable PATH (mode 000): no crash", "panicked" not in err, "no panic", f"rc={rc}", err.strip()[:80])
        rec("D.unreadable PATH: reported as error (not a silent 4 KiB total)", rc != 0 or (d and any(unr in n for n in d["notes"])),
            "rc!=0 or note", f"rc={rc} total={(d or {}).get('total_bytes')}")
    finally:
        os.chmod(unr, 0o755)
    lnk = os.path.join(base, "link_to_empty")
    os.symlink(empty, lnk)
    rc, d, err, _ = run_json(["--home", home, lnk])
    rec("D.symlink PATH -> dir: resolved to target", rc == 0 and d and d["root"] == os.path.realpath(empty), os.path.realpath(empty), (d or {}).get("root"))
    dl = os.path.join(base, "dangling")
    os.symlink("/nonexistent/zzz", dl)
    rc, out, err, _ = run(["--json", "--home", home, dl])
    rec("D.dangling symlink PATH: rc!=0 'cannot access'", rc != 0 and "cannot access" in err, "rc!=0", rc, err.strip()[:80])
    fl = os.path.join(base, "link_to_file")
    os.symlink(f, fl)
    rc, out, err, _ = run(["--json", "--home", home, fl])
    rec("D.symlink PATH -> file: clean error", rc != 0 and "panicked" not in err, "rc!=0", rc, err.strip()[:80])
    rc, out, err, _ = run(["--json", "--home", home, "/dev/null"])
    rec("D.PATH = /dev/null: clean error", rc != 0 and "panicked" not in err, "rc!=0", rc, err.strip()[:80])
    rc, out, err, _ = run(["--json", "--home", home, ""])
    rec("D.PATH = '' : clean error", rc != 0 and "panicked" not in err, "rc!=0", rc, err.strip()[:80])
    # long PATH argument > PATH_MAX
    longp = "/" + "/".join(["x" * 200] * 25)
    rc, out, err, _ = run(["--json", "--home", home, longp])
    rec("D.PATH argument > 4096 bytes: clean error", rc != 0 and "panicked" not in err, "rc!=0", rc, err.strip()[:80])
    # permission-denied home
    ph = os.path.join(base, "locked_home")
    write_file(os.path.join(ph, ".cache/pip/x.bin"), 2 * MiB)
    os.chmod(ph, 0)
    try:
        rc, d, err, _ = run_json(["--home", ph, empty], env=clean_env(ph))
        rec("D.permission-denied home: rc=0, no findings from it, no panic", rc == 0 and d and not any(p.startswith(ph) for x in d["findings"] for p in x["paths"]),
            "rc=0", rc, err.strip()[:80])
        t = Tui(["--tui", "--no-exec", "--home", ph, empty], ph)
        try:
            ok = t.wait(scan_done_re(), 30)
            t.send("q")
            rc = t.wait_exit(10)
            rec("D.permission-denied home: TUI starts and quits", ok and rc == 0, "rc=0", rc)
        finally:
            t.close()
    finally:
        os.chmod(ph, 0o755)
    # HOME unset entirely
    env = clean_env(home)
    env.pop("HOME")
    rc, d, err, _ = run_json([empty], env=env)
    rec("D.HOME unset: runs (falls back)", rc == 0 and d is not None, "rc=0", rc, err.strip()[:80])
    # '/' read-only scan (JSON) vs du -sx /
    t0 = time.time()
    rc, d, err, wall = run_json(["--home", home, "/"], timeout=900)
    t_tool = time.time() - t0
    t0 = time.time()
    ref = du("/")
    t_du = time.time() - t0
    rec("D.PATH '/' scan: rc=0", rc == 0 and d is not None, "rc=0", rc)
    if d:
        rel = abs(d["total_bytes"] - ref) / max(ref, 1)
        rec("D.PATH '/' total within 1% of du -sx / (live system, both unprivileged)", rel < 0.01, ref, d["total_bytes"], f"diff={rel * 100:.3f}% tool={t_tool:.1f}s du={t_du:.1f}s")


# ============================================================ E: performance
def test_perf():
    home = fake_home("perf_home")
    for path in ("/usr",):
        ref_t0 = time.time()
        ref = du(path)
        ref_t = time.time() - ref_t0
        env = clean_env(home)
        p = subprocess.Popen(["/usr/bin/time", "-v", BIN, "--json", "--home", home, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        peak_threads = 0
        child = None
        t0 = time.time()
        while p.poll() is None:
            if child is None:
                try:
                    kids = open(f"/proc/{p.pid}/task/{p.pid}/children").read().split()
                    child = kids[0] if kids else None
                except OSError:
                    pass
            if child:
                try:
                    th = int(re.search(r"Threads:\s+(\d+)", open(f"/proc/{child}/status").read()).group(1))
                    peak_threads = max(peak_threads, th)
                except (OSError, AttributeError):
                    pass
            time.sleep(0.01)
        out, err = p.communicate()
        wall = time.time() - t0
        e = err.decode()
        rss = int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", e).group(1))
        d = json.loads(out)
        rec(f"E.{path}: total == du -sx", d["total_bytes"] == ref, ref, d["total_bytes"])
        rec(f"E.{path}: wall time", wall < 30, "<30s", f"{wall:.2f}s (du -sx: {ref_t:.2f}s)", info=True)
        rec(f"E.{path}: peak RSS", rss < 1024 * 1024, "<1 GiB", f"{rss / 1024:.0f} MiB", info=True)
        rec(f"E.{path}: peak threads (auto)", peak_threads <= 64, "<=64", peak_threads, f"cpus={os.cpu_count()}", info=True)
        for thr in ("1", "4"):
            t0 = time.time()
            rc, dd, _, _ = run_json(["--threads", thr, "--home", home, path])
            rec(f"E.{path}: --threads {thr} same total", dd and dd["total_bytes"] == ref, ref, (dd or {}).get("total_bytes"), f"{time.time() - t0:.2f}s", )
        t0 = time.time()
        rc, dd, _, _ = run_json(["--rules-only", "--home", home, path])
        rec("E.--rules-only wall time", rc == 0, "", f"{time.time() - t0:.2f}s", info=True)


def main():
    global BIN, WORK
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BIN)
    ap.add_argument("--workdir", default=os.path.join(os.environ.get("TMPDIR", "/tmp"), "ldp-functional"))
    ap.add_argument("--only", default="A,B,C,D,E")
    ap.add_argument("--skip-perf", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--results", default=None, help="write results JSON here")
    a = ap.parse_args()
    BIN = os.path.abspath(a.binary)
    WORK = os.path.abspath(os.path.join(a.workdir, "fx"))
    if os.path.exists(WORK):
        nuke(WORK)
    os.makedirs(WORK)
    sections = {"A": test_cli, "B": test_scanner, "C": test_tui, "D": test_robust, "E": test_perf}
    try:
        for k in a.only.split(","):
            if k == "E" and a.skip_perf:
                continue
            try:
                sections[k]()
            except Exception as e:
                import traceback
                traceback.print_exc()
                rec(f"{k}.section crashed", False, "", repr(e))
    finally:
        if not a.keep:
            nuke(WORK)
    print("\n" + "=" * 100)
    for t, s, e, act, n in RESULTS:
        if s != "PASS":
            print(f"{s:4}  {t}  exp={e[:80]}  act={act[:120]}  {n[:100]}")
    c = {s: sum(1 for r in RESULTS if r[1] == s) for s in ("PASS", "FAIL", "INFO")}
    print(f"\n{c}")
    if a.results:
        with open(a.results, "w") as f:
            json.dump(RESULTS, f, indent=1, ensure_ascii=False)
    sys.exit(1 if c["FAIL"] else 0)


if __name__ == "__main__":
    main()
