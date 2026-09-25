#!/usr/bin/env python3
"""End-to-end safety harness for linux_disk_prune's *user-level* cleanup suggestions.

For every case it
  1. builds a throw-away fake HOME and populates it with the REAL tool
     (Chrome, Firefox, Electron, pip, uv, npm/npx, cargo, go, ...),
  2. records a manifest (type/mode/size/sha256/link target) of every file in
     the case sandbox,
  3. runs `linux_disk_prune --json --rules-only --home H --dev-root H`,
  4. executes the finding's exact `command` (after asserting that every path
     it names lies inside the fake HOME),
  5. verifies that the program still works, that nothing outside the
     finding's paths changed, and compares reported vs actually freed bytes.

Nothing ever touches the real home: each case gets its own sandbox under
--work, tool environments point HOME/CARGO_HOME/... into it, and commands that
would reach the user's desktop session (tracker3) only run inside docker.

Usage:
  python3 tests/safety/user/run_user_safety.py --bin target/release/linux_disk_prune \
      --work /tmp/ldp-user-safety [--cases pip,uv,...] [--keep]

Python stdlib only. Needs network for pip/uv/npm/cargo/go/Electron downloads.
"""

import argparse
import hashlib
import http.server
import json
import os
import pty
import pwd
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback

REAL_HOME = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
MIB = 1 << 20

# Tool sub-commands the rules may emit. They act on the environment, so they
# only run with HOME (and friends) pointing into the sandbox.
HOST_TOOL_CMDS = {"uv cache clean", "go clean -cache", "go clean -modcache", "pnpm store prune"}
# Talks to the desktop session (kills the user's miners): docker only.
DOCKER_ONLY_CMDS = {"tracker3 reset -s"}


def which_real(name, extra=()):
    for d in list(extra) + os.environ.get("PATH", "").split(":"):
        p = os.path.join(d, name)
        if d and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


NVM_BIN = os.path.dirname(which_real("node", [os.path.join(REAL_HOME, ".nvm/versions/node/v22.23.2/bin")]) or "/nonexistent/node")
UV_BIN = os.path.dirname(which_real("uv", [os.path.join(REAL_HOME, ".local/bin")]) or "/nonexistent/uv")


def rust_toolchain_bin():
    tc = os.path.join(REAL_HOME, ".rustup/toolchains")
    try:
        for n in sorted(os.listdir(tc)):
            if n.startswith("stable") and os.path.isfile(os.path.join(tc, n, "bin/cargo")):
                return os.path.join(tc, n, "bin")
    except OSError:
        pass
    return None


RUST_BIN = rust_toolchain_bin()


# --------------------------------------------------------------------------- results

class Results:
    def __init__(self):
        self.cases = {}  # name -> dict(status, checks, notes, bugs)

    def case(self, name):
        return self.cases.setdefault(name, {"status": "RUNNING", "checks": [], "notes": [], "bugs": []})


# --------------------------------------------------------------------------- http

class Site:
    """Local web site that sets cookies / localStorage / IndexedDB and serves
    large cacheable resources, and lets pages report their findings back."""

    SET_HTML = """<!doctype html><html><head><title>set</title></head><body>
<h1>safety</h1>
<script>
var steps = {idb:false, fetch:false, js:false};
function step(k){ steps[k]=true; if(steps.idb && steps.fetch && steps.js){ finish(); } }
function finish(){
  var d=document.createElement('div'); d.id='result'; d.textContent='SETDONE'; document.body.appendChild(d);
  fetch('/report?tag=' + encodeURIComponent(TAG), {method:'POST', body: JSON.stringify({set:true, ls: localStorage.getItem('ls_key'), cookie: document.cookie})})
    .then(function(){ if (CLOSE) { setTimeout(function(){ window.close(); }, 300); } });
}
var TAG = new URLSearchParams(location.search).get('tag') || 'x';
var CLOSE = new URLSearchParams(location.search).get('close') === '1';
localStorage.setItem('ls_key', 'ls_val_123');
document.cookie = 'jsck=js456; max-age=864000; path=/';
var req = indexedDB.open('safetydb', 1);
req.onupgradeneeded = function(e){ e.target.result.createObjectStore('s'); };
req.onsuccess = function(e){ var db=e.target.result; var tx=db.transaction('s','readwrite'); tx.objectStore('s').put('idb_val_789','k'); tx.oncomplete=function(){ db.close(); step('idb'); }; };
req.onerror = function(){ step('idb'); };
Promise.all([1,2,3,4,5,6].map(function(i){ return fetch('/blob/'+i).then(function(r){ return r.arrayBuffer(); }); }))
  .then(function(){ step('fetch'); }, function(){ step('fetch'); });
</script>
<script src="/big/1.js"></script><script src="/big/2.js"></script>
<script>step('js');</script>
</body></html>"""

    CHECK_HTML = """<!doctype html><html><head><title>check</title></head><body>
<script src="/big/1.js"></script>
<script>
var TAG = new URLSearchParams(location.search).get('tag') || 'x';
var CLOSE = new URLSearchParams(location.search).get('close') === '1';
var out = {cookie: document.cookie, ls: localStorage.getItem('ls_key'), idb: null, fetch: null, js: (typeof BIGJS_1 !== 'undefined')};
function done(){
  var d=document.createElement('pre'); d.id='result'; d.textContent=JSON.stringify(out); document.body.appendChild(d);
  fetch('/report?tag=' + encodeURIComponent(TAG), {method:'POST', body: JSON.stringify(out)})
    .then(function(){ if (CLOSE) { setTimeout(function(){ window.close(); }, 300); } });
}
fetch('/blob/1').then(function(r){ return r.arrayBuffer(); }).then(function(b){ out.fetch = b.byteLength; }, function(e){ out.fetch = 'ERR ' + e; }).then(function(){
  var req = indexedDB.open('safetydb', 1);
  req.onupgradeneeded = function(e){ e.target.result.createObjectStore('s'); };
  req.onsuccess = function(e){
    try { var db=e.target.result; var g=db.transaction('s').objectStore('s').get('k');
      g.onsuccess=function(){ out.idb = g.result === undefined ? null : g.result; db.close(); done(); };
      g.onerror=function(){ done(); };
    } catch(err) { out.idb = 'ERR ' + err; done(); }
  };
  req.onerror = function(){ out.idb='ERR open'; done(); };
});
</script>
</body></html>"""

    def __init__(self):
        self.reports = {}
        self.cond = threading.Condition()
        self.hits = []
        rnd = os.urandom(3 * MIB)
        self.blob = rnd[: 2 * MIB]
        import base64
        b64 = base64.b64encode(rnd[: 1100 * 1024]).decode()
        self.js = {n: ("var BIGJS_%d = '%s';\nfunction f%d(x){return x+1;}\nfor (var i=0;i<1000;i++) f%d(i);\n" % (n, b64[n:], n, n)).encode() for n in (1, 2)}
        site = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype, extra=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in extra:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                site.hits.append(self.path)
                path = self.path.split("?")[0]
                cache = [("Cache-Control", "public, max-age=864000")]
                if path == "/set":
                    self._send(200, Site.SET_HTML.encode(), "text/html", [("Set-Cookie", "sid=chk123; Max-Age=864000; Path=/")])
                elif path == "/check":
                    self._send(200, Site.CHECK_HTML.encode(), "text/html", [("Cache-Control", "no-store")])
                elif path.startswith("/big/"):
                    n = int(path[5:].split(".")[0])
                    self._send(200, site.js.get(n, b""), "application/javascript", cache)
                elif path.startswith("/blob/"):
                    n = int(path[6:])
                    self._send(200, site.blob[n:] + site.blob[:n], "application/octet-stream", cache)
                elif path == "/favicon.ico":
                    self._send(404, b"", "text/plain")
                else:
                    self._send(200, b"<html><body>blank</body></html>", "text/html")

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                tag = self.path.split("tag=")[-1] if "tag=" in self.path else "x"
                try:
                    data = json.loads(body)
                except ValueError:
                    data = {"raw": body.decode(errors="replace")}
                with site.cond:
                    site.reports[tag] = data
                    site.cond.notify_all()
                self._send(200, b"ok", "text/plain", [("Access-Control-Allow-Origin", "*")])

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, page, tag, close=False):
        return "http://127.0.0.1:%d/%s?tag=%s%s" % (self.port, page, tag, "&close=1" if close else "")

    def wait(self, tag, timeout=60):
        end = time.time() + timeout
        with self.cond:
            while tag not in self.reports and time.time() < end:
                self.cond.wait(0.5)
            return self.reports.get(tag)


# --------------------------------------------------------------------------- harness

class Abort(Exception):
    pass


class NotExecutable(Exception):
    pass


class Harness:
    def __init__(self, args):
        self.bin = os.path.abspath(args.bin)
        self.work = os.path.realpath(args.work)
        self.keep = args.keep
        self.results = Results()
        self.site = None
        self.procs = []  # processes we started (killed at the end)
        # Hard guard: the sandbox must be nowhere near the real home.
        if self.work == REAL_HOME or REAL_HOME.startswith(self.work + "/") or self.work.startswith(REAL_HOME + "/"):
            raise Abort("--work must not be inside (or contain) the real home %s" % REAL_HOME)
        if len(self.work.split("/")) < 3:
            raise Abort("--work too shallow")
        os.makedirs(self.work, exist_ok=True)
        # Unix socket paths (Chrome's SingletonSocket) must stay short.
        import tempfile
        self.short_tmp = tempfile.mkdtemp(prefix="ldp-")
        self.tools = os.path.join(self.work, "_tools")
        os.makedirs(self.tools, exist_ok=True)

    def get_site(self):
        if self.site is None:
            self.site = Site()
        return self.site

    def spawn(self, argv, **kw):
        kw.setdefault("start_new_session", True)
        p = subprocess.Popen(argv, **kw)
        self.procs.append(p)
        return p

    def kill_all(self):
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    p.wait(10)
                except Exception:
                    pass


class Case:
    def __init__(self, h, name):
        self.h = h
        self.name = name
        self.res = h.results.case(name)
        self.root = os.path.join(h.work, name)
        assert self.root.startswith(h.work + "/")
        if os.path.lexists(self.root):
            make_writable(self.root)
            shutil.rmtree(self.root)
        self.home = os.path.join(self.root, "home")
        self.outside = os.path.join(self.root, "outside")
        self.tmp = os.path.join(self.root, "tmp")
        for d in (self.home, self.outside, self.tmp):
            os.makedirs(d)
        self.stmp = os.path.join(h.short_tmp, name[:6])
        rmtree(self.stmp)
        os.makedirs(self.stmp)
        self.env = self.make_env()

    # ---- environment
    def make_env(self, home=None, path_extra=(), drop_tools=()):
        home = home or self.home
        path = [p for p in [UV_BIN, NVM_BIN, RUST_BIN, "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"] if p]
        path = list(path_extra) + [p for p in path if not any(os.path.isfile(os.path.join(p, t)) for t in drop_tools) or p in ("/usr/bin", "/bin")]
        env = {
            "HOME": home,
            "USER": pwd.getpwuid(os.getuid()).pw_name,
            "LOGNAME": pwd.getpwuid(os.getuid()).pw_name,
            "PATH": ":".join(path),
            "LANG": "C.UTF-8",
            "TMPDIR": self.stmp,
            "CARGO_HOME": os.path.join(home, ".cargo"),
            "UV_PYTHON_DOWNLOADS": "never",
            "NO_COLOR": "1",
            "npm_config_update_notifier": "false",
            "npm_config_fund": "false",
            "npm_config_audit": "false",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "GIO_USE_VFS": "local",
            "GOTOOLCHAIN": "local",
            "GOTELEMETRY": "off",
        }
        return env

    # ---- recording
    def check(self, name, ok, evidence=""):
        self.res["checks"].append({"name": name, "ok": bool(ok), "evidence": str(evidence)[:2000]})
        print("   [%s] %s %s" % ("ok" if ok else "FAIL", name, ("— " + str(evidence)[:300]) if evidence else ""), flush=True)
        return ok

    def note(self, text):
        self.res["notes"].append(text)
        print("   note: " + text, flush=True)

    def bug(self, title, repro, severity, fix):
        self.res["bugs"].append({"title": title, "repro": repro, "severity": severity, "fix": fix})
        print("   BUG[%s]: %s" % (severity, title), flush=True)

    # ---- processes
    def sh(self, cmd, env=None, cwd=None, check=True, timeout=900, input=None):
        env = env or self.env
        p = subprocess.run(["/bin/sh", "-c", cmd], env=env, cwd=cwd or self.home, capture_output=True, text=True, timeout=timeout,
                           input=input, stdin=None if input is not None else subprocess.DEVNULL)
        if check and p.returncode != 0:
            raise RuntimeError("command failed (%d): %s\nstdout: %s\nstderr: %s" % (p.returncode, cmd, p.stdout[-3000:], p.stderr[-3000:]))
        return p

    def tool(self, env=None, home=None, wrap=(), expect_readonly=False):
        """Run linux_disk_prune and return {id: finding} for user-level findings."""
        home = home or self.home
        env = dict(env or self.env)
        argv = list(wrap) + [self.h.bin, "--json", "--rules-only", "--home", home, "--dev-root", home]
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL, cwd=self.root)
        if p.returncode != 0:
            raise RuntimeError("tool failed: %s" % p.stderr[-2000:])
        data = json.loads(p.stdout)
        out = {}
        for f in data["findings"]:
            if f.get("needs_root"):
                continue
            if not f["paths"] or not all(inside(x, home) for x in f["paths"]):
                continue
            out[f["id"]] = f
        return out

    # ---- safety guard
    def assert_confined(self, path, home=None):
        home = home or self.home
        norm = os.path.normpath(path)
        if norm != path.rstrip("/") or ".." in path.split("/"):
            raise Abort("non-normalised path %r" % path)
        if not norm.startswith(home + "/"):
            raise Abort("path outside fake home: %r" % path)
        # Whatever the literal path resolves to must stay inside the sandbox.
        for probe in (os.path.dirname(norm), norm):
            rp = os.path.realpath(probe)
            if not (rp + "/").startswith(self.root + "/"):
                raise Abort("path resolves outside the sandbox: %r -> %r" % (probe, rp))

    def guard(self, f, home=None, allow_docker_only=False):
        home = home or self.home
        cmd = f["command"]
        if cmd.startswith("("):
            raise NotExecutable(cmd)
        if f.get("needs_root") or re.search(r"(^|[;&|]\s*)sudo\b", cmd):
            raise Abort("root command refused: %s" % cmd)
        for p in f["paths"]:
            self.assert_confined(p, home)
        if cmd in HOST_TOOL_CMDS or (allow_docker_only and cmd in DOCKER_ONLY_CMDS):
            return "tool"
        if cmd in DOCKER_ONLY_CMDS:
            raise Abort("%r only runs inside docker" % cmd)
        toks = shlex.split(cmd)
        listed = set(f["paths"])
        # Shape 1: find P -xdev -mindepth 1 -delete [&& find P2 -xdev -mindepth 1 -delete ...]
        if toks and toks[0] == "find":
            i = 0
            while i < len(toks):
                seg = toks[i:i + 6]
                if len(seg) != 6 or seg[0] != "find" or seg[2:] != ["-xdev", "-mindepth", "1", "-delete"] or seg[1] not in listed:
                    raise Abort("unexpected find command shape: %s" % cmd)
                self.assert_confined(seg[1], home)
                i += 6
                if i < len(toks):
                    if toks[i] != "&&":
                        raise Abort("unexpected separator in %s" % cmd)
                    i += 1
            return "find"
        # Shape 2: rm -rf --one-file-system -- P...
        if toks[:4] == ["rm", "-rf", "--one-file-system", "--"] and len(toks) > 4:
            for p in toks[4:]:
                if p not in listed:
                    raise Abort("rm of unlisted path %r" % p)
                self.assert_confined(p, home)
            return "rm"
        # Shape 3: <home>/<conda>/bin/conda clean -a -y
        if len(toks) == 4 and toks[1:] == ["clean", "-a", "-y"] and toks[0].startswith(home + "/"):
            self.assert_confined(toks[0], home)
            return "tool"
        raise Abort("unrecognised command, refusing to run: %s" % cmd)

    def execute(self, f, env=None, home=None):
        kind = self.guard(f, home)
        env = dict(env or self.env)
        if kind == "tool":
            h = home or self.home
            if env.get("HOME") != h:
                raise Abort("tool command must run with HOME=%s" % h)
            for k in ("XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "GOPATH", "GOCACHE", "GOMODCACHE", "UV_CACHE_DIR"):
                v = env.get(k)
                if v and not inside(v, h):
                    raise Abort("%s points outside the fake home" % k)
        p = subprocess.run(["/bin/sh", "-c", f["command"]], env=env, cwd=self.root, capture_output=True, text=True, timeout=900, stdin=subprocess.DEVNULL)
        return p

    # ---- manifests
    def manifest(self, exclude=()):
        return manifest(self.root, [self.tmp] + list(exclude))

    def run_finding(self, fid, findings, risk=None, env=None, verify=None, expect_keep_dirs=None, bytes_tolerance=None, home=None, extra_allowed=()):
        """Execute one finding with full bookkeeping. Returns (finding, proc)."""
        f = findings.get(fid)
        if not self.check("%s: finding present" % fid, f is not None, "ids=%s" % sorted(findings)):
            return None, None
        if risk:
            self.check("%s: risk %s" % (fid, risk), f["risk"] == risk, f["risk"])
        before = self.manifest()
        a0 = alloc(self.root, [self.tmp])
        try:
            p = self.execute(f, env=env, home=home)
        except NotExecutable:
            self.check("%s: actionable" % fid, False, f["command"])
            return f, None
        a1 = alloc(self.root, [self.tmp])
        after = self.manifest()
        self.check("%s: command exit 0" % fid, p.returncode == 0, "cmd=%s rc=%d err=%s" % (short(f["command"]), p.returncode, p.stderr[-500:]))
        allowed = list(f["paths"]) + list(extra_allowed)
        allowed += [os.path.realpath(x) for x in allowed]
        diffs = diff_manifest(before, after, self.root, allowed)
        self.check("%s: nothing changed outside the finding's paths" % fid, not diffs, "; ".join(diffs[:12]))
        keep = expect_keep_dirs if expect_keep_dirs is not None else (f["command"].startswith("find "))
        if keep:
            # A cache path that was a symlink must survive as that symlink.
            missing = [x for x in f["paths"] if not (os.path.islink(x) if x in before and before[x][0] == "l" else os.path.isdir(x) and not os.path.islink(x))]
            self.check("%s: cache dirs themselves kept" % fid, not missing, missing)
        freed = a0 - a1
        tol = bytes_tolerance if bytes_tolerance is not None else max(256 * 1024, int(0.05 * max(freed, f["bytes"])))
        # Over-reporting misleads the user; under-reporting is only noted.
        self.check("%s: reported bytes not above freed" % fid, f["bytes"] - freed <= tol,
                   "reported=%s freed=%s" % (human(f["bytes"]), human(freed)))
        if freed - f["bytes"] > tol:
            self.note("%s under-reports: reported %s, freed %s" % (fid, human(f["bytes"]), human(freed)))
        self.res.setdefault("bytes", []).append({"id": fid, "reported": f["bytes"], "freed": freed})
        if verify:
            verify()
        return f, p


# --------------------------------------------------------------------------- fs helpers

def inside(p, root):
    p = os.path.normpath(p)
    return p.startswith(root.rstrip("/") + "/")


def short(s, n=160):
    return s if len(s) <= n else s[:n] + "…"


def human(n):
    for u in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or u == "GiB":
            return "%.1f%s" % (n, u) if u != "B" else "%d%s" % (n, u)
        n /= 1024.0


def make_writable(root):
    for dp, dns, fns in os.walk(root):
        for n in dns:
            p = os.path.join(dp, n)
            try:
                if not os.path.islink(p):
                    os.chmod(p, stat.S_IMODE(os.lstat(p).st_mode) | 0o700)
            except OSError:
                pass
    try:
        os.chmod(root, 0o755)
    except OSError:
        pass


def rmtree(p):
    if os.path.lexists(p):
        make_writable(p)
        shutil.rmtree(p, ignore_errors=True)


def sha256(p):
    h = hashlib.sha256()
    try:
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        return "ERR:%s" % e.errno
    return h.hexdigest()


def manifest(root, exclude=()):
    out = {}
    ex = [os.path.normpath(e) for e in exclude]
    for dp, dns, fns in os.walk(root, followlinks=False):
        if any(dp == e or dp.startswith(e + "/") for e in ex):
            dns[:] = []
            continue
        for n in dns + fns:
            p = os.path.join(dp, n)
            if any(p == e for e in ex):
                continue
            try:
                st = os.lstat(p)
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                out[p] = ("l", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[p] = ("d", mode)
            elif stat.S_ISREG(st.st_mode):
                out[p] = ("f", mode, st.st_size, sha256(p) if st.st_size < 512 * MIB else "big")
            else:
                out[p] = ("o", mode)
    return out


def diff_manifest(before, after, root, allowed):
    allowed = [os.path.normpath(a) for a in allowed]

    def ok(p):
        return any(p == a or p.startswith(a + "/") for a in allowed)

    diffs = []
    for p, v in before.items():
        if ok(p):
            continue
        if p not in after:
            diffs.append("DELETED " + os.path.relpath(p, root))
        elif after[p] != v:
            diffs.append("CHANGED " + os.path.relpath(p, root))
    for p in after:
        if p not in before and not ok(p):
            diffs.append("NEW " + os.path.relpath(p, root))
    return diffs


def alloc(root, exclude=()):
    """Allocated bytes of the unique inodes below root (hard links once)."""
    seen = set()
    total = 0
    for dp, dns, fns in os.walk(root, followlinks=False):
        if any(dp == e or dp.startswith(e + "/") for e in exclude):
            dns[:] = []
            continue
        for n in dns + fns:
            try:
                st = os.lstat(os.path.join(dp, n))
            except OSError:
                continue
            k = (st.st_dev, st.st_ino)
            if k in seen:
                continue
            seen.add(k)
            total += st.st_blocks * 512
    return total


def write(p, data=b"", size=None, mode=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as fh:
        if size is not None:
            fh.write(os.urandom(size))
        else:
            fh.write(data if isinstance(data, bytes) else data.encode())
    if mode is not None:
        os.chmod(p, mode)
    return p


def tree_files(d):
    n = 0
    for _dp, _dns, fns in os.walk(d):
        n += len(fns)
    return n


def wait_for(pred, timeout=30, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def stop(proc, timeout=30, sig=signal.SIGTERM):
    """Stop a process we started (only its own process group)."""
    if proc.poll() is not None:
        return proc.returncode
    try:
        os.kill(proc.pid, sig)
    except OSError:
        pass
    try:
        return proc.wait(timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        return proc.wait(10)


def killpg_wait(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        proc.wait(10)
    except Exception:
        pass


# =========================================================================== cases

def case_pip(h):
    c = Case(h, "pip")
    c.sh("pip3 install --user --no-warn-script-location requests==2.31.0 rich==13.7.1")
    c.sh("pip3 download -d %s six==1.16.0 packaging==24.0" % shlex.quote(c.outside))
    imp = "python3 -c 'import requests, rich, pygments; print(requests.__file__)'"
    r = c.sh(imp)
    c.check("pip: packages import before", r.stdout.strip().startswith(c.home), r.stdout.strip())
    cache_dir = c.sh("pip3 cache dir").stdout.strip()
    f = c.tool()
    if "pip-cache" in f:
        # Only pip's own sub-folders of `pip cache dir` (what `pip cache purge` clears).
        own = {os.path.join(cache_dir, x) for x in ("http", "http-v2", "wheels", "selfcheck")}
        ps = f["pip-cache"]["paths"]
        c.check("pip-cache: paths are pip's own folders in `pip cache dir`", ps and set(ps) <= own, "%s vs %s" % (ps, cache_dir))

    def verify():
        r = c.sh(imp, check=False)
        c.check("pip: installed packages still import", r.returncode == 0, r.stderr[-300:])
        r = c.sh("pip3 install --user --force-reinstall --no-deps six==1.16.0", check=False)
        c.check("pip: pip install works after purge", r.returncode == 0, r.stderr[-300:])
        c.check("pip: cache repopulated", tree_files(cache_dir) > 0)
    c.run_finding("pip-cache", f, risk="SAFE", verify=verify)


def case_uv(h):
    c = Case(h, "uv")
    if not os.path.isfile(os.path.join(UV_BIN, "uv")):
        c.note("uv not installed: skipped")
        c.res["status"] = "SKIP"
        return
    for proj in ("p1", "p2"):
        d = os.path.join(c.home, "code", proj)
        os.makedirs(d)
        c.sh("uv venv -q .venv && uv pip install -q --python .venv/bin/python requests==2.31.0 rich==13.7.1 pyyaml==6.0.1", cwd=d)
    # A uvx tool environment lives inside the cache.
    c.sh("uvx --quiet pycowsay==0.0.0.2 hi")
    venv_file = os.path.join(c.home, "code/p1/.venv/lib/python3.10/site-packages/rich/console.py")
    nl = os.stat(venv_file).st_nlink if os.path.exists(venv_file) else 0
    c.check("uv: venv files hard-linked from cache", nl >= 2, "nlink=%d" % nl)
    cache = os.path.join(c.home, ".cache/uv")
    total = alloc(cache)
    f = c.tool()
    uvf = f.get("uv-cache")
    if uvf:
        c.check("uv-cache: counts only unique data (< total cache)", uvf["bytes"] < total, "reported=%s cache_total=%s" % (human(uvf["bytes"]), human(total)))
        c.check("uv-cache: command is `uv cache clean`", uvf["command"] == "uv cache clean", uvf["command"])
    imp = ".venv/bin/python -c 'import requests, rich, yaml; print(\"ok\")'"

    def verify():
        for proj in ("p1", "p2"):
            r = c.sh(imp, cwd=os.path.join(c.home, "code", proj), check=False)
            c.check("uv: venv %s still imports packages" % proj, r.returncode == 0 and "ok" in r.stdout, r.stderr[-300:])
        r = c.sh("uvx --quiet pycowsay==0.0.0.2 again", check=False)
        c.check("uv: uvx works after cache clean", r.returncode == 0, r.stderr[-300:])
        d = os.path.join(c.home, "code", "p3-%d" % len(c.res["checks"]))
        os.makedirs(d)
        r = c.sh("uv venv -q .venv && uv pip install -q --python .venv/bin/python rich==13.7.1 && " + imp.replace("requests, ", "").replace(", yaml", ""), cwd=d, check=False)
        c.check("uv: new venv + install works after clean", r.returncode == 0, r.stderr[-300:])
    # uv cache clean removes the cache dir itself.
    c.run_finding("uv-cache", f, risk="SAFE", verify=verify, expect_keep_dirs=False)

    # Without uv on PATH the rule falls back to emptying the directory. Make
    # cache data unique again by dropping a venv that linked it.
    d4 = os.path.join(c.home, "code", "p4")
    os.makedirs(d4)
    c.sh("uv venv -q .venv && uv pip install -q --python .venv/bin/python requests==2.31.0 rich==13.7.1 pyyaml==6.0.1 && rm -rf .venv", cwd=d4)
    env2 = c.make_env(drop_tools=("uv",))
    f2 = c.tool(env=env2)
    if "uv-cache" in f2:
        c.check("uv-cache (no uv on PATH): falls back to find -delete", f2["uv-cache"]["command"].startswith("find "), f2["uv-cache"]["command"])
        c.run_finding("uv-cache", f2, risk="SAFE", env=env2, verify=verify)
    else:
        c.note("uv-cache fallback not reported (cache below 1 MiB after reinstall?)")

    # Consistency: UV_CACHE_DIR is honoured by uv but not by the rule.
    alt = os.path.join(c.home, "alt-uv-cache")
    env3 = dict(c.env, UV_CACHE_DIR=alt)
    c.sh("uv pip install -q --python code/p1/.venv/bin/python --reinstall six==1.16.0", env=env3)
    write(os.path.join(c.home, ".cache/uv/sdists-v9/pad.bin"), size=2 * MIB)
    f3 = c.tool(env=env3)
    u = f3.get("uv-cache")
    if u and u["command"] == "uv cache clean":
        before_alt = tree_files(alt)
        p = c.execute(u, env=env3)
        cleaned_alt = tree_files(alt) == 0 and before_alt > 0
        still_default = tree_files(os.path.join(c.home, ".cache/uv")) > 0
        if cleaned_alt and still_default:
            c.bug("uv-cache ignores UV_CACHE_DIR: reports ~/.cache/uv but `uv cache clean` empties $UV_CACHE_DIR",
                  "UV_CACHE_DIR=$H/alt uv pip install six; put 2 MiB in $H/.cache/uv; run tool -> uv-cache lists ~/.cache/uv; "
                  "`uv cache clean` empties $H/alt instead and ~/.cache/uv stays.",
                  "low", "src/rules/extra.rs tool_cache_findings: resolve the uv cache from UV_CACHE_DIR (like Dirs.pip) or run `uv cache dir`")
        c.check("uv-cache with UV_CACHE_DIR: reported path is what the command cleans", not (cleaned_alt and still_default),
                "alt emptied=%s default kept=%s rc=%d" % (cleaned_alt, still_default, p.returncode))


def npm_project(d, deps):
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "package.json"), json.dumps({"name": "proj", "version": "1.0.0", "private": True, "dependencies": deps}))
    write(os.path.join(d, "index.js"), "const _ = require('lodash'); const m = require('moment'); console.log('works', _.chunk([1,2,3,4],2).length, typeof m);\n")


def case_npm(h):
    c = Case(h, "npm")
    web = os.path.join(c.home, "src", "web")
    npm_project(web, {"lodash": "4.17.21", "moment": "2.30.1", "typescript": "5.4.5"})
    c.sh("npm install --no-audit --no-fund --loglevel=error", cwd=web)
    c.sh("npx -y prettier@3.3.3 --version")
    # node_modules without package.json, and a global prefix install: never artifacts.
    write(os.path.join(c.home, "src/nopkg/node_modules/big.bin"), size=3 * MIB)
    c.sh("npm install -g --prefix %s --loglevel=error cowsay@1.6.0" % shlex.quote(os.path.join(c.home, "nodeprefix")))
    # An app bundle shipped with its node_modules (e.g. VS Code tarball in ~/apps).
    app = os.path.join(c.home, "apps/VSCode-linux-x64/resources/app")
    write(os.path.join(app, "package.json"), json.dumps({"name": "code-oss", "version": "1.90.0", "main": "out/main.js"}))
    write(os.path.join(app, "node_modules/some-native-dep/index.js"), size=3 * MIB)
    run_web = "node index.js"
    r = c.sh(run_web, cwd=web)
    c.check("npm: project runs before", "works" in r.stdout, r.stdout)

    f = c.tool()
    ids = sorted(f)
    nm = "node:%s" % os.path.join(web, "node_modules")
    c.check("node_modules reported for the project", nm in f, ids)
    c.check("no node_modules without package.json", not any("nopkg" in i for i in ids), ids)
    glob = [i for i in ids if "nodeprefix" in i]
    if glob:
        c.bug("node_modules rule descends into unreported node_modules trees and proposes nested ones (breaks global npm installs)",
              "npm install -g --prefix ~/nodeprefix cowsay  ->  tool lists %s (CAUTION, rm -rf). Running it breaks the globally installed "
              "`cowsay` CLI (its dependencies are gone) and `npm ci` cannot restore it (no project there)." % glob[0][5:],
              "medium", "src/rules/ubuntu.rs run_artifact_check: never push a child named node_modules onto the stack (stop at every "
              "node_modules, reported or not); skip lib/node_modules under npm prefixes")
    c.check("no node_modules inside a global npm prefix", not glob, glob)
    bundle = [i for i in ids if "VSCode-linux-x64" in i]
    if bundle:
        c.bug("node_modules of an application bundle (e.g. VS Code tarball in ~/apps/.../resources/app) is proposed as a project artifact",
              "mkdir -p ~/apps/VSCode-linux-x64/resources/app && echo '{\"name\":\"code-oss\"}' > .../package.json; put 3 MiB in "
              ".../node_modules  ->  finding %s, detail says 'Restored with npm ci' — for an app bundle it is not." % bundle[0][5:],
              "low", "src/rules/ubuntu.rs run_artifact_check: require a lockfile (package-lock.json/yarn.lock/pnpm-lock.yaml) or "
              "node_modules/.package-lock.json next to package.json before proposing node_modules")
    c.check("no node_modules of an app bundle without lockfile", not bundle, bundle)
    if "npx-cache" in f and f["npx-cache"]["command"].startswith("("):
        c.note("npx-cache is Manual because *some other* process on this machine runs from an /_npx/ path "
               "(the check matches any process, not this home's cache). Conservative, not unsafe. Re-running in a PID namespace.")
        f_np = c.tool(wrap=["unshare", "-c", "-p", "-f", "-m", "--mount-proc"])
    else:
        f_np = f

    def verify_cache():
        r = c.sh(run_web, cwd=web, check=False)
        c.check("npm: project still runs", "works" in r.stdout, r.stderr[-300:])
        r = c.sh("npm cache verify", check=False)
        c.check("npm: `npm cache verify` ok", r.returncode == 0, r.stderr[-300:])
        r = c.sh("rm -rf node_modules && npm ci --no-audit --no-fund --loglevel=error && node index.js", cwd=web, check=False)
        c.check("npm: `npm ci` works after cache clean", "works" in r.stdout, r.stderr[-300:])
    c.run_finding("npm-cache", f, risk="SAFE", verify=verify_cache,
                  extra_allowed=[os.path.join(web, "node_modules")])

    def verify_npx():
        r = c.sh("npx -y prettier@3.3.3 --version", check=False)
        c.check("npx: works after cache removal", r.returncode == 0 and r.stdout.strip() == "3.3.3", r.stdout + r.stderr[-300:])
    c.run_finding("npx-cache", f_np, risk="SAFE", verify=verify_npx)

    f = c.tool()

    def verify_nm():
        r = c.sh("npm ci --no-audit --no-fund --loglevel=error && node index.js", cwd=web, check=False)
        c.check("node_modules: `npm ci` restores a working project", "works" in r.stdout, r.stderr[-300:])
        c.check("node_modules: package.json/lock kept", os.path.isfile(os.path.join(web, "package-lock.json")))
    c.run_finding(nm, f, risk="CAUTION", verify=verify_nm, expect_keep_dirs=False)
    r = c.sh(os.path.join(c.home, "nodeprefix/bin/cowsay") + " moo", check=False)
    c.check("global npm prefix install untouched", r.returncode == 0, r.stderr[-200:])


def case_cargo(h):
    c = Case(h, "cargo")
    if not RUST_BIN:
        c.note("no rust toolchain: skipped")
        c.res["status"] = "SKIP"
        return
    proj = os.path.join(c.home, "code", "rs1")
    c.sh("cargo new -q --vcs none %s" % shlex.quote(proj))
    with open(os.path.join(proj, "Cargo.toml"), "a") as fh:
        fh.write('serde = { version = "1", features = ["derive"] }\n'
                 'serde_json = { git = "https://github.com/serde-rs/json", tag = "v1.0.128" }\n')
    write(os.path.join(proj, "src/main.rs"),
          '#[derive(serde::Serialize)] struct P { x: u32 }\nfn main() { println!("works {}", serde_json::to_string(&P { x: 7 }).unwrap()); }\n')
    build = "cargo build -q && ./target/debug/rs1"
    r = c.sh(build, cwd=proj)
    c.check("cargo: builds and runs before", "works" in r.stdout, r.stdout)
    f = c.tool()
    tgt = "rust:%s" % os.path.join(proj, "target")

    def verify(label):
        def v():
            r = c.sh(build, cwd=proj, check=False)
            c.check("cargo: build works after %s" % label, "works" in r.stdout, r.stderr[-400:])
        return v
    c.run_finding("cargo-registry", f, risk="MODERATE", verify=verify("registry clean"),
                  extra_allowed=[os.path.join(proj, "target")])
    ck = os.path.join(c.home, ".cargo/git/checkouts")
    linked = sum(os.lstat(os.path.join(dp, n)).st_blocks * 512 for dp, _d, fns in os.walk(ck) for n in fns
                 if os.lstat(os.path.join(dp, n)).st_nlink > 1)
    fg = c.tool()
    if "cargo-git" in fg:
        c.note("cargo git checkouts: %s of the reported %s are files hard-linked with ~/.cargo/git/db (freeing nothing)"
               % (human(linked), human(fg["cargo-git"]["bytes"])))
        unlinked = sum(os.lstat(os.path.join(dp, n)).st_blocks * 512 for dp, ds, fns in os.walk(ck) for n in fns + ds
                       if os.lstat(os.path.join(dp, n)).st_nlink <= 1 or os.path.isdir(os.path.join(dp, n)))
        if linked > MIB and fg["cargo-git"]["bytes"] > unlinked + MIB:
            c.bug("cargo-git overstates reclaimable bytes: checkouts hard-link pack files from ~/.cargo/git/db",
                  "cargo build a project with a git dependency (serde_json from GitHub): tool reports cargo-git ~%s, "
                  "deleting frees only the unlinked part (%s are hard links)." % (human(fg["cargo-git"]["bytes"]), human(linked)),
                  "low", "src/rules/ubuntu.rs check_user_caches: size cargo-git with extra::unique_bytes (as uv/conda do)")
    c.run_finding("cargo-git", fg, risk="SAFE", verify=verify("git checkout clean"),
                  extra_allowed=[os.path.join(proj, "target"), os.path.join(c.home, ".cargo/registry")])
    f = c.tool()
    # Moderate rationale: offline builds fail until the network is back.
    c.run_finding("cargo-registry", f, risk="MODERATE", extra_allowed=[os.path.join(proj, "target")])
    r = c.sh("cargo build -q --offline", cwd=proj, check=False)
    c.note("cargo-registry MODERATE rationale: after clearing with an intact target/, --offline build rc=%d (%s)"
           % (r.returncode, (r.stderr.strip().splitlines() or [""])[-1][:160]))
    c.sh(build, cwd=proj)
    f = c.tool()

    def v_target():
        r = c.sh(build, cwd=proj, check=False)
        c.check("cargo target/: full rebuild works", "works" in r.stdout, r.stderr[-400:])
    c.run_finding(tgt, f, risk="CAUTION", verify=v_target, expect_keep_dirs=False)


def case_go(h):
    c = Case(h, "go")
    if not which_real("go"):
        c.note("go missing: skipped")
        c.res["status"] = "SKIP"
        return
    proj = os.path.join(c.home, "code", "g1")
    os.makedirs(proj)
    write(os.path.join(proj, "main.go"), 'package main\nimport (\n"fmt"\n"github.com/google/uuid"\n"golang.org/x/text/language"\n)\n'
          'func main(){ fmt.Println("works", len(uuid.NewString()), language.English) }\n')
    c.sh("go mod init example.com/g1 && go mod tidy && go build -o g1 . && ./g1", cwd=proj)
    f = c.tool()
    build = "go build -o g1 . && ./g1"

    def v(label):
        def inner():
            r = c.sh(build, cwd=proj, check=False)
            c.check("go: build works after %s" % label, "works" in r.stdout, r.stderr[-300:])
        return inner
    c.run_finding("go-build-cache", f, risk="SAFE", verify=v("go clean -cache"), expect_keep_dirs=False,
                  extra_allowed=[os.path.join(proj, "g1")])
    f = c.tool()
    c.run_finding("go-mod-cache", f, risk="MODERATE", verify=v("go clean -modcache"), expect_keep_dirs=False,
                  extra_allowed=[os.path.join(proj, "g1"), os.path.join(c.home, ".cache/go-build")])
    # Without go on PATH: build cache falls back to find -delete, module cache is manual.
    env2 = c.make_env(drop_tools=("go",))
    env2["PATH"] = ":".join(p for p in env2["PATH"].split(":") if p not in ("/usr/bin", "/bin")) + ":" + make_bin_without(c, ["go"])
    f2 = c.tool(env=env2)
    if "go-mod-cache" in f2:
        c.check("go-mod-cache without go: Manual", f2["go-mod-cache"]["command"].startswith("("), f2["go-mod-cache"]["command"])
    if "go-build-cache" in f2:
        c.check("go-build-cache without go: find -delete", f2["go-build-cache"]["command"].startswith("find "), f2["go-build-cache"]["command"])
        c.run_finding("go-build-cache", f2, risk="SAFE", env=env2, verify=v("find -delete of go-build"))
    # GOMODCACHE override: rule looks at ~/go/pkg/mod, `go clean -modcache` at $GOMODCACHE.
    alt = os.path.join(c.home, "gomodalt")
    env3 = dict(c.env, GOMODCACHE=alt)
    c.sh("go mod download all", cwd=proj, env=env3)
    c.sh("go mod download all", cwd=proj)
    f3 = c.tool(env=env3)
    g = f3.get("go-mod-cache")
    if g:
        n_alt, n_def = tree_files(alt), tree_files(os.path.join(c.home, "go/pkg/mod"))
        c.execute(g, env=env3)
        emptied_alt = n_alt > 0 and tree_files(alt) == 0
        kept_def = tree_files(os.path.join(c.home, "go/pkg/mod")) == n_def
        reports_alt = g["paths"] == [alt]
        if emptied_alt and kept_def and not reports_alt:
            c.bug("go-mod-cache/go-build-cache ignore GOMODCACHE/GOPATH/GOCACHE: finding shows ~/go/pkg/mod but `go clean -modcache` removes $GOMODCACHE",
                  "GOMODCACHE=$H/gomodalt go mod download; also populate ~/go/pkg/mod; tool reports ~/go/pkg/mod (size of that dir); "
                  "executing `go clean -modcache` empties $H/gomodalt and leaves ~/go/pkg/mod.",
                  "low", "src/rules/extra.rs tool_cache_findings: take paths from `go env GOMODCACHE GOCACHE` (or env GOMODCACHE/GOPATH/GOCACHE)")
        c.check("go-mod-cache with GOMODCACHE: reported path is what the command cleans", reports_alt or not (emptied_alt and kept_def),
                "alt emptied=%s ~/go/pkg/mod kept=%s" % (emptied_alt, kept_def))
        c.sh("go clean -modcache", env=env3, check=False)


def make_bin_without(c, names):
    """A PATH dir that mirrors /usr/bin and /bin except `names`."""
    d = os.path.join(c.root, "_bin_wo_" + "_".join(names))
    if not os.path.isdir(d):
        os.makedirs(d)
        for src in ("/usr/bin", "/bin"):
            for n in os.listdir(src):
                if n in names or os.path.lexists(os.path.join(d, n)):
                    continue
                os.symlink(os.path.join(src, n), os.path.join(d, n))
    return d


# --------------------------------------------------------------------------- browsers

def browser_state_ok(c, rep, label):
    ok = bool(rep) and "sid=chk123" in (rep.get("cookie") or "") and "jsck=js456" in (rep.get("cookie") or "") \
        and rep.get("ls") == "ls_val_123" and rep.get("idb") == "idb_val_789" and rep.get("fetch") == 2 * MIB and rep.get("js")
    c.check("%s: cookies, localStorage, IndexedDB intact and page loads" % label, ok, rep)
    return ok


def chrome_cmd(c, url, extra=()):
    return ["google-chrome", "--headless=new", "--user-data-dir=" + os.path.join(c.home, ".config/google-chrome"),
            "--no-first-run", "--no-default-browser-check", "--password-store=basic", "--disable-gpu",
            "--disable-background-networking", "--disable-component-update", "--disable-sync"] + list(extra) + [url]


def case_chrome(h):
    c = Case(h, "chrome")
    if not which_real("google-chrome"):
        c.note("google-chrome missing")
        c.res["status"] = "SKIP"
        return
    site = h.get_site()
    prof = os.path.join(c.home, ".config/google-chrome/Default")
    write(os.path.join(prof, "Bookmarks"), json.dumps({"version": 1, "roots": {
        "bookmark_bar": {"children": [{"name": "SafetyBookmark", "type": "url", "url": "https://example.org/", "id": "5"}],
                         "name": "Bookmarks bar", "type": "folder", "id": "1"},
        "other": {"children": [], "name": "Other", "type": "folder", "id": "2"},
        "synced": {"children": [], "name": "Mobile", "type": "folder", "id": "3"}}}))
    log = open(os.path.join(c.tmp, "chrome.log"), "w")
    def chrome_page(page, tag):
        # window.close() on the only tab makes headless Chrome shut down
        # cleanly (SIGTERM does not flush the cookie store).
        p = h.spawn(chrome_cmd(c, site.url(page, tag, close=True)), env=c.env, stdout=log, stderr=log)
        rep = site.wait(tag, 90)
        try:
            p.wait(60)
        except subprocess.TimeoutExpired:
            stop(p, 30)
        return rep
    for tag in ("c-set1", "c-set2"):
        rep = chrome_page("set", tag)
        c.check("chrome: populate run %s reported" % tag, rep and rep.get("set"), rep)
    browser_state_ok(c, chrome_page("check", "c-base"), "chrome baseline (before any cleanup)")
    lock = os.path.join(c.home, ".config/google-chrome/SingletonLock")

    def lock_is(pid):
        try:
            return os.readlink(lock).endswith("-%d" % pid)
        except OSError:
            return False
    cache_root = os.path.join(c.home, ".cache/google-chrome")
    c.check("chrome: fake-HOME Chrome keeps its disk cache in ~/.cache/google-chrome/<profile>/{Cache,Code Cache}",
            os.path.isdir(os.path.join(cache_root, "Default/Cache")), sorted(os.listdir(os.path.join(cache_root, "Default"))) if os.path.isdir(os.path.join(cache_root, "Default")) else "missing")
    c.note("chrome cache layout: %s" % sorted(os.path.relpath(os.path.join(dp, d), cache_root) for dp, dns, _ in os.walk(cache_root) for d in dns if dp.count("/") - cache_root.count("/") < 2))

    # While Chrome runs with this profile the finding must be manual.
    p = h.spawn(chrome_cmd(c, site.url("blank", "run")), env=c.env, stdout=log, stderr=log)
    c.check("chrome: running instance holds SingletonLock", wait_for(lambda: lock_is(p.pid), 30), os.path.islink(lock) and os.readlink(lock))
    f = c.tool()
    cf = f.get("chrome-cache")
    c.check("chrome running: chrome-cache is Manual", cf is not None and cf["command"].startswith("("), cf and cf["command"])
    stop(p, 30)
    wait_for(lambda: not os.path.lexists(lock), 15)
    # Crash leaves a stale lock naming a dead pid: the cache is actionable again.
    p = h.spawn(chrome_cmd(c, site.url("blank", "run2")), env=c.env, stdout=log, stderr=log)
    wait_for(lambda: lock_is(p.pid), 30)
    time.sleep(1)
    killpg_wait(p)
    time.sleep(1)
    f = c.tool()
    cf = f.get("chrome-cache")
    c.check("chrome crashed (stale SingletonLock, dead pid): chrome-cache actionable", cf is not None and not cf["command"].startswith("("),
            "lock=%s cmd=%s" % (os.readlink(lock) if os.path.islink(lock) else None, cf and short(cf["command"])))
    if cf:
        bad = [x for x in cf["paths"] if not inside(x, cache_root) or os.path.basename(x) not in ("Cache", "Code Cache", "GPUCache")]
        c.check("chrome-cache: only Cache/Code Cache/GPUCache under ~/.cache/google-chrome", not bad, bad or cf["paths"])

    def verify():
        browser_state_ok(c, chrome_page("check", "c-check"), "chrome")
        try:
            prefs = json.load(open(os.path.join(prof, "Preferences")))
            c.check("chrome: Preferences still valid", isinstance(prefs, dict) and "profile" in prefs)
        except Exception as e:
            c.check("chrome: Preferences still valid", False, e)
        c.check("chrome: Bookmarks kept", "SafetyBookmark" in open(os.path.join(prof, "Bookmarks")).read())
        c.check("chrome: cache rebuilt on next run", tree_files(os.path.join(cache_root, "Default/Cache")) > 0)
    c.run_finding("chrome-cache", f, risk="SAFE", verify=verify)
    log.close()


FF_USERJS = """
user_pref("dom.allow_scripts_to_close_windows", true);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("app.update.auto", false);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.cache.disk.enable", true);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("network.cookie.cookieBehavior", 0);
"""


def firefox_bin(h):
    if h.firefox and os.path.isfile(h.firefox):
        return h.firefox
    ff = os.path.join(h.tools, "firefox/firefox")
    if not os.path.isfile(ff):
        tar = os.path.join(h.tools, "firefox.tar.xz")
        subprocess.run(["curl", "-sSL", "-o", tar, "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=en-US"], check=True)
        subprocess.run(["tar", "xf", tar, "-C", h.tools], check=True)
        os.unlink(tar)
    return ff


def case_firefox(h):
    c = Case(h, "firefox")
    ff = firefox_bin(h)
    ver = subprocess.run([ff, "--version"], capture_output=True, text=True).stdout.strip()
    c.note("using %s (%s); the system /usr/bin/firefox is the snap wrapper" % (ver, ff))
    env = dict(c.env, MOZ_CRASHREPORTER_DISABLE="1", MOZ_HEADLESS="1")
    site = h.get_site()
    r = subprocess.run([ff, "--headless", "-CreateProfile", "tp"], env=env, capture_output=True, text=True, timeout=120)
    m = re.search(r"at '([^']+)'", r.stdout + r.stderr)
    prof = os.path.dirname(m.group(1)) if m else None
    if not prof:
        for base in (".mozilla/firefox", ".config/mozilla/firefox"):
            d = os.path.join(c.home, base)
            for n in (os.listdir(d) if os.path.isdir(d) else []):
                if n.endswith(".tp"):
                    prof = os.path.join(d, n)
    c.check("firefox: profile created in fake home", prof and inside(prof, c.home), r.stdout + r.stderr)
    if not prof:
        return
    c.note("firefox profile dir: ~/%s" % os.path.relpath(prof, c.home))
    write(os.path.join(prof, "user.js"), FF_USERJS)
    write(os.path.join(prof, "logins.json"), json.dumps({"nextId": 2, "logins": [{"id": 1, "hostname": "https://example.org", "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECKyLx3v2Un9KBAh9YkL3PpdmvQ==", "encryptedPassword": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECKyLx3v2Un9KBAh9YkL3PpdmvQ==", "formSubmitURL": "", "httpRealm": None, "usernameField": "", "passwordField": "", "guid": "{11111111-2222-3333-4444-555555555555}", "encType": 1, "timeCreated": 1, "timeLastUsed": 1, "timePasswordChanged": 1, "timesUsed": 1}], "potentiallyVulnerablePasswords": [], "dismissedBreachAlertsByLoginGUID": {}, "version": 3}))
    log = open(os.path.join(c.tmp, "firefox.log"), "w")

    def ffrun(page, tag, wait_exit=True):
        p = h.spawn([ff, "--headless", "--no-remote", "-P", "tp", site.url(page, tag, close=True)], env=env, stdout=log, stderr=log)
        rep = site.wait(tag, 120)
        if wait_exit:
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                stop(p, 30)
        return rep, p
    for tag in ("f-set1", "f-set2"):
        rep, _ = ffrun("set", tag)
        c.check("firefox: populate run %s reported" % tag, rep and rep.get("set"), rep)
    cache2 = [os.path.join(dp, d) for dp, dns, _ in os.walk(c.home) for d in dns if d == "cache2"]
    c.note("firefox cache2 dirs: %s" % [os.path.relpath(x, c.home) for x in cache2])

    # Running Firefox: the finding must be manual.
    p = h.spawn([ff, "--headless", "--no-remote", "-P", "tp", site.url("blank", "ffrun")], env=env, stdout=log, stderr=log)
    c.check("firefox: running instance holds profile lock", wait_for(lambda: os.path.lexists(os.path.join(prof, "lock")), 60),
            os.path.islink(os.path.join(prof, "lock")) and os.readlink(os.path.join(prof, "lock")))
    time.sleep(2)
    f = c.tool()
    fc = f.get("firefox-cache")
    running_ok = fc is not None and fc["command"].startswith("(")
    c.check("firefox running: firefox-cache is Manual", running_ok, fc and short(fc["command"]))
    if fc is not None and not running_ok:
        c.bug("Running Firefox not detected for profiles under ~/.config/mozilla/firefox (Firefox >= 147 XDG layout): cache2 offered for deletion while Firefox runs",
              "HOME=$H %s --headless -CreateProfile tp  (profile lands in %s); start firefox -P tp; run tool -> firefox-cache is actionable "
              "although %s/lock exists." % (os.path.basename(ff), os.path.relpath(prof, c.home), os.path.relpath(prof, c.home)),
              "low", "src/rules/extra.rs browser_findings: also scan <config>/mozilla/firefox (and profiles.ini Path= entries) for `lock`")
        # Impact: empty cache2 under the running browser, then check the profile.
        pr = c.execute(fc)
        c.note("emptied cache2 while Firefox was running: rc=%d" % pr.returncode)
        stop(p, 60)
        rep, _ = ffrun("check", "f-check-after-live-delete")
        browser_state_ok(c, rep, "firefox after cache2 was emptied while running")
        for tag in ("f-set3",):
            ffrun("set", tag)
    stop(p, 60)
    f = c.tool()

    def verify():
        rep, _ = ffrun("check", "f-check")
        browser_state_ok(c, rep, "firefox")
        import sqlite3
        try:
            con = sqlite3.connect("file:%s?mode=ro" % os.path.join(prof, "places.sqlite"), uri=True)
            n = con.execute("select count(*) from moz_places where url like 'http://127.0.0.1:%'").fetchone()[0]
            con.close()
        except Exception as e:
            n = "ERR %s" % e
        c.check("firefox: history (places.sqlite) intact", isinstance(n, int) and n > 0, n)
        c.check("firefox: logins.json kept", os.path.isfile(os.path.join(prof, "logins.json")))
        c.check("firefox: cache rebuilt", any(tree_files(x) > 0 for x in cache2))
    c.run_finding("firefox-cache", f, risk="SAFE", verify=verify)
    log.close()


ELECTRON_MAIN = r"""
const { app, BrowserWindow, session } = require('electron');
const fs = require('fs'); const path = require('path');
app.setPath('userData', path.join(app.getPath('appData'), 'FakeApp'));
if (process.env.FAKE_LOCK === '1' && !app.requestSingleInstanceLock()) { app.quit(); }
async function waitResult(w) {
  for (let i = 0; i < 600; i++) {
    const ok = await w.webContents.executeJavaScript("!!document.getElementById('result')");
    if (ok) return true;
    await new Promise(r => setTimeout(r, 100));
  }
  return false;
}
app.whenReady().then(async () => {
  const w = new BrowserWindow({ show: false });
  await w.loadURL(process.env.FAKE_URL);
  await waitResult(w);
  if (process.env.FAKE_TRIGGER) {
    fs.writeFileSync(process.env.FAKE_TRIGGER + '.ready', 'x');
    while (!fs.existsSync(process.env.FAKE_TRIGGER)) await new Promise(r => setTimeout(r, 200));
    await w.loadURL(process.env.FAKE_URL2);
    await waitResult(w);
  }
  await session.defaultSession.cookies.flushStore();
  session.defaultSession.flushStorageData();
  await new Promise(r => setTimeout(r, 500));
  app.quit();
});
"""


def electron_bin(h):
    for cand in (os.environ.get("LDP_ELECTRON"), os.path.join(h.tools, "electron-app/node_modules/electron/dist/electron")):
        if cand and os.path.isfile(cand):
            return cand
    d = os.path.join(h.tools, "electron-app")
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "package.json"), json.dumps({"name": "fakeapp", "version": "1.0.0", "main": "main.js"}))
    env = {"HOME": os.path.join(h.tools, "npm-home"), "PATH": NVM_BIN + ":/usr/bin:/bin"}
    subprocess.run(["npm", "install", "--no-audit", "--no-fund", "electron@33"], cwd=d, env=env, check=True, capture_output=True)
    # npm >= 12 blocks install scripts: fetch the binary explicitly.
    subprocess.run(["node", "node_modules/electron/install.js"], cwd=d, env=env, check=True, capture_output=True)
    return os.path.join(d, "node_modules/electron/dist/electron")


def synth_electron(cfg):
    for app in ("SynthApp",):
        a = os.path.join(cfg, app)
        write(os.path.join(a, "Cache/Cache_Data/index"), size=8192)
        write(os.path.join(a, "Cache/Cache_Data/data_1"), size=2 * MIB)
        write(os.path.join(a, "Code Cache/js/index"), size=4096)
        write(os.path.join(a, "Code Cache/js/abc_0"), size=MIB)
        write(os.path.join(a, "GPUCache/data_0"), size=MIB)
        write(os.path.join(a, "CachedData/1234/chrome/js/x.code"), size=MIB)
        write(os.path.join(a, "Local Storage/leveldb/000003.log"), size=MIB)
        write(os.path.join(a, "IndexedDB/https_x_0.indexeddb.leveldb/000003.log"), size=MIB)
        write(os.path.join(a, "Cookies"), size=64 * 1024)
        write(os.path.join(a, "Preferences"), '{"x":1}')
        write(os.path.join(a, "User/settings.json"), '{"editor.fontSize": 14}')
        write(os.path.join(a, "Service Worker/CacheStorage/x/data"), size=MIB)


def case_electron(h):
    c = Case(h, "electron")
    # --- synthetic Electron-style apps
    cfg = os.path.join(c.home, ".config")
    synth_electron(cfg)
    write(os.path.join(cfg, "SomeTool/Cache/important.db"), size=2 * MIB)  # no index: not a Chromium cache
    busy = os.path.join(cfg, "BusyApp")
    write(os.path.join(busy, "Cache/index"), size=4096)
    write(os.path.join(busy, "Cache/data_1"), size=2 * MIB)
    sleeper = h.spawn(["sleep", "3600"])
    host = open("/proc/sys/kernel/hostname").read().strip()
    os.symlink("%s-%d" % (host, sleeper.pid), os.path.join(busy, "SingletonLock"))

    # --- a real Electron app
    try:
        eb = electron_bin(h)
    except Exception as e:
        eb = None
        c.note("could not install electron: %s" % e)
    site = h.get_site()
    appdir = os.path.join(h.tools, "electron-app")
    if eb:
        write(os.path.join(appdir, "main.js"), ELECTRON_MAIN)
        base = ["xvfb-run", "-a", eb, "--no-sandbox", "--disable-gpu-sandbox", appdir]
        env = dict(c.env)
        env.pop("DISPLAY", None)
        log = open(os.path.join(c.tmp, "electron.log"), "w")
        for tag in ("e-set1", "e-set2"):
            p = h.spawn(base, env=dict(env, FAKE_URL=site.url("set", tag)), stdout=log, stderr=log)
            rep = site.wait(tag, 120)
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                stop(p)
            c.check("electron: populate run %s" % tag, rep and rep.get("set"), rep)
        c.note("real Electron userData: %s" % sorted(os.listdir(os.path.join(cfg, "FakeApp"))))

        # Running app WITHOUT requestSingleInstanceLock: is it detected?
        trig = os.path.join(c.tmp, "trigger")
        p = h.spawn(base, env=dict(env, FAKE_URL=site.url("set", "e-run"), FAKE_URL2=site.url("check", "e-run-check"), FAKE_TRIGGER=trig), stdout=log, stderr=log)
        wait_for(lambda: os.path.exists(trig + ".ready"), 120)
        f = c.tool()
        ef = f.get("electron-cache")
        running_listed = ef is not None and any(inside(x, os.path.join(cfg, "FakeApp")) for x in ef["paths"]) and not ef["command"].startswith("(")
        if running_listed:
            c.note("A running Electron app that does not take Chromium's SingletonLock (app.requestSingleInstanceLock not called) is not "
                   "detected: its caches are offered while it runs. Executing now to see if the running app survives.")
            pr = c.execute(ef)
            write(trig, "go")
            rep = site.wait("e-run-check", 120)
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                stop(p)
            c.check("electron: app whose cache was emptied WHILE RUNNING keeps working and keeps its data", rep and rep.get("ls") == "ls_val_123" and rep.get("fetch") == 2 * MIB, rep)
            c.note("cache emptied while running: rc=%d; app report=%s" % (pr.returncode, rep))
        else:
            write(trig, "go")
            site.wait("e-run-check", 120)
            stop(p, 60)
        # Running app WITH the singleton lock: must be skipped.
        trig2 = os.path.join(c.tmp, "trigger2")
        p = h.spawn(base, env=dict(env, FAKE_LOCK="1", FAKE_URL=site.url("set", "e-lock"), FAKE_URL2=site.url("check", "e-lock-check"), FAKE_TRIGGER=trig2), stdout=log, stderr=log)
        wait_for(lambda: os.path.exists(trig2 + ".ready"), 120)
        f = c.tool()
        ef = f.get("electron-cache")
        c.check("electron app holding SingletonLock is skipped", ef is None or not any(inside(x, os.path.join(cfg, "FakeApp")) for x in ef["paths"]) and "FakeApp" in ef["detail"],
                ef and (ef["paths"], ef["detail"][-120:]))
        write(trig2, "go")
        site.wait("e-lock-check", 120)
        try:
            p.wait(60)
        except subprocess.TimeoutExpired:
            stop(p)
    synth_electron(cfg)  # the live-delete above may have emptied it
    f = c.tool()
    ef = f.get("electron-cache")
    if ef:
        want = {os.path.join(cfg, "SynthApp", x) for x in ("Cache", "Code Cache", "GPUCache", "CachedData")}
        if eb:
            want |= {x for x in (os.path.join(cfg, "FakeApp", y) for y in ("Cache", "Code Cache", "GPUCache", "CachedData")) if os.path.isdir(x)}
        c.check("electron-cache: exactly the cache children of idle Chromium-cache apps", set(ef["paths"]) == want,
                "got=%s want=%s" % (sorted(os.path.relpath(x, cfg) for x in ef["paths"]), sorted(os.path.relpath(x, cfg) for x in want)))
        c.check("electron-cache: busy app named in detail", "BusyApp" in ef["detail"], ef["detail"][-100:])

    def verify():
        if eb:
            p = h.spawn(base, env=dict(env, FAKE_URL=site.url("check", "e-check")), stdout=log, stderr=log)
            rep = site.wait("e-check", 120)
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                stop(p)
            browser_state_ok(c, rep, "electron")
        for x in ("Local Storage/leveldb/000003.log", "IndexedDB/https_x_0.indexeddb.leveldb/000003.log", "Cookies", "Preferences", "User/settings.json"):
            c.check("electron synthetic: %s kept" % x, os.path.isfile(os.path.join(cfg, "SynthApp", x)))
        c.check("electron: non-Chromium 'Cache' folder untouched", os.path.isfile(os.path.join(cfg, "SomeTool/Cache/important.db")))
        c.check("electron: running app's cache untouched", os.path.isfile(os.path.join(busy, "Cache/data_1")))
    c.run_finding("electron-cache", f, risk="SAFE", verify=verify)
    stop(sleeper, 5, signal.SIGKILL)
    if eb:
        log.close()


# --------------------------------------------------------------------------- desktop / misc caches

def gio_env(c):
    e = dict(c.env, GIO_USE_VFS="local")
    e.pop("DBUS_SESSION_BUS_ADDRESS", None)
    return e


def case_desktop(h):
    c = Case(h, "desktop")
    H = c.home
    j = lambda *a: os.path.join(H, *a)
    # thumbnails
    for i in range(6):
        write(j(".cache/thumbnails/large", "%032x.png" % i), size=400 * 1024)
    write(j(".cache/thumbnails/fail/gnome-thumbnail-factory/x.png"), size=1024)
    # Trash, filled by gio itself (local VFS, fake HOME, no session bus).
    docs = j("Documents")
    write(os.path.join(docs, "old report.odt"), size=2 * MIB)
    write(os.path.join(docs, "keep-me.txt"), "precious")
    os.makedirs(os.path.join(docs, "olddir/sub"))
    write(os.path.join(docs, "olddir/sub/a.txt"), size=4096)
    write(os.path.join(docs, "olddir/ro.txt"), size=4096, mode=0o444)
    r = c.sh("gio trash %s %s" % (shlex.quote(os.path.join(docs, "old report.odt")), shlex.quote(os.path.join(docs, "olddir"))), env=gio_env(c), check=False)
    c.check("trash: gio trash into fake home works", r.returncode == 0 and os.path.isdir(j(".local/share/Trash/info")), r.stderr[-200:])
    # __pycache__
    proj = j("code/pyproj")
    write(os.path.join(proj, "pkg/__init__.py"), "")
    write(os.path.join(proj, "pkg/big.py"), "".join("V%d = %r\n" % (i, "x" * 40 + str(i)) for i in range(40000)) + "def f():\n    return 'works'\n")
    c.sh("python3 -c 'import pkg.big as b; print(b.f())'", cwd=proj)
    write(j(".local/lib/python3.10/site-packages/hiddenpkg/__pycache__/m.cpython-310.pyc"), size=2 * MIB)
    # synthetic tool caches
    write(j(".cache/tracker3/files/meta.db"), size=2 * MIB)
    write(j(".cache/mesa_shader_cache/index"), size=4096)
    write(j(".cache/mesa_shader_cache/0a/abcdef"), size=2 * MIB)
    write(j(".cache/mesa_shader_cache_db/part0/mesa_cache.db"), size=MIB)
    write(j(".cache/selenium/chromedriver/linux64/126.0/chromedriver"), size=2 * MIB)
    write(j(".cache/selenium/se-metadata.json"), "{}")
    write(j(".cache/ms-playwright/chromium-1117/chrome-linux/chrome"), size=2 * MIB)
    write(j(".cache/huggingface/hub/models--org--private-finetune/blobs/abc"), size=3 * MIB)
    write(j(".cache/huggingface/token"), "hf_secret")
    write(j(".cache/pypoetry/cache/repositories/pypi/x"), size=2 * MIB)
    write(j(".cache/pypoetry/virtualenvs/proj-abc-py3.10/pyvenv.cfg"), "home = /usr/bin")
    write(j(".cache/yarn/v6/npm-left-pad-1.3.0/package.json"), size=2 * MIB)
    write(j(".gradle/caches/modules-2/files-2.1/x.jar"), size=2 * MIB)
    write(j(".gradle/wrapper/dists/gradle-8.5-bin/x/gradle-8.5.zip"), size=MIB)
    write(j(".gradle/gradle.properties"), "org.gradle.jvmargs=-Xmx2g")
    write(j(".var/app/org.example.App/cache/fontconfig/x"), size=2 * MIB)
    write(j(".var/app/org.example.App/data/important.db"), size=MIB)
    write(j(".var/app/org.example.App/config/settings.ini"), "a=1")
    # conda package cache hard-linked into an environment, no bin/conda
    lib = write(j("miniconda3/pkgs/libfoo-1.0-0/lib/libfoo.so"), size=3 * MIB)
    write(j("miniconda3/pkgs/unused-2.0-0/lib/libunused.so"), size=2 * MIB)
    os.makedirs(j("miniconda3/envs/e1/lib"))
    os.link(lib, j("miniconda3/envs/e1/lib/libfoo.so"))
    env_sum = sha256(j("miniconda3/envs/e1/lib/libfoo.so"))

    m0 = c.manifest()
    f = c.tool()
    d = diff_manifest(m0, c.manifest(), c.root, [])
    fp = [x for x in d if "flatpak" in x]
    c.check("analysis itself changes nothing in the home (besides flatpak's own dirs)", not [x for x in d if x not in fp], d[:8])
    if fp:
        c.note("analysis side effect: `flatpak list` (run by the flatpak rule) creates ~/.local/share/flatpak and ~/.cache/flatpak "
               "in a home that has none (%d entries)" % len(fp))
    c.check("tracker3: MODERATE with `tracker3 reset -s` (executed only in docker case)",
            f.get("tracker3", {}).get("risk") == "MODERATE" and f.get("tracker3", {}).get("command") in ("tracker3 reset -s",) or
            f.get("tracker3", {}).get("command", "").startswith("("), f.get("tracker3"))
    hf = f.get("huggingface-hub")
    c.check("huggingface-hub: CAUTION and Manual only", hf and hf["risk"] == "CAUTION" and hf["command"].startswith("("), hf and (hf["risk"], hf["command"]))
    try:
        c.guard(hf)
        c.check("huggingface-hub: harness refuses to execute", False)
    except NotExecutable:
        c.check("huggingface-hub: not executable", True)
    py = f.get("pycache")
    c.check("pycache: hidden dirs (~/.local) not included", py and not any("/.local/" in x for x in py["paths"]), py and py["paths"])

    c.run_finding("thumbnails", f, risk="SAFE")

    def v_trash():
        r = c.sh("gio trash %s" % shlex.quote(os.path.join(docs, "keep-me.txt")), env=gio_env(c), check=False)
        c.check("trash: trashing works after emptying", r.returncode == 0 and os.listdir(j(".local/share/Trash/files")) == ["keep-me.txt"], r.stderr[-200:])
    f_tr, p_tr = c.run_finding("trash", f, risk="MODERATE", verify=v_trash, bytes_tolerance=64 * 1024 * 1024)
    if p_tr is not None and p_tr.returncode != 0:
        c.note("trash with a read-only item fails part-way: %s" % p_tr.stderr.strip()[:200])

    def v_py():
        r = c.sh("python3 -c 'import pkg.big as b; print(b.f())'", cwd=proj, check=False)
        c.check("pycache: module still imports and bytecode regenerates", "works" in r.stdout and os.path.isdir(os.path.join(proj, "pkg/__pycache__")), r.stderr[-200:])
    c.run_finding("pycache", f, risk="SAFE", verify=v_py, expect_keep_dirs=False)
    for fid, risk in (("mesa-shader-cache", "SAFE"), ("selenium-cache", "SAFE"), ("playwright-cache", "SAFE"), ("poetry-cache", "SAFE"),
                      ("yarn-cache", "SAFE"), ("gradle-cache", "MODERATE"), ("flatpak-app-cache", "SAFE")):
        c.run_finding(fid, f, risk=risk)
    c.check("poetry virtualenvs untouched", os.path.isfile(j(".cache/pypoetry/virtualenvs/proj-abc-py3.10/pyvenv.cfg")))
    c.check("flatpak app data/config untouched", os.path.isfile(j(".var/app/org.example.App/data/important.db")))
    c.check("gradle.properties untouched", os.path.isfile(j(".gradle/gradle.properties")))

    def v_conda():
        c.check("conda: environment file (hard link) intact", sha256(j("miniconda3/envs/e1/lib/libfoo.so")) == env_sum)
    fc = f.get("conda-pkgs:miniconda3")
    if fc:
        c.check("conda-pkgs: bytes count only unlinked packages", fc["bytes"] < 3 * MIB, human(fc["bytes"]))
    # Without bin/conda the cache is only a manual step (environments may soft-link
    # into pkgs, so only `conda clean` itself may remove it).
    if fc:
        c.check("conda-pkgs without conda: manual step only", fc["command"].startswith("(no automatic"), fc["command"])
    v_conda()
    c.check("huggingface token/models untouched", os.path.isfile(j(".cache/huggingface/token")) and tree_files(j(".cache/huggingface/hub")) == 1)


def case_editors(h):
    c = Case(h, "editors")
    j = lambda *a: os.path.join(c.home, *a)
    precious = write(os.path.join(c.outside, "precious/data.txt"), "precious")
    write(os.path.join(c.outside, "x/keep.txt"), "x")
    for base in (".vscode/extensions", ".cursor/extensions", ".vscode-server/extensions"):
        root = j(base)
        write(os.path.join(root, "pub.old-1.0.0/dist/ext.js"), size=MIB)
        write(os.path.join(root, "pub.new-2.0.0/dist/ext.js"), size=MIB)
        write(os.path.join(root, "pub.cur-3.0.0/dist/ext.js"), size=MIB)
        write(os.path.join(root, "extensions.json"), '[{"identifier":{"id":"pub.new"},"version":"2.0.0"}]')
        os.symlink(os.path.join(c.outside, "precious"), os.path.join(root, "pub.link-1.0.0"))
        rel_outside = os.path.relpath(os.path.join(c.outside, "x"), root)
        write(os.path.join(root, ".obsolete"), json.dumps({
            "pub.old-1.0.0": True, "pub.new-2.0.0": False, "pub.link-1.0.0": True, rel_outside: True,
            "../../outside/x": True, "/etc": True, "..": True, ".": True, "": True, "a/b": True, "missing-9.9.9": True,
            os.path.join(c.outside, "x"): True, "pub.cur-3.0.0 ": True}))
    # JetBrains: caches per version; settings in ~/.config, plugins in ~/.local/share.
    for v in ("PyCharmCE2023.1", "PyCharmCE2024.9", "PyCharmCE2024.10", "GoLand2024.1", "IntelliJIdea2023.3", "IntelliJIdea2024.3", "IdeaIC2022.1"):
        write(j(".cache/JetBrains", v, "caches/content.dat"), size=MIB)
        write(j(".config/JetBrains", v, "options/ide.general.xml"), "<x/>")
        write(j(".local/share/JetBrains", v, "plugin/x.jar"), size=64 * 1024)
    write(j(".cache/JetBrains/Toolbox/cache/x"), size=2 * MIB)
    write(j(".cache/JetBrains/PyCharmCE2024.1.backup/x"), size=MIB)
    f = c.tool()
    ob = f.get("obsolete-extensions")
    want = sorted(j(b, "pub.old-1.0.0") for b in (".vscode/extensions", ".cursor/extensions", ".vscode-server/extensions"))
    c.check("obsolete-extensions: exactly the listed plain dirs (no symlink, traversal, absolute, current)",
            ob and sorted(ob["paths"]) == want, ob and [os.path.relpath(x, c.home) for x in ob["paths"]])
    c.run_finding("obsolete-extensions", f, risk="SAFE", expect_keep_dirs=False)
    c.check("obsolete: symlink target and outside dirs intact", open(precious).read() == "precious" and os.path.isfile(os.path.join(c.outside, "x/keep.txt")))
    c.check("obsolete: current versions + extensions.json intact", all(os.path.isdir(j(b, "pub.new-2.0.0")) and os.path.isdir(j(b, "pub.cur-3.0.0"))
                                                                     and os.path.isfile(j(b, "extensions.json")) for b in (".vscode/extensions",)))
    jb = f.get("jetbrains-old-caches")
    want = sorted(j(".cache/JetBrains", v) for v in ("PyCharmCE2023.1", "PyCharmCE2024.9", "IntelliJIdea2023.3"))
    c.check("jetbrains: only superseded versions (newest per product kept, 2024.10 > 2024.9)", jb and sorted(jb["paths"]) == want,
            jb and [os.path.basename(x) for x in jb["paths"]])
    c.run_finding("jetbrains-old-caches", f, risk="SAFE", expect_keep_dirs=False)
    c.check("jetbrains: settings and plugins of all versions kept", all(os.path.isfile(j(".config/JetBrains", v, "options/ide.general.xml"))
                                                                         for v in ("PyCharmCE2023.1", "PyCharmCE2024.9")))


HOSTILE_NAMES = ["sp ace", "new\nline", "q'uote", 'dq"uote', "-rf", "$(touch PWNED)", "`touch PWNED2`", "star*", "semi;touch PWNED3", "tab\there", "back\\slash"]


def pwned(root):
    return [os.path.join(dp, n) for dp, dns, fns in os.walk(root) for n in fns + dns if n.startswith("PWNED")]


def case_traps(h):
    c = Case(h, "traps")
    j = lambda *a: os.path.join(c.home, *a)
    O = c.outside
    precious_dir = os.path.join(O, "precious_dir")
    write(os.path.join(precious_dir, "a.txt"), "A")
    write(os.path.join(precious_dir, "sub/b.txt"), "B")
    precious_file = write(os.path.join(O, "precious.txt"), "P")
    hl = write(os.path.join(O, "hardlinked.txt"), "H")
    sums = {p: sha256(p) for p in (os.path.join(precious_dir, "a.txt"), os.path.join(precious_dir, "sub/b.txt"), precious_file, hl)}
    # 1. pip cache: symlinks and hard links to precious data, hostile names, read-only subtree
    write(j(".cache/pip/http/big"), size=2 * MIB)
    os.symlink(precious_dir, j(".cache/pip/evil_dirlink"))
    os.symlink(precious_file, j(".cache/pip/http/evil_filelink"))
    os.symlink("../../../outside/precious_dir", j(".cache/pip/rel_link"))
    os.link(hl, j(".cache/pip/hardlink"))
    for n in HOSTILE_NAMES:
        write(j(".cache/pip/hostile", n, "f"), size=1024)
    # 2. a cache that is itself a symlink elsewhere (thumbnails -> outside)
    write(os.path.join(O, "thumbs_real/large/x.png"), size=2 * MIB)
    os.makedirs(j(".cache"), exist_ok=True)
    os.symlink(os.path.join(O, "thumbs_real"), j(".cache/thumbnails"))
    # 3. chrome profile with a hostile name
    for n in ("Profile $(touch PWNED)", "Profile 'q\"\nx"):
        write(j(".cache/google-chrome", n, "Cache/Cache_Data/data_1"), size=MIB)
        write(j(".cache/google-chrome", n, "Other/keep"), "keep")
    os.makedirs(j(".config/google-chrome"), exist_ok=True)
    # 4. projects with hostile names
    for n in ("-rf evil $(touch PWNED) `id` 'q\"", "evil", "sp ace\nnl"):
        d = j("code", n)
        write(os.path.join(d, "package.json"), '{"name":"x"}')
        write(os.path.join(d, "node_modules/dep/index.js"), size=2 * MIB)
        write(os.path.join(d, "src/main.js"), "keep")
    # 5. symlinked node_modules / __pycache__ / target pointing outside
    write(j("code/linked/package.json"), "{}")
    os.symlink(precious_dir, j("code/linked/node_modules"))
    write(j("code/linkedpy/m.py"), "")
    os.symlink(precious_dir, j("code/linkedpy/__pycache__"))
    write(j("code/rs/Cargo.toml"), '[package]\nname="rs"\n')
    write(j("code/rs/target/debug/app"), size=2 * MIB)
    os.symlink(precious_dir, j("code/rs/target/escape"))
    os.symlink(precious_file, j("code/rs/target/escape_file"))
    # 6. Electron app whose Cache is a symlink to a precious dir that has an `index`
    write(os.path.join(O, "fake_cache/index"), "idx")
    write(os.path.join(O, "fake_cache/precious.db"), size=2 * MIB)
    write(j(".config/LinkApp/Preferences"), "{}")
    os.symlink(os.path.join(O, "fake_cache"), j(".config/LinkApp/Cache"))
    synth_electron(j(".config"))
    # 7. a non-UTF-8 project directory
    nd = os.path.join(c.home.encode(), b"code", b"bad\xff name")
    os.makedirs(nd + b"/node_modules/dep")
    with open(nd + b"/package.json", "wb") as fh:
        fh.write(b"{}")
    with open(nd + b"/package-lock.json", "wb") as fh:  # a restorable project
        fh.write(b"{}")
    with open(nd + b"/node_modules/dep/big", "wb") as fh:
        fh.write(os.urandom(2 * MIB))

    f = c.tool()
    ids = sorted(f)
    c.check("symlinked node_modules / __pycache__ are not proposed", not any("linked" in i for i in ids) and
            not any("linkedpy" in x for x in f.get("pycache", {}).get("paths", [])), ids)
    raw = subprocess.run([h.bin, "--json", "--rules-only", "--home", c.home, "--dev-root", c.home], env=c.env, capture_output=True, text=True).stdout
    bad = [x for x in json.loads(raw)["findings"] if "bad" in x["id"]]
    c.check("non-UTF-8 project: no shell command offered", bad and bad[0]["command"].startswith("("), bad and bad[0]["command"])
    ef = f.get("electron-cache")
    if ef and j(".config/LinkApp/Cache") in ef["paths"]:
        c.note("electron-cache lists a Cache *symlink* (~/.config/LinkApp/Cache -> elsewhere): the shell command (find -P) leaves it alone, "
               "the in-app removal unlinks the symlink (see tui case); the target is never emptied.")
    th = f.get("thumbnails")
    if th:
        c.note("thumbnails reported although ~/.cache/thumbnails is a symlink (size of the target: %s)" % human(th["bytes"]))

    for fid in ["pip-cache", "chrome-cache", "thumbnails", "electron-cache"] + [i for i in ids if i.startswith(("node:", "rust:"))]:
        if fid not in f or f[fid]["command"].startswith("("):
            continue
        before_pw = pwned(c.root)
        c.run_finding(fid, f, bytes_tolerance=64 * MIB)
        c.check("%s: no injected command ran" % fid, pwned(c.root) == before_pw, pwned(c.root))
    for p, s in sums.items():
        c.check("precious %s intact" % os.path.relpath(p, c.root), os.path.isfile(p) and sha256(p) == s)
    c.check("electron: precious data behind Cache symlink intact", os.path.isfile(os.path.join(O, "fake_cache/precious.db")))
    c.check("electron: the Cache symlink itself kept by the shell command (find -P)", os.path.islink(j(".config/LinkApp/Cache")))
    c.check("sibling project 'evil' sources intact", os.path.isfile(j("code/evil/src/main.js")))
    c.check("chrome non-cache profile dirs intact", all(os.path.isfile(j(".cache/google-chrome", n, "Other/keep")) for n in ("Profile $(touch PWNED)", "Profile 'q\"\nx")))
    thr = os.path.join(O, "thumbs_real/large/x.png")
    c.note("symlinked ~/.cache/thumbnails after the shell command: link %s, target file %s" %
           ("kept" if os.path.islink(j(".cache/thumbnails")) else "GONE", "kept" if os.path.isfile(thr) else "deleted"))
    # read-only subtree in a cache
    write(j(".cache/pip/http/ro/sub/x"), size=2 * MIB)
    os.chmod(j(".cache/pip/http/ro/sub"), 0o555)
    os.chmod(j(".cache/pip/http/ro"), 0o555)
    f = c.tool()
    before = c.manifest()
    pr = c.execute(f["pip-cache"])
    diffs = diff_manifest(before, c.manifest(), c.root, [j(".cache/pip")])
    c.check("read-only subtree in cache: nothing outside changed", not diffs, diffs[:5])
    c.note("read-only dir in a cache: rc=%d, left behind %d file(s): %s" % (pr.returncode, tree_files(j(".cache/pip")), pr.stderr.strip().splitlines()[-1][-120:] if pr.stderr.strip() else ""))
    make_writable(j(".cache/pip"))


BINDMOUNT_INNER = r"""
import json, os, subprocess, sys
sys.path.insert(0, %(here)r)
import run_user_safety as r
root, home, binp = %(root)r, %(home)r, %(bin)r
out = {}
subprocess.run(["mount", "--bind", os.path.join(root, "outside/precious"), os.path.join(home, ".cache/pip/mnt")], check=True)
subprocess.run(["mount", "--bind", os.path.join(root, "outside/precious2"), os.path.join(home, "code/web/node_modules/mnt")], check=True)
env = {"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
data = json.loads(subprocess.run([binp, "--json", "--rules-only", "--home", home, "--dev-root", home], env=env, capture_output=True, text=True, cwd=root).stdout)
fs = {f["id"]: f for f in data["findings"] if f["paths"] and all(r.inside(p, home) for p in f["paths"])}
class C: pass
c = r.Case.__new__(r.Case); c.root = root; c.home = home; c.env = env
for fid in ("pip-cache", "node:" + os.path.join(home, "code/web/node_modules")):
    f = fs.get(fid)
    if not f:
        out[fid] = "missing"
        continue
    c.guard(f)
    p = subprocess.run(["/bin/sh", "-c", f["command"]], env=env, capture_output=True, text=True, cwd=root)
    out[fid] = {"bytes": f["bytes"], "command": f["command"], "rc": p.returncode, "stderr": p.stderr[-300:]}
out["precious"] = sorted(os.listdir(os.path.join(root, "outside/precious")))
out["precious2"] = sorted(os.listdir(os.path.join(root, "outside/precious2")))
print("@@JSON" + json.dumps(out))
"""


def case_bindmount(h):
    c = Case(h, "bindmount")
    j = lambda *a: os.path.join(c.home, *a)
    for d in ("precious", "precious2"):
        write(os.path.join(c.outside, d, "data.txt"), size=2 * MIB)
        write(os.path.join(c.outside, d, "notes.txt"), "keep")
    write(j(".cache/pip/http/x"), size=2 * MIB)
    os.makedirs(j(".cache/pip/mnt"))
    write(j("code/web/package.json"), "{}")
    write(j("code/web/node_modules/dep/index.js"), size=2 * MIB)
    os.makedirs(j("code/web/node_modules/mnt"))
    code = BINDMOUNT_INNER % {"here": HERE, "root": c.root, "home": c.home, "bin": h.bin}
    p = subprocess.run(["unshare", "-r", "-m", "python3", "-c", code], capture_output=True, text=True, timeout=300, cwd=c.root)
    m = re.search(r"@@JSON(.*)", p.stdout)
    if not c.check("bindmount: namespace run", m, p.stderr[-800:]):
        return
    out = json.loads(m.group(1))
    c.note("bind mount results: %s" % json.dumps(out)[:600])
    for key, fid in (("precious", "pip-cache"), ("precious2", "node:" + j("code/web/node_modules"))):
        ok = "data.txt" in out[key]
        c.check("%s: data bind-mounted inside the cache survives the shell command" % fid, ok, out[key])
        if not ok:
            cmd = out.get(fid, {}).get("command", "")
            c.bug("Shell command of %s crosses into a filesystem mounted inside the cache and deletes its contents" % fid.split(":")[0],
                  "unshare -r -m; mount --bind ~/precious %s; run tool; run the finding's command `%s` -> ~/precious emptied. "
                  "The in-app removal refuses (mountinfo check) but the command shown as the 'exact shell equivalent' does not."
                  % ("~/.cache/pip/mnt" if key == "precious" else "~/code/web/node_modules/mnt", short(cmd.replace(c.home, "~"), 90)),
                  "medium", "src/rules/mod.rs Finding::command_text: emit `find P -xdev -mindepth 1 -delete` and `rm -rf --one-file-system --`")


def case_many_files(h):
    c = Case(h, "many_files")
    base = os.path.join(c.home, ".cache/thumbnails/normal")
    os.makedirs(base)
    n = 50000
    for i in range(n):
        with open(os.path.join(base, "%08d.png" % i), "wb") as fh:
            fh.write(b"x")
    # A path longer than PATH_MAX inside the cache.
    deep = os.path.join(c.home, ".cache/thumbnails")
    fd = os.open(deep, os.O_RDONLY)
    for i in range(220):
        os.mkdir("d" * 20, dir_fd=fd)
        nfd = os.open("d" * 20, os.O_RDONLY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    wfd = os.open("deepfile", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd)
    os.write(wfd, b"deep")
    os.close(wfd)
    os.close(fd)
    t = time.time()
    f = c.tool()
    c.note("tool scan with %d files + 4.6 KB-deep path: %.1fs" % (n, time.time() - t))
    t = time.time()
    c.run_finding("thumbnails", f, risk="SAFE")
    c.note("find -delete of %d files: %.1fs" % (n, time.time() - t))


# --------------------------------------------------------------------------- TUI (in-process removal paths)

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>]|\x1b\][^\x07]*\x07")


class Tui:
    def __init__(self, argv, env, rows=60, cols=220, log=None):
        import fcntl
        import struct
        import termios
        self.buf = b""
        self.log = log
        pid, fd = pty.fork()
        if pid == 0:
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                os.execvpe(argv[0], argv, env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd

    def pump(self, t=0.2):
        end = time.time() + t
        while True:
            left = end - time.time()
            if left <= 0:
                break
            r, _, _ = select.select([self.fd], [], [], left)
            if not r:
                continue
            try:
                d = os.read(self.fd, 65536)
            except OSError:
                break
            if not d:
                break
            if b"\x1b[6n" in d:  # cursor position query (crossterm): answer it
                os.write(self.fd, b"\x1b[1;1R")
            self.buf += d
            if self.log:
                self.log.write(d)

    def text(self):
        return ANSI.sub(b" ", self.buf).decode("utf-8", "replace")

    def expect(self, pat, timeout=60):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.3)
            if re.search(pat, self.text()):
                return True
        return False

    def send(self, keys, pause=0.25):
        for k in keys:
            os.write(self.fd, k if isinstance(k, bytes) else k.encode())
            self.pump(pause)

    def mark(self):
        self.buf = b""

    def close(self):
        try:
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass
        for _ in range(50):
            try:
                if os.waitpid(self.pid, os.WNOHANG)[0]:
                    break
            except ChildProcessError:
                break
            time.sleep(0.1)
        else:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except OSError:
                pass
        try:
            os.close(self.fd)
        except OSError:
            pass


def shim_dir(c):
    """PATH entries that neutralise anything able to touch the real system."""
    d = os.path.join(c.root, "_shims")
    os.makedirs(d, exist_ok=True)
    for n in ("sudo", "pkexec", "docker", "snap", "apt-get", "apt", "journalctl", "flatpak", "tracker3", "dpkg"):
        write(os.path.join(d, n), "#!/bin/sh\necho \"SHIM-BLOCKED %s $*\" >> %s\nexit 1\n" % (n, shlex.quote(os.path.join(c.tmp, "shim.log"))), mode=0o755)
    return d


def tui_run(c, h, targets, marks=(), mode="p", wrap=(), label="tui"):
    """Select `targets` (finding ids) in the Prune tab and `marks` (top-level
    dirs in home) in the tree, review, confirm with `mode`, return output."""
    env = dict(c.env, TERM="xterm-256color", PATH=shim_dir(c) + ":" + c.env["PATH"])
    raw = subprocess.run(list(wrap) + [h.bin, "--json", "--rules-only", "--home", c.home, "--dev-root", c.home], env=env,
                         capture_output=True, text=True, cwd=c.root).stdout
    order = [f["id"] for f in json.loads(raw)["findings"]]
    titles = {f["id"]: f["title"] for f in json.loads(raw)["findings"]}
    logf = open(os.path.join(c.tmp, label + ".pty.log"), "wb")
    t = Tui(list(wrap) + [h.bin, "--tui", "--home", c.home, "--dev-root", c.home, c.home], env, log=logf)
    out = {"ok": False}
    try:
        if not t.expect(r"Prune|PRUNE|prune", 60):
            out["err"] = "TUI did not start"
            return out
        time.sleep(3)
        t.pump(1)
        t.send(["3"])
        t.pump(2)
        for fid in targets:
            idx = order.index(fid)
            t.send(["g"] + ["j"] * idx + [" "], pause=0.08)
        for m in marks:
            t.send(["2", "g"])
            # rows under the root are sorted by size: walk down until the flash names our dir
            found = False
            for _ in range(12):
                t.mark()
                t.send(["j", "x"], pause=0.4)
                if re.search(r"Marked %s " % re.escape(m), t.text()):
                    found = True
                    break
                if re.search(r"Unmarked|Marked ", t.text()):
                    t.send(["x"], pause=0.4)  # undo a wrong mark
            if not found:
                out["err"] = "could not mark %s" % m
                return out
        t.mark()
        t.send(["c"], pause=1.0)
        scr = t.text()
        n_ok = re.search(r"RECOMMENDED CLEANUPS \(%d\)" % len(targets), scr) if targets else "RECOMMENDED CLEANUPS" not in scr
        m_ok = re.search(r"MARKED IN THE TREEMAP \(%d\)" % len(marks), scr) if marks else "MARKED IN THE TREEMAP" not in scr
        titles_ok = all(titles[x][:40] in re.sub(r"\s+", " ", scr) for x in targets)
        if not (n_ok and m_ok and titles_ok):
            t.send([b"\x1b"])
            out["err"] = "review screen does not show exactly the intended selection (n=%s m=%s titles=%s)" % (bool(n_ok), bool(m_ok), titles_ok)
            out["screen"] = scr[-1500:]
            return out
        t.mark()
        shim_log = os.path.join(c.tmp, "shim.log")
        if os.path.exists(shim_log):
            os.unlink(shim_log)  # analysis-time probes (snap list, apt-get -s, ...) are fine
        t.send([mode], pause=1.0)
        t.expect(r"Press Enter to return", 120)
        out["output"] = t.text()
        t.send([b"\r"], pause=1.0)
        t.pump(2)
        t.send(["q"], pause=0.5)
        out["ok"] = True
        return out
    finally:
        t.close()
        logf.close()
        out["shim_log"] = open(os.path.join(c.tmp, "shim.log")).read() if os.path.exists(os.path.join(c.tmp, "shim.log")) else ""


def case_tui(h):
    c = Case(h, "tui")
    j = lambda *a: os.path.join(c.home, *a)
    O = c.outside
    pd = os.path.join(O, "precious_dir")
    write(os.path.join(pd, "a.txt"), "A")
    write(j(".cache/pip/http/big"), size=2 * MIB)
    os.symlink(pd, j(".cache/pip/evil_dirlink"))
    for n in HOSTILE_NAMES:
        write(j(".cache/pip/hostile", n, "f"), size=1024)
    write(os.path.join(O, "thumbs_real/large/x.png"), size=2 * MIB)
    os.makedirs(j(".cache"), exist_ok=True)
    os.symlink(os.path.join(O, "thumbs_real"), j(".cache/thumbnails"))
    # Electron: one real idle app plus one whose Cache is a symlink to precious data.
    synth_electron(j(".config"))
    write(os.path.join(O, "fake_cache/index"), "idx")
    write(os.path.join(O, "fake_cache/precious.db"), size=MIB)
    write(j(".config/LinkApp/Preferences"), "{}")
    os.symlink(os.path.join(O, "fake_cache"), j(".config/LinkApp/Cache"))
    write(j("BIGDIR/blob.bin"), size=24 * MIB)
    os.symlink(pd, j("BIGDIR/link_to_precious"))
    write(j("TRASHME/blob.bin"), size=12 * MIB)
    write(j("Documents/keep.txt"), "keep")
    shim_dir(c)
    fj = c.tool()
    before = c.manifest()
    c.check("tui: symlinked ~/.cache/thumbnails is not reported (du does not follow it)", "thumbnails" not in fj, sorted(fj))
    c.check("tui: electron-cache leaves the LinkApp/Cache symlink out", j(".config/LinkApp/Cache") not in fj.get("electron-cache", {}).get("paths", []),
            fj.get("electron-cache", {}).get("paths"))
    res = tui_run(c, h, ["pip-cache", "electron-cache"], marks=["BIGDIR"], mode="p")
    c.check("tui: run 1 driven (findings + permanent mark)", res["ok"], res.get("err", "") + res.get("screen", "")[-600:])
    probes = ("snap list", "snap debug", "flatpak --installations", "flatpak list", "apt-get -s")
    bad = [l for l in res.get("shim_log", "").splitlines() if not any(l.startswith("SHIM-BLOCKED " + x) for x in probes)]
    c.check("tui: no root/system command was attempted", not bad, bad)
    after = c.manifest()
    allowed = [j(".cache/pip"), j("BIGDIR")] + fj.get("electron-cache", {}).get("paths", [])
    diffs = diff_manifest(before, after, c.root, allowed)
    c.check("tui: nothing outside the selected paths changed", not diffs, diffs[:10])
    c.check("tui: precious data behind symlinks intact", os.path.isfile(os.path.join(pd, "a.txt")) and os.path.isfile(os.path.join(O, "thumbs_real/large/x.png")))
    c.check("tui: pip's own cache folder emptied in-process, folder kept", os.path.isdir(j(".cache/pip/http")) and not os.listdir(j(".cache/pip/http")), os.listdir(j(".cache/pip/http")) if os.path.isdir(j(".cache/pip/http")) else "gone")
    c.check("tui: marked BIGDIR deleted permanently", not os.path.exists(j("BIGDIR")))
    link = j(".config/LinkApp/Cache")
    link_gone = not os.path.lexists(link)
    c.check("tui: precious data behind an Electron Cache symlink intact", os.path.isfile(os.path.join(O, "fake_cache/precious.db")))
    c.check("tui: SynthApp caches emptied, dirs kept", os.path.isdir(j(".config/SynthApp/Cache")) and not os.listdir(j(".config/SynthApp/Cache")))
    c.note("tui keep_dir removal of a symlinked cache dir (~/.config/LinkApp/Cache -> elsewhere): symlink %s; target %s"
           % ("REMOVED" if link_gone else "kept", "kept" if os.path.isfile(os.path.join(O, "fake_cache/precious.db")) else "deleted"))
    if link_gone:
        c.bug("In-app keep_dir removal unlinks a cache directory that is a symlink (keep_dir not honoured)",
              "~/.config/LinkApp/Cache -> /elsewhere/cache (with an `index`), plus any other idle Electron app so the finding exists; "
              "run 'Electron app caches' in the TUI/GUI -> the symlink ~/.config/LinkApp/Cache is deleted (target untouched). "
              "The shell command (find -P) leaves it alone, so app and shell disagree. Same for chrome/firefox/cargo/pip paths "
              "that are symlinks.",
              "low", "src/cleanup.rs remove_path: with keep_dir and a symlink, do nothing (or refuse); src/rules/ubuntu.rs cache_dir_finding / "
              "extra.rs contents_finding: skip (or resolve) cache dirs that are symlinks instead of is_dir() which follows them")
    # Trash mode for a mark.
    res = tui_run(c, h, [], marks=["TRASHME"], mode="t", label="tui2")
    if res.get("err", "").startswith("review") or res["ok"]:
        trashed = os.path.isdir(j(".local/share/Trash/files/TRASHME"))
        c.check("tui: marked dir moved to the (fake home) Trash with gio", res["ok"] and trashed and not os.path.exists(j("TRASHME")),
                res.get("err", "") + (res.get("output", "")[-300:]))
    else:
        c.check("tui: run 2 driven (trash mark)", False, res.get("err"))
    # In-process removal with a bind mount inside the cache (namespace).
    write(os.path.join(O, "precious3/data.txt"), size=2 * MIB)
    write(j(".cache/pip/http/big2"), size=2 * MIB)
    os.makedirs(j(".cache/pip/mnt"))
    helper = os.path.join(c.root, "_ns.sh")
    write(helper, "#!/bin/sh\nmount --bind %s %s || exit 99\nexec \"$@\"\n" % (shlex.quote(os.path.join(O, "precious3")), shlex.quote(j(".cache/pip/mnt"))), mode=0o755)
    res = tui_run(c, h, ["pip-cache"], wrap=["unshare", "-r", "-m", helper], label="tui3")
    c.check("tui (bind mount in cache): run driven", res["ok"], res.get("err"))
    c.check("tui (bind mount in cache): in-process removal refuses, mounted data intact", os.path.isfile(os.path.join(O, "precious3/data.txt")),
            re.sub(r"\s+", " ", res.get("output", ""))[-300:])


# --------------------------------------------------------------------------- tracker3 (docker only)

TRACKER_SCRIPT = r"""
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq tracker tracker-miner-fs dbus python3 >/dev/null 2>&1
useradd -m u
cat > /home/u/run.sh <<'EOS'
set -x
export HOME=/home/u
mkdir -p ~/Documents
for i in $(seq 1 300); do echo "hello document $i searchable-word-$i" > ~/Documents/doc$i.txt; done
dbus-run-session -- sh -c '/usr/libexec/tracker-miner-fs-3 >/dev/null 2>&1 & sleep 25; echo "@@SEARCH0 $(tracker3 search searchable-word-7 | grep -c doc7)"; kill $! 2>/dev/null; wait; true'
sleep 3
du -sh ~/.cache/tracker3 || true
find ~/.cache/tracker3 -type f -exec ls -ls {} \;
[ "$(du -sk ~/.cache/tracker3 | cut -f1)" -lt 1100 ] && head -c 2000000 /dev/urandom > ~/.cache/tracker3/files/padding.bin
find ~/.cache/tracker3 | head
/ldp --json --rules-only --home /home/u --dev-root /home/u > /tmp/f.json
python3 - <<'EOP'
import json
fs = {f["id"]: f for f in json.load(open("/tmp/f.json"))["findings"]}
f = fs.get("tracker3")
print("@@FINDING " + json.dumps(f))
open("/tmp/cmd", "w").write(f["command"] if f else "")
EOP
echo "@@BEFORE $(find ~/.cache/tracker3 -type f | wc -l) files $(du -sk ~/.cache/tracker3 | cut -f1) KiB"
# GUI semantics: stdin is /dev/null.
dbus-run-session -- sh -c 'sh -c "$(cat /tmp/cmd)" < /dev/null; echo "@@RC $?"'
echo "@@AFTER $(find ~/.cache/tracker3 -type f 2>/dev/null | wc -l) files $(du -sk ~/.cache/tracker3 2>/dev/null | cut -f1) KiB"
find ~/.cache/tracker3 2>/dev/null | head
echo "@@DOCS $(ls ~/Documents | wc -l)"
dbus-run-session -- sh -c '/usr/libexec/tracker-miner-fs-3 >/dev/null 2>&1 & sleep 25; echo "@@SEARCH $(tracker3 search searchable-word-7 | grep -c doc7)"; echo "@@REINDEX $(find ~/.cache/tracker3 -type f | wc -l)"; kill $! 2>/dev/null; wait; true'
EOS
chown u:u /home/u/run.sh
su u -c 'sh /home/u/run.sh' 2>&1
"""


def case_tracker3_docker(h):
    c = Case(h, "tracker3_docker")
    if not which_real("docker"):
        c.note("docker missing")
        c.res["status"] = "SKIP"
        return
    p = subprocess.run(["docker", "run", "--rm", "-v", "%s:/ldp:ro" % h.bin, "ubuntu:22.04", "bash", "-c", TRACKER_SCRIPT],
                       capture_output=True, text=True, timeout=1200)
    out = p.stdout + p.stderr
    os.makedirs(os.path.join(h.work, "logs"), exist_ok=True)
    write(os.path.join(h.work, "logs", "tracker3_docker.log"), out)
    s0 = re.search(r"@@SEARCH0 (\d+)", out)
    c.note("tracker3 search before reset: %s" % (s0 and s0.group(1)))
    m = re.search(r"@@FINDING (.*)", out)
    f = json.loads(m.group(1)) if m and m.group(1) != "null" else None
    c.check("tracker3: finding present (MODERATE, `tracker3 reset -s`)", f and f["risk"] == "MODERATE" and f["command"] == "tracker3 reset -s", f and (f["risk"], f["command"]))
    rc = re.search(r"@@RC (\d+)", out)
    b = re.search(r"@@BEFORE (\d+) files (\d+) KiB", out)
    a = re.search(r"@@AFTER (\d+) files (\d*) ?KiB", out)
    c.check("tracker3: command exit 0 with stdin=/dev/null (GUI)", rc and rc.group(1) == "0", rc and rc.group(1))
    c.note("tracker3 before: %s; after: %s; reported %s" % (b and b.group(0), a and a.group(0), f and human(f["bytes"])))
    c.check("tracker3: documents untouched", "@@DOCS 300" in out)
    s = re.search(r"@@SEARCH (\d+)", out)
    ri = re.search(r"@@REINDEX (\d+)", out)
    c.check("tracker3: miner rebuilds its index after the reset", ri and int(ri.group(1)) > 0, ri and ri.group(0))
    if s0 and s and int(s0.group(1)) > 0:
        c.check("tracker3: search works again after re-index", int(s.group(1)) > 0, s.group(0))
    if a and b and f:
        freed_kib = int(b.group(2)) - int(a.group(2) or 0)
        c.check("tracker3: reported bytes ~ freed", abs(f["bytes"] / 1024 - freed_kib) < max(256, 0.1 * freed_kib),
                "reported=%s freed=%dKiB" % (human(f["bytes"]), freed_kib))


def case_pnpm(h):
    c = Case(h, "pnpm")
    pdir = os.path.join(h.tools, "pnpm")
    if not os.path.isfile(os.path.join(pdir, "bin/pnpm")):
        subprocess.run(["npm", "install", "-g", "--prefix", pdir, "--loglevel=error", "pnpm@9.12.0"], env={"HOME": os.path.join(h.tools, "npm-home"), "PATH": NVM_BIN + ":/usr/bin:/bin"}, check=True, capture_output=True)
    env = dict(c.env, PATH=os.path.join(pdir, "bin") + ":" + c.env["PATH"])
    web = os.path.join(c.home, "src/web")
    npm_project(web, {"lodash": "4.17.21", "moment": "2.30.1", "typescript": "5.4.5"})
    c.sh("pnpm install --reporter=silent", cwd=web, env=env)
    # A removed project leaves unreferenced packages in the store.
    old = os.path.join(c.home, "src/old")
    npm_project(old, {"rxjs": "7.8.1", "date-fns": "3.6.0"})
    c.sh("pnpm install --reporter=silent && cd .. && rm -rf old", cwd=old, env=env)
    store = c.sh("pnpm store path", env=env).stdout.strip()
    c.note("pnpm store: ~/%s" % os.path.relpath(store, c.home))
    f = c.tool(env=env)
    ps = f.get("pnpm-store")
    if ps:
        c.check("pnpm-store: command `pnpm store prune`", ps["command"] == "pnpm store prune", ps["command"])

    def verify():
        r = c.sh("node index.js", cwd=web, env=env, check=False)
        c.check("pnpm: project still runs (hard links survive)", "works" in r.stdout, r.stderr[-300:])
        r = c.sh("pnpm install --frozen-lockfile --reporter=silent && node index.js", cwd=web, env=env, check=False)
        c.check("pnpm: install still works", "works" in r.stdout, r.stderr[-300:])
    c.run_finding("pnpm-store", f, risk="SAFE", env=env, verify=verify, expect_keep_dirs=False, bytes_tolerance=None,
                  extra_allowed=[os.path.join(c.home, ".cache/pnpm")])
    f2 = c.tool()
    if "pnpm-store" in f2:
        c.check("pnpm-store without pnpm on PATH: Manual", f2["pnpm-store"]["command"].startswith("("), f2["pnpm-store"]["command"])


def case_snap_browsers(h):
    c = Case(h, "snap_browsers")
    j = lambda *a: os.path.join(c.home, *a)
    write(j("snap/firefox/common/.cache/mozilla/firefox/abc.default/cache2/entries/E1"), size=2 * MIB)
    write(j("snap/firefox/common/.cache/mozilla/firefox/abc.default/startupCache/x"), size=MIB)
    write(j("snap/firefox/common/.mozilla/firefox/abc.default/cookies.sqlite"), size=MIB)
    write(j("snap/firefox/common/.mozilla/firefox/abc.default/places.sqlite"), size=MIB)
    write(j("snap/chromium/common/.cache/chromium/Default/Cache/Cache_Data/data_1"), size=2 * MIB)
    write(j("snap/chromium/common/chromium/Default/Cookies"), size=64 * 1024)
    write(j("snap/chromium/common/chromium/Default/Bookmarks"), "{}")
    sleeper = h.spawn(["sleep", "600"])
    host = open("/proc/sys/kernel/hostname").read().strip()
    os.symlink("127.0.1.1:+%d" % sleeper.pid, j("snap/firefox/common/.mozilla/firefox/abc.default/lock"))
    os.symlink("%s-%d" % (host, sleeper.pid), j("snap/chromium/common/chromium/SingletonLock"))
    f = c.tool()
    for fid in ("firefox-snap-cache", "chromium-snap-cache"):
        c.check("%s: Manual while the snap browser holds its lock" % fid, fid in f and f[fid]["command"].startswith("("), f.get(fid, {}).get("command"))
    stop(sleeper, 5, signal.SIGKILL)
    f = c.tool()
    c.run_finding("firefox-snap-cache", f, risk="SAFE")
    c.run_finding("chromium-snap-cache", f, risk="SAFE")
    c.check("snap browsers: profile data untouched", all(os.path.isfile(j(x)) for x in (
        "snap/firefox/common/.mozilla/firefox/abc.default/cookies.sqlite", "snap/firefox/common/.mozilla/firefox/abc.default/places.sqlite",
        "snap/chromium/common/chromium/Default/Cookies", "snap/chromium/common/chromium/Default/Bookmarks",
        "snap/firefox/common/.cache/mozilla/firefox/abc.default/startupCache/x")))


# =========================================================================== main

CASES = [
    ("pip", "case_pip"), ("uv", "case_uv"), ("npm", "case_npm"), ("pnpm", "case_pnpm"), ("cargo", "case_cargo"), ("go", "case_go"),
    ("chrome", "case_chrome"), ("firefox", "case_firefox"), ("snap_browsers", "case_snap_browsers"), ("electron", "case_electron"),
    ("desktop", "case_desktop"), ("editors", "case_editors"), ("traps", "case_traps"), ("bindmount", "case_bindmount"),
    ("many_files", "case_many_files"), ("tracker3_docker", "case_tracker3_docker"), ("tui", "case_tui"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default=os.environ.get("LDP_BIN", os.path.join(PROJECT, "target/release/linux_disk_prune")))
    ap.add_argument("--work", default=os.environ.get("LDP_SAFETY_WORK", "/tmp/ldp-user-safety"))
    ap.add_argument("--cases", default="all", help="comma list of: " + ",".join(n for n, _ in CASES))
    ap.add_argument("--firefox", default=os.environ.get("LDP_FIREFOX"), help="non-snap firefox binary (tarball); downloaded if missing")
    ap.add_argument("--keep", action="store_true", help="keep the sandboxes afterwards")
    ap.add_argument("--results", default=os.path.join(HERE, "results.json"))
    args = ap.parse_args()
    h = Harness(args)
    h.firefox = args.firefox
    want = [n for n, _ in CASES] if args.cases == "all" else args.cases.split(",")
    try:
        for name, fn in CASES:
            if name not in want:
                continue
            print("\n=== %s" % name, flush=True)
            res = h.results.case(name)
            try:
                globals()[fn](h)
            except Abort as e:
                res["checks"].append({"name": "SAFETY GUARD ABORT", "ok": False, "evidence": str(e)})
                print("   ABORT: %s" % e)
            except Exception as e:
                res["checks"].append({"name": "harness error", "ok": False, "evidence": "%s\n%s" % (e, traceback.format_exc()[-1500:])})
                print("   ERROR: %s" % e)
                traceback.print_exc()
            if res["status"] == "RUNNING":
                res["status"] = "PASS" if all(ch["ok"] for ch in res["checks"]) and not res["bugs"] else "FAIL"
            if not args.keep:
                rmtree(os.path.join(h.work, name))
    finally:
        h.kill_all()
        rmtree(h.short_tmp)
    print("\n%-16s %-6s %s" % ("case", "status", "checks (failed)"))
    for name, r in h.results.cases.items():
        failed = [ch["name"] for ch in r["checks"] if not ch["ok"]]
        print("%-16s %-6s %d/%d %s" % (name, r["status"], len(r["checks"]) - len(failed), len(r["checks"]), "; ".join(failed)[:200]))
        for b in r["bugs"]:
            print("    BUG[%s] %s" % (b["severity"], b["title"]))
    with open(args.results, "w") as fh:
        json.dump(h.results.cases, fh, indent=1)
    print("\nresults: %s" % args.results)
    return 0 if all(r["status"] in ("PASS", "SKIP") for r in h.results.cases.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
