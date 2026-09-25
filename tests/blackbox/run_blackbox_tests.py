#!/usr/bin/env python3
"""Black-box validation of linux_disk_prune (stdlib only).

Usage: cargo build --release && python3 tests/blackbox/run_blackbox_tests.py [--binary PATH] [--skip-perf] [--skip-home] [--keep]

Builds fixtures under ./fx (next to this script), runs the binary in --json mode,
compares against GNU du, and prints a PASS/FAIL/INFO table.  Destructive commands
emitted by the tool are only ever executed after verifying (via shlex) that every
path they touch lies inside ./fx.
"""
import argparse, json, os, re, shlex, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
# Default: the release build of this repository (cargo build --release).
DEFAULT_BIN = os.path.join(HERE, "..", "..", "target", "release", "linux_disk_prune")
FX = os.path.join(HERE, "fx")
MiB = 1 << 20
RESULTS = []  # (test, status, expected, actual, note)


def rec(test, ok, expected="", actual="", note="", info=False):
    status = "INFO" if info else ("PASS" if ok else "FAIL")
    RESULTS.append((test, status, str(expected), str(actual), note))
    print(f"[{status}] {test}: expected={expected} actual={actual} {note}", flush=True)
    return ok


def run(args, cwd=None, timed=False, timeout=3600):
    cmd = ([ "/usr/bin/time", "-v"] if timed else []) + [BIN] + args
    os.sync()
    t0 = time.time()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
    wall = time.time() - t0
    out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    rss = None
    if timed:
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", err)
        rss = int(m.group(1)) if m else None
    return p.returncode, out, err, wall, rss


def run_json(args, cwd=None, timed=False):
    rc, out, err, wall, rss = run(["--json"] + args, cwd=cwd, timed=timed)
    try:
        data = json.loads(out)
    except Exception:
        data = None
    return rc, data, err, wall, rss


def du(path, extra=()):
    p = subprocess.run(["du", "-s", "-B1", *extra, "--", path], capture_output=True)
    line = p.stdout.decode("utf-8", "surrogateescape").strip().splitlines()
    return int(line[-1].split("\t")[0]) if line else None


def own_blocks(path):
    return os.lstat(path).st_blocks * 512


def write_file(path, nbytes, rand=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        if nbytes:
            f.write(os.urandom(nbytes) if rand else b"x" * nbytes)


def snapshot(root):
    s = set()
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            s.add(os.path.join(dp, n))
    return s


def find_pwned():
    hits = []
    for dp, dns, fns in os.walk(HERE):
        hits += [os.path.join(dp, n) for n in fns + dns if n.startswith("PWNED")]
    for base in (os.getcwd(), "/tmp", os.path.expanduser("~")):
        hits += [os.path.join(base, n) for n in os.listdir(base) if n.startswith("PWNED")]
    return hits


def fixture_findings(data, prefix):
    return [f for f in data["findings"]
            if any(p.startswith(prefix) for p in f["paths"])]


def split_segments(cmd):
    """shlex-split a command and break it on && tokens."""
    argv = shlex.split(cmd)
    segs, cur = [], []
    for t in argv:
        if t == "&&":
            segs.append(cur); cur = []
        else:
            cur.append(t)
    segs.append(cur)
    return segs


# --------------------------------------------------------------------------- 1
def test_sizes():
    root = os.path.join(FX, "size", "tree")
    outside = os.path.join(FX, "size", "outside")
    os.makedirs(root); os.makedirs(outside)
    write_file(os.path.join(outside, "big_outside.bin"), 20 * MiB, rand=False)
    for i in range(3):  # nested
        write_file(os.path.join(root, "nest", "l1", "l2", "l3", f"deep{i}.bin"), 1500 * 1024)
    for i in range(600):  # many small files
        write_file(os.path.join(root, "small", f"s{i:04}.txt"), 100 + i, rand=False)
    for i, sz in enumerate((2, 3, 5)):  # multi-MB
        write_file(os.path.join(root, "big", f"b{i}.bin"), sz * MiB)
    sp = os.path.join(root, "sparse", "sparse.img")
    os.makedirs(os.path.dirname(sp))
    subprocess.run(["truncate", "-s", "1G", sp], check=True)
    with open(sp, "r+b") as f:
        f.seek(512 * MiB); f.write(os.urandom(MiB))
    write_file(os.path.join(root, "hl", "orig.bin"), 3 * MiB)
    os.link(os.path.join(root, "hl", "orig.bin"), os.path.join(root, "hl", "link.bin"))
    os.makedirs(os.path.join(root, "links"))
    os.symlink(os.path.join(outside, "big_outside.bin"), os.path.join(root, "links", "sl_to_big"))
    os.symlink(outside, os.path.join(root, "links", "sl_to_dir"))
    os.makedirs(os.path.join(root, "empty"))
    weird = ["sp ace dir", "it's", "$(touch PWNED)", "`touch PWNED2`", "-leading", "日本語 ñ", 'dq"uote', "semi;colon&amp", "glob*?[x]"]
    for w in weird:
        write_file(os.path.join(root, w, w + ".bin"), 1100 * 1024)
    # cross-dir hard link (test 6)
    write_file(os.path.join(root, "xhl_a", "shared.bin"), 4 * MiB)
    os.makedirs(os.path.join(root, "xhl_b"))
    os.link(os.path.join(root, "xhl_a", "shared.bin"), os.path.join(root, "xhl_b", "shared.bin"))
    write_file(os.path.join(root, "xhl_b", "own.bin"), 1 * MiB)
    # non-UTF-8 directory name
    bad = os.path.join(os.fsencode(root), b"latin1_caf\xe9")
    os.makedirs(bad)
    with open(os.path.join(bad, b"f.bin"), "wb") as f:
        f.write(os.urandom(1200 * 1024))
    os.sync()  # flush delayed allocation so st_blocks is stable for both du and the tool

    rc, d, err, _, _ = run_json(["--top", "1000", "--depth", "20", root])
    if not rec("1.run", rc == 0 and d is not None, "rc=0 + JSON", f"rc={rc}", err.strip()[:200]):
        return
    du_B1, du_l, du_app = du(root), du(root, ["-l"]), du(root, ["--apparent-size"])
    rec("1.total_bytes vs du -s -B1", d["total_bytes"] == du_B1, du_B1, d["total_bytes"],
        f"delta={d['total_bytes'] - du_B1}; du -l (hardlinks counted twice)={du_l} (diff {du_l - du_B1}); apparent={du_app}")
    rec("1.sparse not counted as 1G", d["total_bytes"] < 200 * MiB, "<200MiB", d["total_bytes"],
        f"du sparse.img={du(sp)} apparent={os.path.getsize(sp)}")
    rec("1.symlink not followed", d["total_bytes"] < du(root, ["-L"]), f"< du -L={du(root, ['-L'])}", d["total_bytes"])
    rec("1.root is absolute canonical", d["root"] == os.path.realpath(root), os.path.realpath(root), d["root"])

    # Non-UTF-8 names can only be shown lossily in JSON; they are flagged `lossy`.
    lossy = [e["path"] for e in d["largest_dirs"] if e.get("lossy")]
    rec("1.non-UTF8 largest_dirs entries flagged lossy", all("\ufffd" in p for p in lossy), "flagged", lossy)
    listed = {e["path"]: e["bytes"] for e in d["largest_dirs"] if not e.get("lossy")}
    mism, missing_fs = [], []
    for p, b in listed.items():
        if not os.path.isdir(p):
            missing_fs.append(p); continue
        expect = du(p)
        if b != expect:
            mism.append((os.path.relpath(p, root), expect, b, b - expect))
    xhl = [m for m in mism if m[0].startswith("xhl_")]
    other = [m for m in mism if not m[0].startswith("xhl_")]
    rec("1.largest_dirs bytes == du (excluding cross-dir hardlink dirs)", not other, "0 mismatches",
        f"{len(other)} mismatches", "; ".join(f"{a}: du={b} tool={c} d={e}" for a, b, c, e in other)[:600])
    rec("1.largest_dirs paths exist on disk", not missing_fs, "all exist", f"{len(missing_fs)} missing",
        "; ".join(repr(p) for p in missing_fs)[:400])
    all_dirs = set()
    for dp, dns, fns in os.walk(root):
        for n in dns:
            full = os.path.join(dp, n)
            if not os.path.islink(full):
                all_dirs.add(full)
    not_listed = sorted(os.path.relpath(p, root) for p in all_dirs if p not in listed)
    rec("1.dirs absent from largest_dirs (top=1000, depth=20)", True, "", not_listed, info=True)
    rec("1.symlinked dir not listed", os.path.join(root, "links", "sl_to_dir") not in listed, "absent",
        "present" if os.path.join(root, "links", "sl_to_dir") in listed else "absent")
    for w in weird:
        p = os.path.join(root, w)
        rec(f"1.weird name {w!r}", listed.get(p) == du(p), du(p), listed.get(p))
    # sorting / top / depth
    bl = [e["bytes"] for e in d["largest_dirs"]]
    rec("1.largest_dirs sorted desc", bl == sorted(bl, reverse=True), "sorted", "sorted" if bl == sorted(bl, reverse=True) else bl[:10])
    rc2, d2, *_ = run_json(["--top", "3", "--depth", "1", root])
    depths = [os.path.relpath(e["path"], root).count(os.sep) + 1 for e in d2["largest_dirs"]]
    rec("1.--top 3 --depth 1", len(d2["largest_dirs"]) <= 3 and all(x <= 1 for x in depths), "<=3 entries, depth<=1",
        f"{len(d2['largest_dirs'])} entries depths={depths}")
    # determinism across runs and thread counts
    tots = set()
    per = set()
    for extra in [[], [], ["--threads", "1"]] + [["--threads", "16"]] * 12:
        _, dd, *_ = run_json(extra + ["--top", "1000", "--depth", "20", root])
        tots.add(dd["total_bytes"])
        per.add(json.dumps(sorted((e["path"], e["bytes"]) for e in dd["largest_dirs"])))
    rec("1.deterministic total across runs/threads", len(tots) == 1, "1 distinct", sorted(tots))
    rec("1.deterministic largest_dirs across runs/threads", len(per) == 1, "1 distinct", len(per),
        ("per-dir attribution of cross-dir hardlinks varies between runs (intermittent, ~1/15 at --threads 16): " + str(sorted({tuple((os.path.basename(p), b) for p, b in json.loads(x) if "xhl_" in p) for x in per}))) if len(per) > 1 else "")

    # non-UTF-8 name
    badp = [p for p in listed if "latin1_caf" in p]
    rec("1.non-UTF8 dir name reported", bool(badp), "present", badp,
        "exists-on-disk=" + str([os.path.isdir(p) for p in badp]), info=True)

    # 6 cross-dir hard link
    a, b = os.path.join(root, "xhl_a"), os.path.join(root, "xhl_b")
    rec("6.cross-dir hardlink: attribution", True, f"du a={du(a)} du b={du(b)} du a+b together={du_pair(a, b)}",
        f"tool a={listed.get(a)} b={listed.get(b)}", "tool counts the shared inode once overall; see per-dir", info=True)
    s = (listed.get(a) or 0) + (listed.get(b) or 0)
    rec("6.cross-dir hardlink: a+b counted once", s == du_pair(a, b), du_pair(a, b), s)
    # additivity: total == root own + files in root + sum(top-level dirs)
    top = [e for e in d["largest_dirs"] if os.path.dirname(e["path"]) == root]
    add = own_blocks(root) + sum(e["bytes"] for e in top) + sum(
        own_blocks(os.path.join(root, n)) for n in os.listdir(root)
        if not os.path.isdir(os.path.join(root, n)) or os.path.islink(os.path.join(root, n)))
    rec("1.additivity total = root + top-level dirs", add == d["total_bytes"], add, d["total_bytes"],
        f"unlisted top-level dirs={[n for n in os.listdir(root) if os.path.isdir(os.path.join(root, n)) and os.path.join(root, n) not in listed]}")
    return root


def du_pair(a, b):
    p = subprocess.run(["du", "-s", "-B1", "-c", a, b], capture_output=True, text=True)
    return int(p.stdout.strip().splitlines()[-1].split("\t")[0])


# --------------------------------------------------------------------------- 2
def test_unreadable():
    root = os.path.join(FX, "unread")
    write_file(os.path.join(root, "ok", "a.bin"), 2 * MiB)
    write_file(os.path.join(root, "locked", "secret.bin"), 3 * MiB)
    write_file(os.path.join(root, "noexec", "x.bin"), 2 * MiB)
    os.chmod(os.path.join(root, "locked"), 0)
    os.chmod(os.path.join(root, "noexec"), 0o444)  # readable listing but not traversable
    try:
        rc, d, err, _, _ = run_json(["--top", "100", "--depth", "5", root])
        ok = rc == 0 and d is not None and "panicked" not in err
        rec("2.unreadable dir: no crash", ok, "rc=0, JSON, no panic", f"rc={rc}", err.strip()[:200])
        if d:
            dup = du(root)
            listed = {e["path"]: e["bytes"] for e in d["largest_dirs"]}
            rec("2.unreadable: total vs du (du also can't read)", d["total_bytes"] == dup, dup, d["total_bytes"],
                f"locked listed as {listed.get(os.path.join(root, 'locked'))}, noexec as {listed.get(os.path.join(root, 'noexec'))}; notes={d['notes']}")
            rec("2.unreadable: warning surfaced in notes/stderr", any("readable" in n.lower() or "permission" in n.lower() or "denied" in n.lower() for n in d["notes"]) or "denied" in err.lower(),
                "some mention", d["notes"], info=True)
    finally:
        os.chmod(os.path.join(root, "locked"), 0o755)
        os.chmod(os.path.join(root, "noexec"), 0o755)


# --------------------------------------------------------------------------- 3
def test_artifacts():
    home = os.path.join(FX, "arthome")
    S = 1200 * 1024  # >1MiB
    pos = {}
    def mk(rel, marker=None, marker_content=b"", payload=S):
        d = os.path.join(home, rel)
        write_file(os.path.join(d, "payload.bin"), payload)
        write_file(os.path.join(d, "sub", "more.bin"), 64 * 1024)
        if marker:
            with open(os.path.join(os.path.dirname(d) if marker != "CACHEDIR.TAG" else d, marker), "wb") as f:
                f.write(marker_content)
        return d
    pos["rust"] = mk("code/rustproj/target", "Cargo.toml", b"[package]\nname='x'\n")
    pos["rust_tag"] = mk("code/tagonly/target", "CACHEDIR.TAG", b"Signature: 8a477f597d28d172789f06886806bc55\n")
    pos["node"] = mk("code/webapp/node_modules", "package.json", b"{}")
    # node_modules only counts when a package manager can restore it (lockfile)
    with open(os.path.join(home, "code/webapp/package-lock.json"), "wb") as f:
        f.write(b"{}")
    # nested node_modules inside the flagged one must not be flagged separately
    mk("code/webapp/node_modules/dep/node_modules", "package.json", b"{}")
    # __pycache__ group: two dirs 600K each -> group > 1MiB
    py1 = os.path.join(home, "code/py/pkg/__pycache__"); write_file(os.path.join(py1, "a.pyc"), 600 * 1024)
    py2 = os.path.join(home, "code/py2/__pycache__"); write_file(os.path.join(py2, "b.pyc"), 600 * 1024)
    # negatives
    neg = {
        "photo target": mk("Pictures/target"),
        "node_modules w/o package.json": mk("code/nopkg/node_modules"),
        "hidden .nvm node_modules": mk(".nvm/versions/node/v20/lib/node_modules", "package.json", b"{}"),
        "hidden .config node_modules": mk(".config/app/node_modules", "package.json", b"{}"),
        "hidden project target": mk(".hidden/proj/target", "Cargo.toml", b"[package]"),
        "snap target": mk("snap/foo/proj/target", "Cargo.toml", b"[package]"),
        "snap node_modules": mk("snap/bar/node_modules", "package.json", b"{}"),
        "Cargo.toml inside target (target/sub)": mk("code/rustproj2/target/nested/target", "Cargo.toml", b"[package]"),
    }
    npy_hidden = os.path.join(home, ".venv/lib/__pycache__"); write_file(os.path.join(npy_hidden, "c.pyc"), 1200 * 1024)
    npy_snap = os.path.join(home, "snap/x/__pycache__"); write_file(os.path.join(npy_snap, "d.pyc"), 1200 * 1024)
    neg["hidden __pycache__"] = npy_hidden
    neg["snap __pycache__"] = npy_snap
    # tiny artifact below threshold
    tiny = os.path.join(home, "code/tiny/target"); write_file(os.path.join(tiny, "t.bin"), 100 * 1024)
    write_file(os.path.join(home, "code/tiny/Cargo.toml"), 10, rand=False)
    neg["tiny target < 1MiB"] = tiny
    # rustproj2 is a real project too (positive): its target contains a nested target w/ Cargo.toml
    write_file(os.path.join(home, "code/rustproj2/Cargo.toml"), 10, rand=False)
    pos["rust2"] = os.path.join(home, "code/rustproj2/target")

    rc, d, err, _, _ = run_json(["--rules-only", "--home", home, "--dev-root", home, home])
    if not rec("3.run", rc == 0 and d is not None, "rc=0", rc, err[:200]):
        return
    ff = fixture_findings(d, home)
    flagged = {}
    for f in ff:
        for p in f["paths"]:
            flagged[p] = f
    expect_risk = {"rust": "CAUTION", "rust_tag": "CAUTION", "node": "CAUTION", "rust2": "CAUTION"}
    for k, p in pos.items():
        f = flagged.get(p)
        rec(f"3.pos {k} flagged", f is not None, p.replace(home, "~"), "flagged" if f else "NOT flagged")
        if f:
            rec(f"3.pos {k} risk", f["risk"] == expect_risk[k], expect_risk[k], f["risk"])
            rec(f"3.pos {k} bytes vs du", f["bytes"] == du(p), du(p), f["bytes"], f"delta={f['bytes'] - du(p)}")
            rec(f"3.pos {k} paths exactly [dir]", f["paths"] == [p], [p.replace(home, '~')], [x.replace(home, '~') for x in f["paths"]])
    pyf = [f for f in ff if py1 in f["paths"] or py2 in f["paths"]]
    rec("3.pos __pycache__ grouped single finding", len(pyf) == 1, 1, len(pyf))
    if pyf:
        f = pyf[0]
        rec("3.pos __pycache__ risk", f["risk"] == "SAFE", "SAFE", f["risk"])
        rec("3.pos __pycache__ paths", sorted(f["paths"]) == sorted([py1, py2]), sorted(x.replace(home, "~") for x in [py1, py2]),
            sorted(x.replace(home, "~") for x in f["paths"]))
        exp = du_pair(py1, py2)
        rec("3.pos __pycache__ bytes vs du", f["bytes"] == exp, exp, f["bytes"], f"delta={f['bytes'] - exp}; cmd={f['command'][:160]}")
    nested_nm = os.path.join(pos["node"], "dep", "node_modules")
    rec("3.neg nested node_modules not separately flagged", nested_nm not in flagged, "absent", "present" if nested_nm in flagged else "absent")
    for k, p in neg.items():
        hit = [x for x in flagged if x == p or x.startswith(p + "/")]
        rec(f"3.neg {k}", not hit, "not flagged", [x.replace(home, "~") for x in hit] or "not flagged")
    # every fixture finding path must be one of the expected ones
    allowed = set(pos.values()) | {py1, py2}
    extra = [p for p in flagged if p not in allowed]
    rec("3.no unexpected artifact paths", not extra, "none", [x.replace(home, "~") for x in extra])
    # consistency: rules-only vs full scan
    rc, d2, *_ = run_json(["--home", home, "--dev-root", home, home])
    a = sorted((f["id"], f["bytes"]) for f in fixture_findings(d, home))
    b = sorted((f["id"], f["bytes"]) for f in fixture_findings(d2, home))
    rec("3.findings same with/without --rules-only", a == b, a[:3], b[:3] if a != b else "same")
    # dev-root different from home: only dev-root is searched for artifacts
    rc, d3, *_ = run_json(["--rules-only", "--home", home, "--dev-root", os.path.join(home, "code", "webapp"), home])
    fp = sorted(p for f in fixture_findings(d3, home) for p in f["paths"])
    rec("3.--dev-root limits artifact search", fp == [pos["node"]], ["~/code/webapp/node_modules"], [x.replace(home, "~") for x in fp])
    return home


# --------------------------------------------------------------------------- 4
CACHES = {  # rel path -> (id-ish, tier)
    # pip: only pip's own sub-folders (what `pip cache purge` clears) since the safety audit.
    ".cache/thumbnails": "SAFE", ".cache/pip/http": "SAFE",
    # Cargo registry is MODERATE since the safety review (deleting it mid-build breaks cargo).
    ".cargo/registry/cache": "MODERATE", ".cargo/registry/src": "MODERATE",
    ".cargo/git/checkouts": "SAFE", ".npm/_cacache": "SAFE",
    ".local/share/Trash/files": "MODERATE", ".local/share/Trash/info": "MODERATE",
}


def test_caches():
    home = os.path.join(FX, "cachehome")
    for rel in CACHES:
        write_file(os.path.join(home, rel, "sub dir", "blob.bin"), 1100 * 1024)
        write_file(os.path.join(home, rel, "top.bin"), 64 * 1024)
    decoys = [".cache/other/x.bin", ".cargo/bin/cargo-x", ".npm/other/x.bin", ".cache/keep.bin",
              ".local/share/keep.bin", ".cargo/registry/index/x.bin", "Documents/important.bin"]
    for rel in decoys:
        write_file(os.path.join(home, rel), 1100 * 1024)
    rc, d, err, _, _ = run_json(["--rules-only", "--home", home, "--dev-root", home, home])
    if not rec("4.run", rc == 0 and d is not None, "rc=0", rc, err[:200]):
        return
    ff = fixture_findings(d, home)
    by_path = {p: f for f in ff for p in f["paths"]}
    for rel, tier in CACHES.items():
        p = os.path.join(home, rel)
        f = by_path.get(p)
        if not rec(f"4.{rel} flagged", f is not None, "flagged", "flagged" if f else "NOT flagged"):
            continue
        rec(f"4.{rel} tier", f["risk"] == tier, tier, f["risk"])
    for f in ff:
        exp_full = sum(du(p) for p in f["paths"])
        exp_contents = sum(du(p) - own_blocks(p) for p in f["paths"])
        rec(f"4.{f['id']} bytes vs du(contents)", f["bytes"] == exp_contents, exp_contents, f["bytes"],
            f"du incl. dir entry={exp_full} (tool excludes the kept dir's own {exp_full - exp_contents}B; cmd keeps dir via -mindepth 1)")
        segs = split_segments(f["command"])
        ok = len(segs) == len(f["paths"]) and all(
            s == ["find", p, "-xdev", "-mindepth", "1", "-delete"] for s, p in zip(segs, f["paths"]))
        rec(f"4.{f['id']} command argv exact", ok, "find <dir> -xdev -mindepth 1 -delete per path", segs)
        rec(f"4.{f['id']} needs_root false", f["needs_root"] is False, False, f["needs_root"])
    decoy_hits = [p for p in by_path if not any(p == os.path.join(home, r) for r in CACHES)]
    rec("4.no decoy/other user paths flagged", not decoy_hits, "none", decoy_hits)
    # execute the commands on the fixture (all paths verified inside FX)
    before = snapshot(home)
    for f in ff:
        for s in split_segments(f["command"]):
            assert all(not t.startswith("/") or t.startswith(FX + "/") for t in s), s
        subprocess.run(["bash", "-c", f["command"]], cwd=FX, check=False)
    after = snapshot(home)
    removed = before - after
    bad = [p for p in removed if not any(p.startswith(os.path.join(home, r) + "/") for r in CACHES)]
    dirs_kept = all(os.path.isdir(os.path.join(home, r)) and not os.listdir(os.path.join(home, r)) for r in CACHES)
    rec("4.executed commands: only cache contents removed, dirs kept & empty", not bad and dirs_kept,
        "decoys intact", f"unexpected removals={bad} dirs_kept_empty={dirs_kept}")
    # relative --home
    rel_home = os.path.relpath(home, FX)
    shutil.rmtree(home)
    for rel in CACHES:
        write_file(os.path.join(home, rel, "blob.bin"), 1100 * 1024)
    rc, d, *_ = run_json(["--rules-only", "--home", rel_home, "--dev-root", rel_home, rel_home], cwd=FX)
    rp = [p for f in d["findings"] for p in f["paths"] if "cachehome" in p]
    rel_cmds = [f["command"] for f in d["findings"] if any("cachehome" in p for p in f["paths"])]
    rec("4.relative --home yields absolute paths/commands", rp and all(p.startswith("/") for p in rp), "absolute paths",
        rp[:2], f"e.g. command: {rel_cmds[:1]}")
    # small caches dropped (< 1 MiB)
    shutil.rmtree(home)
    for rel in CACHES:
        write_file(os.path.join(home, rel, "blob.bin"), 900 * 1024)
    rc, d, *_ = run_json(["--rules-only", "--home", home, "--dev-root", home, home])
    ff = fixture_findings(d, home)
    rec("4.caches < 1MiB dropped", all(f["bytes"] >= MiB for f in ff), "only findings >= 1MiB",
        [(f["id"], f["bytes"]) for f in ff])
    # boundary: exactly 1 MiB of contents in pip
    shutil.rmtree(home)
    write_file(os.path.join(home, ".cache/pip/blob.bin"), MiB)
    rc, d, *_ = run_json(["--rules-only", "--home", home, "--dev-root", home, home])
    ff = fixture_findings(d, home)
    rec("4.boundary: exactly 1MiB pip cache", True, "kept (>=1MiB?)", [(f["id"], f["bytes"]) for f in ff] or "dropped", info=True)


# --------------------------------------------------------------------------- 5
def test_quoting():
    home = os.path.join(FX, "quotehome")
    names = ["sp ace", "it's", "$(touch PWNED)", "`touch PWNED2`", "-dash", "semi;rm -rf x", 'dq"$HOME', "glob*", "back\\slash", "tab\tname", "日本語"]
    projs = {}
    for n in names:
        pr = os.path.join(home, n)
        write_file(os.path.join(pr, "Cargo.toml"), 10, rand=False)
        write_file(os.path.join(pr, "target", "debug", "blob.bin"), 1100 * 1024)
        projs[os.path.join(pr, "target")] = "rust"
        pr2 = os.path.join(home, "node " + n)
        write_file(os.path.join(pr2, "package.json"), 2, rand=False)
        write_file(os.path.join(pr2, "package-lock.json"), 2, rand=False)
        write_file(os.path.join(pr2, "node_modules", "blob.bin"), 1100 * 1024)
        projs[os.path.join(pr2, "node_modules")] = "node"
    # a pycache under a weird dir
    for n in ("py $(touch PWNED3)", "py 'q'"):
        write_file(os.path.join(home, n, "__pycache__", "m.pyc"), 700 * 1024)
    # non-UTF-8 project directory
    badproj = os.path.join(os.fsencode(home), b"caf\xe9")
    os.makedirs(os.path.join(badproj, b"target"))
    open(os.path.join(badproj, b"Cargo.toml"), "wb").close()
    with open(os.path.join(badproj, b"target", b"x.bin"), "wb") as f:
        f.write(os.urandom(1100 * 1024))
    decoy_utf8 = os.path.join(home, "caf�", "target")  # what a lossy conversion would name
    write_file(os.path.join(decoy_utf8, "DO_NOT_DELETE.bin"), 10, rand=False)

    rc, d, err, _, _ = run_json(["--rules-only", "--home", home, "--dev-root", home, home])
    if not rec("5.run", rc == 0 and d is not None, "rc=0", rc, err[:200]):
        return
    ff = fixture_findings(d, home)
    by_path = {p: f for f in ff for p in f["paths"]}
    for p, kind in projs.items():
        f = by_path.get(p)
        label = os.path.relpath(p, home)
        if not rec(f"5.{label!r} flagged", f is not None, "flagged", "flagged" if f else "NOT flagged"):
            continue
        argv = shlex.split(f["command"])
        rec(f"5.{label!r} command argv", argv == ["rm", "-rf", "--one-file-system", "--", p], ["rm", "-rf", "--one-file-system", "--", label], argv[:4] + [os.path.relpath(a, home) if a.startswith("/") else a for a in argv[4:]])
        m = re.search(r"Equivalent: (.*)", f["detail"])
        if kind == "rust" and m:
            ea = shlex.split(m.group(1))
            exp = ["cargo", "clean", "--manifest-path", os.path.join(os.path.dirname(p), "Cargo.toml")]
            rec(f"5.{label!r} detail 'Equivalent' argv", ea == exp, "cargo clean --manifest-path <quoted>", ea[:3] + ["..."] if ea == exp else ea)
    pyf = [f for f in ff if any("__pycache__" in p for p in f["paths"])]
    for f in pyf:
        segs = split_segments(f["command"])
        flat = [t for s in segs for t in s]
        wrong = [t for t in flat if t.startswith("/") and t not in f["paths"]]
        rec("5.__pycache__ group command argv", not wrong and all(p in flat for p in f["paths"]), "only listed paths", segs)
    # non-UTF-8: the reported path must round-trip to the real on-disk bytes
    real_bad_target = os.path.join(badproj, b"target")
    bad_find = [f for f in ff if any("caf" in p for p in f["paths"])]
    rt = [os.fsencode(p) == real_bad_target for f in bad_find for p in f["paths"]]
    # JSON strings must be UTF-8, so a non-UTF-8 path can only be shown lossily. Contract:
    # such findings are flagged `lossy_paths` and their shell command never names the
    # lossy (decoy) path; the app removes the real directory in-process from exact bytes.
    rec("5.non-UTF8 project flagged (lossy_paths)", bool(bad_find) and all(f.get("lossy_paths") for f in bad_find),
        "reported with lossy_paths=true", [(f["paths"][0][-12:], f.get("lossy_paths")) for f in bad_find] or "not reported")
    rec("5.non-UTF8 command never targets the lossy decoy path",
        all(decoy_utf8 not in f["command"] and os.path.dirname(decoy_utf8) not in f["command"] for f in bad_find),
        "no lossy path in command", [f["command"][:120] for f in bad_find])
    ff = [f for f in ff if not f.get("lossy_paths")]

    # execute every artifact command against the fixture from an empty cwd
    cwd = os.path.join(FX, "exec_cwd"); os.makedirs(cwd, exist_ok=True)
    before = snapshot(home)
    executed = 0
    for f in ff:
        toks = [t for s in split_segments(f["command"]) for t in s]
        if not all(not t.startswith("/") or t.startswith(home + "/") for t in toks):
            rec("5.exec guard", False, "all abs paths inside fixture", f["command"]); continue
        subprocess.run(["bash", "-c", f["command"]], cwd=cwd)
        executed += 1
    after = snapshot(home)
    removed = before - after
    targets = [p for f in ff for p in f["paths"]]
    unexpected = [p for p in removed if not any(p == t or p.startswith(t + "/") for t in targets)]
    still = [t for t in targets if os.path.exists(t)]
    pw = find_pwned()
    rec("5.executed commands: only reported targets removed", not unexpected, "none", unexpected[:5], f"executed {executed}")
    rec("5.executed commands: all targets gone", not still, "none left", still[:5])
    rec("5.exec: decoy with U+FFFD name kept", os.path.exists(decoy_utf8),
        "decoy kept", f"decoy exists={os.path.exists(decoy_utf8)}")
    rec("5.no PWNED file created", not pw, "none", pw)
    rec("5.cwd untouched", os.listdir(cwd) == [], [], os.listdir(cwd))


# --------------------------------------------------------------------------- 7
def test_perf(skip_home):
    root = os.path.join(FX, "many")
    t0 = time.time()
    for i in range(200):
        dd = os.path.join(root, f"d{i:03}", f"sub{i % 7}")
        os.makedirs(dd)
        for j in range(1000):
            fd = os.open(os.path.join(dd, f"f{j:04}"), os.O_CREAT | os.O_WRONLY, 0o644)
            if j % 100 == 0:
                os.write(fd, b"x")
            os.close(fd)
    rec("7.fixture build", True, "200k files", f"{time.time() - t0:.1f}s, du={du(root)}", info=True)
    subprocess.run(["sync"])
    for label, extra in (("default threads", []), ("--threads 1", ["--threads", "1"])):
        rc, d, err, wall, rss = run_json(extra + [root], timed=True)
        rec(f"7.200k files {label}", rc == 0 and d["total_bytes"] == du(root), f"total={du(root)}",
            f"total={d['total_bytes'] if d else None} wall={wall:.2f}s peakRSS={rss / 1024 if rss else '?':.1f}MiB", "")
    t0 = time.time(); du(root); rec("7.du -s on same tree (reference)", True, "", f"{time.time() - t0:.2f}s", info=True)
    if skip_home:
        return
    H = os.path.expanduser("~")
    for label, extra in (("--rules-only", ["--rules-only"]), ("full scan", [])):
        rc, d, err, wall, rss = run_json(extra + [H], timed=True)
        rec(f"7.real $HOME {label}", rc == 0 and d is not None, "rc=0",
            f"rc={rc} wall={wall:.1f}s peakRSS={rss / 1024 if rss else 0:.1f}MiB total={d.get('total_bytes') if d else None} findings={len(d['findings']) if d else None}",
            err.strip()[-200:])
        if d and label == "full scan":
            t0 = time.time(); dh = du(H, ["-x"]); tdu = time.time() - t0
            rec("7.real $HOME total vs du -sx -B1", True, dh, d["total_bytes"],
                f"delta={d['total_bytes'] - dh} ({(d['total_bytes'] - dh) / max(dh, 1) * 100:.3f}%), du took {tdu:.1f}s (live FS, drift expected)", info=True)


# --------------------------------------------------------------------------- 8
def test_robustness():
    base = os.path.join(FX, "robust")
    write_file(os.path.join(base, "d", "a.bin"), 2 * MiB)
    write_file(os.path.join(base, "file.bin"), 2 * MiB)
    rc, out, err, *_ = run(["--json", os.path.join(base, "nope")])
    rec("8.nonexistent path", rc != 0 and "panicked" not in err and err.strip() != "", "rc!=0, clean msg", f"rc={rc}", err.strip()[:150])
    rc, out, err, *_ = run(["--json", os.path.join(base, "file.bin")])
    rec("8.file path instead of dir", "panicked" not in err, "no panic (error or file-size report)", f"rc={rc}", (err.strip() or out.strip())[:200])
    _, d0, *_ = run_json([os.path.join(base, "d")])
    _, d1, *_ = run_json([os.path.join(base, "d") + "/"])
    rec("8.trailing slash", d0 and d1 and d0["root"] == d1["root"] and d0["total_bytes"] == d1["total_bytes"],
        (d0["root"][-10:], d0["total_bytes"]), (d1["root"][-10:], d1["total_bytes"]))
    _, d2, *_ = run_json(["d"], cwd=base)
    rec("8.relative path", d2 and d2["root"] == d0["root"] and d2["total_bytes"] == d0["total_bytes"],
        (d0["root"][-10:], d0["total_bytes"]), (d2["root"][-10:] if d2 else None, d2["total_bytes"] if d2 else None))
    _, d3, *_ = run_json(["."], cwd=os.path.join(base, "d"))
    rec("8.'.' path", d3 and d3["root"] == d0["root"], d0["root"][-10:], d3["root"][-10:] if d3 else None)
    rc, out, err, *_ = run(["--json", "--top", "0", "--depth", "0", os.path.join(base, "d")])
    rec("8.--top 0 --depth 0", rc == 0 and "panicked" not in err, "rc=0", f"rc={rc}", err.strip()[:100])
    rc, out, err, *_ = run(["--json", "--rules-only", "--home", os.path.join(base, "nohome"), "--dev-root", os.path.join(base, "nohome"), base])
    rec("8.nonexistent --home/--dev-root", rc == 0 and "panicked" not in err, "rc=0 no panic", f"rc={rc}", err.strip()[:100])
    rc, out, err, *_ = run(["--json", "--min-file-size", "garbage", base])
    rec("8.bad --min-file-size", rc != 0 and "panicked" not in err, "rc!=0 clean", f"rc={rc}", err.strip()[:100])
    rc, out, err, *_ = run(["--summary", "--home", base, "--dev-root", base, os.path.join(base, "d")])
    rec("8.--summary text", rc == 0 and "LARGEST" in out, "rc=0 w/ report", f"rc={rc}", "")
    # symlink as the scan root
    os.symlink(os.path.join(base, "d"), os.path.join(base, "link_to_d"))
    _, d4, *_ = run_json([os.path.join(base, "link_to_d")])
    rec("8.symlink as root path", True, "follows root symlink?", (d4["root"][-12:], d4["total_bytes"]) if d4 else None, info=True)


def main():
    global BIN
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BIN)
    ap.add_argument("--skip-perf", action="store_true")
    ap.add_argument("--skip-home", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep fixtures afterwards")
    a = ap.parse_args()
    BIN = os.path.abspath(a.binary)
    if os.path.exists(FX):
        subprocess.run(["chmod", "-R", "u+rwx", FX]); shutil.rmtree(FX)
    os.makedirs(FX)
    try:
        test_sizes()
        test_unreadable()
        test_artifacts()
        test_caches()
        test_quoting()
        test_robustness()
        if not a.skip_perf:
            test_perf(a.skip_home)
    finally:
        if not a.keep:
            subprocess.run(["chmod", "-R", "u+rwx", FX]); shutil.rmtree(FX, ignore_errors=True)
    print("\n" + "=" * 100)
    w = max(len(r[0]) for r in RESULTS)
    for t, s, e, act, n in RESULTS:
        print(f"{s:4}  {t:<{w}}  exp={e[:70]}  act={act[:90]}")
    c = {s: sum(1 for r in RESULTS if r[1] == s) for s in ("PASS", "FAIL", "INFO")}
    print(f"\n{c}")
    with open(os.path.join(HERE, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1, ensure_ascii=False)
    sys.exit(1 if c["FAIL"] else 0)


if __name__ == "__main__":
    main()
