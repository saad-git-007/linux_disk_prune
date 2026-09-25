#!/usr/bin/env python3
"""Independent ground-truth validation of linux_disk_prune's Ubuntu rules.

Read-only. Runs the tool in report mode (as the user and as root via sudo -n),
recomputes every rule's expected result from first principles (apt, dpkg, snap,
journald's vacuum algorithm, find/du/stat), and prints a per-rule verdict table.

Only read-only commands are executed. Nothing is deleted or modified.

Usage: python3 tests/system/validate_ubuntu_rules.py [--tool /usr/bin/linux_disk_prune] [--json OUT]
"""
import argparse
import glob
import json
import os
import re
import stat
import subprocess
import sys
from collections import defaultdict

MIB = 1 << 20
HOME = os.path.expanduser("~")
_REPO_BUILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "target", "release", "linux_disk_prune")
TOOL = _REPO_BUILD if os.path.exists(_REPO_BUILD) else "/usr/bin/linux_disk_prune"
JOURNAL_KEEP = 500 * MIB  # tool default (--journal-keep)
MIN_FINDING = MIB          # rules/mod.rs MIN_FINDING_BYTES
MAX_PROJECT_FINDINGS = 60


# ------------------------------------------------------------------ helpers

def run(cmd, sudo=False, check=False, input=None):
    if sudo:
        cmd = ["sudo", "-n"] + cmd
    p = subprocess.run(cmd, capture_output=True, text=True, input=input)
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd}: {p.stderr.strip()}")
    return p


def lines(cmd, sudo=False):
    return [l for l in run(cmd, sudo).stdout.splitlines() if l]


def stat_blocks(path, sudo=True):
    """(bytes-on-disk, nlink, inode) via stat, or None."""
    p = run(["stat", "-c", "%b %B %h %i", path], sudo)
    if p.returncode != 0:
        return None
    b, bs, h, i = map(int, p.stdout.split())
    return b * bs, h, i


def du_each(paths, sudo=False):
    """du -sB1 -x per path, one process per path (no cross-path hard-link dedup,
    same as the tool which runs its du once per directory)."""
    out = {}
    for p in paths:
        r = run(["du", "-sxB1", "--", p], sudo)
        out[p] = int(r.stdout.split()[0]) if r.stdout.strip() else 0
    return out


def du_batch(paths, sudo=False):
    """du -sB1 -x over many paths in one invocation (hard links counted once)."""
    if not paths:
        return {}
    r = run(["du", "-sxB1", "--files0-from=-"], sudo, input="\0".join(paths) + "\0")
    out = {}
    for l in r.stdout.splitlines():
        n, p = l.split("\t", 1)
        out[p] = int(n)
    return out


def fmt(n):
    if n is None:
        return "-"
    neg = n < 0
    n = abs(n)
    for u in ["B", "KiB", "MiB", "GiB"]:
        if n < 1024 or u == "GiB":
            s = f"{n:.1f}{u}" if u != "B" else f"{n}B"
            return ("-" if neg else "") + s
        n /= 1024


def tool_report(sudo):
    p = run([TOOL, "--json", "--rules-only"], sudo)
    if p.returncode != 0:
        raise SystemExit(f"tool failed (sudo={sudo}): {p.stderr}")
    return json.loads(p.stdout)


def by_id(rep):
    return {f["id"]: f for f in rep["findings"]}


class Row:
    def __init__(self, rule, exp_items, exp_bytes, rep_items, rep_bytes, verdict, why=""):
        self.rule, self.exp_items, self.exp_bytes = rule, exp_items, exp_bytes
        self.rep_items, self.rep_bytes, self.verdict, self.why = rep_items, rep_bytes, verdict, why

    def delta(self):
        if self.exp_bytes is None or self.rep_bytes is None:
            return None
        return self.rep_bytes - self.exp_bytes


ROWS = []
DETAILS = defaultdict(list)


def note(rule, msg):
    DETAILS[rule].append(msg)


def verdict_bytes(exp, rep, tol_abs=0, tol_rel=0.0):
    if exp == rep:
        return "EXACT"
    if abs(rep - exp) <= max(tol_abs, tol_rel * max(exp, 1)):
        return "OK-within-tolerance"
    return "WRONG"


def compare_sets(rule, exp_set, rep_set):
    missing = sorted(exp_set - rep_set)
    extra = sorted(rep_set - exp_set)
    for m in missing[:15]:
        note(rule, f"MISSING (expected, not reported): {m}")
    if len(missing) > 15:
        note(rule, f"... {len(missing) - 15} more missing")
    for e in extra[:15]:
        note(rule, f"EXTRA (reported, not expected): {e}")
    if len(extra) > 15:
        note(rule, f"... {len(extra) - 15} more extra")
    return missing, extra


def set_verdict(missing, extra, bv):
    if missing and not extra:
        return "MISSING"
    if extra and not missing:
        return "FALSE-POSITIVE"
    if missing or extra:
        return "WRONG"
    return bv


# ------------------------------------------------------------------ 1. APT

def check_apt(rep):
    R = "apt-cache"
    sim = run(["apt-get", "-s", "clean"]).stdout
    globs = []
    for l in sim.splitlines():
        if l.startswith("Del "):
            globs += l[4:].split()
    cfg = run(["apt-config", "dump"]).stdout
    note(R, "apt-config: " + "; ".join(l for l in cfg.splitlines() if "Dir::Cache" in l))
    exp = {}
    for g in globs:
        d, pat = os.path.split(g)
        if pat == "*":
            # apt's Clean() removes every regular file in the dir except 'lock'
            for l in lines(["find", d, "-maxdepth", "1", "-type", "f", "!", "-name", "lock",
                            "-printf", "%p\t%b\n"], sudo=True):
                p, b = l.split("\t")
                exp[p] = int(b) * 512
        else:
            s = stat_blocks(g)
            if s:
                exp[g] = s[0]
    f = rep.get(R)
    rep_items = {p: None for p in (f["paths"] if f else [])}
    # pkgcache.bin/srcpkgcache.bin are rebuilt by apt's very next run: not lasting
    # savings, so only .debs and partial downloads count (and alone justify a finding).
    exp_b = sum(v for p, v in exp.items() if not p.endswith(".bin"))
    exp_eff = exp_b if exp_b >= MIN_FINDING else 0
    rep_b = f["bytes"] if f else 0
    missing, extra = compare_sets(R, set(exp) if exp_eff else set(), set(rep_items))
    bins = [p for p in exp if p.endswith(".bin")]
    if bins and exp_b == sum(exp[p] for p in bins):
        note(R, "All reclaimable bytes are pkgcache.bin/srcpkgcache.bin: apt regenerates them on "
                "the very next apt/apt-get invocation (even `apt-get -s`), so the saving is transient.")
    ROWS.append(Row(R, len(exp), exp_eff, len(rep_items), rep_b,
                    set_verdict(missing, extra, verdict_bytes(exp_eff, rep_b)),
                    "apt-get -s clean Del globs expanded + stat blocks"))


# ------------------------------------------------------------------ 2. Kernels

def vkey(v):
    return [int(x) for x in re.findall(r"\d+", v)]


def check_kernels(rep):
    R = "kernels"
    running = run(["uname", "-r"]).stdout.strip()
    st = {}
    for l in lines(["dpkg-query", "-W", "-f", "${Package}\t${db:Status-Abbrev}\t${Installed-Size}\n"]):
        pkg, s, sz = (l.split("\t") + ["", ""])[:3]
        st[pkg] = (s.strip(), int(sz) * 1024 if sz.strip().isdigit() else 0)
    installed = {p for p, (s, _) in st.items() if s.startswith("ii")}
    images = sorted({m.group(1) for p in installed
                     if (m := re.match(r"linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+-[a-z0-9-]+)$", p))},
                    key=vkey)
    keep = set(images[-2:]) | {running}
    note(R, f"running={running}; installed images={images}; keep(running+2 newest)={sorted(keep, key=vkey)}")
    ak = "/etc/apt/apt.conf.d/01autoremove-kernels"
    if os.path.exists(ak):
        prot = re.findall(r'"\^linux-.*?-(\d[^"$]*?)\$"', open(ak).read())
        note(R, f"{ak} protects: {sorted(set(prot))}")
    else:
        note(R, f"{ak} absent (APT >= 2.x computes protected kernels in-process); "
                "relying on `apt-get -s autoremove --purge`.")
    auto = [l.split()[1] for l in lines(["apt-get", "-s", "autoremove", "--purge"])
            if l.startswith(("Purg ", "Remv "))]
    auto_k = [p for p in auto if p.startswith("linux-")]
    note(R, f"apt autoremove would purge linux pkgs: {auto_k or 'none'}")
    exp_old = [v for v in images if v not in keep]
    reported = {fid[len("kernel:"):]: f for fid, f in rep.items() if fid.startswith("kernel:")}
    missing, extra = compare_sets(R, set(exp_old), set(reported))
    exp_b, rep_b = 0, 0
    for ver, f in reported.items():
        rep_b += f["bytes"]
        m = re.search(r"purge -y (.*)$", f["command"] or "")
        if m:
            pk = [x.strip("'") for x in m.group(1).split()]
            removed = [l.split()[1] for l in lines(["apt-get", "-s", "purge"] + pk)
                       if l.startswith(("Purg ", "Remv "))]
            extra_rm = sorted(set(removed) - set(pk))
            note(R, f"kernel {ver}: apt-get -s purge removes extra={extra_rm or 'nothing'}")
            dsize = sum(st.get(p, ("", 0))[1] for p in pk)
            note(R, f"kernel {ver}: dpkg Installed-Size sum={fmt(dsize)} vs tool {fmt(f['bytes'])}")
    for ver in exp_old:
        base = re.sub(r"-[a-z]+(-[a-z]+)*$", "", ver)
        ps = [f"/boot/{x}-{ver}" for x in ("vmlinuz", "initrd.img", "System.map", "config")]
        ps += [f"/lib/modules/{ver}"] + glob.glob(f"/usr/src/linux*-headers-{base}*") \
            + glob.glob(f"/usr/lib/linux*tools*{base}*")
        exp_b += sum(du_batch([p for p in ps if os.path.exists(p)], sudo=True).values())
    # Dry-run the purge path the tool would take for the oldest installed non-running kernel,
    # even when it is protected, to validate package selection and byte accounting.
    probe = [v for v in images if v != running]
    if probe:
        ver = probe[0]
        base = re.sub(r"-[a-z]+(-[a-z]+)*$", "", ver)
        pk = sorted(p for p in installed if p.startswith("linux-") and (p.endswith("-" + ver) or p.endswith("-" + base)
                    or re.search(r"-(headers|tools)-" + re.escape(base) + "$", p)))
        removed = [l.split()[1] for l in lines(["apt-get", "-s", "purge"] + pk) if l.startswith(("Purg ", "Remv "))]
        ps = [f"/boot/{x}-{ver}" for x in ("vmlinuz", "initrd.img", "System.map", "config")]
        ps += [f"/lib/modules/{ver}"] + glob.glob(f"/usr/src/linux*-headers-{base}*") \
            + glob.glob(f"/usr/lib/linux*tools*{base}*")
        dub = sum(du_batch([p for p in ps if os.path.exists(p)], sudo=True).values())
        dsz = sum(st[p][1] for p in pk)
        note(R, f"probe (protected, not proposed) {ver}: pkgs={pk}; apt-get -s purge extra removals="
                f"{sorted(set(removed) - set(pk)) or 'none'}; du={fmt(dub)} dpkg Installed-Size={fmt(dsz)}")
    if exp_old and set(auto_k) and not set(auto_k) & {p for p in installed if any(v in p for v in exp_old)}:
        note(R, "apt autoremove disagrees with expected purge set")
    ROWS.append(Row("kernel:<ver>", len(exp_old), exp_b, len(reported), rep_b,
                    set_verdict(missing, extra, verdict_bytes(exp_b, rep_b, tol_rel=0.02)),
                    "installed images minus {running, 2 newest}; cross-checked with apt autoremove"))

    # leftover /lib/modules dirs
    R2 = "kernel-leftovers"
    exp = {}
    rc_pkgs = []
    for d in sorted(glob.glob(os.path.realpath("/lib/modules") + "/*")):
        ver = os.path.basename(d)
        if ver in keep or not os.path.isdir(d) or os.path.islink(d):
            continue
        owners = run(["dpkg", "-S", d]).stdout
        owner_pkgs = set()
        for l in owners.splitlines():
            if ":" in l:
                owner_pkgs |= {x.strip() for x in l.split(":")[0].split(",")}
        inst_owner = owner_pkgs & installed
        if inst_owner:
            note(R2, f"{d} owned by installed {sorted(inst_owner)} -> not a leftover")
            continue
        if any(ver in p for p in installed):
            continue
        if any(os.path.exists(f"/boot/{x}-{ver}") for x in ("vmlinuz", "initrd.img")):
            continue
        exp[d] = None
        # every linux-* package of this version still in dpkg's rc state
        rc_pkgs += sorted(p for p, (s_, _) in st.items()
                          if s_.startswith("rc") and p.startswith("linux-") and p.endswith("-" + ver))
    sizes = du_each(list(exp), sudo=True)
    f = rep.get(R2)
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(R2, set(exp), rp)
    eb, rb = sum(sizes.values()), (f["bytes"] if f else 0)
    if f and rc_pkgs:
        cmd = f["command"]
        m = re.search(r"dpkg --purge ([^;&]+)", cmd)
        got = sorted(m.group(1).split()) if m else []
        if got != sorted(set(rc_pkgs)):
            note(R2, f"WRONG rc purge list: expected {sorted(set(rc_pkgs))}, tool {got}")
            missing = missing or {"rc-purge"}
        else:
            note(R2, f"rc purge list matches dpkg-query: {got}")
    rc_all = sorted(p for p, (s, _) in st.items() if s.startswith("rc") and p.startswith("linux-"))
    note(R2, f"{len(rc_pkgs)} of these dirs are still listed by dpkg for packages in 'rc' state "
             f"(removed, config remains); {len(rc_all)} linux-* rc packages total. "
             f"`dpkg --purge` of them would run postrm purge (removes modules.* files) and clear the records.")
    ROWS.append(Row(R2, len(exp), eb, len(rp), rb,
                    set_verdict(missing, extra, verdict_bytes(eb, rb)),
                    "dirs in /lib/modules not kept, no *installed* owner (dpkg -S), du -sB1"))


# ------------------------------------------------------------------ 3. Snap

def check_snaps(rep):
    R = "snap-revisions"
    exp = {}
    rows = lines(["snap", "list", "--all"])[1:]
    for l in rows:
        c = l.split()
        if "disabled" in c[-1].split(","):
            exp[f"/var/lib/snapd/snaps/{c[0]}_{c[2]}.snap"] = (c[0], c[2])
    cache_inodes = {}
    for l in lines(["find", "/var/lib/snapd/cache", "-maxdepth", "1", "-type", "f",
                    "-printf", "%i\t%b\n"], sudo=True):
        i, b = l.split("\t")
        cache_inodes[int(i)] = int(b) * 512
    sizes, immediate, extra_data = {}, 0, 0
    for p, (name, rev) in exp.items():
        s = stat_blocks(p)
        if not s:
            note(R, f"{p}: missing on disk")
            continue
        b, nl, ino = s
        sizes[p] = b
        cached = ino in cache_inodes
        if nl == 1:
            immediate += b
        data = [d for d in (f"/var/snap/{name}/{rev}", f"{HOME}/snap/{name}/{rev}") if os.path.isdir(d)]
        dsz = sum(du_each(data, sudo=True).values())
        extra_data += dsz
        if nl != 1 or dsz > MIB:
            note(R, f"{name} r{rev}: {fmt(b)} nlink={nl} in-cache={cached} per-revision data={fmt(dsz)}")
    f = rep.get(R)
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(R, set(exp), rp)
    eb, rb = sum(sizes.values()) + extra_data, (f["bytes"] if f else 0)
    note(R, f"bytes freed immediately (nlink==1): {fmt(immediate)} of {fmt(eb)}; the rest waits for "
            f"snapd's cache cleanup to drop the /var/lib/snapd/cache hard link.")
    note(R, f"per-revision data dirs deleted by `snap remove --revision`: {fmt(extra_data)} "
            f"(counted, and named in the detail when >1 MiB)")
    if f and fmt(immediate) not in f["detail"] and fmt(immediate + extra_data) not in f["detail"]:
        note(R, "detail does not state the immediately-freed amount")
    ROWS.append(Row(R, len(exp), eb, len(rp), rb,
                    set_verdict(missing, extra, verdict_bytes(eb, rb)),
                    "snap list --all disabled rows, stat blocks of .snap + du of per-revision data"))


# ------------------------------------------------------------------ 4. Journal

JRE1 = re.compile(r"^(.+)@([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{16})\.journal$")
JRE2 = re.compile(r"^(.+)@([0-9a-f]{16})-([0-9a-f]{16})\.journal~$")


def check_journal(rep):
    R = "journal"
    du_line = run(["journalctl", "--disk-usage"], sudo=True).stdout.strip()
    note(R, "journalctl --disk-usage: " + du_line)
    files = []
    for l in lines(["find", "/var/log/journal", "-type", "f", "(", "-name", "*.journal",
                    "-o", "-name", "*.journal~", ")", "-printf", "%h\t%f\t%b\n"], sudo=True):
        d, n, b = l.split("\t")
        files.append((d, n, int(b) * 512))
    dirs = defaultdict(list)
    for d, n, b in files:
        dirs[d].append((n, b))
    total_files = sum(b for _, _, b in files)
    freed, removed = 0, []
    # systemd journal_directory_vacuum(): per directory, sum = all files (active too),
    # archived sorted by (seqnum within same seqnum_id | realtime), delete while sum > max.
    for d, fl in dirs.items():
        s = sum(b for _, b in fl)
        arch = []
        for n, b in fl:
            m = JRE1.match(n)
            if m:
                arch.append((m.group(2), int(m.group(4), 16), int(m.group(3), 16), n, b))
                continue
            m = JRE2.match(n)
            if m:
                arch.append((None, int(m.group(2), 16), 0, n, b))

        import functools

        def cmp(a, b):
            if a[0] and a[0] == b[0]:
                return (a[2] > b[2]) - (a[2] < b[2])
            r = (a[1] > b[1]) - (a[1] < b[1])
            return r if r else (a[3] > b[3]) - (a[3] < b[3])
        arch.sort(key=functools.cmp_to_key(cmp))
        for _, _, _, n, b in arch:
            if s <= JOURNAL_KEEP:
                break
            s -= b
            freed += b
            removed.append(n)
    f = rep.get(R)
    rb = f["bytes"] if f else 0
    measured = (rb + JOURNAL_KEEP) if f else None
    note(R, f"journal files total={fmt(total_files)}; tool measured size={fmt(measured)} "
            f"(includes directory blocks)")
    note(R, f"simulated vacuum-size=500M removes {len(removed)} archived files: {', '.join(removed)}")
    exp_min = max(0, total_files - JOURNAL_KEEP)
    if rb == freed:
        v = "EXACT"
    elif f and exp_min - 64 * 1024 <= rb <= freed:
        v = "OK-within-tolerance"
        note(R, f"tool estimate (size-keep) is a lower bound: vacuum removes whole files, so it frees "
                f"{fmt(freed)} (overshoot {fmt(freed - exp_min)} past the keep target).")
    elif not f and freed == 0:
        v = "EXACT"
    else:
        v = "WRONG"
    ROWS.append(Row(R, len(removed), freed, 1 if f else 0, rb, v,
                    "journald vacuum algorithm replayed on find -printf %b"))


# ------------------------------------------------------------------ 5. Rotated logs

STRICT = re.compile(r"(\.gz|\.xz|\.\d{1,3})$")
DATED = re.compile(r"\.log\.20\d\d(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\d{6})?$")


def rotated_name(n):
    """logrotate names: .gz/.xz, .N (1-3 digits, stem not ending in a number),
    or a date-stamped .log.YYYYMMDD[hhmmss]."""
    if n.endswith((".gz", ".xz")) or DATED.search(n):
        return True
    m = re.search(r"^(.*)\.(\d{1,3})$", n)
    return bool(m) and not re.search(r"(^|\.)\d+$", m.group(1))
EXTENDED = re.compile(r"(\.bz2|\.zst|\.lz4|\.old|\.Z|[-_.]\d{8}(\.\w+)?)$")


def check_rotated(rep):
    R = "rotated-logs"
    allf = {}
    for l in lines(["find", "/var/log", "(", "-path", "/var/log/journal", "-o", "-path",
                    "/var/log/installer", ")", "-prune", "-o", "-type", "f", "-printf", "%p\t%b\t%T@\n"],
                   sudo=True):
        p, b, t = l.split("\t")
        allf[p] = (int(b) * 512, float(t))
    exp = {p: v for p, v in allf.items()
           if rotated_name(os.path.basename(p)) and p != "/var/log/apt/eipp.log.xz"
           and not any(x.endswith(".index") for x in os.listdir(os.path.dirname(p)))}
    ext = {p: v for p, v in allf.items() if p not in exp and EXTENDED.search(os.path.basename(p))}
    f = rep.get(R)
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(R, set(exp), rp)
    eb, rb = sum(v[0] for v in exp.values()), (f["bytes"] if f else 0)
    # live-log check: open by a process, or no base log beside it
    openl = set(lines(["find", "/proc", "-mindepth", "3", "-maxdepth", "3", "-path", "/proc/[0-9]*/fd/*",
                       "-lname", "/var/log/*", "-printf", "%l\n"], sudo=True))
    for p in sorted(rp):
        if p in openl:
            note(R, f"LIVE: {p} is currently open by a process")
        base = re.sub(r"(\.\d+)?(\.gz|\.xz)?$", "", p)
        if base == p or not os.path.exists(base):
            note(R, f"SUSPECT (no base log '{os.path.basename(base)}' beside it): {p}")
    sl = lines(["find", "/var/log", "-type", "l", "-printf", "%p -> %l\n"], sudo=True)
    for s in sl:
        note(R, f"symlink under /var/log (not traversed by tool: Rust DirEntry::metadata is lstat on Unix; "
                f"also not counted here since find -type f): {s}")
    if ext:
        note(R, f"rotated-looking files outside the tool's predicate ({len(ext)}, "
                f"{fmt(sum(v[0] for v in ext.values()))}): " + ", ".join(sorted(ext)[:10]))
    ROWS.append(Row(R, len(exp), eb, len(rp), rb,
                    set_verdict(missing, extra, verdict_bytes(eb, rb, tol_abs=64 * 1024)),
                    "sudo find /var/log; .N/.gz/.xz; excl journal/installer/eipp.log.xz"))


# ------------------------------------------------------------------ 6. Crash

def check_crash(rep):
    R = "crash"
    exp = {}
    for l in lines(["find", "/var/crash", "-maxdepth", "1", "-type", "f", "!", "-name", ".*",
                    "-printf", "%p\t%b\n"], sudo=True):
        p, b = l.split("\t")
        exp[p] = int(b) * 512
    other = lines(["find", "/var/crash", "-mindepth", "1", "(", "-name", ".*", "-o", "!", "-type", "f", ")"],
                  sudo=True)
    if other:
        note(R, f"not covered (hidden/non-regular): {other}")
    f = rep.get(R)
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(R, set(exp), rp)
    eb, rb = sum(exp.values()), (f["bytes"] if f else 0)
    ROWS.append(Row(R, len(exp), eb, len(rp), rb, set_verdict(missing, extra, verdict_bytes(eb, rb)),
                    "find /var/crash -maxdepth 1 -type f"))


# ------------------------------------------------------------------ 7. Docker

UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


def dsize(s):
    m = re.match(r"([\d.]+)\s*([kKMGT]?B)", s or "0B")
    return int(float(m.group(1)) * UNITS[m.group(2)]) if m else 0


def check_docker(rep):
    R = "docker"
    for sudo in (False, True):
        p = run(["docker", "system", "df", "-v", "--format", "{{json .}}"], sudo)
        if p.returncode == 0:
            break
    else:
        note(R, "docker not accessible; skipped")
        ROWS.append(Row(R, None, None, None, None, "SKIPPED"))
        return
    df = json.loads(p.stdout)
    dang = [i for i in df.get("Images") or []
            if i.get("Repository") in ("<none>", "") and i.get("Tag") in ("<none>", "")
            and int(i.get("Containers") or 0) <= 0]
    dang_b = sum(dsize(i.get("UniqueSize")) for i in dang)
    bc = [c for c in df.get("BuildCache") or [] if not c.get("InUse") and not c.get("Shared")]
    bc_b = sum(dsize(c.get("Size")) for c in bc)
    note(R, f"docker images -f dangling=true -q: {lines(['docker', 'images', '-f', 'dangling=true', '-q'], sudo) or 'none'}")
    note(R, f"build cache records {len(df.get('BuildCache') or [])}, prunable non-shared {len(bc)}")
    vols = [v for v in df.get("Volumes") or [] if str(v.get("Links")) == "0"]
    if vols:
        note(R, f"scope gap (not a tool rule): {len(vols)} unreferenced volumes "
                f"{fmt(sum(dsize(v.get('Size')) for v in vols))} (docker volume prune)")
    for fid, eb, n in (("docker-dangling", dang_b, len(dang)), ("docker-builder", bc_b, len(bc))):
        f = rep.get(fid)
        rb = f["bytes"] if f else 0
        eff = eb if eb >= MIN_FINDING else 0
        v = verdict_bytes(eff, rb, tol_rel=0.01)  # docker df rounds to 3-4 sig digits
        if eff and not f:
            v = "MISSING"
        if f and not eff:
            v = "FALSE-POSITIVE"
        ROWS.append(Row(fid, n, eff, 1 if f else 0, rb, v, "docker system df -v (decimal units, rounded)"))


# ------------------------------------------------------------------ 8. User caches

CACHES = {
    "thumbnails": [".cache/thumbnails"],
    "pip-cache": [".cache/pip/http", ".cache/pip/http-v2", ".cache/pip/wheels", ".cache/pip/selfcheck"],
    "cargo-registry": [".cargo/registry/cache", ".cargo/registry/src"],
    "cargo-git": [".cargo/git/checkouts"],
    "npm-cache": [".npm/_cacache"],
    "trash": [".local/share/Trash/files", ".local/share/Trash/info"],
}


def check_user_caches(rep):
    for fid, rels in CACHES.items():
        dirs = [os.path.join(HOME, r) for r in rels if os.path.isdir(os.path.join(HOME, r))]
        sizes = du_each(dirs)
        eb = sum(sizes[d] - stat_blocks(d, sudo=False)[0] for d in dirs)
        eff = eb if eb >= MIN_FINDING else 0
        f = rep.get(fid)
        rb = f["bytes"] if f else 0
        rp = set(f["paths"]) if f else set()
        missing, extra = compare_sets(fid, set(dirs) if eff else set(), rp)
        if eb and not eff:
            note(fid, f"{fmt(eb)} below the 1 MiB finding threshold")
        ROWS.append(Row(fid, len(dirs), eff, len(rp), rb,
                        set_verdict(missing, extra, verdict_bytes(eff, rb, tol_rel=0.002)),
                        "du -sxB1 minus dir's own blocks"))
    other_trash = [p for p in glob.glob("/media/*/*/.Trash-1000") + glob.glob("/mnt/*/.Trash-1000")]
    if other_trash:
        note("trash", f"per-volume trash dirs not covered: "
                      f"{ {p: fmt(v) for p, v in du_each(other_trash).items()} }")


# ------------------------------------------------------------------ 9. Project artifacts

def walk_artifacts(root, skip_hidden=True, skip=(), hidden_log=None):
    """Independent walk (-xdev, no symlink following). Returns (rust, node, pycache) lists."""
    rust, node, pyc = [], [], []
    dev = os.lstat(root).st_dev
    stack = [(root, False)]
    while stack:
        d, in_nm = stack.pop()
        try:
            ents = list(os.scandir(d))
        except OSError:
            continue
        names = {e.name for e in ents}
        for e in ents:
            try:
                if not e.is_dir(follow_symlinks=False):
                    continue
                if e.stat(follow_symlinks=False).st_dev != dev:
                    continue
            except OSError:
                continue
            p = e.path
            if p in skip:
                if hidden_log is not None:
                    hidden_log.append(p)
                continue
            if e.name.startswith(".") and skip_hidden:
                if hidden_log is not None:
                    hidden_log.append(p)
                continue
            if e.name == "target" and ("Cargo.toml" in names or os.path.exists(os.path.join(p, "CACHEDIR.TAG"))):
                rust.append(p)
            elif e.name == "node_modules":
                # Restorable project installs only: package.json + a lockfile (or the
                # package manager's install record), never inside an app bundle; and
                # never descend into any node_modules.
                locks = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"}
                marks = (".package-lock.json", ".yarn-integrity", ".modules.yaml", ".yarn-state.yml")
                restorable = (names & locks) or any(os.path.isfile(os.path.join(p, m)) for m in marks)
                bundle = "/resources/app" in d or d.endswith("/resources") or any(
                    x.endswith(".asar") for dd in (d, os.path.dirname(d)) for x in (os.listdir(dd) if os.path.isdir(dd) else []))
                if "package.json" in names and not in_nm and restorable and not bundle:
                    node.append(p)
            elif e.name == "__pycache__":
                pyc.append(p)
            else:
                stack.append((p, in_nm))
    return rust, node, pyc


def check_artifacts(rep):
    hidden = []
    rust, node, pyc = walk_artifacts(HOME, skip=(os.path.join(HOME, "snap"),), hidden_log=hidden)
    art = rust + node
    asz = du_each(art)
    psz = du_batch(pyc)
    # tool reports node/rust individually (>=1 MiB, top 60 by size)
    ranked = sorted((p for p in art if asz[p] >= MIN_FINDING), key=lambda p: -asz[p])
    exp_art = {p: asz[p] for p in ranked[:MAX_PROJECT_FINDINGS]}
    rep_art = {f["paths"][0]: f["bytes"] for fid, f in rep.items() if fid.startswith(("rust:", "node:"))}
    R = "project-artifacts"
    missing, extra = compare_sets(R, set(exp_art), set(rep_art))
    worst = 0.0
    for p in set(exp_art) & set(rep_art):
        d = rep_art[p] - exp_art[p]
        rel = abs(d) / max(exp_art[p], 1)
        worst = max(worst, rel)
        if d:
            try:
                age = subprocess.run(["find", p, "-newermt", "-10 minutes", "-print", "-quit"],
                                     capture_output=True, text=True).stdout.strip()
            except Exception:
                age = ""
            note(R, f"{p}: expected {asz[p]} reported {rep_art[p]} delta {fmt(d)}"
                    + (" (tree modified in last 10 min: live build)" if age else ""))
    below = [p for p in art if asz[p] < MIN_FINDING]
    if below:
        note(R, f"{len(below)} artifacts below 1 MiB not listed (by design)")
    eb, rb = sum(exp_art.values()), sum(rep_art.values())
    bv = verdict_bytes(eb, rb, tol_rel=0.05) if worst > 0 else "EXACT"
    ROWS.append(Row("rust:/node: artifacts", len(exp_art), eb, len(rep_art), rb,
                    set_verdict(missing, extra, bv), "own walk: target+Cargo.toml|CACHEDIR.TAG, node_modules+package.json"))

    R = "pycache"
    f = rep.get(R)
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(R, set(pyc), rp)
    eb, rb = sum(psz.values()), (f["bytes"] if f else 0)
    ROWS.append(Row(R, len(pyc), eb, len(rp), rb, set_verdict(missing, extra, verdict_bytes(eb, rb, tol_rel=0.002)),
                    "own walk, du -sxB1 batch"))

    # hidden-dir policy: what the exclusion hides
    Rh = "hidden-policy"
    tot = defaultdict(int)
    for h in hidden:
        r2, n2, p2 = walk_artifacts(h, skip_hidden=False)
        if os.path.basename(h) in ("target", "node_modules") and False:
            pass
        items = r2 + n2
        s_items = du_each(items)
        s_py = sum(du_batch(p2).values())
        big = sorted(((s, p) for p, s in s_items.items() if s >= 10 * MIB), reverse=True)
        tot[h] = sum(s_items.values()) + s_py
        for s, p in big[:4]:
            note(Rh, f"excluded by hidden/~snap policy: {p} {fmt(s)}")
        if s_py >= 10 * MIB:
            note(Rh, f"excluded __pycache__ under {h}: {fmt(s_py)} in {len(p2)} dirs")
    top = sorted(tot.items(), key=lambda x: -x[1])[:6]
    note(Rh, "per excluded root: " + ", ".join(f"{p.replace(HOME, '~')}={fmt(s)}" for p, s in top if s))
    ROWS.append(Row(Rh, None, sum(tot.values()), None, None, "INFO", "artifacts inside hidden dirs and ~/snap"))


# ------------------------------------------------------------------ 10. Totals / overlap

def check_totals(rep_json, label):
    R = f"totals({label})"
    sums = defaultdict(int)
    for f in rep_json["findings"]:
        sums[f["risk"].lower()] += f["bytes"]
    ok = all(sums[k] == v for k, v in rep_json["reclaimable"].items())
    for k, v in rep_json["reclaimable"].items():
        if sums[k] != v:
            note(R, f"{k}: reported {v} != sum of findings {sums[k]}")
    owner = {}
    over = []
    for f in rep_json["findings"]:
        for p in f["paths"]:
            if p in owner and owner[p] != f["id"]:
                over.append((p, owner[p], f["id"]))
            owner.setdefault(p, f["id"])
    allp = sorted(owner)
    ps = set(allp)
    for p in allp:
        a = os.path.dirname(p)
        while a and a != "/":
            if a in ps and owner[a] != owner[p]:
                over.append((p, owner[a], owner[p]))
                break
            a = os.path.dirname(a)
    for o in over[:10]:
        note(R, f"OVERLAP: {o[0]} in {o[1]} and {o[2]}")
    ROWS.append(Row(R, None, sum(rep_json["reclaimable"].values()), None, sum(sums.values()),
                    "EXACT" if ok and not over else "WRONG", f"{len(over)} overlaps"))


def consistency(user, root):
    R = "user-vs-root"
    u, r = by_id(user), by_id(root)
    for fid in sorted(set(u) | set(r)):
        a, b = u.get(fid), r.get(fid)
        if not a or not b:
            note(R, f"{fid}: only in {'root' if b else 'user'} run")
        elif a["bytes"] != b["bytes"]:
            note(R, f"{fid}: user {a['bytes']} root {b['bytes']} ({fmt(b['bytes'] - a['bytes'])})")
    if user.get("notes"):
        note(R, "user-run notes: " + " | ".join(user["notes"]))


# ------------------------------------------------------------------ 11. Desktop & developer rules

def is_manual(f):
    return f["command"].startswith("(no automatic")


def pgrep(*args):
    return run(["pgrep", *args]).returncode == 0


def contents_bytes(dirs):
    sizes = du_each(dirs)
    return sum(sizes[d] - stat_blocks(d, sudo=False)[0] for d in dirs)


def unique_bytes(d):
    """Blocks freed by emptying d: dirs + files with a single link (find -links 1)."""
    tot = 0
    for l in lines(["find", d, "-mindepth", "1", "-xdev", "(", "-type", "d", "-o", "-links", "1", ")",
                    "-printf", "%b\n"]):
        tot += int(l) * 512
    return tot


def row_for(fid, rep, exp_dirs, exp_bytes, why, expect_manual=None, tol_rel=0.002):
    eff = exp_bytes if exp_bytes >= MIN_FINDING else 0
    f = rep.get(fid)
    rb = f["bytes"] if f else 0
    rp = set(f["paths"]) if f else set()
    missing, extra = compare_sets(fid, set(exp_dirs) if eff else set(), rp)
    v = set_verdict(missing, extra, verdict_bytes(eff, rb, tol_rel=tol_rel))
    if f and expect_manual is not None and is_manual(f) != expect_manual:
        v = "WRONG"
        note(fid, f"expected {'MANUAL (app running)' if expect_manual else 'actionable'}, "
                  f"tool reported {'MANUAL' if is_manual(f) else 'actionable'}")
    if f and is_manual(f):
        note(fid, "manual step: " + f["detail"].split("\n")[0][:140])
    ROWS.append(Row(fid, len(exp_dirs), eff, len(rp), rb, v, why))


def check_desktop_rules(rep, root_rep):
    H = HOME
    # --- plain cache dirs (contents only; dirs are kept)
    plain = {
        "selenium-cache": [".cache/selenium"], "playwright-cache": [".cache/ms-playwright"],
        "mesa-shader-cache": [".cache/mesa_shader_cache", ".cache/mesa_shader_cache_db"],
        "yarn-cache": [".cache/yarn"], "go-build-cache": [".cache/go-build"],
        "poetry-cache": [".cache/pypoetry/cache"], "gradle-cache": [".gradle/caches", ".gradle/wrapper/dists"],
        "tracker3": [".cache/tracker3"], "huggingface-hub": [".cache/huggingface/hub"],
        "go-mod-cache": ["go/pkg/mod"],
    }
    for fid, rels in plain.items():
        dirs = [os.path.join(H, r) for r in rels if os.path.isdir(os.path.join(H, r))]
        manual = True if fid == "huggingface-hub" else None
        row_for(fid, rep, dirs, contents_bytes(dirs), "du -sxB1 minus dir's own blocks", manual)
    # npx: manual while an npx-launched program runs
    npx = os.path.join(H, ".npm/_npx")
    if os.path.isdir(npx):
        row_for("npx-cache", rep, [npx], contents_bytes([npx]), "du; running via pgrep -f /_npx/",
                pgrep("-f", "/_npx/"))
    # --- hard-link-aware caches
    for fid, rel in {"uv-cache": ".cache/uv", "pnpm-store": ".local/share/pnpm/store"}.items():
        d = os.path.join(H, rel)
        if os.path.isdir(d):
            row_for(fid, rep, [d], unique_bytes(d), "find -links 1 (dirs + single-link files)")
            note(fid, f"plain du would say {fmt(du_each([d])[d])}")
    # --- browsers: exact cache children; manual iff the browser runs (pgrep)
    chrome = sorted(glob.glob(f"{H}/.cache/google-chrome/*/Cache") + glob.glob(f"{H}/.cache/google-chrome/*/Code Cache")
                    + glob.glob(f"{H}/.cache/google-chrome/*/GPUCache"))
    if chrome:
        row_for("chrome-cache", rep, chrome, contents_bytes(chrome), "glob profile Cache dirs; pgrep -x chrome",
                pgrep("-x", "chrome"))
    ffs = sorted(glob.glob(f"{H}/snap/firefox/common/.cache/mozilla/firefox/*/cache2"))
    if ffs:
        row_for("firefox-snap-cache", rep, ffs, contents_bytes(ffs), "glob cache2; pgrep -x firefox",
                pgrep("-x", "firefox"))
    ffd = sorted(glob.glob(f"{H}/.cache/mozilla/firefox/*/cache2"))
    if ffd:
        row_for("firefox-cache", rep, ffd, contents_bytes(ffd), "glob cache2; pgrep -x firefox", pgrep("-x", "firefox"))
    # --- Electron apps: Chromium disk cache marker; idle = no SingletonLock; cross-check pgrep
    idle, busy = [], []
    for app in sorted(glob.glob(f"{H}/.config/*/")):
        app = app.rstrip("/")
        name = os.path.basename(app)
        if name in ("google-chrome", "chromium", "BraveSoftware", "microsoft-edge"):
            continue
        c = os.path.join(app, "Cache")
        if not (os.path.exists(os.path.join(c, "index")) or os.path.exists(os.path.join(c, "Cache_Data", "index"))):
            continue
        locked = os.path.lexists(os.path.join(app, "SingletonLock")) or os.path.lexists(os.path.join(app, "code.lock"))
        running = pgrep("-if", f"/{name.lower()}") or pgrep("-if", f"{name}")
        lk = os.path.join(app, "SingletonLock")
        if os.path.islink(lk):
            m = re.match(r"^(.*)-(\d+)$", os.readlink(lk))
            if m and m.group(1) == os.uname().nodename and not os.path.exists(f"/proc/{m.group(2)}"):
                locked = False  # stale lock left by a crash
                note("electron-cache", f"{name}: stale SingletonLock (pid {m.group(2)} gone) -> idle")
        if locked != running:
            note("electron-cache", f"{name}: lock={locked} but pgrep running={running}")
        (busy if locked else idle).extend([] if locked else
            [os.path.join(app, x) for x in ("Cache", "Code Cache", "GPUCache", "CachedData") if os.path.isdir(os.path.join(app, x))])
        if locked:
            busy.append(name)
    row_for("electron-cache", rep, idle, contents_bytes(idle), "Chromium cache marker; SingletonLock; pgrep cross-check")
    if busy:
        note("electron-cache", "skipped (running): " + ", ".join(busy))
    # --- obsolete editor extensions (independent JSON parse)
    obs = []
    for base in (".vscode/extensions", ".vscode-oss/extensions", ".cursor/extensions", ".windsurf/extensions", ".vscode-server/extensions"):
        root = os.path.join(H, base)
        try:
            data = json.load(open(os.path.join(root, ".obsolete")))
        except (OSError, ValueError):
            continue
        for k, v in (data.items() if isinstance(data, dict) else []):
            p = os.path.join(root, k)
            if v is True and "/" not in k and k not in (".", "..") and os.path.isdir(p) and not os.path.islink(p):
                obs.append(p)
    if obs:
        row_for("obsolete-extensions", rep, sorted(obs), sum(du_each(obs).values()), ".obsolete JSON parsed independently")
    # --- JetBrains superseded versions (independent regex)
    groups = defaultdict(list)
    for p in glob.glob(f"{H}/.cache/JetBrains/*"):
        m = re.match(r"^([A-Za-z]+)(\d+(?:\.\d+)*)$", os.path.basename(p))
        if m:
            groups[m.group(1)].append((tuple(int(x) for x in m.group(2).split(".")), p))
    old = sorted(p for g in groups.values() for _, p in sorted(g)[:-1])
    row_for("jetbrains-old-caches", rep, old, sum(du_each(old).values()) if old else 0, "regex product+version, keep newest")
    # --- root-side: snapd orphans, core dumps, orphaned packages
    orphans = {}
    for l in lines(["find", "/var/lib/snapd/cache", "-maxdepth", "1", "-type", "f", "-links", "1",
                    "-printf", "%p\t%b\n"], sudo=True):
        pth, b = l.split("\t")
        orphans[pth] = int(b) * 512
    row_for("snapd-cache-orphans", root_rep, sorted(orphans), sum(orphans.values()), "sudo find -links 1")
    cores = {}
    for l in lines(["find", "/var/lib/systemd/coredump", "-maxdepth", "1", "-type", "f", "-printf", "%p\t%b\n"], sudo=True):
        pth, b = l.split("\t")
        cores[pth] = int(b) * 512
    row_for("coredumps", root_rep, sorted(cores), sum(cores.values()), "sudo find /var/lib/systemd/coredump")
    sim = run(["apt-get", "-s", "autoremove", "--purge"]).stdout
    pk = sorted({l.split()[1].split(":")[0] for l in sim.splitlines() if l.startswith(("Remv ", "Purg "))
                 if not re.match(r"linux-(image|modules|headers|tools|hwe)-", l.split()[1])})
    size = 0
    for l in lines(["dpkg-query", "-W", "-f", "${Package} ${Installed-Size} ${db:Status-Abbrev}\n"]):
        c = l.split()
        if len(c) >= 3 and c[0] in pk and c[2].startswith("ii"):
            size += int(c[1]) * 1024
    f = root_rep.get("apt-autoremove")
    eff = size if size >= MIN_FINDING else 0
    rb = f["bytes"] if f else 0
    ROWS.append(Row("apt-autoremove", len(pk), eff, 1 if f else 0, rb, verdict_bytes(eff, rb),
                    "apt-get -s autoremove (non-kernel) + dpkg-query Installed-Size"))
    if pk:
        note("apt-autoremove", "would remove: " + ", ".join(pk))


def coverage_report(rep):
    """Every ~/.cache child over 50 MiB, and whether any finding covers it."""
    R = "coverage(~/.cache)"
    paths = [p for f in rep["findings"] for p in f["paths"]]
    kids = [os.path.join(HOME, ".cache", k) for k in os.listdir(os.path.join(HOME, ".cache"))]
    sizes = du_each([k for k in kids if os.path.isdir(k) and not os.path.islink(k)])
    covered = uncovered = 0
    for k, sz in sorted(sizes.items(), key=lambda x: -x[1]):
        if sz < 50 * MIB:
            continue
        hit = any(p == k or p.startswith(k + "/") for p in paths)
        covered += sz if hit else 0
        uncovered += 0 if hit else sz
        note(R, f"{'covered  ' if hit else 'UNCOVERED'} {fmt(sz):>10}  {k.replace(HOME, '~')}")
    ROWS.append(Row(R, None, None, None, None, "INFO",
                    f"covered {fmt(covered)}, not covered {fmt(uncovered)}"))


# ------------------------------------------------------------------ main

def main():
    global TOOL
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", default=TOOL)
    ap.add_argument("--json")
    a = ap.parse_args()
    TOOL = a.tool
    if run(["sudo", "-n", "true"]).returncode != 0:
        raise SystemExit("needs passwordless sudo for read-only inspection")
    root = tool_report(sudo=True)
    user = tool_report(sudo=False)
    rr, ur = by_id(root), by_id(user)
    consistency(user, root)
    check_apt(rr)
    check_kernels(rr)
    check_snaps(rr)
    check_journal(rr)
    check_rotated(rr)
    check_crash(rr)
    check_docker(ur)
    # user-side rules: re-run the user report right before measuring (live dirs)
    user2 = tool_report(sudo=False)
    check_user_caches(by_id(user2))
    user3 = tool_report(sudo=False)
    check_artifacts(by_id(user3))
    user4 = tool_report(sudo=False)
    check_desktop_rules(by_id(user4), rr)
    coverage_report(user4)
    check_totals(user, "user")
    check_totals(root, "root")

    hdr = f"{'rule':26} {'exp#':>5} {'expected':>11} {'rep#':>5} {'reported':>11} {'delta':>10}  verdict"
    print(hdr)
    print("-" * len(hdr))
    for r in ROWS:
        e = "-" if r.exp_items is None else r.exp_items
        p = "-" if r.rep_items is None else r.rep_items
        print(f"{r.rule[:26]:26} {e:>5} {fmt(r.exp_bytes):>11} {p:>5} {fmt(r.rep_bytes):>11} "
              f"{fmt(r.delta()):>10}  {r.verdict}")
    print()
    for rule, msgs in DETAILS.items():
        print(f"[{rule}]")
        for m in msgs:
            print("  - " + m)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"rows": [r.__dict__ for r in ROWS], "details": DETAILS}, fh, indent=1)
    bad = [r for r in ROWS if r.verdict in ("WRONG", "MISSING", "FALSE-POSITIVE")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
