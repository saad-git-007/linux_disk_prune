#!/usr/bin/env python3
"""Safety-audit reproducers for linux_disk_prune.

Every reproducer builds a throw-away fixture (under $AUDIT_TMP, default: a new
temp dir) or runs inside a disposable ubuntu:22.04 container, runs the app in
read-only report mode (--json --rules-only), and — where a deletion has to be
shown — executes the emitted command ONLY against the fixture / container.
Nothing is ever deleted on the real system.

Exit status: 0 when no reproducer shows a bug, 1 otherwise.

  LDP_BIN=/path/to/linux_disk_prune python3 tests/safety/audit/run_audit_repros.py [--no-docker]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("LDP_BIN") or shutil.which("linux_disk_prune") or os.path.join(HERE, "../../../target/release/linux_disk_prune")
BASE = os.environ.get("AUDIT_TMP") or tempfile.mkdtemp(prefix="ldp-audit-")
os.makedirs(BASE, exist_ok=True)
MIB = 1 << 20
results = []  # (name, severity, bug, evidence)


def record(name, severity, bug, evidence):
    results.append((name, severity, bug, evidence))
    print(f"[{'BUG ' if bug else 'ok  '}] {severity:8} {name}: {evidence}")


def fixture(name):
    d = os.path.join(BASE, name)
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)
    return d


def put(path, size=0, text=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(text.encode() if text is not None else os.urandom(size))
    return path


def run_ldp(home, extra_env=None, path_prefix=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C"}
    if path_prefix:
        env["PATH"] = path_prefix + ":" + env["PATH"]
    env.update(extra_env or {})
    out = subprocess.run([BIN, "--json", "--rules-only", "--home", home, "--dev-root", home],
                         env=env, capture_output=True, text=True, timeout=300)
    return json.loads(out.stdout)


def by_id(report, fid):
    return next((f for f in report["findings"] if f["id"] == fid), None)


# ----------------------------------------------------------------------------- host fixtures

def repro_node_modules_in_app_bundle():
    """A tarball-installed Electron app (VS Code, Discord, Obsidian …) unpacked in
    $HOME has resources/app/package.json + node_modules: offered for deletion as
    'restorable with npm ci' — deleting it breaks the program."""
    h = fixture("node-bundle")
    app = os.path.join(h, "VSCode-linux-x64/resources/app")
    put(os.path.join(app, "package.json"), text='{"name":"code-oss-dev","main":"./out/main"}')
    put(os.path.join(app, "node_modules/vscode-oniguruma/release/onig.wasm"), 2 * MIB)
    r = run_ldp(h)
    f = by_id(r, "node:" + os.path.join(app, "node_modules"))
    record("node_modules_inside_installed_app", "HIGH", f is not None,
           f"{f['risk']} finding, command: {f['command']}" if f else "not offered")


def repro_pip_cache_dir_is_home():
    """PIP_CACHE_DIR is emptied wholesale; nothing validates it."""
    h = fixture("pip-home")
    put(os.path.join(h, "Documents/thesis.odt"), 2 * MIB)
    r = run_ldp(h, {"PIP_CACHE_DIR": h})
    f = by_id(r, "pip-cache")
    bug = f is not None and f["paths"] == [h]
    record("pip_cache_dir_equals_home", "HIGH", bug,
           f"{f['risk']} finding, command: {f['command']}" if f else "not offered")

    h = fixture("pip-cache-root")
    put(os.path.join(h, ".cache/huggingface/hub/models--private--finetune/blob"), 2 * MIB)
    r = run_ldp(h, {"PIP_CACHE_DIR": os.path.join(h, ".cache")})
    f = by_id(r, "pip-cache")
    hf = by_id(r, "huggingface-hub")
    bug = f is not None and f["risk"] == "SAFE" and hf is not None and hf["risk"] == "CAUTION"
    record("pip_cache_dir_is_whole_xdg_cache", "HIGH", bug,
           f"pip-cache SAFE `{f['command']}` would also wipe the model that huggingface-hub marks {hf['risk']}" if bug else "n/a")


def repro_apport_report_dir():
    """APPORT_REPORT_DIR is trusted and every non-hidden file in it is deleted as SAFE."""
    h = fixture("apport")
    docs = os.path.join(h, "Documents")
    put(os.path.join(docs, "thesis.pdf"), 2 * MIB)
    r = run_ldp(h, {"APPORT_REPORT_DIR": docs})
    f = by_id(r, "crash")
    # A crash finding for the real /var/crash is fine; only one reaching into docs is a bug.
    record("apport_report_dir_env_deletes_any_file", "MEDIUM", f is not None and (docs in f["command"] or any(docs in p for p in f["paths"])),
           f"{f['risk']} `{f['command']}`" if f else "not offered")


def repro_snap_reverted_revision():
    """After `snap revert`, the *newer* revision is 'disabled' and its per-revision
    data dir holds the most recent user data; it is removed like any old revision."""
    h = fixture("snap-revert")
    fake = os.path.join(h, "fakebin")
    mount = os.path.join(h, "snapmount")
    os.makedirs(os.path.join(mount, "notes-app"))
    os.symlink("4900", os.path.join(mount, "notes-app/current"))
    put(os.path.join(h, "snap/notes-app/5000/notes.db"), 3 * MIB)   # data written with rev 5000
    put(os.path.join(h, "snap/notes-app/4900/notes.db"), 1 * MIB)   # older copy
    put(os.path.join(fake, "snap"), text=f"""#!/bin/sh
case "$1 $2" in
"list --all") printf 'Name       Version  Rev   Tracking       Publisher  Notes\\nnotes-app  2.0      5000  latest/stable  someone    disabled\\nnotes-app  1.9      4900  latest/stable  someone    -\\n';;
"debug paths") printf 'SNAPD_MOUNT={mount}\\n';;
*) exit 1;;
esac
""")
    os.chmod(os.path.join(fake, "snap"), 0o755)
    r = run_ldp(h, path_prefix=fake)
    f = by_id(r, "snap-revisions")
    bug = f is not None and "--revision=5000" in f["command"] and f["risk"] == "MODERATE"
    record("snap_removes_newer_reverted_revision", "MEDIUM", bug,
           f"{f['risk']} `{f['command']}` although current=4900 < 5000" if f else "not offered")


def repro_flatpak_running_app_not_detected():
    """Running Flatpak apps are detected by their app id appearing in some
    process cmdline; bwrap passes arguments via fd, so most apps are missed.
    Their cache dir is also their TMPDIR (…/cache/tmp)."""
    h = fixture("flatpak-busy")
    app = "org.example.Editor"
    tmp = os.path.join(h, f".var/app/{app}/cache/tmp")
    put(os.path.join(tmp, "unsaved-autosave.odt"), 2 * MIB)
    env = dict(os.environ, FLATPAK_ID=app, TMPDIR=tmp)
    # Same shape as a real sandboxed process: cmdline is the in-sandbox binary.
    p = subprocess.Popen(["bash", "-c", "exec -a /app/bin/editor sleep 30"], env=env)
    try:
        time.sleep(0.3)
        r = run_ldp(h)
    finally:
        p.kill()
    f = by_id(r, "flatpak-app-cache")
    bug = f is not None and any(app in pth for pth in f["paths"])
    record("flatpak_running_app_cache_offered", "MEDIUM", bug,
           f"running app's cache (its TMPDIR) offered: `{f['command']}`" if bug else "skipped")


def repro_home_flag_env_leak():
    """--home names the user whose caches are analysed, but XDG_*/CARGO_HOME of the
    invoking user still apply."""
    h = fixture("home-leak")
    other = fixture("home-leak-other")
    put(os.path.join(other, "thumbnails/large/x.png"), 2 * MIB)
    r = run_ldp(h, {"XDG_CACHE_HOME": other})
    f = by_id(r, "thumbnails")
    # HOME is the fixture too, so XDG_CACHE_HOME is that user's own setting and
    # honouring it is correct; a leak is only when --home differs from $HOME.
    r2 = run_ldp(h, {"XDG_CACHE_HOME": other, "HOME": other})
    f2 = by_id(r2, "thumbnails")
    bug = f2 is not None and f2["paths"][0].startswith(other)
    f = f2
    record("home_flag_mixes_callers_env", "LOW", bug, f"--home {h} but target {f['paths']}" if bug else "n/a")


def repro_find_crosses_mounts():
    """The displayed keep_dir command (`find X -mindepth 1 -delete`, printed with
    'Run the commands above yourself') has no -xdev: it empties filesystems
    mounted below X, which the in-process remover refuses to do."""
    h = fixture("xdev")
    put(os.path.join(h, ".cache/thumbnails/large/a.png"), 2 * MIB)
    os.makedirs(os.path.join(h, ".cache/thumbnails/usb"))
    script = f"""
mount -t tmpfs tmpfs {h}/.cache/thumbnails/usb
echo precious > {h}/.cache/thumbnails/usb/on-other-fs.txt
cmd=$(env -i PATH=/usr/bin:/bin HOME={h} LC_ALL=C {BIN} --json --rules-only --home {h} --dev-root {h} | python3 -c 'import json,sys; print(next(f["command"] for f in json.load(sys.stdin)["findings"] if f["id"]=="thumbnails"))')
echo "CMD $cmd"
sh -c "$cmd" 2>&1 | sed "s/^/FIND: /" || true
[ -e {h}/.cache/thumbnails/usb/on-other-fs.txt ] && echo SURVIVED || echo DELETED
"""
    try:
        o = subprocess.run(["unshare", "-rm", "bash", "-c", script], capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return record("find_command_crosses_mounts", "LOW", False, "unshare unavailable (skipped)")
    out = o.stdout
    record("find_command_crosses_mounts", "LOW", "DELETED" in out,
           (out.strip().replace("\n", " | ") or o.stderr.strip())[:300])


def repro_docker_context_mismatch():
    """Analysis talks to /var/run/docker.sock (or DOCKER_HOST=unix://); the
    command `docker image prune -f` goes to the CLI's current context."""
    if not shutil.which("docker") or not os.path.exists("/var/run/docker.sock"):
        return record("docker_prune_targets_other_daemon", "MEDIUM", False, "docker unavailable (skipped)")
    h = fixture("docker-ctx")
    cfg = os.path.join(h, "dockercfg")
    os.makedirs(cfg)
    env = dict(os.environ, DOCKER_CONFIG=cfg)
    subprocess.run(["docker", "context", "create", "prod", "--docker", "host=ssh://deploy@203.0.113.10"],
                   env=env, capture_output=True)
    subprocess.run(["docker", "context", "use", "prod"], env=env, capture_output=True)
    ctx = subprocess.run(["docker", "context", "show"], env=env, capture_output=True, text=True).stdout.strip()
    r = run_ldp(h, {"DOCKER_CONFIG": cfg})
    f = by_id(r, "docker-dangling") or by_id(r, "docker-builder")
    # `docker -H <socket>` ignores the current context: only a bare command is a bug.
    bug = f is not None and ctx == "prod" and " -H " not in f["command"]
    record("docker_prune_targets_other_daemon", "MEDIUM", bug,
           f"sized from local socket, but `{f['command']}` would run against context '{ctx}' (ssh://deploy@203.0.113.10)"
           if bug else f"no docker finding on this host (context={ctx})")


# ----------------------------------------------------------------------------- containers

def repro_containers():
    if not shutil.which("docker"):
        return print("docker not available: container reproducers skipped")
    if subprocess.run(["docker", "image", "inspect", "ubuntu:22.04"], capture_output=True).returncode != 0:
        return print("ubuntu:22.04 image not present: container reproducers skipped")
    sev = {
        "kernel_leftover_toctou": "CRITICAL",
        "rotated_logs_mysql_binlog": "HIGH",
        "rotated_logs_ip_named_file": "MEDIUM",
        "root_rm_follows_parent_symlink": "MEDIUM",
        "autoremove_purges": "HIGH",
    }
    for phase in ["kernel", "logs", "autoremove", "autoremove_contrast"]:
        o = subprocess.run(["docker", "run", "--rm", "--network", "none",
                            "-v", f"{os.path.abspath(BIN)}:/ldp:ro",
                            "-v", f"{HERE}/container_repro.sh:/repro.sh:ro",
                            "ubuntu:22.04", "bash", "/repro.sh", phase],
                           capture_output=True, text=True, timeout=600)
        for line in o.stdout.splitlines():
            if line.startswith("INFO"):
                print("      " + line[:400])
            elif line.startswith("RESULT"):
                _, name, verdict, ev = (line.split(" ", 3) + ["", "", ""])[:4]
                if verdict == "INFO":
                    print(f"      {name}: {ev}")
                else:
                    record(name, sev.get(name, "?"), verdict == "BUG", ev)


def main():
    if not os.access(BIN, os.X_OK):
        sys.exit(f"binary not found: {BIN} (set LDP_BIN)")
    print(f"binary: {BIN}\nfixtures: {BASE}\n")
    repro_node_modules_in_app_bundle()
    repro_pip_cache_dir_is_home()
    repro_apport_report_dir()
    repro_snap_reverted_revision()
    repro_flatpak_running_app_not_detected()
    repro_home_flag_env_leak()
    repro_find_crosses_mounts()
    repro_docker_context_mismatch()
    if "--no-docker" not in sys.argv:
        repro_containers()
    bugs = [r for r in results if r[2]]
    print(f"\n{len(bugs)} of {len(results)} reproducers show a bug")
    sys.exit(1 if bugs else 0)


if __name__ == "__main__":
    main()
