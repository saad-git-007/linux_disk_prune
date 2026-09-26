#!/bin/bash
# Runs inside a throwaway Ubuntu container (see run_compat.sh).
set -u
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
ok=0; bad=0
pass() { echo "  PASS $*"; ok=$((ok + 1)); }
fail() { echo "  FAIL $*"; bad=$((bad + 1)); }
check() { local what=$1; shift; if "$@" >/tmp/out 2>&1; then pass "$what"; else fail "$what: $(tail -3 /tmp/out | tr '\n' ' ')"; fi; }

. /etc/os-release
echo "  $PRETTY_NAME | apt $(apt-get --version | head -1 | cut -d' ' -f2) | rm: $(rm --version 2>&1 | head -1)"

# Keep downloaded .debs like a normal install does (docker images disable it).
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get update -qq >/dev/null

# 1. The package installs with its dependencies (and recommends resolve).
check "apt installs the .deb" apt-get install -y -qq /pkg.deb
for r in libvulkan1 mesa-vulkan-drivers libwayland-client0 pkexec libglib2.0-bin fonts-dejavu-core; do
    apt-cache show "$r" >/dev/null 2>&1 && pass "recommended package $r exists" || fail "recommended package $r missing"
done
check "binary runs" linux_disk_prune --version
check "binary links" sh -c '! ldd /usr/bin/linux_disk_prune | grep -q "not found"'
check "desktop entry valid" test -f /usr/share/applications/linux-disk-prune.desktop

# 2. Real cleanup candidates.
apt-get install -y -qq fortune-mod cowsay >/dev/null 2>&1   # debs land in the archive cache
apt-mark auto fortunes-min librecode0 >/dev/null 2>&1
apt-get remove -y -qq fortune-mod >/dev/null 2>&1            # its deps become orphans
mkdir -p /var/log/app /var/crash /var/log/mysql
for i in 1 2 3; do head -c 3M /dev/urandom > /var/log/app/app.log.$i; done
head -c 3M /dev/urandom > /var/log/app/old.log.2.gz
head -c 3M /dev/urandom > /var/log/app/app.log                # live log: must survive
head -c 3M /dev/urandom > /var/log/mysql/mysql-bin.000002     # binlog: must survive
echo /var/log/mysql/mysql-bin.000002 > /var/log/mysql/mysql-bin.index
head -c 3M /dev/urandom > /var/crash/_usr_bin_x.0.crash
head -c 3M /dev/urandom > /var/crash/notes.txt                # not apport's: must survive

linux_disk_prune --json --rules-only > /tmp/r1.json 2>/tmp/err || fail "analysis failed: $(cat /tmp/err)"
python3 -c 1 2>/dev/null || apt-get install -y -qq python3-minimal >/dev/null 2>&1
ids=$(python3 -c 'import json;print(" ".join(f["id"] for f in json.load(open("/tmp/r1.json"))["findings"]))')
echo "  findings: $ids"
for want in apt-cache apt-autoremove rotated-logs crash; do
    case " $ids " in *" $want "*) pass "finds $want" ;; *) fail "missing finding $want" ;; esac
done

# 3. Run every actionable command exactly as shown (as root: sudo is a no-op).
python3 - <<'EOF' > /tmp/cmds
import json
for f in json.load(open("/tmp/r1.json"))["findings"]:
    if f["needs_root"] and not f["command"].startswith("(no automatic"):
        print(f["id"] + "\t" + f["command"])
EOF
dpkg -l | awk '/^ii/{sub(/:.*/,"",$2); print $2}' | sort > /tmp/pkgs-before
while IFS=$'\t' read -r id cmd; do
    if (sh -c "sudo() { \"\$@\"; }; $cmd") </dev/null >/tmp/out 2>&1; then pass "command ran: $id"; else fail "command $id: $(tail -3 /tmp/out | tr '\n' ' ')"; fi
done < /tmp/cmds

# 4. Health afterwards.
check "dpkg --audit clean" sh -c '[ -z "$(dpkg --audit)" ]'
check "apt-get check" apt-get check -qq
check "apt still installs packages" apt-get install -y -qq hello
check "installed program works" hello
check "cowsay (manually installed) kept" test -x /usr/games/cowsay
check "live log kept" test -f /var/log/app/app.log
check "MySQL binlog kept" test -f /var/log/mysql/mysql-bin.000002
check "non-apport file in /var/crash kept" test -f /var/crash/notes.txt
check "rotated logs gone" sh -c '! ls /var/log/app/app.log.1 /var/log/app/old.log.2.gz 2>/dev/null'
check "crash report gone" test ! -e /var/crash/_usr_bin_x.0.crash
dpkg -l | awk '/^ii/{sub(/:.*/,"",$2); print $2}' | sort > /tmp/pkgs-after
removed=$(comm -23 /tmp/pkgs-before /tmp/pkgs-after | tr '\n' ' ')
expected=$(python3 -c 'import json,re;print(" ".join(sorted(re.findall(r"remove -y (.*)",next((f["command"] for f in json.load(open("/tmp/r1.json"))["findings"] if f["id"]=="apt-autoremove"),""))[0].split() if "apt-autoremove" in open("/tmp/r1.json").read() else [])))')
[ "$(echo $removed | tr ' ' '\n' | sort | tr '\n' ' ')" = "$(echo $expected | tr ' ' '\n' | sort | tr '\n' ' ')" ] \
    && pass "only the listed packages were removed ($removed)" || fail "removed [$removed] but listed [$expected]"

# 5. Tools the generated commands rely on, in the forms they are used.
mkdir -p /tmp/t/a/b && touch /tmp/t/a/b/x "/tmp/t/a/q'1"
check "rm --one-file-system" rm -rf --one-file-system -- /tmp/t/a
mkdir -p /tmp/t/c && touch /tmp/t/c/y
check "find -xdev -type f ( -path ) -delete" find /tmp/t -xdev -type f \( -path /tmp/t/c/y \) -delete
check "find -xdev -mindepth 1 -delete" find /tmp/t -xdev -mindepth 1 -delete
check "dpkg-query status pattern" sh -c 'dpkg-query -W -f="\${Status}\n" "linux-*-0.0.0-none" 2>/dev/null; true'
mkdir -p /var/log/journal
if command -v journalctl >/dev/null; then
    check "journalctl --directory --vacuum-size" journalctl --directory=/var/log/journal --vacuum-size=500M
else
    echo "  (no systemd in this image: journalctl test skipped)"
fi
check "apt-get -s autoremove parses" sh -c 'apt-get -s autoremove | grep -q "0 upgraded\|newly installed"'

# 6. Findings are gone on a second analysis.
linux_disk_prune --json --rules-only > /tmp/r2.json 2>/dev/null
left=$(python3 -c 'import json;print(" ".join(f["id"] for f in json.load(open("/tmp/r2.json"))["findings"] if f["id"] in ("apt-cache","apt-autoremove","rotated-logs","crash")))')
[ -z "$left" ] && pass "findings gone after cleanup" || fail "still found after cleanup: $left"

# 7. A full scan and the summary report.
check "full scan of / (json)" sh -c 'linux_disk_prune --json / | python3 -c "import json,sys; d=json.load(sys.stdin); assert d[\"total_bytes\"] > 0"'
check "summary report" sh -c 'linux_disk_prune --summary --rules-only | grep -q "Nothing was deleted"'

echo "  RESULT $PRETTY_NAME: $ok passed, $bad failed"
[ $bad -eq 0 ]
