#!/bin/bash
# Runs INSIDE a throw-away ubuntu:22.04 container (never on a real system).
# Usage: container_repro.sh <phase>; the app binary is mounted at /ldp.
# Prints one line per check:  RESULT <name> <BUG|OK> <evidence>
set -u
SHIM='sudo() { "$@"; }'
ldp_json() { /ldp --json --rules-only --home /root/h --dev-root /root/h 2>/dev/null; }
# python3 is not in the base image: extract with grep/sed on pretty JSON.
finding_cmd() { # $1 = finding id -> prints its command (JSON-unescaped enough for our fixtures)
  ldp_json | awk -v id="\"id\": \"$1\"" '
    index($0,"\"command\":") {cmd=$0}
    index($0,id) {print cmd; exit}' | sed 's/^ *"command": "//; s/",$//'
}
mkdir -p /root/h
phase=$1
case "$phase" in
kernel)
  K=$(uname -r); NEW=6.99.0-1-generic
  cat >> /var/lib/dpkg/status <<ST

Package: linux-image-$K
Status: install ok installed
Priority: optional
Section: kernel
Installed-Size: 1
Maintainer: audit <a@b>
Architecture: amd64
Version: 1
Description: stand-in for the running kernel's image

Package: linux-modules-$NEW
Status: install ok unpacked
Priority: optional
Section: kernel
Installed-Size: 1
Maintainer: audit <a@b>
Architecture: amd64
Version: 6.99.0-1.1
Description: newest kernel, being unpacked by unattended-upgrades right now
ST
  mkdir -p /usr/lib/modules/$NEW/kernel/drivers /boot
  head -c 3000000 /dev/urandom > /usr/lib/modules/$NEW/kernel/drivers/storage.ko
  C=$(finding_cmd kernel-leftovers)
  echo "INFO analysis command: $C"
  # unattended-upgrades finishes: image unpacked + everything configured.
  sed -i "s/^Status: install ok unpacked/Status: install ok installed/" /var/lib/dpkg/status
  cat >> /var/lib/dpkg/status <<ST

Package: linux-image-$NEW
Status: install ok installed
Priority: optional
Section: kernel
Installed-Size: 1
Maintainer: audit <a@b>
Architecture: amd64
Version: 6.99.0-1.1
Description: newest kernel image
ST
  echo kernel > /boot/vmlinuz-$NEW
  echo "INFO re-analysis now proposes: $(finding_cmd kernel-leftovers)"
  [ -n "$C" ] && sh -c "$SHIM
$C" >/dev/null 2>&1
  if [ -n "$C" ] && [ ! -e /usr/lib/modules/$NEW ]; then
    echo "RESULT kernel_leftover_toctou BUG modules of the now-installed newest kernel $NEW deleted (dpkg: $(dpkg-query -W -f='${Status}' linux-image-$NEW))"
  else
    echo "RESULT kernel_leftover_toctou OK not proposed or not deleted"
  fi
  ;;
logs)
  mkdir -p /var/log/mysql /var/log/remote /var/log/evil
  head -c 1500000 /dev/urandom > /var/log/mysql/mysql-bin.000001
  head -c 1500000 /dev/urandom > /var/log/mysql/mysql-bin.000002   # the ACTIVE binlog
  printf './mysql-bin.000001\n./mysql-bin.000002\n' > /var/log/mysql/mysql-bin.index
  head -c 500000 /dev/urandom > /var/log/remote/10.0.0.5              # live per-host rsyslog file
  head -c 100000 /dev/urandom > /var/log/evil/libc.so.6
  C=$(finding_cmd rotated-logs)
  echo "INFO rotated-logs command: $C"
  case "$C" in *mysql-bin.000002*) echo "RESULT rotated_logs_mysql_binlog BUG active MySQL binlog /var/log/mysql/mysql-bin.000002 is in the rm list";;
                *) echo "RESULT rotated_logs_mysql_binlog OK";; esac
  case "$C" in */var/log/remote/10.0.0.5*) echo "RESULT rotated_logs_ip_named_file BUG live log /var/log/remote/10.0.0.5 is in the rm list";;
                *) echo "RESULT rotated_logs_ip_named_file OK";; esac
  # A process in group syslog (/var/log is root:syslog 0775) swaps the dir for a symlink.
  mkdir -p /opt/victim && echo precious > /opt/victim/libc.so.6
  rm -rf /var/log/evil && ln -s /opt/victim /var/log/evil
  sh -c "$SHIM
$C" >/dev/null 2>&1
  if [ ! -e /opt/victim/libc.so.6 ]; then echo "RESULT root_rm_follows_parent_symlink BUG /opt/victim/libc.so.6 deleted through /var/log/evil -> /opt/victim"
  else echo "RESULT root_rm_follows_parent_symlink OK"; fi
  ;;
autoremove|autoremove_contrast)
  mkdir -p /tmp/pkg/DEBIAN /tmp/pkg/etc
  printf 'Package: auditpkg\nVersion: 1.0\nArchitecture: all\nMaintainer: audit <a@b>\nInstalled-Size: 3000\nDescription: audit test package\n' > /tmp/pkg/DEBIAN/control
  echo /etc/auditpkg.conf > /tmp/pkg/DEBIAN/conffiles
  echo default > /tmp/pkg/etc/auditpkg.conf
  printf '#!/bin/sh\nif [ "$1" = purge ]; then rm -rf /var/lib/auditpkg; fi\n' > /tmp/pkg/DEBIAN/postrm
  chmod 755 /tmp/pkg/DEBIAN/postrm
  dpkg-deb -b /tmp/pkg /tmp/auditpkg.deb >/dev/null && dpkg -i /tmp/auditpkg.deb >/dev/null && apt-mark auto auditpkg >/dev/null
  mkdir -p /var/lib/auditpkg && echo "user database" > /var/lib/auditpkg/db
  echo "user-tuned setting" > /etc/auditpkg.conf
  if [ "$phase" = autoremove_contrast ]; then
    apt-get -y autoremove >/dev/null 2>&1
    echo "RESULT apt_autoremove_reference INFO after plain 'apt-get autoremove': conf=$(cat /etc/auditpkg.conf 2>/dev/null || echo GONE) db=$(cat /var/lib/auditpkg/db 2>/dev/null || echo GONE)"
    exit 0
  fi
  C=$(finding_cmd apt-autoremove)
  echo "INFO apt-autoremove command: $C"
  sh -c "export DEBIAN_FRONTEND=noninteractive; $SHIM
$C" >/dev/null 2>&1
  if [ -n "$C" ] && [ ! -e /var/lib/auditpkg/db ] && [ ! -e /etc/auditpkg.conf ]; then
    echo "RESULT autoremove_purges BUG app's autoremove purged: edited /etc/auditpkg.conf and /var/lib/auditpkg/db are gone"
  else echo "RESULT autoremove_purges OK"; fi
  ;;
esac
