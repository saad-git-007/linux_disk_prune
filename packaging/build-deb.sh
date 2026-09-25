#!/usr/bin/env bash
# Build dist/linux-disk-prune_<version>_amd64.deb with only cargo + dpkg-deb.
set -euo pipefail
cd "$(dirname "$0")/.."

PKG=linux-disk-prune
BIN=linux_disk_prune
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
ARCH=$(dpkg --print-architecture)

cargo build --release --locked

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"
install -Dm755 "target/release/$BIN" "$STAGE/usr/bin/$BIN"
ln -s "$BIN" "$STAGE/usr/bin/$PKG"                      # both names work
install -Dm644 README.md "$STAGE/usr/share/doc/$PKG/README.md"
install -Dm644 LICENSE   "$STAGE/usr/share/doc/$PKG/copyright"
install -Dm644 packaging/linux-disk-prune.desktop \
    "$STAGE/usr/share/applications/linux-disk-prune.desktop"
install -Dm644 packaging/linux-disk-prune.svg \
    "$STAGE/usr/share/icons/hicolor/scalable/apps/linux-disk-prune.svg"

# Minimum glibc actually referenced by the binary.
GLIBC=$(objdump -T "target/release/$BIN" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1 | cut -d_ -f2)
SIZE=$(du -sk "$STAGE/usr" | cut -f1)

mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<CTRL
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: saad-git-007 <saadwaraich007@gmail.com>
Installed-Size: $SIZE
Depends: libc6 (>= $GLIBC), libgcc-s1, libxkbcommon0, libxkbcommon-x11-0, libx11-6, libx11-xcb1, libxcursor1, libxi6, libxrandr2, libegl1 | libgl1
Recommends: libvulkan1, mesa-vulkan-drivers, libwayland-client0, pkexec | policykit-1, libglib2.0-bin, fonts-dejavu-core
Section: utils
Priority: optional
Homepage: https://github.com/saad-git-007/linux_disk_prune
Description: fast terminal disk analyzer and safe cleanup assistant for Ubuntu
 Scans a directory tree in parallel and shows where the space goes as a
 treemap and a size tree, then finds reclaimable space in known Ubuntu 22.04
 bloat locations: APT cache, inactive kernels, disabled snap revisions, the
 systemd journal, rotated logs, crash dumps, developer caches (pip, cargo,
 npm, Docker) and project build output. Read-only until you confirm.
 .
 Desktop app drawn on the GPU (Vulkan on the integrated GPU, OpenGL fallback)
 plus a terminal UI (--tui) for SSH sessions. Inspired by disktree by Tobi Lütke.
CTRL

mkdir -p dist
OUT="dist/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT"
echo "Built $OUT"
echo "Install with: sudo apt install ./$OUT"
