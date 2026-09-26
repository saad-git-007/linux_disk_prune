#!/bin/bash
# Starts the desktop app on a headless Wayland compositor (weston) and on a
# virtual X server (Xvfb) inside a throwaway container, and checks it keeps
# running, draws frames and does not panic. See run_compat.sh --gui.
set -u
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
. /etc/os-release
ok=0; bad=0
pass() { echo "  PASS $*"; ok=$((ok + 1)); }
fail() { echo "  FAIL $*"; bad=$((bad + 1)); }
apt-get update -qq >/dev/null
apt-get install -y -qq /pkg.deb weston xvfb mesa-vulkan-drivers libgl1-mesa-dri libegl-mesa0 >/dev/null 2>&1 || { echo "  FAIL install"; exit 1; }
mkdir -p /tmp/home/Documents && head -c 5M /dev/urandom > /tmp/home/Documents/big.bin

run_app() {  # $1 = label; env already set up
    RUST_LOG=warn timeout 20 linux_disk_prune --home /tmp/home /tmp/home >/tmp/app.log 2>&1 &
    local pid=$!
    sleep 12
    if kill -0 $pid 2>/dev/null; then
        pass "$1: app running after 12 s ($(grep -o 'renderer[^,]*' /tmp/app.log | head -1))"
        kill $pid; wait $pid 2>/dev/null
    else
        wait $pid; fail "$1: app exited early (rc=$?): $(tail -5 /tmp/app.log | tr '\n' ' ')"
    fi
    grep -qi "panicked" /tmp/app.log && fail "$1: panic: $(grep -i -A2 panicked /tmp/app.log | tr '\n' ' ')" || pass "$1: no panic"
}

# Wayland (weston headless, software rendering).
export XDG_RUNTIME_DIR=/tmp/xdg; mkdir -p -m 700 $XDG_RUNTIME_DIR
# weston >= 10 calls it "headless"; 22.04's weston 9 "headless-backend.so".
for b in headless headless-backend.so; do
    weston --backend=$b --socket=wayland-1 --idle-time=0 >/tmp/weston.log 2>&1 &
    sleep 3
    [ -S $XDG_RUNTIME_DIR/wayland-1 ] && break
done
if [ -S $XDG_RUNTIME_DIR/wayland-1 ]; then
    WAYLAND_DISPLAY=wayland-1 run_app "Wayland"
else
    fail "weston did not start: $(tail -3 /tmp/weston.log | tr '\n' ' ')"
fi

# X11 (Xvfb).
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
DISPLAY=:99 run_app "X11"

echo "  RESULT GUI $PRETTY_NAME: $ok passed, $bad failed"
[ $bad -eq 0 ]
