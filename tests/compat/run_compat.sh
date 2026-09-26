#!/bin/bash
# Compatibility test on newer Ubuntu releases, in disposable containers.
#
# For each image: install the .deb with apt (dependency names must resolve),
# create real cleanup candidates (apt archives, orphaned packages, rotated
# logs, crash reports), run the tool as root, execute every actionable
# command it suggests exactly as printed, then check the system is healthy
# and the findings are gone. Then start the desktop app on Wayland (weston)
# and X11 (Xvfb) and check it runs without panicking.
#
#   tests/compat/run_compat.sh dist/linux-disk-prune_X_amd64.deb [image ...]
set -u
DEB=$(realpath "${1:?usage: run_compat.sh <deb> [image ...]}")
shift
IMAGES=("$@")
[ $# -eq 0 ] && IMAGES=(ubuntu:22.04 ubuntu:24.04 ubuntu:latest ubuntu:devel)
HERE=$(cd "$(dirname "$0")" && pwd)
fail=0
for img in "${IMAGES[@]}"; do
    echo "=================== $img"
    for script in inside.sh gui_inside.sh; do
        if ! docker run --rm -v "$DEB:/pkg.deb:ro" -v "$HERE/$script:/t.sh:ro" "$img" bash /t.sh; then
            fail=1
        fi
    done
done
exit $fail
