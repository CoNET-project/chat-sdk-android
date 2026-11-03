#!/usr/bin/env bash
# Copy the ChatDaemon protocol shared vectors from @conet.project/chat-sdk (the
# spec) into spec/ here (used by the JVM and instrumented conformance tests).
# Never edit the copy: change the spec, regenerate, then sync.
#   scripts/sync-protocol-vectors.sh [path/to/conet-chat-sdk]
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
spec="${1:-$here/../BeamioContract/src/SilentPassUI/vendor/conet-chat-sdk}"
src="$spec/spec/chat-daemon-vectors.v1.json"
dst="$here/spec/chat-daemon-vectors.v1.json"
[ -f "$src" ] || { echo "no vectors at $src" >&2; exit 1; }
cp "$src" "$dst"
shasum -a 256 "$dst"
