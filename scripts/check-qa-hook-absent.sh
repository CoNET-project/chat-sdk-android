#!/bin/sh
# Release gate (spec r3bw §25.52AA.5): a production AAR must contain no QA hook identifier. Exits 1 when one is found, 0 when none is.
# Usage: scripts/check-qa-hook-absent.sh <path-to-aar>
set -eu
if [ "$#" -ne 1 ]; then
  echo "usage: $0 <path-to-aar>" >&2
  exit 2
fi
aar="$1"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
unzip -q "$aar" -d "$tmp/aar"
if [ -f "$tmp/aar/classes.jar" ]; then
  mkdir "$tmp/classes"
  unzip -q "$tmp/aar/classes.jar" -d "$tmp/classes"
fi
if grep -rl -e 'NativeQaHooks' -e 'dropEoaKey' "$tmp/aar" >/dev/null 2>&1; then
  echo "FAIL: QA hook identifier found in $(basename "$aar")"
  exit 1
fi
echo "PASS: no QA hook identifier in $(basename "$aar")"
