#!/bin/sh
# Release gate (spec r3bw §25.52AA.5; r3cf §25.52AH.6 item 2): a production AAR must contain no QA hook identifier, in its file names or in its
# contents. The scan covers the unpacked AAR (file names, manifest, resources, native libraries) and the unpacked classes.jar, whose class files are
# compressed inside the jar, so their constant pools (strings and symbols) are scanned too. Exits 1 when one is found, 0 when none is, 2 on misuse.
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
targets="$tmp/aar"
if [ -f "$tmp/aar/classes.jar" ]; then
  mkdir "$tmp/classes"
  unzip -q "$tmp/aar/classes.jar" -d "$tmp/classes"
  targets="$targets $tmp/classes"
fi
# Names and contents: any hit in any file under the targets is a failure. Only the file names of hits are printed, never the matched bytes.
hits=$(grep -rl -e 'NativeQaHooks' -e 'dropEoaKey' $targets 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "FAIL: QA hook identifier found in $(basename "$aar") (in: $(echo "$hits" | sed "s#$tmp/##g" | tr '\n' ' '))"
  exit 1
fi
echo "PASS: no QA hook identifier in $(basename "$aar") (names and class contents; sha256 $(shasum -a 256 "$aar" | cut -c1-64))"
