#!/bin/sh
# QA exclusion scan for one artifact (spec r3bw §25.52AA.5; r3cf §25.52AH.6 item 2; r3cl §25.52AN.3 and AN.4; r3cn §25.52AP).
# It counts the hits of each binary QA identifier of §25.52AN.2 (Android, AU.3, AX.3: swapWebEmit included) and of removeEOAPrivateKey (AN.5), in the FILE NAMES and in the CONTENTS of the
# artifact. The artifact may be an AAR, APK, AAB or JAR (archives unpacked recursively, three levels deep, so classes.jar and dex files are
# scanned) or a POM. Matching is case-sensitive and case-insensitive; the case-insensitive count includes the case-sensitive one.
# Only the counts and the paths of hits are printed, never matched bytes.
# Exit 0: no identifier hit (the release gate passes). Exit 1: at least one hit. Exit 2: misuse.
# Positive control (25.52AP.2), run on a QA build: `--positive` checks that each POSITIVE_IDENTIFIERS entry hits at least once, which proves the scan sees
# QA code. Only identifiers that a QA build really contains are listed there. removeEOAPrivateKey (AN.5) is never in the SDK, so it is only in the
# exclusion scan, where its absence is the expected result.
# Usage: scripts/check-qa-hook-absent.sh [--positive] <artifact>
set -eu
IDENTIFIERS="NativeQaHooks dropEoaKeyOfAccount dropEoaKey runCommand runWith ALLOWED_COMMANDS swapWebEmit removeEOAPrivateKey"
POSITIVE_IDENTIFIERS="NativeQaHooks VaultDiagnostic dropEoaKeyOfAccount runWith swapWebEmit"
mode=scan
if [ "${1:-}" = "--positive" ]; then
  mode=positive
  shift
fi
if [ "$#" -ne 1 ]; then
  echo "usage: $0 [--positive] <artifact>" >&2
  exit 2
fi
artifact="$1"
if [ ! -f "$artifact" ]; then
  echo "no such artifact: $(basename "$artifact")" >&2
  exit 2
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
root="$tmp/tree"
mkdir -p "$root"
case "$artifact" in
  *.aar|*.apk|*.aab|*.jar|*.zip) unzip -q "$artifact" -d "$root/unpacked" ;;
  *.pom|*.xml) cp "$artifact" "$root/" ;;
  *) echo "unsupported artifact type: $(basename "$artifact")" >&2; exit 2 ;;
esac
# Nested archives (classes.jar inside an AAR, dex-holding jars): each is unpacked once, next to itself as <name>.d.
level=0
while [ "$level" -lt 3 ]; do
  level=$((level + 1))
  find "$root" -type f \( -name '*.jar' -o -name '*.aar' -o -name '*.apk' -o -name '*.aab' \) | while IFS= read -r f; do
    if [ ! -d "$f.d" ]; then
      mkdir "$f.d"
      unzip -q "$f" -d "$f.d" 2>/dev/null || true
    fi
  done
done
echo "scanner sha256 $(shasum -a 256 "$0" | cut -c1-64)"
echo "artifact $(basename "$artifact") sha256 $(shasum -a 256 "$artifact" | cut -c1-64)"
echo "files scanned $(find "$root" -type f | wc -l | tr -d ' ')"
failed=0
if [ "$mode" = positive ]; then
  for ident in $POSITIVE_IDENTIFIERS; do
    names=$(find "$root" -iname "*${ident}*" | wc -l | tr -d ' ')
    content_i=$(grep -rhoai -e "$ident" "$root" 2>/dev/null | wc -l | tr -d ' ')
    echo "positive $ident names $names contents-insensitive $content_i"
    if [ "$names" -eq 0 ] && [ "$content_i" -eq 0 ]; then
      failed=1
      echo "  no hit: $ident"
    fi
  done
  if [ "$failed" -ne 0 ]; then
    echo "FAIL: positive control, a QA-only identifier has no hit in $(basename "$artifact")"
    exit 1
  fi
  echo "PASS: positive control, every QA-only identifier hits in $(basename "$artifact")"
  exit 0
fi
for ident in $IDENTIFIERS; do
  names=$(find "$root" -iname "*${ident}*" | wc -l | tr -d ' ')
  content=$(grep -rhoa -e "$ident" "$root" 2>/dev/null | wc -l | tr -d ' ')
  content_i=$(grep -rhoai -e "$ident" "$root" 2>/dev/null | wc -l | tr -d ' ')
  echo "identifier $ident names $names contents $content contents-insensitive $content_i"
  if [ "$names" -ne 0 ] || [ "$content_i" -ne 0 ]; then
    failed=1
    find "$root" -iname "*${ident}*" | sed "s#$root/##" | sed 's/^/  name hit: /' || true
    grep -rlai -e "$ident" "$root" 2>/dev/null | sed "s#$root/##" | sed 's/^/  content hit: /' || true
  fi
done
if [ "$failed" -ne 0 ]; then
  echo "FAIL: a QA identifier hit in $(basename "$artifact")"
  exit 1
fi
echo "PASS: no QA identifier in $(basename "$artifact") (file names and contents, case-sensitive and case-insensitive)"
