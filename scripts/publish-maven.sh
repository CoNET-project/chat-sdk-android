#!/usr/bin/env bash
# Publish network.conet:chat to the in-repo Maven layout (./maven), served over
# https://raw.githubusercontent.com/CoNET-project/chat-sdk-android/main/maven
# Extra arguments go to gradle, for example -PchatQaHooks=true -PchatArtifactSuffix=qa-wk21b for a QA build. A QA build must not be
# published into this repository's maven/ (its metadata would list the QA version): run it from a separate export and pass the output directory.
set -euo pipefail
cd "$(dirname "$0")/.."

# A QA build must not write into this repository's maven/: its metadata would list the QA version (reviewer, B1). Run it from a separate export.
for arg in "$@"; do
  case "$arg" in
    -PchatQaHooks*|-PchatArtifactSuffix*)
      echo "refused: a QA build must not write into this repository's maven/. Run it from a separate export." >&2
      exit 2 ;;
  esac
done

GRADLE_ARGS=("$@")
./gradlew --no-daemon :chat:testDebugUnitTest :chat:publishReleasePublicationToRepoMavenRepository ${GRADLE_ARGS[@]+"${GRADLE_ARGS[@]}"}

# The version is the one the build computes (the build file uses an if expression for the QA suffix), read from gradle itself.
VERSION="$(./gradlew -q --no-daemon :chat:properties ${GRADLE_ARGS[@]+"${GRADLE_ARGS[@]}"} | sed -n 's/^version: //p' | head -1)"
test -n "${VERSION}" || { echo "cannot read the version from gradle" >&2; exit 1; }
OUT="maven/network/conet/chat/${VERSION}"
test -f "${OUT}/chat-${VERSION}.aar" || { echo "missing ${OUT}/chat-${VERSION}.aar" >&2; exit 1; }
test -f "${OUT}/chat-${VERSION}.pom" || { echo "missing ${OUT}/chat-${VERSION}.pom" >&2; exit 1; }
echo "published network.conet:chat:${VERSION} -> ${OUT}"
echo "Next: review ${OUT}, then git add and commit (no push)"
