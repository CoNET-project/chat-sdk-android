#!/usr/bin/env bash
# Publish network.conet:chat to the in-repo Maven layout (./maven), served over
# https://raw.githubusercontent.com/CoNET-project/chat-sdk-android/main/maven
set -euo pipefail
cd "$(dirname "$0")/.."

./gradlew --no-daemon :chat:testDebugUnitTest :chat:publishReleasePublicationToRepoMavenRepository

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' chat/build.gradle.kts | head -1)"
OUT="maven/network/conet/chat/${VERSION}"
test -f "${OUT}/chat-${VERSION}.aar" || { echo "missing ${OUT}/chat-${VERSION}.aar" >&2; exit 1; }
test -f "${OUT}/chat-${VERSION}.pom" || { echo "missing ${OUT}/chat-${VERSION}.pom" >&2; exit 1; }
echo "published network.conet:chat:${VERSION} -> ${OUT}"
echo "Next: git add maven && git commit && git tag v${VERSION} && git push origin main --tags"
