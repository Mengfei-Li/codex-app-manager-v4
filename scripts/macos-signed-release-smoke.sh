#!/usr/bin/env bash
# Native-architecture release smoke for the final signed/notarized DMG.
set -euo pipefail

DMG="${1:-}"
EXPECTED_ARCH="${2:-}"
EXPECTED_TEAM_ID="${3:-}"
[[ -f "$DMG" && -n "$EXPECTED_ARCH" && -n "$EXPECTED_TEAM_ID" ]] || {
  echo "usage: $0 DMG EXPECTED_ARCH EXPECTED_TEAM_ID" >&2
  exit 2
}

WORK="$(mktemp -d)"
MOUNT="$WORK/mount"
COPY_ROOT="$WORK/Applications"
mkdir -p "$MOUNT" "$COPY_ROOT"
cleanup() {
  pkill -f "$COPY_ROOT/.*/Contents/MacOS/codex-app-manager" 2>/dev/null || true
  hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

codesign --verify --strict --verbose=2 "$DMG"
xcrun stapler validate "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=4 "$DMG"
hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MOUNT" >/dev/null
APP="$(find "$MOUNT" -maxdepth 1 -type d -name '*.app' | head -1)"
[[ -n "$APP" ]] || { echo "release DMG has no app" >&2; exit 1; }
ditto "$APP" "$COPY_ROOT/$(basename "$APP")"
hdiutil detach "$MOUNT" >/dev/null
APP="$COPY_ROOT/$(basename "$APP")"

codesign --verify --deep --strict --verbose=2 "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=4 "$APP"
TEAM_ID="$(codesign -dvv "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | tail -1)"
[[ "$TEAM_ID" == "$EXPECTED_TEAM_ID" ]] || {
  echo "unexpected Developer ID team: $TEAM_ID" >&2
  exit 1
}
BINARY="$APP/Contents/MacOS/codex-app-manager"
[[ -x "$BINARY" ]] || { echo "main executable missing" >&2; exit 1; }
ARCHES="$(lipo -archs "$BINARY")"
case " $ARCHES " in
  *" $EXPECTED_ARCH "*) ;;
  *) echo "expected architecture $EXPECTED_ARCH, found $ARCHES" >&2; exit 1 ;;
esac

RUN_ID="release-$RANDOM-$$"
DATA_DIR="${TMPDIR%/}/codex-app-manager-smoke-$RUN_ID"
mkdir -m 700 "$DATA_DIR"
xattr -w com.apple.quarantine "0083;$(printf '%x' "$(date +%s)");GitHubActions;" "$APP"
open -n -F \
  --env "CAM_PACKAGED_SMOKE_RUN=$RUN_ID" \
  --env "CAM_PACKAGED_SMOKE_DATA_DIR=$DATA_DIR" \
  "$APP"
deadline=$((SECONDS + 20))
pid=""
while (( SECONDS < deadline )); do
  pid="$(pgrep -f "$BINARY" | head -1 || true)"
  [[ -n "$pid" ]] && break
  sleep 1
done
[[ -n "$pid" ]] || { echo "signed release app did not launch" >&2; exit 1; }
sleep 8
kill -0 "$pid" 2>/dev/null || { echo "signed release app exited during observation" >&2; exit 1; }
kill "$pid" 2>/dev/null || true
rm -rf -- "$DATA_DIR"
echo "macOS signed release smoke passed: arch=$EXPECTED_ARCH team=$TEAM_ID"
