#!/usr/bin/env bash
set -euo pipefail

DMG="${1:-}"
TARGET="${2:-}"
COMMIT="${3:-}"
RELEASE_TAG="${4:-}"
RUN_ID="${5:-}"
EXPECTED_TEAM_ID="${6:-}"
OUTPUT="${7:-}"
SMOKE_EVIDENCE="${8:-}"

[[ -f "$DMG" && -f "$SMOKE_EVIDENCE" && -n "$OUTPUT" && -n "$EXPECTED_TEAM_ID" ]] || {
  echo "usage: $0 DMG TARGET COMMIT RELEASE_TAG RUN_ID TEAM_ID OUTPUT SMOKE_EVIDENCE" >&2
  exit 2
}
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid release commit" >&2; exit 2; }
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] || {
  echo "invalid release tag" >&2
  exit 2
}
case "$TARGET" in
  aarch64-apple-darwin) EXPECTED_ARCH="arm64" ;;
  x86_64-apple-darwin) EXPECTED_ARCH="x86_64" ;;
  *) echo "invalid macOS target" >&2; exit 2 ;;
esac
RUNNER_ARCH="$(uname -m)"
[[ "$RUNNER_ARCH" == "$EXPECTED_ARCH" ]] || {
  echo "G6 evidence requires native $EXPECTED_ARCH runner, found $RUNNER_ARCH" >&2
  exit 1
}

WORK="$(mktemp -d)"
MOUNT="$WORK/mount"
mkdir -p "$MOUNT"
cleanup() {
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
codesign --verify --deep --strict --verbose=2 "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=4 "$APP"
TEAM_ID="$(codesign -dvv "$APP" 2>&1 | sed -n 's/^TeamIdentifier=//p' | tail -1)"
AUTHORITY="$(codesign -dvv "$APP" 2>&1 | sed -n 's/^Authority=//p' | head -1)"
[[ "$TEAM_ID" == "$EXPECTED_TEAM_ID" ]] || {
  echo "unexpected Developer ID team: $TEAM_ID" >&2
  exit 1
}
BINARY="$APP/Contents/MacOS/codex-app-manager"
ARCHES="$(lipo -archs "$BINARY")"
case " $ARCHES " in
  *" $EXPECTED_ARCH "*) ;;
  *) echo "expected architecture $EXPECTED_ARCH, found $ARCHES" >&2; exit 1 ;;
esac

export G6_DMG="$DMG" G6_TARGET="$TARGET" G6_COMMIT="$COMMIT"
export G6_RELEASE_TAG="$RELEASE_TAG" G6_RUN_ID="$RUN_ID"
export G6_EXPECTED_ARCH="$EXPECTED_ARCH" G6_RUNNER_ARCH="$RUNNER_ARCH"
export G6_TEAM_ID="$TEAM_ID" G6_AUTHORITY="$AUTHORITY" G6_OUTPUT="$OUTPUT"
export G6_SMOKE_EVIDENCE="$SMOKE_EVIDENCE"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

dmg = Path(os.environ["G6_DMG"])
output = Path(os.environ["G6_OUTPUT"])
smoke_path = Path(os.environ["G6_SMOKE_EVIDENCE"])
smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
dmg_sha256 = hashlib.file_digest(dmg.open("rb"), "sha256").hexdigest()
if (
    smoke.get("schema_version") != 1
    or smoke.get("status") != "passed"
    or smoke.get("platform") != "macos"
    or smoke.get("runner_architecture") != os.environ["G6_EXPECTED_ARCH"]
    or smoke.get("artifact_sha256") != dmg_sha256
    or smoke.get("developer_id_team") != os.environ["G6_TEAM_ID"]
    or smoke.get("production_side_effects") is not False
    or not all(smoke.get("lifecycle", {}).get(name) is True for name in (
        "mount", "copy", "launch", "quarantine_launch"
    ))
):
    raise SystemExit("G6 macOS lifecycle receipt is invalid or not bound to this artifact")
evidence = {
    "schema_version": 1,
    "gate": "G6",
    "status": "passed",
    "platform": "macos",
    "target": os.environ["G6_TARGET"],
    "runner_architecture": os.environ["G6_RUNNER_ARCH"],
    "native_runner": True,
    "release_tag": os.environ["G6_RELEASE_TAG"],
    "release_commit": os.environ["G6_COMMIT"],
    "release_run_id": os.environ["G6_RUN_ID"],
    "artifact": {
        "name": dmg.name,
        "size": dmg.stat().st_size,
        "sha256": dmg_sha256,
    },
    "developer_id": {
        "authority": os.environ["G6_AUTHORITY"],
        "team_id": os.environ["G6_TEAM_ID"],
        "notarized": True,
        "stapled": True,
        "gatekeeper": True,
        "hardened_runtime": True,
    },
    "lifecycle": smoke["lifecycle"],
    "lifecycle_receipt_sha256": hashlib.file_digest(smoke_path.open("rb"), "sha256").hexdigest(),
    "production_side_effects": False,
}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
print(f"G6 macOS evidence written: {output}")
PY
