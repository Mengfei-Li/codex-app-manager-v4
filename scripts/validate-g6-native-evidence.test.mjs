import { describe, expect, it } from "vitest";
import { REQUIRED_TARGETS, validateG6Evidence } from "./validate-g6-native-evidence.mjs";

const commit = "a".repeat(40);
const tag = "v4.0.0-rc.1";
const run = "12345";

function record(target) {
  const windows = target.endsWith("pc-windows-msvc");
  return {
    schema_version: 1,
    gate: "G6",
    status: "passed",
    platform: windows ? "windows" : "macos",
    target,
    native_runner: true,
    release_tag: tag,
    release_commit: commit,
    release_run_id: run,
    artifact: { name: `${target}.bin`, size: 10, sha256: "b".repeat(64) },
    lifecycle_receipt_sha256: "c".repeat(64),
    ...(windows
      ? {
          authenticode: { status: "Valid", signer_subject: "CN=Provider", timestamp_subject: "CN=TSA" },
          lifecycle: {
            install: true,
            launch: true,
            upgrade: true,
            uninstall: true,
            signature_reverified_after_install: true,
          },
        }
      : {
          developer_id: { team_id: "TEAM123456", notarized: true, stapled: true, gatekeeper: true, hardened_runtime: true },
          lifecycle: { mount: true, copy: true, launch: true, quarantine_launch: true },
        }),
    production_side_effects: false,
  };
}

describe("G6 native evidence", () => {
  it("accepts one signed native record for every target", () => {
    const result = validateG6Evidence(REQUIRED_TARGETS.map(record), tag, commit, run);
    expect(result.status).toBe("passed");
    expect(result.targets).toHaveLength(4);
  });

  it("rejects a record from a different candidate commit", () => {
    const records = REQUIRED_TARGETS.map(record);
    records[2].release_commit = "c".repeat(40);
    expect(() => validateG6Evidence(records, tag, commit, run)).toThrow("release commit mismatch");
  });

  it("allows immutable-release reuse while still requiring one original run", () => {
    const records = REQUIRED_TARGETS.map(record);
    expect(validateG6Evidence(records, tag, commit, "auto").release_run_id).toBe(run);
    records[1].release_run_id = "different";
    expect(() => validateG6Evidence(records, tag, commit, "auto")).toThrow("do not share one release run");
  });

  it("rejects unsigned Windows and unnotarized macOS evidence", () => {
    const windows = REQUIRED_TARGETS.map(record);
    windows[2].authenticode.status = "NotSigned";
    expect(() => validateG6Evidence(windows, tag, commit, run)).toThrow("Authenticode invalid");
    const mac = REQUIRED_TARGETS.map(record);
    mac[0].developer_id.notarized = false;
    expect(() => validateG6Evidence(mac, tag, commit, run)).toThrow("notarized missing");
  });

  it("rejects an unbound or incomplete lifecycle receipt", () => {
    const unbound = REQUIRED_TARGETS.map(record);
    unbound[0].lifecycle_receipt_sha256 = "";
    expect(() => validateG6Evidence(unbound, tag, commit, run)).toThrow(
      "lifecycle receipt hash missing",
    );
    const incomplete = REQUIRED_TARGETS.map(record);
    incomplete[2].lifecycle.signature_reverified_after_install = false;
    expect(() => validateG6Evidence(incomplete, tag, commit, run)).toThrow(
      "signature_reverified_after_install missing",
    );
  });
});
