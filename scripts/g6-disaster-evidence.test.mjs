import { describe, expect, it } from "vitest";
import { REQUIRED_DISASTER_CASES, validateDisasterEvidence } from "./g6-disaster-evidence.mjs";

const tag = "v4.0.0-rc.1";
const commit = "a".repeat(40);
const run = "42";

function fixture() {
  return {
    schema_version: 1,
    gate: "G6",
    status: "passed",
    release_tag: tag,
    release_commit: commit,
    release_run_id: run,
    isolated: true,
    production_side_effects: false,
    skipped_required_tests: 0,
    cases: [...REQUIRED_DISASTER_CASES],
    rollback: {
      target_rto_seconds: 300,
      maximum_rto_seconds: 30,
      known_good_restored: true,
      mixed_version_observed: false,
    },
  };
}

describe("G6 disaster evidence", () => {
  it("accepts the complete isolated recovery matrix", () => {
    expect(validateDisasterEvidence(fixture(), tag, commit, run).status).toBe("passed");
  });

  it("rejects a missing outage or rollback failure", () => {
    const missing = fixture();
    missing.cases.pop();
    expect(() => validateDisasterEvidence(missing, tag, commit, run)).toThrow("case missing");
    const failed = fixture();
    failed.rollback.known_good_restored = false;
    expect(() => validateDisasterEvidence(failed, tag, commit, run)).toThrow("not restored");
  });

  it("rejects a drill that touched production", () => {
    const evidence = fixture();
    evidence.production_side_effects = true;
    expect(() => validateDisasterEvidence(evidence, tag, commit, run)).toThrow("changed production");
  });
});
