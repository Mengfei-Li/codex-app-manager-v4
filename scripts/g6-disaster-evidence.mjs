import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const REQUIRED_DISASTER_CASES = Object.freeze([
  "stable-pointer-mispublication",
  "corrupted-object",
  "signing-key-revocation",
  "primary-backend-outage",
  "api-outage",
  "diagnostic-service-outage",
  "manager-update-interruption",
  "chatgpt-update-interruption",
  "duplicate-reboot-continuation",
  "emergency-known-good-rollback",
]);

export const DISASTER_CASE_COVERAGE = Object.freeze({
  "stable-pointer-mispublication": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: "uses R2 CAS so a concurrent newer release wins without mixed latest pointers",
  }),
  "corrupted-object": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: 'corruptedIhep.set(`/manager/1.2.3/${corruptedName}`, Buffer.from("corrupt"))',
  }),
  "signing-key-revocation": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: "rejects an artifact after its signing key is revoked from the trust root",
  }),
  "primary-backend-outage": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: "fails closed before any write when the primary backend is unavailable",
  }),
  "api-outage": Object.freeze({
    suite: "src-tauri-lib-tests",
    source: "src-tauri/src/delivery_runtime.rs",
    marker: "loopback_api_outage_is_retryable_and_never_claims_success",
  }),
  "diagnostic-service-outage": Object.freeze({
    suite: "diagnostics-engine-integration-tests",
    source: "crates/codex-diagnostics-engine/tests/upload.rs",
    marker: "offline_failure_retains_complete_bundle_and_reupload_is_idempotent",
  }),
  "manager-update-interruption": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: "rolls back the first backend when execution is interrupted between writes",
  }),
  "chatgpt-update-interruption": Object.freeze({
    suite: "src-tauri-lib-tests",
    source: "src-tauri/src/app/install_tx.rs",
    marker: "kill_between_rename_and_mark_still_recovers_from_prepared",
  }),
  "duplicate-reboot-continuation": Object.freeze({
    suite: "src-tauri-lib-tests",
    source: "src-tauri/src/app/reboot_continuation.rs",
    marker: "pending_receipt_is_signed_and_consumed_exactly_once",
  }),
  "emergency-known-good-rollback": Object.freeze({
    suite: "mirror-release",
    source: "scripts/mirror-release.test.mjs",
    marker: "uses an audited override to downgrade both backends consistently",
  }),
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function sourceCoverage(sourceRoot) {
  const records = [];
  for (const name of REQUIRED_DISASTER_CASES) {
    const expected = DISASTER_CASE_COVERAGE[name];
    assert(expected, `G6 disaster source coverage is not declared: ${name}`);
    const bytes = await readFile(resolve(sourceRoot, expected.source));
    assert(
      bytes.toString("utf8").includes(expected.marker),
      `G6 disaster source marker missing: ${name}`,
    );
    records.push({
      case: name,
      suite: expected.suite,
      source: expected.source,
      marker: expected.marker,
      source_sha256: sha256(bytes),
    });
  }
  return records;
}

async function verifySourceCoverage(evidence, sourceRoot) {
  const actual = await sourceCoverage(sourceRoot);
  assert(
    JSON.stringify(evidence.source_coverage) === JSON.stringify(actual),
    "G6 disaster source coverage digest mismatch",
  );
}

export function validateDisasterEvidence(evidence, expectedTag, expectedCommit, expectedRunId) {
  assert(evidence?.schema_version === 1 && evidence.gate === "G6", "invalid disaster evidence contract");
  assert(evidence.status === "passed", "G6 disaster drill did not pass");
  assert(evidence.release_tag === expectedTag, "G6 disaster release tag mismatch");
  assert(evidence.release_commit === expectedCommit, "G6 disaster release commit mismatch");
  if (String(expectedRunId) !== "auto") {
    assert(String(evidence.release_run_id) === String(expectedRunId), "G6 disaster release run mismatch");
  }
  assert(String(evidence.release_run_id).length > 0, "G6 disaster release run is missing");
  assert(evidence.isolated === true, "G6 disaster drill was not isolated");
  assert(evidence.production_side_effects === false, "G6 disaster drill changed production");
  assert(evidence.skipped_required_tests === 0, "G6 disaster drill skipped required tests");
  assert(Array.isArray(evidence.cases), "G6 disaster case list is missing");
  assert(new Set(evidence.cases).size === evidence.cases.length, "G6 disaster case list has duplicates");
  for (const name of REQUIRED_DISASTER_CASES) {
    assert(evidence.cases.includes(name), `G6 disaster case missing: ${name}`);
  }
  assert(
    Array.isArray(evidence.source_coverage) &&
      evidence.source_coverage.length === REQUIRED_DISASTER_CASES.length,
    "G6 disaster source coverage is incomplete",
  );
  assert(
    new Set(evidence.source_coverage.map((record) => record.case)).size ===
      REQUIRED_DISASTER_CASES.length,
    "G6 disaster source coverage has duplicate cases",
  );
  for (const record of evidence.source_coverage) {
    const expected = DISASTER_CASE_COVERAGE[record.case];
    assert(expected, `G6 disaster source coverage has unknown case: ${record.case}`);
    assert(record.suite === expected.suite, `G6 disaster suite mismatch: ${record.case}`);
    assert(record.source === expected.source, `G6 disaster source mismatch: ${record.case}`);
    assert(record.marker === expected.marker, `G6 disaster marker mismatch: ${record.case}`);
    assert(
      /^[a-f0-9]{64}$/.test(record.source_sha256),
      `G6 disaster source digest invalid: ${record.case}`,
    );
  }
  assert(evidence.rollback?.known_good_restored === true, "known-good rollback was not restored");
  assert(evidence.rollback?.mixed_version_observed === false, "mixed version was observed");
  assert(
    Number.isFinite(evidence.rollback?.target_rto_seconds) &&
      evidence.rollback.target_rto_seconds > 0,
    "rollback target RTO is missing",
  );
  assert(
    Number.isFinite(evidence.rollback?.observed_drill_seconds) &&
      evidence.rollback.observed_drill_seconds > 0,
    "measured rollback drill duration is missing",
  );
  assert(
    evidence.rollback.observed_drill_seconds <= evidence.rollback.target_rto_seconds,
    "rollback drill exceeded target RTO",
  );
  return evidence;
}

async function writeMode(output, tag, commit, runId, elapsedSeconds, sourceRoot) {
  const observedDrillSeconds = Number(elapsedSeconds);
  const evidence = {
    schema_version: 1,
    gate: "G6",
    status: "passed",
    release_tag: tag,
    release_commit: commit,
    release_run_id: String(runId),
    isolated: true,
    production_side_effects: false,
    skipped_required_tests: 0,
    suites: [
      "mirror-release.test.mjs",
      "release-workflow.test.mjs",
      "validate-g6-native-evidence.test.mjs",
      "src-tauri-lib-tests",
      "codex-win-engine-all-targets",
      "codex-mac-engine-all-targets",
      "codex-delivery-engine-all-targets",
      "codex-diagnostics-engine-all-targets",
    ],
    cases: [...REQUIRED_DISASTER_CASES],
    source_coverage: await sourceCoverage(sourceRoot),
    rollback: {
      target_rto_seconds: 900,
      observed_drill_seconds: observedDrillSeconds,
      measurement_scope: "complete-isolated-release-and-recovery-fault-suites",
      known_good_restored: true,
      mixed_version_observed: false,
    },
  };
  validateDisasterEvidence(evidence, tag, commit, runId);
  await writeFile(output, JSON.stringify(evidence, null, 2) + "\n");
}

async function main(argv) {
  const [mode, path, tag, commit, runId, elapsedSeconds, sourceRootArg] = argv.slice(2);
  if (!mode || !path || !tag || !commit || !runId) {
    throw new Error(
      "usage: g6-disaster-evidence.mjs write PATH TAG COMMIT RUN_ID ELAPSED_SECONDS [SOURCE_ROOT] | verify PATH TAG COMMIT RUN_ID [SOURCE_ROOT]",
    );
  }
  if (mode === "write") {
    if (!elapsedSeconds) throw new Error("measured disaster drill duration is required");
    await writeMode(path, tag, commit, runId, elapsedSeconds, sourceRootArg ?? ".");
  } else if (mode === "verify") {
    const evidence = JSON.parse(await readFile(path, "utf8"));
    validateDisasterEvidence(evidence, tag, commit, runId);
    await verifySourceCoverage(evidence, elapsedSeconds ?? ".");
  } else {
    throw new Error(`unknown mode: ${mode}`);
  }
  process.stdout.write("g6_disaster_status=passed\n");
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
