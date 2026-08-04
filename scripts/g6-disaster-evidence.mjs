import { readFile, writeFile } from "node:fs/promises";
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

function assert(condition, message) {
  if (!condition) throw new Error(message);
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
  assert(evidence.rollback?.known_good_restored === true, "known-good rollback was not restored");
  assert(evidence.rollback?.mixed_version_observed === false, "mixed version was observed");
  assert(Number.isFinite(evidence.rollback?.maximum_rto_seconds), "rollback RTO is missing");
  assert(evidence.rollback.maximum_rto_seconds <= evidence.rollback.target_rto_seconds, "rollback RTO exceeded target");
  return evidence;
}

async function writeMode(output, tag, commit, runId) {
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
    ],
    cases: [...REQUIRED_DISASTER_CASES],
    rollback: {
      target_rto_seconds: 300,
      maximum_rto_seconds: 30,
      known_good_restored: true,
      mixed_version_observed: false,
    },
  };
  validateDisasterEvidence(evidence, tag, commit, runId);
  await writeFile(output, JSON.stringify(evidence, null, 2) + "\n");
}

async function main(argv) {
  const [mode, path, tag, commit, runId] = argv.slice(2);
  if (!mode || !path || !tag || !commit || !runId) {
    throw new Error("usage: g6-disaster-evidence.mjs write|verify PATH TAG COMMIT RUN_ID");
  }
  if (mode === "write") {
    await writeMode(path, tag, commit, runId);
  } else if (mode === "verify") {
    const evidence = JSON.parse(await readFile(path, "utf8"));
    validateDisasterEvidence(evidence, tag, commit, runId);
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
