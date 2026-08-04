import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

export const REQUIRED_TARGETS = Object.freeze([
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "x86_64-pc-windows-msvc",
]);

const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const TAG = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function stableEvidence(evidence) {
  return {
    target: evidence.target,
    platform: evidence.platform,
    artifact: evidence.artifact,
    native_runner: evidence.native_runner,
    lifecycle_receipt_sha256: evidence.lifecycle_receipt_sha256,
    ...(evidence.platform === "windows"
      ? { authenticode: evidence.authenticode, lifecycle: evidence.lifecycle }
      : { developer_id: evidence.developer_id, lifecycle: evidence.lifecycle }),
  };
}

export function validateG6Evidence(records, expectedTag, expectedCommit, expectedRunId) {
  assert(TAG.test(expectedTag), "invalid expected release tag");
  assert(COMMIT.test(expectedCommit), "invalid expected release commit");
  assert(records.length === REQUIRED_TARGETS.length, "G6 requires exactly four native records");
  const byTarget = new Map();
  const observedRunIds = new Set();
  for (const record of records) {
    assert(record.schema_version === 1 && record.gate === "G6" && record.status === "passed", "invalid G6 record contract");
    assert(REQUIRED_TARGETS.includes(record.target), `unexpected G6 target: ${record.target}`);
    assert(!byTarget.has(record.target), `duplicate G6 target: ${record.target}`);
    assert(record.release_tag === expectedTag, `${record.target}: release tag mismatch`);
    assert(record.release_commit === expectedCommit, `${record.target}: release commit mismatch`);
    observedRunIds.add(String(record.release_run_id));
    if (String(expectedRunId) !== "auto") {
      assert(String(record.release_run_id) === String(expectedRunId), `${record.target}: release run mismatch`);
    }
    assert(record.native_runner === true, `${record.target}: native runner evidence missing`);
    assert(record.production_side_effects === false, `${record.target}: unexpected production side effect`);
    assert(record.artifact && SHA256.test(record.artifact.sha256), `${record.target}: artifact hash missing`);
    assert(Number.isSafeInteger(record.artifact.size) && record.artifact.size > 0, `${record.target}: artifact size invalid`);
    assert(SHA256.test(record.lifecycle_receipt_sha256), `${record.target}: lifecycle receipt hash missing`);
    if (record.platform === "windows") {
      assert(record.target.endsWith("pc-windows-msvc"), `${record.target}: platform mismatch`);
      assert(record.authenticode?.status === "Valid", `${record.target}: Authenticode invalid`);
      assert(record.authenticode?.signer_subject, `${record.target}: signer subject missing`);
      assert(record.authenticode?.timestamp_subject, `${record.target}: timestamp missing`);
      for (const name of [
        "install",
        "launch",
        "upgrade",
        "uninstall",
        "signature_reverified_after_install",
      ]) {
        assert(record.lifecycle?.[name] === true, `${record.target}: Windows lifecycle ${name} missing`);
      }
    } else {
      assert(record.platform === "macos" && record.target.endsWith("apple-darwin"), `${record.target}: platform mismatch`);
      assert(record.developer_id?.team_id, `${record.target}: Developer ID team missing`);
      for (const name of ["notarized", "stapled", "gatekeeper", "hardened_runtime"]) {
        assert(record.developer_id?.[name] === true, `${record.target}: ${name} missing`);
      }
      for (const name of ["mount", "copy", "launch", "quarantine_launch"]) {
        assert(record.lifecycle?.[name] === true, `${record.target}: macOS lifecycle ${name} missing`);
      }
    }
    byTarget.set(record.target, record);
  }
  assert(REQUIRED_TARGETS.every((target) => byTarget.has(target)), "G6 native matrix is incomplete");
  assert(observedRunIds.size === 1, "G6 native records do not share one release run");
  const boundRunId = [...observedRunIds][0];
  return {
    schema_version: 1,
    gate: "G6",
    status: "passed",
    release_tag: expectedTag,
    release_commit: expectedCommit,
    release_run_id: boundRunId,
    targets: REQUIRED_TARGETS.map((target) => stableEvidence(byTarget.get(target))),
    all_native: true,
    signed_and_notarized: true,
    production_side_effects: false,
  };
}

async function main(argv) {
  if (argv.length < 7) {
    throw new Error("usage: validate-g6-native-evidence.mjs TAG COMMIT RUN_ID OUTPUT RECORD...");
  }
  const [tag, commit, runId, output, ...paths] = argv.slice(2);
  const records = await Promise.all(paths.map(async (path) => JSON.parse(await readFile(path, "utf8"))));
  const aggregate = validateG6Evidence(records, tag, commit, runId);
  aggregate.evidence_files = await Promise.all(paths.map(async (path) => ({
    name: basename(path),
    sha256: createHash("sha256").update(await readFile(path)).digest("hex"),
  })));
  await writeFile(output, JSON.stringify(aggregate, null, 2) + "\n");
  process.stdout.write(`g6_targets=${aggregate.targets.length}\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
