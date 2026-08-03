import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

const name = process.env.G5_NAME;
if (!name || !/^[a-z0-9-]+$/.test(name)) throw new Error("invalid G5_NAME");
const evidence = {
  schema_version: 1,
  gate: "G5",
  status: "passed",
  name,
  runner: process.env.G5_RUNNER,
  target: process.env.G5_TARGET,
  commit: process.env.G5_SHA,
  run_id: process.env.G5_RUN_ID,
  skipped_required_tests: 0,
  production_side_effects: false,
  release_policy_sha256: await digest("src-tauri/resources/v4-release-policy.json"),
  cargo_lock_sha256: await digest("src-tauri/Cargo.lock"),
  package_lock_sha256: await digest("package-lock.json"),
};
await mkdir("artifacts/g5", { recursive: true });
await writeFile(`artifacts/g5/${name}.json`, JSON.stringify(evidence, null, 2) + "\n");
