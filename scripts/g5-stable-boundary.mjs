import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";

const roots = ["src", "src-tauri/installer", "src-tauri/resources"];
const forbidden = [
  /\bcanary\b/i,
  /\bengineering\b/i,
  /api\/bootstrap\/v4\/claim\?[^\s"']+/i,
];
const allowedPlaceholder = "src-tauri/resources/v4-release-policy.json";

async function files(root) {
  const output = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) output.push(...await files(path));
    else if (entry.isFile()) output.push(path);
  }
  return output;
}

const violations = [];
for (const root of roots) {
  for (const path of await files(root)) {
    const normalized = relative(".", path).replaceAll("\\", "/");
    const text = await readFile(path, "utf8").catch(() => "");
    for (const pattern of forbidden) {
      if (pattern.test(text)) violations.push(`${normalized}: ${pattern}`);
    }
    if (normalized !== allowedPlaceholder && text.includes("placeholder.invalid")) {
      violations.push(`${normalized}: placeholder.invalid`);
    }
  }
}

const policy = JSON.parse(await readFile(allowedPlaceholder, "utf8"));
if (policy.state !== "unpublished") {
  throw new Error("P5 source policy must stay unpublished until the signed P6 release build");
}
if (violations.length) {
  throw new Error(`stable/canary boundary violations:\n${violations.join("\n")}`);
}
process.stdout.write(JSON.stringify({
  schema_version: 1,
  status: "passed",
  stable_canary_isolated: true,
  release_policy_state: policy.state,
  scanned_roots: roots,
  production_changed: false,
}, null, 2) + "\n");
