import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const sourcePath = resolve(
  repoRoot,
  process.argv[2] || "release/v4-release-policy.production.json",
);
const destinationPath = resolve(
  repoRoot,
  process.argv[3] || "src-tauri/resources/v4-release-policy.json",
);

function fail(message) {
  throw new Error(`V4 release policy injection failed: ${message}`);
}

function exactHttps(value, pathname) {
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== pathname
  ) {
    fail(`invalid endpoint ${pathname}`);
  }
}

const [rawPolicy, rawPackage] = await Promise.all([
  readFile(sourcePath, "utf8"),
  readFile(resolve(repoRoot, "package.json"), "utf8"),
]);
const policy = JSON.parse(rawPolicy);
const packageJson = JSON.parse(rawPackage);
const requiredBuildId = `codex-app-manager-v4-${packageJson.version}`;

if (
  policy.schema_version !== 1 ||
  policy.state !== "release" ||
  policy.build_id !== requiredBuildId ||
  policy.issuer !== "provider-codex-v4" ||
  policy.audience !== "codex-app-manager" ||
  policy.claim_endpoint_id !== "customer-portal-v4-claim" ||
  !/^[A-Za-z0-9_-]{43}$/.test(policy.public_key_b64)
) {
  fail("identity contract mismatch");
}
exactHttps(policy.claim_endpoint_url, "/api/bootstrap/v4/claim");
exactHttps(
  policy.diagnostic_endpoint,
  "/api/installer/v4/diagnostics/bundles",
);
if (
  !Array.isArray(policy.allowed_api_origins) ||
  policy.allowed_api_origins.length === 0 ||
  policy.allowed_api_origins.some((value) => {
    const url = new URL(value);
    return (
      url.protocol !== "https:" ||
      url.origin !== value ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    );
  })
) {
  fail("API origin allowlist is invalid");
}

const canonical = `${JSON.stringify(policy, null, 2)}\n`;
await writeFile(destinationPath, canonical, { encoding: "utf8", mode: 0o644 });
const sha256 = createHash("sha256").update(canonical).digest("hex");
process.stdout.write(`release_policy_build_id=${policy.build_id}\n`);
process.stdout.write(`release_policy_sha256=${sha256}\n`);
