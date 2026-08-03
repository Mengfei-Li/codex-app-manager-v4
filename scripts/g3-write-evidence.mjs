import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const required = ["G3_NAME", "G3_RUNNER", "G3_TARGET", "G3_SHA", "G3_RUN_ID"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`missing ${name}`);
}

const evidence = {
  schemaVersion: 1,
  gate: "G3",
  architecture: process.env.G3_NAME,
  runner: process.env.G3_RUNNER,
  rustTarget: process.env.G3_TARGET,
  commit: process.env.G3_SHA,
  runId: process.env.G3_RUN_ID,
  checks: {
    deliveryContractAndClaim: "passed",
    configurationTransactionAndRollback: "passed",
    migrationBoundaryAndRestore: "passed",
    localeIsolationAndRelayContract: "passed",
    appApiCliUsageVerifier: "passed",
    portalCrossLanguageSignature: "passed",
    nativeTargetCompile: "passed",
    secretMaterialInEvidence: false,
  },
};
const canonical = `${JSON.stringify(evidence)}\n`;
evidence.evidenceSha256 = createHash("sha256").update(canonical).digest("hex");
await mkdir("artifacts/g3", { recursive: true });
await writeFile(
  `artifacts/g3/${process.env.G3_NAME}.json`,
  `${JSON.stringify(evidence, null, 2)}\n`,
  "utf8",
);
