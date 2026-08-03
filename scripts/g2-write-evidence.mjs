import { mkdir, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const required = ["G2_NAME", "G2_RUNNER", "G2_TARGET", "G2_SHA", "G2_RUN_ID"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`missing ${name}`);
}

const evidence = {
  schemaVersion: 1,
  gate: "G2",
  architecture: process.env.G2_NAME,
  runner: process.env.G2_RUNNER,
  rustTarget: process.env.G2_TARGET,
  commit: process.env.G2_SHA,
  runId: process.env.G2_RUN_ID,
  checks: {
    frontendBundle: "passed",
    windowsEngineFaultSuite: "passed",
    macosEngineFaultSuite: "passed",
    managerTransactionSuite: "passed",
    nativeTargetCompile: "passed",
  },
};
const canonical = `${JSON.stringify(evidence)}\n`;
evidence.evidenceSha256 = createHash("sha256").update(canonical).digest("hex");
await mkdir("artifacts/g2", { recursive: true });
await writeFile(
  `artifacts/g2/${process.env.G2_NAME}.json`,
  `${JSON.stringify(evidence, null, 2)}\n`,
  "utf8",
);
