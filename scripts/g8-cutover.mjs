#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile, writeFile, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  backendConfigsFromEnv,
  candidateIdFromEnv,
  candidateKeyFor,
  createMirrorManifest,
  downgradeOverrideFromEnv,
  promoteMirrorsTransaction,
  rollbackCompletedPromotion,
} from "./mirror-release.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");

function utcNow() {
  return new Date().toISOString();
}

function errorCode(error) {
  return error instanceof Error && error.name ? error.name : "Error";
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonical(child)]),
    );
  }
  return value;
}

function sameManifest(left, right) {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

async function writeAudit(path, value) {
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export class G8CutoverError extends Error {
  constructor(outcome) {
    super(`G8 atomic cutover ended with ${outcome}`);
    this.name = "G8CutoverError";
    this.outcome = outcome;
  }
}

export async function executeAtomicCutover({
  preflight,
  promoteMirror,
  rollbackMirror,
  cutoverPortal,
  rollbackPortal,
  postcheck,
  auditPath,
}) {
  const audit = {
    schemaVersion: 1,
    startedAtUtc: utcNow(),
    finishedAtUtc: null,
    outcome: "running",
    productionChanged: false,
    secretValuesRecorded: false,
    preflight: null,
    mirror: { promotion: "not-started", rollback: "not-needed" },
    portal: { cutover: "not-started", rollback: "not-needed" },
    postcheck: "not-started",
  };
  let mirrorRollbackContext = null;
  let portalAttempted = false;
  try {
    const state = await preflight();
    audit.preflight = {
      mirrorMatchesCandidate: state.mirrorMatchesCandidate === true,
      portalProtocol: state.portalProtocol,
    };
    if (state.portalProtocol === "v4" && state.mirrorMatchesCandidate === true) {
      await postcheck();
      audit.postcheck = "passed";
      audit.outcome = "already-committed";
      audit.productionChanged = true;
      return audit;
    }
    if (state.portalProtocol !== "v2") {
      throw new Error("G8 preflight found a partial or unsupported production state");
    }
    if (state.mirrorMatchesCandidate === true) {
      // A previous run may have terminated after the mirror CAS but before the
      // portal transaction.  V2 customers do not consume the V4 Manager pointer,
      // so completing the portal switch is the only safe forward recovery.  If
      // it fails, the portal is restored to V2 and the next run retries here.
      audit.mirror.promotion = "preexisting-candidate";
    } else {
      const promoted = await promoteMirror();
      mirrorRollbackContext = promoted.rollbackContext;
      if (!mirrorRollbackContext || promoted.outcome === "idempotent") {
        throw new Error("G8 did not acquire an owned mirror rollback handle");
      }
      audit.mirror.promotion = "committed";
    }

    portalAttempted = true;
    await cutoverPortal();
    audit.portal.cutover = "committed";

    await postcheck();
    audit.postcheck = "passed";
    audit.outcome = "committed";
    audit.productionChanged = true;
    return audit;
  } catch (error) {
    audit.error = errorCode(error);
    const rollbackFailures = [];
    if (portalAttempted) {
      audit.portal.rollback = "attempting";
      try {
        await rollbackPortal();
        audit.portal.rollback = "restored-v2";
      } catch (rollbackError) {
        audit.portal.rollback = "failed";
        audit.portal.rollbackError = errorCode(rollbackError);
        rollbackFailures.push("portal");
      }
    }
    if (mirrorRollbackContext) {
      audit.mirror.rollback = "attempting";
      try {
        await rollbackMirror(mirrorRollbackContext);
        audit.mirror.rollback = "restored-previous";
      } catch (rollbackError) {
        audit.mirror.rollback = "failed";
        audit.mirror.rollbackError = errorCode(rollbackError);
        rollbackFailures.push("mirror");
      }
    }
    const mutationStarted = portalAttempted || Boolean(mirrorRollbackContext);
    audit.outcome = rollbackFailures.length
      ? "rollback-failed"
      : mutationStarted
        ? "rolled-back"
        : "failed-before-mutation";
    audit.productionChanged = rollbackFailures.length ? null : false;
    throw new G8CutoverError(audit.outcome);
  } finally {
    audit.finishedAtUtc = utcNow();
    await writeAudit(auditPath, audit);
  }
}

function parseArgs(argv) {
  const options = { portalControlArg: [], postcheckArg: [] };
  const repeatable = new Set(["portal-control-arg", "postcheck-arg"]);
  for (let index = 2; index < argv.length; index += 2) {
    const name = argv[index]?.replace(/^--/, "");
    const value = argv[index + 1];
    if (!name || value === undefined) throw new Error("G8 arguments must be --name value pairs");
    const key = name.replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
    if (repeatable.has(name)) options[key].push(value);
    else if (options[key] !== undefined) throw new Error(`duplicate G8 argument: ${name}`);
    else options[key] = value;
  }
  for (const name of [
    "distDir",
    "portalControlProgram",
    "postcheckProgram",
    "portalPublicBase",
    "auditOutput",
  ]) {
    if (!options[name]) throw new Error(`missing required G8 argument: ${name}`);
  }
  return options;
}

async function runProgram(program, args, action) {
  const executable = resolve(program);
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, [...args, action], {
      env: process.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let bytes = 0;
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) child.kill("SIGTERM");
      });
    }
    child.on("error", rejectPromise);
    child.on("exit", (code) => {
      if (code === 0 && bytes <= 1024 * 1024) resolvePromise();
      else rejectPromise(new Error(`${action} control failed`));
    });
  });
}

async function fetchJson(url, label) {
  const response = await fetch(url, {
    headers: { accept: "application/json", "user-agent": "v4-g8-cutover/1" },
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`${label} returned ${response.status}`);
  return await response.json();
}

async function main() {
  const options = parseArgs(process.argv);
  const distDir = resolve(options.distDir);
  const mirrorBase = String(
    process.env.MIRROR_BASE_URL || "https://codexapp.agentsmirror.com/manager",
  ).replace(/\/$/, "");
  const mirror = await createMirrorManifest(distDir, mirrorBase);
  const candidateKey = candidateKeyFor(mirror.version, candidateIdFromEnv(process.env));
  const tempRoot = await mkdtemp(join(tmpdir(), "cam-g8-cutover-"));
  const configPath = join(tempRoot, "aws-config");
  await writeFile(configPath, "[default]\nregion = auto\ns3 =\n    addressing_style = path\n");
  const backends = backendConfigsFromEnv(process.env, configPath);
  const publicKey =
    process.env.MIRROR_UPDATER_PUBLIC_KEY ||
    JSON.parse(await readFile(join(REPO_ROOT, "src-tauri", "tauri.conf.json"), "utf8"))
      .plugins.updater.pubkey;
  const portalBase = String(options.portalPublicBase).replace(/\/$/, "");
  const promotionSummary = join(dirname(resolve(options.auditOutput)), "g8-mirror-promotion.json");
  try {
    await executeAtomicCutover({
      auditPath: resolve(options.auditOutput),
      preflight: async () => {
        const [portal, currentMirror] = await Promise.all([
          fetchJson(`${portalBase}/api/public-config`, "portal preflight"),
          fetchJson(`${mirrorBase}/latest.json`, "mirror preflight"),
        ]);
        return {
          portalProtocol: portal?.data?.installer_protocol,
          mirrorMatchesCandidate: sameManifest(currentMirror, mirror.manifest),
        };
      },
      promoteMirror: async () =>
        await promoteMirrorsTransaction({
          backends,
          candidateKey,
          candidateManifest: mirror.manifest,
          candidatePath: mirror.outputPath,
          distDir,
          mirrorBase,
          override: downgradeOverrideFromEnv(process.env),
          publicKey,
          summaryPath: promotionSummary,
          tempRoot: join(tempRoot, "mirror"),
        }),
      rollbackMirror: async (context) => {
        await rollbackCompletedPromotion(context);
        await writeFile(promotionSummary, `${JSON.stringify(context.summary, null, 2)}\n`);
      },
      cutoverPortal: async () =>
        await runProgram(options.portalControlProgram, options.portalControlArg, "cutover"),
      rollbackPortal: async () =>
        await runProgram(options.portalControlProgram, options.portalControlArg, "rollback"),
      postcheck: async () => {
        const [portal, latest] = await Promise.all([
          fetchJson(`${portalBase}/api/public-config`, "portal postcheck"),
          fetchJson(`${mirrorBase}/latest.json`, "mirror postcheck"),
        ]);
        if (portal?.data?.installer_protocol !== "v4" || !sameManifest(latest, mirror.manifest)) {
          throw new Error("G8 public state is not the exact V4 candidate");
        }
        await runProgram(options.postcheckProgram, options.postcheckArg, "postcheck");
      },
    });
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`G8_CUTOVER_FAILED ${errorCode(error)}\n`);
    process.exitCode = 1;
  });
}
