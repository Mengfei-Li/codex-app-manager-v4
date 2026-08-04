import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { G8CutoverError, executeAtomicCutover } from "./g8-cutover.mjs";

const roots = [];

async function harness(overrides = {}) {
  const root = await mkdtemp(join(tmpdir(), "cam-g8-test-"));
  roots.push(root);
  const calls = [];
  const rollbackContext = { owned: true };
  const dependencies = {
    auditPath: join(root, "audit.json"),
    preflight: async () => ({
      mirrorMatchesCandidate: false,
      portalProtocol: "v2",
    }),
    promoteMirror: async () => {
      calls.push("mirror-promote");
      return { outcome: "promoted", rollbackContext };
    },
    rollbackMirror: async (context) => {
      expect(context).toBe(rollbackContext);
      calls.push("mirror-rollback");
    },
    cutoverPortal: async () => calls.push("portal-cutover"),
    rollbackPortal: async () => calls.push("portal-rollback"),
    postcheck: async () => calls.push("postcheck"),
    ...overrides,
  };
  return {
    audit: async () => JSON.parse(await readFile(dependencies.auditPath, "utf8")),
    calls,
    dependencies,
  };
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("G8 all-at-once cutover", () => {
  it("commits mirror, portal, and postcheck in one owned transaction", async () => {
    const test = await harness();
    const result = await executeAtomicCutover(test.dependencies);
    expect(result.outcome).toBe("committed");
    expect(test.calls).toEqual(["mirror-promote", "portal-cutover", "postcheck"]);
    expect((await test.audit()).productionChanged).toBe(true);
  });

  it("is idempotent only when both public states already expose the candidate", async () => {
    const test = await harness({
      preflight: async () => ({ mirrorMatchesCandidate: true, portalProtocol: "v4" }),
    });
    const result = await executeAtomicCutover(test.dependencies);
    expect(result.outcome).toBe("already-committed");
    expect(test.calls).toEqual(["postcheck"]);
  });

  it("resumes safely after a prior run committed the mirror before the portal", async () => {
    const test = await harness({
      preflight: async () => ({ mirrorMatchesCandidate: true, portalProtocol: "v2" }),
    });
    const result = await executeAtomicCutover(test.dependencies);
    expect(result.outcome).toBe("committed");
    expect(test.calls).toEqual(["portal-cutover", "postcheck"]);
    expect((await test.audit()).mirror.promotion).toBe("preexisting-candidate");
  });

  it("restores V2 when resumed portal cutover fails and leaves the safe V4 pointer retryable", async () => {
    const test = await harness({
      preflight: async () => ({ mirrorMatchesCandidate: true, portalProtocol: "v2" }),
      cutoverPortal: async () => {
        test.calls.push("portal-cutover");
        throw new Error("simulated resumed portal failure");
      },
    });
    await expect(executeAtomicCutover(test.dependencies)).rejects.toMatchObject({ outcome: "rolled-back" });
    expect(test.calls).toEqual(["portal-cutover", "portal-rollback"]);
    expect((await test.audit()).mirror.promotion).toBe("preexisting-candidate");
  });

  it("rolls portal and mirror back when portal cutover fails", async () => {
    const test = await harness({
      cutoverPortal: async () => {
        test.calls.push("portal-cutover");
        throw new Error("simulated portal failure");
      },
    });
    await expect(executeAtomicCutover(test.dependencies)).rejects.toBeInstanceOf(G8CutoverError);
    expect(test.calls).toEqual([
      "mirror-promote",
      "portal-cutover",
      "portal-rollback",
      "mirror-rollback",
    ]);
    expect((await test.audit()).outcome).toBe("rolled-back");
  });

  it("rolls portal and mirror back when the full postcheck fails", async () => {
    const test = await harness({
      postcheck: async () => {
        test.calls.push("postcheck");
        throw new Error("simulated acceptance failure");
      },
    });
    await expect(executeAtomicCutover(test.dependencies)).rejects.toMatchObject({
      outcome: "rolled-back",
    });
    expect(test.calls.slice(-2)).toEqual(["portal-rollback", "mirror-rollback"]);
  });

  it("attempts both rollbacks and raises an alarm if either rollback fails", async () => {
    const test = await harness({
      postcheck: async () => {
        throw new Error("simulated postcheck failure");
      },
      rollbackPortal: async () => {
        test.calls.push("portal-rollback");
        throw new Error("simulated portal rollback failure");
      },
      rollbackMirror: async () => {
        test.calls.push("mirror-rollback");
        throw new Error("simulated mirror rollback failure");
      },
    });
    await expect(executeAtomicCutover(test.dependencies)).rejects.toMatchObject({
      outcome: "rollback-failed",
    });
    expect(test.calls.slice(-2)).toEqual(["portal-rollback", "mirror-rollback"]);
    const audit = await test.audit();
    expect(audit.productionChanged).toBeNull();
    expect(JSON.stringify(audit)).not.toContain("simulated");
  });
});
