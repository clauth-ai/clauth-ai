import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { AuditLogger } from "../src/core/audit.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-audit-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  process.env.CLAUTH_HOME = temp;

  try {
    await run();
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }

    await rm(temp, { recursive: true, force: true });
  }
}

test("audit logger validates untampered hash chain", async () => {
  await withTempHome(async () => {
    const logger = new AuditLogger();
    await logger.load();

    await logger.append({
      ts: new Date().toISOString(),
      event: "daemon.start",
      outcome: "ok"
    });

    await logger.append({
      ts: new Date().toISOString(),
      event: "proxy.allow",
      outcome: "ok",
      skillId: "skill.alpha"
    });

    const integrity = await logger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });
});

test("audit logger detects tampering", async () => {
  await withTempHome(async () => {
    const logger = new AuditLogger();
    await logger.load();

    await logger.append({
      ts: new Date().toISOString(),
      event: "daemon.start",
      outcome: "ok"
    });

    const paths = resolveClauthPaths();
    const raw = await readFile(paths.auditFile, "utf8");
    const lines = raw.trim().split("\n");
    const first = JSON.parse(lines[0]) as { outcome: string };
    first.outcome = "tampered";
    lines[0] = JSON.stringify(first);
    await writeFile(paths.auditFile, `${lines.join("\n")}\n`, "utf8");

    const integrity = await logger.verifyIntegrity();
    assert.equal(integrity.valid, false);
    assert.equal(integrity.brokenAtLine, 1);
  });
});

test("audit logger preserves hash chain under concurrent appends", async () => {
  await withTempHome(async () => {
    const logger = new AuditLogger();
    await logger.load();

    await Promise.all(
      Array.from({ length: 25 }, (_, index) =>
        logger.append({
          ts: new Date().toISOString(),
          event: "proxy.allow",
          outcome: "ok",
          skillId: `skill.${index}`
        })
      )
    );

    const integrity = await logger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });
});

test("audit logger preserves hash chain across concurrent logger instances", async () => {
  await withTempHome(async () => {
    const loggerA = new AuditLogger();
    const loggerB = new AuditLogger();
    await Promise.all([loggerA.load(), loggerB.load()]);

    await Promise.all(
      Array.from({ length: 40 }, (_, index) =>
        (index % 2 === 0 ? loggerA : loggerB).append({
          ts: new Date().toISOString(),
          event: "proxy.allow",
          outcome: "ok",
          skillId: `skill.multi.${index}`
        })
      )
    );

    const verifier = new AuditLogger();
    await verifier.load();
    const integrity = await verifier.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });
});

test("audit logger reports malformed JSON entries as invalid chain", async () => {
  await withTempHome(async () => {
    const logger = new AuditLogger();
    await logger.load();

    const paths = resolveClauthPaths();
    await writeFile(paths.auditFile, "{\"not\":\"closed\"\n", "utf8");

    const integrity = await logger.verifyIntegrity();
    assert.equal(integrity.valid, false);
    assert.equal(integrity.brokenAtLine, 1);
    assert.equal(integrity.reason, "invalid_json");
  });
});

test("audit logger load fails closed for malformed persisted log", async () => {
  await withTempHome(async () => {
    const paths = resolveClauthPaths();
    await writeFile(paths.auditFile, "{\"broken\":\n", "utf8");

    const logger = new AuditLogger();
    await assert.rejects(async () => {
      await logger.load();
    });
  });
});
