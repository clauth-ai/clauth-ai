import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { SkillAuthEngine } from "../src/core/skill-auth.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-skill-auth-test-"));
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

test("skill token issue and verify", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const auth = new SkillAuthEngine(config);
    await auth.load();

    const issued = await auth.issue("skill.alpha");

    assert.equal(auth.verify("skill.alpha", issued.token), true);
    assert.equal(auth.verify("skill.alpha", "invalid"), false);
    assert.equal(auth.verify("skill.beta", issued.token), false);
  });
});

test("revoked token no longer verifies", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const auth = new SkillAuthEngine(config);
    await auth.load();

    const issued = await auth.issue("skill.alpha");
    assert.equal(await auth.revoke("skill.alpha"), true);
    assert.equal(auth.verify("skill.alpha", issued.token), false);
  });
});

test("identify resolves owning skill for active token", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const auth = new SkillAuthEngine(config);
    await auth.load();

    const alpha = await auth.issue("skill.alpha");
    const beta = await auth.issue("skill.beta");
    await auth.revoke("skill.beta");

    assert.equal(auth.identify(alpha.token), "skill.alpha");
    assert.equal(auth.identify(beta.token), null);
    assert.equal(auth.identify("not-a-token"), null);
  });
});

test("skill auth load fails closed for malformed token store", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const paths = resolveClauthPaths();
    await writeFile(paths.skillAuthFile, "{broken-json", "utf8");

    const auth = new SkillAuthEngine(config);
    await assert.rejects(async () => {
      await auth.load();
    });
  });
});
