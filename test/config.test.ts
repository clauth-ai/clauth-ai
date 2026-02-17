import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { loadConfig, saveConfig, defaultConfig } from "../src/core/config.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-config-test-"));
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

test("loadConfig returns defaults when config is absent", async () => {
  await withTempHome(async () => {
    const config = await loadConfig();
    assert.equal(config.transport, "tcp");
    assert.ok(config.skillTokenSalt.length > 0);
    assert.ok(config.socketPath.includes("clauth.sock"));
    assert.equal(config.advisoryFeeds.length >= 1, true);
    assert.equal(config.advisoryFeeds[0].type, "github");
    assert.match(config.advisoryFeeds[0].url, /api\.github\.com\/advisories/);
    assert.equal(config.hardening.identityMaxVerifyAttempts, 5);
    assert.equal(config.hardening.identityVerifyPerSkillPerMinute, 30);
    assert.equal(config.hardening.identityVerifyPerIpPerMinute, 60);
  });
});

test("loadConfig merges partial legacy config safely", async () => {
  await withTempHome(async () => {
    const paths = resolveClauthPaths();
    await writeFile(
      paths.configFile,
      JSON.stringify(
        {
          host: "127.0.0.1",
          port: 9999,
          firewall: {
            burstLimit: 99
          }
        },
        null,
        2
      ),
      "utf8"
    );

    const config = await loadConfig();
    assert.equal(config.port, 9999);
    assert.equal(config.firewall.burstLimit, 99);
    assert.equal(config.transport, "tcp");
    assert.ok(config.skillTokenSalt.length > 0);
  });
});

test("saveConfig persists transport/security values", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "unix";
    config.socketPath = "/tmp/clauth.sock";

    await saveConfig(config);

    const loaded = await loadConfig();
    assert.equal(loaded.transport, "unix");
    assert.equal(loaded.socketPath, "/tmp/clauth.sock");
  });
});

test("loadConfig fails closed for malformed JSON", async () => {
  await withTempHome(async () => {
    const paths = resolveClauthPaths();
    await writeFile(paths.configFile, "{invalid-json", "utf8");

    await assert.rejects(async () => {
      await loadConfig();
    });
  });
});
