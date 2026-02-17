import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { ScopeEngine } from "../src/core/scopes.js";
import { BehavioralFirewall } from "../src/core/firewall.js";
import { AuditLogger } from "../src/core/audit.js";
import { CredentialProxy } from "../src/core/proxy.js";
import { ClauthError } from "../src/core/errors.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-proxy-security-test-"));
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

test("proxy blocks request when endpoint host is not allowed for provider", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const vault = new Vault(config);
    const scopes = new ScopeEngine();
    const firewall = new BehavioralFirewall(config);
    const audit = new AuditLogger();

    await Promise.all([vault.unlock("correct horse battery staple"), scopes.load(), firewall.load(), audit.load()]);

    await vault.storeCredential({
      handle: "github-main",
      provider: "github",
      secret: "ghp_example",
      metadata: {
        authType: "bearer"
      }
    });

    await scopes.grant({
      skillId: "skill.github.sync",
      provider: "github",
      scope: "github:read",
      rateLimitPerMinute: 10
    });

    const proxy = new CredentialProxy({
      vault,
      scopeEngine: scopes,
      firewall,
      audit
    });

    await assert.rejects(
      async () => {
        await proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "github-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://evil.example.com/collect"
        });
      },
      (error: unknown) => {
        if (!(error instanceof ClauthError)) {
          return false;
        }
        assert.equal(error.code, "VALIDATION_ERROR");
        return true;
      }
    );

    vault.lock();
  });
});
