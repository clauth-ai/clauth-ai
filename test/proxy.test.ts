import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { ScopeEngine } from "../src/core/scopes.js";
import { BehavioralFirewall } from "../src/core/firewall.js";
import { AuditLogger } from "../src/core/audit.js";
import { CredentialProxy } from "../src/core/proxy.js";
import { ClauthError } from "../src/core/errors.js";

const PASSPHRASE = "correct horse battery staple";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-proxy-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  const originalHttp = process.env.CLAUTH_ALLOW_INSECURE_HTTP;
  process.env.CLAUTH_HOME = temp;

  try {
    await run();
  } finally {
    if (originalHome === undefined) delete process.env.CLAUTH_HOME;
    else process.env.CLAUTH_HOME = originalHome;

    if (originalHttp === undefined) delete process.env.CLAUTH_ALLOW_INSECURE_HTTP;
    else process.env.CLAUTH_ALLOW_INSECURE_HTTP = originalHttp;

    await rm(temp, { recursive: true, force: true });
  }
}

interface TestStack {
  vault: Vault;
  scopes: ScopeEngine;
  firewall: BehavioralFirewall;
  audit: AuditLogger;
  proxy: CredentialProxy;
}

async function setupStack(): Promise<TestStack> {
  const config = defaultConfig();
  config.firewall.burstLimit = 200; // high limit for most tests
  await saveConfig(config);

  const vault = new Vault(config);
  const scopes = new ScopeEngine();
  const firewall = new BehavioralFirewall(config);
  const audit = new AuditLogger();

  await Promise.all([vault.unlock(PASSPHRASE), scopes.load(), firewall.load(), audit.load()]);

  await vault.storeCredential({
    handle: "gh-main",
    provider: "github",
    secret: "ghp_test_token_123",
    metadata: { authType: "bearer" },
  });

  await scopes.grant({
    skillId: "skill.github.sync",
    provider: "github",
    scope: "github:read",
    rateLimitPerMinute: 60,
  });

  const proxy = new CredentialProxy({ vault, scopeEngine: scopes, firewall, audit });
  return { vault, scopes, firewall, audit, proxy };
}

test("proxy rejects request with missing required fields", async () => {
  await withTempHome(async () => {
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://api.github.com/user",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "VALIDATION_ERROR"
    );

    vault.lock();
  });
});

test("proxy rejects invalid URL endpoint", async () => {
  await withTempHome(async () => {
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "not-a-url",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "VALIDATION_ERROR"
    );

    vault.lock();
  });
});

test("proxy rejects HTTP endpoint when insecure not allowed", async () => {
  await withTempHome(async () => {
    delete process.env.CLAUTH_ALLOW_INSECURE_HTTP;
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "http://api.github.com/user",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "VALIDATION_ERROR"
    );

    vault.lock();
  });
});

test("proxy denies request when scope not granted", async () => {
  await withTempHome(async () => {
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:admin",
          method: "DELETE",
          endpoint: "https://api.github.com/repos/test",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "ACCESS_DENIED"
    );

    vault.lock();
  });
});

test("proxy denies request from unauthorized skill", async () => {
  await withTempHome(async () => {
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "skill.evil.exfiltrate",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://api.github.com/user",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "ACCESS_DENIED"
    );

    vault.lock();
  });
});

test("proxy denies request when firewall burst limit exceeded", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.burstLimit = 3;
    config.firewall.burstWindowMs = 60_000;
    await saveConfig(config);

    const vault = new Vault(config);
    const scopes = new ScopeEngine();
    const firewall = new BehavioralFirewall(config);
    const audit = new AuditLogger();

    await Promise.all([vault.unlock(PASSPHRASE), scopes.load(), firewall.load(), audit.load()]);

    await vault.storeCredential({
      handle: "gh-main",
      provider: "github",
      secret: "ghp_test",
      metadata: { authType: "bearer", allowedHosts: "api.github.com" },
    });

    await scopes.grant({
      skillId: "skill.github.sync",
      provider: "github",
      scope: "github:read",
      rateLimitPerMinute: 200,
    });

    const proxy = new CredentialProxy({ vault, scopeEngine: scopes, firewall, audit });

    // Exhaust the burst limit - these will fail at fetch() since there's no real server,
    // but the firewall counters still increment via the scope+firewall path.
    // We need to trigger the firewall block before the fetch happens.
    // The firewall runs before fetch, so after burstLimit calls, the next should be blocked.
    let firewallBlocked = false;
    for (let i = 0; i < 6; i++) {
      try {
        await proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://api.github.com/user",
        });
      } catch (err) {
        if (err instanceof ClauthError && err.message.includes("Firewall blocked")) {
          firewallBlocked = true;
          break;
        }
        // Other errors (like UPSTREAM_ERROR from failed fetch) are expected, continue
      }
    }
    assert.ok(firewallBlocked, "Expected firewall to block after burst limit exceeded");

    vault.lock();
  });
});

test("proxy blocks request to disallowed endpoint host", async () => {
  await withTempHome(async () => {
    const { proxy, vault } = await setupStack();

    await assert.rejects(
      () =>
        proxy.execute({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "gh-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://evil.example.com/steal",
        }),
      (err: unknown) => err instanceof ClauthError && err.code === "VALIDATION_ERROR"
    );

    vault.lock();
  });
});
