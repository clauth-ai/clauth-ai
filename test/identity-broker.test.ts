import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { AuditLogger } from "../src/core/audit.js";
import { AlertRouter } from "../src/core/alerts.js";
import { SessionEngine } from "../src/core/sessions.js";
import { IdentityBrokerEngine } from "../src/core/identity-broker.js";
import { resolveClauthPaths } from "../src/core/fs.js";

let emailDeliveries: Array<{ challengeId: string; accountId: string; code: string }> = [];

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-identity-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  const originalWebhook = process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;
  const originalFetch = globalThis.fetch;

  process.env.CLAUTH_HOME = temp;
  process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL = "https://example.invalid/clauth/email";
  emailDeliveries = [];

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const webhook = process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;
    const inputUrl =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;

    if (webhook && inputUrl === webhook) {
      const parsed = init?.body ? JSON.parse(String(init.body)) : {};
      emailDeliveries.push({
        challengeId: String((parsed as Record<string, unknown>).challengeId ?? ""),
        accountId: String((parsed as Record<string, unknown>).accountId ?? ""),
        code: String((parsed as Record<string, unknown>).code ?? "")
      });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }

    return originalFetch(input, init);
  };

  try {
    await run(temp);
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }
    if (originalWebhook === undefined) {
      delete process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;
    } else {
      process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL = originalWebhook;
    }
    globalThis.fetch = originalFetch;
    emailDeliveries = [];
    await rm(temp, { recursive: true, force: true });
  }
}

async function buildBroker(config: ReturnType<typeof defaultConfig>): Promise<{
  vault: Vault;
  broker: IdentityBrokerEngine;
  audit: AuditLogger;
}> {
  const vault = new Vault(config);
  await vault.unlock("correct horse battery staple");
  const audit = new AuditLogger();
  await audit.load();
  const alertRouter = new AlertRouter(config);
  await alertRouter.load();
  const sessions = new SessionEngine(vault);
  const broker = new IdentityBrokerEngine({ vault, audit, alertRouter, sessions });
  await broker.load();
  return { vault, broker, audit };
}

function latestEmailCode(expectedChallengeId: string): string {
  const delivery = emailDeliveries.at(-1);
  assert.ok(delivery);
  assert.equal(delivery.challengeId, expectedChallengeId);
  assert.ok(delivery.code);
  return delivery.code;
}

test("IdentityBroker creates a challenge", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "github",
      accountId: "testuser"
    });

    assert.ok(challenge.id);
    assert.ok(challenge.challenge);
    assert.equal(challenge.status, "pending");
    assert.equal(challenge.provider, "github");
    assert.equal(challenge.accountId, "testuser");
    assert.equal(challenge.method, "signed-challenge");
    assert.ok(challenge.expiresAt);

    vault.lock();
  });
});

test("IdentityBroker retrieves challenge status", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "github",
      accountId: "testuser"
    });

    const status = broker.getChallenge(challenge.id);
    assert.ok(status);
    assert.equal(status.status, "pending");

    vault.lock();
  });
});

test("IdentityBroker returns null for unknown challenge", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const result = broker.getChallenge("nonexistent-id");
    assert.equal(result, null);

    vault.lock();
  });
});

test("IdentityBroker email verification succeeds with correct code", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const result = await broker.verifyChallenge(challenge.id, latestEmailCode(challenge.id));
    assert.equal(result.status, "verified");
    assert.ok(result.verifiedAt);

    vault.lock();
  });
});

test("IdentityBroker keeps challenge pending on wrong email code until max attempts reached", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const result = await broker.verifyChallenge(challenge.id, "wrong-code");
    assert.equal(result.status, "pending");
    const status = broker.getChallenge(challenge.id);
    assert.ok(status);
    assert.equal(status.status, "pending");
    assert.equal(status.attempts, 1);

    vault.lock();
  });
});

test("IdentityBroker rejects email challenges when webhook delivery is not configured", async () => {
  await withTempHome(async () => {
    const originalWebhook = process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;
    delete process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;

    try {
      const config = defaultConfig();
      await saveConfig(config);
      const { vault, broker } = await buildBroker(config);

      await assert.rejects(
        () =>
          broker.createChallenge({
            skillId: "test-skill",
            provider: "email",
            accountId: "user@example.com",
            method: "email"
          }),
        /CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL/
      );

      vault.lock();
    } finally {
      if (originalWebhook === undefined) {
        delete process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL;
      } else {
        process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL = originalWebhook;
      }
    }
  });
});

test("IdentityBroker requires structured signed-challenge proof payload", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "github",
      accountId: "octocat",
      method: "signed-challenge"
    });

    const missingContract = await broker.verifyChallenge(challenge.id, "github-main");
    assert.equal(missingContract.status, "pending");

    vault.lock();
  });
});

test("IdentityBroker fails challenge after max verify attempts", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();
    const sessions = new SessionEngine(vault);
    const broker = new IdentityBrokerEngine({
      vault,
      audit,
      alertRouter,
      sessions,
      maxVerifyAttempts: 2
    });
    await broker.load();

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const first = await broker.verifyChallenge(challenge.id, "wrong-code-1");
    assert.equal(first.status, "pending");

    const second = await broker.verifyChallenge(challenge.id, "wrong-code-2");
    assert.equal(second.status, "failed");

    const status = broker.getChallenge(challenge.id);
    assert.ok(status);
    assert.equal(status.status, "failed");
    assert.equal(status.attempts, 2);

    vault.lock();
  });
});

test("IdentityBroker verifies signed-challenge payload bound to challenge nonce", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    await vault.storeCredential({
      handle: "github-main",
      provider: "github",
      secret: "ghp_token"
    });

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "github",
      accountId: "octocat",
      method: "signed-challenge"
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const inputUrl =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;

      if (inputUrl === "https://api.github.com/user") {
        return new Response(JSON.stringify({ login: "octocat" }), {
          status: 200,
          headers: { "content-type": "application/json" }
        });
      }
      return originalFetch(input, init);
    };

    try {
      const proof = JSON.stringify({
        credentialHandle: "github-main",
        challenge: challenge.challenge,
        accountId: "octocat"
      });
      const result = await broker.verifyChallenge(challenge.id, proof);
      assert.equal(result.status, "verified");
    } finally {
      globalThis.fetch = originalFetch;
    }

    vault.lock();
  });
});

test("IdentityBroker lists verified proofs", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    await broker.verifyChallenge(challenge.id, latestEmailCode(challenge.id));

    const allProofs = broker.listProofs();
    assert.equal(allProofs.length, 1);
    assert.equal(allProofs[0].provider, "email");
    assert.equal(allProofs[0].accountId, "user@example.com");

    const skillProofs = broker.listProofs("test-skill");
    assert.equal(skillProofs.length, 1);

    const otherProofs = broker.listProofs("other-skill");
    assert.equal(otherProofs.length, 0);

    vault.lock();
  });
});

test("IdentityBroker revokes a proof", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    await broker.verifyChallenge(challenge.id, latestEmailCode(challenge.id));
    assert.equal(broker.listProofs().length, 1);

    const revoked = await broker.revokeProof(challenge.id);
    assert.ok(revoked);
    assert.equal(broker.listProofs().length, 0);

    vault.lock();
  });
});

test("IdentityBroker revokeProof returns false for unknown proofId", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const result = await broker.revokeProof("nonexistent");
    assert.equal(result, false);

    vault.lock();
  });
});

test("IdentityBroker verifyChallenge returns failed for unknown challengeId", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const result = await broker.verifyChallenge("unknown-id", "some-proof");
    assert.equal(result.status, "failed");

    vault.lock();
  });
});

test("IdentityBroker persists state across reloads", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const { vault, audit } = await buildBroker(config);
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();
    const sessions = new SessionEngine(vault);

    const broker1 = new IdentityBrokerEngine({ vault, audit, alertRouter, sessions });
    await broker1.load();

    const challenge = await broker1.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });
    await broker1.verifyChallenge(challenge.id, latestEmailCode(challenge.id));

    const broker2 = new IdentityBrokerEngine({ vault, audit, alertRouter, sessions });
    await broker2.load();

    const proofs = broker2.listProofs();
    assert.equal(proofs.length, 1);

    vault.lock();
  });
});

test("IdentityBroker rejects already-verified challenge", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const emailCode = latestEmailCode(challenge.id);
    await broker.verifyChallenge(challenge.id, emailCode);

    const result = await broker.verifyChallenge(challenge.id, emailCode);
    assert.equal(result.status, "verified");

    vault.lock();
  });
});

test("IdentityBroker creates challenges with different proof methods", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const signedChallenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "github",
      accountId: "testuser",
      method: "signed-challenge"
    });
    assert.equal(signedChallenge.method, "signed-challenge");

    const emailChallenge = await broker.createChallenge({
      skillId: "test-skill",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });
    assert.equal(emailChallenge.method, "email");

    vault.lock();
  });
});

test("IdentityBroker blocks cross-skill verification without mutating challenge", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "skill.alpha",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const result = await broker.verifyChallenge(challenge.id, latestEmailCode(challenge.id), {
      requesterSkillId: "skill.beta"
    });
    assert.equal(result.status, "failed");

    const status = broker.getChallenge(challenge.id);
    assert.ok(status);
    assert.equal(status.status, "pending");

    vault.lock();
  });
});

test("IdentityBroker getChallengeForSkill hides other skills", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "skill.alpha",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });

    const denied = broker.getChallengeForSkill(challenge.id, { requesterSkillId: "skill.beta" });
    const allowed = broker.getChallengeForSkill(challenge.id, { requesterSkillId: "skill.alpha" });
    assert.equal(denied, null);
    assert.ok(allowed);

    vault.lock();
  });
});

test("IdentityBroker writes identity-specific audit events", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "skill.alpha",
      provider: "email",
      accountId: "user@example.com",
      method: "email"
    });
    await broker.verifyChallenge(challenge.id, latestEmailCode(challenge.id), {
      requesterSkillId: "skill.alpha"
    });
    await broker.revokeProof(challenge.id);

    const raw = await readFile(resolveClauthPaths().auditFile, "utf8");
    const events = raw
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { event: string });

    assert.equal(events.some((entry) => entry.event === "identity.challenge"), true);
    assert.equal(events.some((entry) => entry.event === "identity.verify"), true);
    assert.equal(events.some((entry) => entry.event === "identity.revoke"), true);

    vault.lock();
  });
});

test("IdentityBroker rejects tampered OAuth state without mutating challenge", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const { vault, broker } = await buildBroker(config);

    const challenge = await broker.createChallenge({
      skillId: "skill.alpha",
      provider: "github",
      accountId: "octocat",
      method: "oauth"
    });

    const oauthUrl = broker.generateOAuthUrl(challenge.id);
    assert.ok(oauthUrl);
    const state = new URL(oauthUrl).searchParams.get("state");
    assert.ok(state);

    const tamperedState = `${state!.slice(0, -1)}${state!.slice(-1) === "a" ? "b" : "a"}`;
    const result = await broker.completeOAuthCallback(tamperedState, "dummy-code");
    assert.equal(result.status, "failed");

    const status = broker.getChallenge(challenge.id);
    assert.ok(status);
    assert.equal(status.status, "pending");

    vault.lock();
  });
});
