import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { buildRuntime } from "../src/daemon/runtime.js";
import { createClauthServer, listenClauthServer } from "../src/daemon/app.js";
import { ClauthClient, ClauthError } from "../src/client/index.js";

const PASSPHRASE = "correct horse battery staple";

async function withTestDaemon(
  run: (ctx: { daemonUrl: string; skillToken: string }) => Promise<void>
): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-client-test-"));
  const saved = {
    home: process.env.CLAUTH_HOME,
    pass: process.env.CLAUTH_PASSPHRASE,
    admin: process.env.CLAUTH_ADMIN_TOKEN,
  };

  process.env.CLAUTH_HOME = temp;
  process.env.CLAUTH_PASSPHRASE = PASSPHRASE;
  process.env.CLAUTH_ADMIN_TOKEN = "test-admin";

  try {
    const config = defaultConfig();
    await saveConfig(config);

    const runtime = await buildRuntime(PASSPHRASE);
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, { port: 0 });

    // Store a credential and grant scope
    await runtime.vault.storeCredential({
      handle: "gh-main",
      provider: "github",
      secret: "ghp_fake_test_token",
      metadata: { authType: "bearer" },
    });

    await runtime.scopes.grant({
      skillId: "skill.test",
      provider: "github",
      scope: "github:read",
      rateLimitPerMinute: 60,
    });

    const issued = await runtime.skillAuth.issue("skill.test");

    try {
      await run({ daemonUrl: listening.endpoint, skillToken: issued.token });
    } finally {
      server.close();
    }
  } finally {
    for (const [key, val] of Object.entries(saved)) {
      const envKey =
        key === "home" ? "CLAUTH_HOME" :
        key === "pass" ? "CLAUTH_PASSPHRASE" :
        "CLAUTH_ADMIN_TOKEN";
      if (val === undefined) delete process.env[envKey];
      else process.env[envKey] = val;
    }
    await rm(temp, { recursive: true, force: true });
  }
}

test("ClauthClient requires skillId", () => {
  assert.throws(
    () => new ClauthClient({ skillToken: "tok" }),
    (err: unknown) => err instanceof ClauthError && err.code === "CONFIG_ERROR"
  );
});

test("ClauthClient requires skillToken", () => {
  assert.throws(
    () => new ClauthClient({ skillId: "skill.test" }),
    (err: unknown) => err instanceof ClauthError && err.code === "CONFIG_ERROR"
  );
});

test("ClauthClient auto-discovers from env vars", () => {
  const savedId = process.env.CLAUTH_SKILL_ID;
  const savedToken = process.env.CLAUTH_SKILL_TOKEN;
  process.env.CLAUTH_SKILL_ID = "skill.env";
  process.env.CLAUTH_SKILL_TOKEN = "tok-env";

  try {
    const client = new ClauthClient();
    assert.ok(client);
  } finally {
    if (savedId === undefined) delete process.env.CLAUTH_SKILL_ID;
    else process.env.CLAUTH_SKILL_ID = savedId;
    if (savedToken === undefined) delete process.env.CLAUTH_SKILL_TOKEN;
    else process.env.CLAUTH_SKILL_TOKEN = savedToken;
  }
});

test("ClauthClient builds signed-challenge proof payload", () => {
  const client = new ClauthClient({ skillId: "skill.test", skillToken: "tok" });
  const payload = client.buildSignedChallengeProof("github-main", "challenge-nonce", "octocat");
  const parsed = JSON.parse(payload) as {
    credentialHandle: string;
    challenge: string;
    accountId: string;
  };

  assert.equal(parsed.credentialHandle, "github-main");
  assert.equal(parsed.challenge, "challenge-nonce");
  assert.equal(parsed.accountId, "octocat");
});

test("client.health() returns true for running daemon", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });
    const ok = await client.health();
    assert.equal(ok, true);
  });
});

test("client.status() returns daemon info", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });
    const status = await client.status();
    assert.equal(status.vaultUnlocked, true);
    assert.equal(status.activeGrants, 1);
  });
});

test("client.fetch() executes brokered request through proxy", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });

    // This will reach GitHub with a fake token and get a 401 back,
    // proving the full pipeline works: client -> proxy -> scope check -> firewall -> vault -> GitHub
    const res = await client.fetch("github", "gh-main", "github:read", "https://api.github.com/user");
    assert.equal(res.status, 401);
    assert.ok(res.headers);
    assert.ok((res.body as Record<string, unknown>).message);
  });
});

test("client.fetch() throws on scope denial", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });

    await assert.rejects(
      () => client.fetch("github", "gh-main", "github:admin", "https://api.github.com/user"),
      (err: unknown) => err instanceof ClauthError && err.code === "ACCESS_DENIED"
    );
  });
});

test("client.fetch() throws on disallowed host", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });

    await assert.rejects(
      () => client.fetch("github", "gh-main", "github:read", "https://evil.example.com/steal"),
      (err: unknown) => err instanceof ClauthError && err.code === "VALIDATION_ERROR"
    );
  });
});

test("client.fetch() supports POST with body", async () => {
  await withTestDaemon(async ({ daemonUrl, skillToken }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken });

    // POST to GitHub API - will get 401 but proves body forwarding works
    const res = await client.fetch("github", "gh-main", "github:read", "https://api.github.com/graphql", {
      method: "POST",
      body: { query: "{ viewer { login } }" },
    });
    assert.equal(res.status, 401);
  });
});

test("client with wrong skill token throws UNAUTHORIZED", async () => {
  await withTestDaemon(async ({ daemonUrl }) => {
    const client = new ClauthClient({ daemonUrl, skillId: "skill.test", skillToken: "wrong-token" });

    await assert.rejects(
      () => client.fetch("github", "gh-main", "github:read", "https://api.github.com/user"),
      (err: unknown) => err instanceof ClauthError && err.code === "UNAUTHORIZED"
    );
  });
});
