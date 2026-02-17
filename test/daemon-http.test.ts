import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { ScopeEngine } from "../src/core/scopes.js";
import { SkillAuthEngine } from "../src/core/skill-auth.js";
import { SessionEngine } from "../src/core/sessions.js";
import { Vault } from "../src/core/vault.js";
import { buildRuntime } from "../src/daemon/runtime.js";
import { createClauthServer, listenClauthServer } from "../src/daemon/app.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-daemon-http-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  const originalAdmin = process.env.CLAUTH_ADMIN_TOKEN;
  process.env.CLAUTH_HOME = temp;
  process.env.CLAUTH_ADMIN_TOKEN = "test-admin-token";

  try {
    await run();
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }

    if (originalAdmin === undefined) {
      delete process.env.CLAUTH_ADMIN_TOKEN;
    } else {
      process.env.CLAUTH_ADMIN_TOKEN = originalAdmin;
    }

    await rm(temp, { recursive: true, force: true });
  }
}

test("daemon rejects proxy call without skill token", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const response = await fetch(`${listening.endpoint}/clauth/v1/proxy`, {
        method: "POST",
        headers: {
          "content-type": "application/json"
        },
        body: JSON.stringify({
          skillId: "skill.github.sync",
          provider: "github",
          credentialHandle: "github-main",
          scope: "github:read",
          method: "GET",
          endpoint: "https://api.github.com/user"
        })
      });

      assert.equal(response.status, 401);
      const body = (await response.json()) as { error?: { code?: string } };
      assert.equal(body.error?.code, "UNAUTHORIZED");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon admin skill-token issue/list/revoke roundtrip", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const issueResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/skill-token/issue`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-admin-token": "test-admin-token"
        },
        body: JSON.stringify({ skillId: "skill.alpha" })
      });
      assert.equal(issueResponse.status, 200);
      const issueBody = (await issueResponse.json()) as { skillId: string; token: string };
      assert.equal(issueBody.skillId, "skill.alpha");
      assert.ok(issueBody.token.length > 10);

      const listResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/skill-token/list`, {
        method: "GET",
        headers: {
          "x-clauth-admin-token": "test-admin-token"
        }
      });
      assert.equal(listResponse.status, 200);
      const listBody = (await listResponse.json()) as { tokens: Array<{ skillId: string; active: boolean }> };
      assert.equal(listBody.tokens.some((entry) => entry.skillId === "skill.alpha" && entry.active), true);

      const revokeResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/skill-token/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-admin-token": "test-admin-token"
        },
        body: JSON.stringify({ skillId: "skill.alpha" })
      });
      assert.equal(revokeResponse.status, 200);
      const revokeBody = (await revokeResponse.json()) as { revoked: boolean };
      assert.equal(revokeBody.revoked, true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon admin session-token issue/revoke/list roundtrip", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const issueResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/session-token/issue`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-admin-token": "test-admin-token"
        },
        body: JSON.stringify({ skillId: "skill.jwt", ttlSeconds: 300 })
      });
      assert.equal(issueResponse.status, 200);
      const issueBody = (await issueResponse.json()) as {
        token: string;
        jti: string;
        skillId: string;
      };
      assert.equal(issueBody.skillId, "skill.jwt");
      assert.ok(issueBody.token.length > 20);
      assert.ok(issueBody.jti.length > 10);

      const revokeResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/session-token/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-admin-token": "test-admin-token"
        },
        body: JSON.stringify({ token: issueBody.token })
      });
      assert.equal(revokeResponse.status, 200);
      const revokeBody = (await revokeResponse.json()) as { revoked: boolean; jti: string };
      assert.equal(revokeBody.revoked, true);
      assert.equal(revokeBody.jti, issueBody.jti);

      const listResponse = await fetch(`${listening.endpoint}/clauth/v1/admin/session-token/revocations`, {
        method: "GET",
        headers: {
          "x-clauth-admin-token": "test-admin-token"
        }
      });
      assert.equal(listResponse.status, 200);
      const listBody = (await listResponse.json()) as {
        revocations: Array<{ jti: string }>;
      };
      assert.equal(listBody.revocations.some((entry) => entry.jti === issueBody.jti), true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon reloads file-backed auth state without restart", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    config.hardening.enforceHttps = false;
    await saveConfig(config);

    const passphrase = "correct horse battery staple";

    const seedVault = new Vault(config);
    await seedVault.unlock(passphrase);
    await seedVault.storeCredential({
      handle: "custom-main",
      provider: "custom",
      secret: "sk-live",
      metadata: {
        authType: "bearer",
        allowedHosts: "127.0.0.1"
      }
    });
    seedVault.lock();

    const seedScopes = new ScopeEngine();
    await seedScopes.load();
    await seedScopes.grant({
      skillId: "skill.live",
      provider: "custom",
      scope: "custom:read",
      rateLimitPerMinute: 60
    });

    const seedSkillAuth = new SkillAuthEngine(config);
    await seedSkillAuth.load();
    const initialToken = await seedSkillAuth.issue("skill.live");

    const runtime = await buildRuntime(passphrase);
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    const upstream = http.createServer((req, res) => {
      const auth = req.headers.authorization ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, auth }));
    });

    await new Promise<void>((resolve, reject) => {
      upstream.listen(0, "127.0.0.1", () => resolve());
      upstream.once("error", reject);
    });

    try {
      const upstreamAddress = upstream.address();
      assert.ok(upstreamAddress && typeof upstreamAddress === "object");
      const endpoint = `http://127.0.0.1:${upstreamAddress.port}/echo`;

      async function proxyWithHeaders(headers: Record<string, string>): Promise<Response> {
        return fetch(`${listening.endpoint}/clauth/v1/proxy`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...headers
          },
          body: JSON.stringify({
            provider: "custom",
            credentialHandle: "custom-main",
            scope: "custom:read",
            method: "GET",
            endpoint
          })
        });
      }

      async function proxy(token: string): Promise<Response> {
        return proxyWithHeaders({ "x-clauth-skill-token": token });
      }

      async function proxyWithSession(token: string): Promise<Response> {
        return proxyWithHeaders({ authorization: `Bearer ${token}` });
      }

      const allowed = await proxy(initialToken.token);
      assert.equal(allowed.status, 200);
      const allowedBody = (await allowed.json()) as { status: number; body?: { auth?: string } };
      assert.equal(allowedBody.status, 200);
      assert.equal(allowedBody.body?.auth, "Bearer sk-live");

      const cliScopes = new ScopeEngine();
      await cliScopes.load();
      await cliScopes.revoke({
        skillId: "skill.live",
        provider: "custom",
        scope: "custom:read"
      });

      const afterRevoke = await proxy(initialToken.token);
      assert.equal(afterRevoke.status, 403);
      const afterRevokeBody = (await afterRevoke.json()) as { error?: { code?: string } };
      assert.equal(afterRevokeBody.error?.code, "ACCESS_DENIED");

      await cliScopes.grant({
        skillId: "skill.live",
        provider: "custom",
        scope: "custom:read",
        rateLimitPerMinute: 60
      });

      const afterGrant = await proxy(initialToken.token);
      assert.equal(afterGrant.status, 200);

      const cliSkill = new SkillAuthEngine(config);
      await cliSkill.load();
      await cliSkill.revoke("skill.live");

      const afterTokenRevoke = await proxy(initialToken.token);
      assert.equal(afterTokenRevoke.status, 401);
      const afterTokenRevokeBody = (await afterTokenRevoke.json()) as { error?: { code?: string } };
      assert.equal(afterTokenRevokeBody.error?.code, "UNAUTHORIZED");

      const rotatedToken = await cliSkill.issue("skill.live");
      const afterRotate = await proxy(rotatedToken.token);
      assert.equal(afterRotate.status, 200);

      const cliSessionVault = new Vault(config);
      await cliSessionVault.unlock(passphrase);
      const cliSessions = new SessionEngine(cliSessionVault, config.hardening.sessionTtlSeconds);
      await cliSessions.load();
      const sessionToken = cliSessions.issue({ sub: "skill.live" }, 300);

      const allowedWithSession = await proxyWithSession(sessionToken);
      assert.equal(allowedWithSession.status, 200);

      const revokedSession = await cliSessions.revokeToken(sessionToken, "test-revoke");
      assert.equal(revokedSession.revoked, true);

      const afterSessionRevoke = await proxyWithSession(sessionToken);
      assert.equal(afterSessionRevoke.status, 401);
      const afterSessionRevokeBody = (await afterSessionRevoke.json()) as { error?: { code?: string } };
      assert.equal(afterSessionRevokeBody.error?.code, "UNAUTHORIZED");
      cliSessionVault.lock();

      const cliVault = new Vault(config);
      await cliVault.unlock(passphrase);
      await cliVault.deleteCredential("custom-main");
      cliVault.lock();

      const afterCredentialDelete = await proxy(rotatedToken.token);
      assert.equal(afterCredentialDelete.status, 404);
      const afterCredentialDeleteBody = (await afterCredentialDelete.json()) as { error?: { code?: string } };
      assert.equal(afterCredentialDeleteBody.error?.code, "NOT_FOUND");
    } finally {
      await new Promise<void>((resolve, reject) => {
        upstream.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon serves dashboard html", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const response = await fetch(`${listening.endpoint}/dashboard`);
      assert.equal(response.status, 200);
      const contentType = response.headers.get("content-type") ?? "";
      assert.match(contentType, /text\/html/);
      const html = await response.text();
      assert.match(html, /Clauth Control Room/);
      assert.match(html, /\/clauth\/v1\/status/);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon serves dashboard html at root", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const response = await fetch(`${listening.endpoint}/`);
      assert.equal(response.status, 200);
      const contentType = response.headers.get("content-type") ?? "";
      assert.match(contentType, /text\/html/);
      const html = await response.text();
      assert.match(html, /Clauth Control Room/);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});

test("daemon rate limits identity verify attempts per skill", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.transport = "tcp";
    config.hardening.identityVerifyPerSkillPerMinute = 1;
    config.hardening.identityVerifyPerIpPerMinute = 100;
    config.hardening.identityMaxVerifyAttempts = 5;
    await saveConfig(config);

    const runtime = await buildRuntime("correct horse battery staple");
    const server = createClauthServer(runtime);
    const listening = await listenClauthServer(server, runtime, {
      transport: "tcp",
      host: "127.0.0.1",
      port: 0
    });

    try {
      const issued = await runtime.skillAuth.issue("skill.rate");
      const challengeResponse = await fetch(`${listening.endpoint}/clauth/v1/identity/challenge`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-skill-token": issued.token
        },
        body: JSON.stringify({
          provider: "github",
          accountId: "octocat",
          method: "signed-challenge"
        })
      });
      assert.equal(challengeResponse.status, 200);
      const challengeBody = (await challengeResponse.json()) as { challengeId: string };
      assert.ok(challengeBody.challengeId);

      const verifyPayload = {
        challengeId: challengeBody.challengeId,
        proof: "invalid-proof-payload"
      };

      const firstVerify = await fetch(`${listening.endpoint}/clauth/v1/identity/verify`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-skill-token": issued.token
        },
        body: JSON.stringify(verifyPayload)
      });
      assert.equal(firstVerify.status, 200);
      const firstBody = (await firstVerify.json()) as { status: string };
      assert.equal(firstBody.status, "pending");

      const secondVerify = await fetch(`${listening.endpoint}/clauth/v1/identity/verify`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-clauth-skill-token": issued.token
        },
        body: JSON.stringify(verifyPayload)
      });
      assert.equal(secondVerify.status, 429);
      const secondBody = (await secondVerify.json()) as { error?: { code?: string } };
      assert.equal(secondBody.error?.code, "RATE_LIMITED");
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
      runtime.vault.lock();
    }
  });
});
