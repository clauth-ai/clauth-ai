import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { SessionEngine } from "../src/core/sessions.js";

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-session-test-"));
  const originalHome = process.env.CLAUTH_HOME;

  process.env.CLAUTH_HOME = temp;

  try {
    await run(temp);
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }
    await rm(temp, { recursive: true, force: true });
  }
}

test("SessionEngine issues and verifies JWT", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1", scope: "read" });

    assert.ok(token);
    assert.equal(token.split(".").length, 3);

    const claims = sessions.verify(token);
    assert.ok(claims);
    assert.equal(claims.sub, "skill-1");
    assert.equal(claims.scope, "read");
    assert.equal(claims.iss, "clauth");
    assert.ok(claims.iat > 0);
    assert.ok(claims.exp > claims.iat);

    vault.lock();
  });
});

test("SessionEngine rejects tampered JWT", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1" });

    const parts = token.split(".");
    parts[1] = Buffer.from(JSON.stringify({ sub: "evil", iss: "clauth", iat: 1, exp: 99999999999 })).toString("base64url");
    const tampered = parts.join(".");

    const claims = sessions.verify(tampered);
    assert.equal(claims, null);

    vault.lock();
  });
});

test("SessionEngine rejects expired JWT", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1" }, -1);

    const claims = sessions.verify(token);
    assert.equal(claims, null);

    vault.lock();
  });
});

test("SessionEngine rejects invalid format", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);

    assert.equal(sessions.verify(""), null);
    assert.equal(sessions.verify("a.b"), null);
    assert.equal(sessions.verify("a.b.c.d"), null);
    assert.equal(sessions.verify("not-a-jwt"), null);

    vault.lock();
  });
});

test("SessionEngine produces different tokens for different subjects", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token1 = sessions.issue({ sub: "skill-1" });
    const token2 = sessions.issue({ sub: "skill-2" });

    assert.notEqual(token1, token2);

    const claims1 = sessions.verify(token1);
    const claims2 = sessions.verify(token2);
    assert.ok(claims1);
    assert.ok(claims2);
    assert.equal(claims1.sub, "skill-1");
    assert.equal(claims2.sub, "skill-2");

    vault.lock();
  });
});

test("SessionEngine JWT has correct header", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1" });

    const headerStr = Buffer.from(token.split(".")[0], "base64url").toString("utf8");
    const header = JSON.parse(headerStr);
    assert.equal(header.alg, "HS256");
    assert.equal(header.typ, "JWT");

    vault.lock();
  });
});

test("SessionEngine uses custom TTL", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1" }, 60);

    const claims = sessions.verify(token);
    assert.ok(claims);
    assert.equal(claims.exp - claims.iat, 60);

    vault.lock();
  });
});

test("SessionEngine invalidateCache clears cached secret", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    const token = sessions.issue({ sub: "skill-1" });

    sessions.invalidateCache();

    // After invalidating, it should re-derive the secret and still work.
    const claims = sessions.verify(token);
    assert.ok(claims);
    assert.equal(claims.sub, "skill-1");

    vault.lock();
  });
});

test("SessionEngine rejects revoked JWT by jti", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessions = new SessionEngine(vault);
    await sessions.load();
    const issued = sessions.issueWithMetadata({ sub: "skill-1" }, 600);

    const before = sessions.verify(issued.token);
    assert.ok(before);

    const revoked = await sessions.revokeJti(issued.jti, issued.exp, "test");
    assert.equal(revoked, true);
    assert.equal(sessions.verify(issued.token), null);

    vault.lock();
  });
});

test("SessionEngine revocation store persists across reloads", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    const sessionsA = new SessionEngine(vault);
    await sessionsA.load();
    const issued = sessionsA.issueWithMetadata({ sub: "skill-1" }, 600);
    const result = await sessionsA.revokeToken(issued.token, "test");
    assert.equal(result.revoked, true);

    const sessionsB = new SessionEngine(vault);
    await sessionsB.load();
    assert.equal(sessionsB.verify(issued.token), null);

    const revocations = sessionsB.listRevocations();
    assert.ok(revocations.some((entry) => entry.jti === issued.jti));

    vault.lock();
  });
});
