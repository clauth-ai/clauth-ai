import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { AuditLogger } from "../src/core/audit.js";
import { ValidationError } from "../src/core/errors.js";
import { OAuthRefresher } from "../src/core/oauth-refresh.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-oauth-test-"));
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

test("OAuthRefresher registers and retrieves token sets", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("gh-token", {
      accessToken: "access-123",
      refreshToken: "refresh-456",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    const ts = refresher.getTokenSet("gh-token");
    assert.ok(ts);
    assert.equal(ts.accessToken, "access-123");
    assert.equal(ts.refreshToken, "refresh-456");

    assert.equal(refresher.listTokenHandles().length, 1);

    await refresher.removeToken("gh-token");
    assert.equal(refresher.getTokenSet("gh-token"), undefined);

    vault.lock();
  });
});

test("OAuthRefresher detects expired tokens", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("expired-token", {
      accessToken: "old-access",
      refreshToken: "old-refresh",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    assert.ok(refresher.isExpired("expired-token"));

    await refresher.registerToken("valid-token", {
      accessToken: "good-access",
      refreshToken: "good-refresh",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    assert.ok(!refresher.isExpired("valid-token"));

    vault.lock();
  });
});

test("OAuthRefresher persists encrypted envelope on disk", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();
    await refresher.registerToken("enc-token", {
      accessToken: "access-enc",
      refreshToken: "refresh-enc",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    const raw = await readFile(resolveClauthPaths().oauthTokensFile, "utf8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(parsed.cipher, "aes-256-gcm");
    assert.equal(typeof parsed.ciphertext, "string");
    assert.equal("tokens" in parsed, false);

    vault.lock();
  });
});

test("OAuthRefresher migrates plaintext token store to encrypted format", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    await writeFile(
      resolveClauthPaths().oauthTokensFile,
      JSON.stringify(
        {
          tokens: {
            legacy: {
              accessToken: "legacy-access",
              refreshToken: "legacy-refresh",
              expiresAt: new Date(Date.now() + 3600_000).toISOString(),
              tokenUrl: "https://example.com/token"
            }
          }
        },
        null,
        2
      ),
      "utf8"
    );

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();
    assert.equal(refresher.getTokenSet("legacy")?.accessToken, "legacy-access");

    const raw = await readFile(resolveClauthPaths().oauthTokensFile, "utf8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    assert.equal(parsed.cipher, "aes-256-gcm");
    assert.equal(typeof parsed.ciphertext, "string");

    vault.lock();
  });
});

test("OAuthRefresher rejects tampered encrypted token store", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();
    await refresher.registerToken("enc-token", {
      accessToken: "access-enc",
      refreshToken: "refresh-enc",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    const path = resolveClauthPaths().oauthTokensFile;
    const envelope = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
    const tag = Buffer.from(String(envelope.tag ?? ""), "base64url");
    tag[0] ^= 0xff;
    envelope.tag = tag.toString("base64url");
    await writeFile(path, JSON.stringify(envelope, null, 2), "utf8");

    const reloaded = new OAuthRefresher({ vault, audit });
    await assert.rejects(
      async () => reloaded.load(),
      (error: unknown) => error instanceof ValidationError
    );

    vault.lock();
  });
});

test("OAuthRefresher.forceRefresh calls token endpoint and updates vault", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    await vault.storeCredential({
      handle: "oauth-cred",
      provider: "github",
      secret: "old-access-token"
    });

    const tokenServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({
          access_token: "new-access-token",
          refresh_token: "new-refresh-token",
          expires_in: 7200
        }));
      });
    });

    await new Promise<void>((resolve) => {
      tokenServer.listen(0, "127.0.0.1", () => resolve());
    });

    const addr = tokenServer.address() as { port: number };
    const tokenUrl = `http://127.0.0.1:${addr.port}/token`;

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("oauth-cred", {
      accessToken: "old-access-token",
      refreshToken: "old-refresh",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      tokenUrl
    });

    const result = await refresher.forceRefresh("oauth-cred");
    assert.ok(result);

    const updated = refresher.getTokenSet("oauth-cred");
    assert.ok(updated);
    assert.equal(updated.accessToken, "new-access-token");
    assert.equal(updated.refreshToken, "new-refresh-token");

    const cred = await vault.getCredential("oauth-cred");
    assert.equal(cred.secret, "new-access-token");

    tokenServer.close();
    vault.lock();
  });
});

test("OAuthRefresher.forceRefresh handles failure gracefully", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("fail-token", {
      accessToken: "old",
      refreshToken: "old-refresh",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      tokenUrl: "http://127.0.0.1:1/nonexistent"
    });

    const result = await refresher.forceRefresh("fail-token");
    assert.equal(result, false);

    vault.lock();
  });
});

test("OAuthRefresher.refreshIfNeeded skips non-expired tokens", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("fresh-token", {
      accessToken: "access",
      refreshToken: "refresh",
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    const result = await refresher.refreshIfNeeded("fresh-token");
    assert.equal(result, false);

    vault.lock();
  });
});

test("OAuthRefresher.forceRefresh returns false for unknown handle", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    const result = await refresher.forceRefresh("nonexistent");
    assert.equal(result, false);

    vault.lock();
  });
});

test("OAuthRefresher persists state across reloads", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const refresher1 = new OAuthRefresher({ vault, audit });
    await refresher1.load();
    await refresher1.registerToken("persist-test", {
      accessToken: "a",
      refreshToken: "r",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      tokenUrl: "https://example.com/token"
    });

    const refresher2 = new OAuthRefresher({ vault, audit });
    await refresher2.load();
    const ts = refresher2.getTokenSet("persist-test");
    assert.ok(ts);
    assert.equal(ts.accessToken, "a");

    vault.lock();
  });
});

test("OAuthRefresher.forceRefresh handles 401 from token endpoint", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();

    const tokenServer = http.createServer((_, res) => {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    });

    await new Promise<void>((resolve) => {
      tokenServer.listen(0, "127.0.0.1", () => resolve());
    });

    const addr = tokenServer.address() as { port: number };
    const tokenUrl = `http://127.0.0.1:${addr.port}/token`;

    const refresher = new OAuthRefresher({ vault, audit });
    await refresher.load();

    await refresher.registerToken("bad-refresh", {
      accessToken: "old",
      refreshToken: "bad",
      expiresAt: new Date(Date.now() - 1000).toISOString(),
      tokenUrl
    });

    const result = await refresher.forceRefresh("bad-refresh");
    assert.equal(result, false);

    tokenServer.close();
    vault.lock();
  });
});
