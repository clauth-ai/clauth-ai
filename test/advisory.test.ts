import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";
import { AuditLogger } from "../src/core/audit.js";
import { AlertRouter } from "../src/core/alerts.js";
import { AdvisoryMonitor } from "../src/core/advisory.js";
import { ScopeEngine } from "../src/core/scopes.js";
import { NotFoundError } from "../src/core/errors.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-advisory-test-"));
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

test("AdvisoryMonitor processes new advisories from feed", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const advisories = [
      { ghsa_id: "GHSA-1234-abcd", severity: "critical", summary: "Critical vuln in pkg-a" },
      { ghsa_id: "GHSA-5678-efgh", severity: "moderate", summary: "Moderate issue in pkg-b" }
    ];

    const feedServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(advisories));
    });

    await new Promise<void>((resolve) => {
      feedServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = feedServer.address() as { port: number };

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();

    const newItems = await monitor.checkFeed({
      name: "test-feed",
      url: `http://127.0.0.1:${addr.port}/advisories`,
      type: "github"
    });

    assert.equal(newItems.length, 2);
    assert.equal(monitor.getSeenCount(), 2);

    feedServer.close();
    vault.lock();
  });
});

test("AdvisoryMonitor deduplicates advisories", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const advisories = [
      { ghsa_id: "GHSA-dupe-1234", severity: "high", summary: "Duplicate test" }
    ];

    const feedServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(advisories));
    });

    await new Promise<void>((resolve) => {
      feedServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = feedServer.address() as { port: number };
    const feedSource = {
      name: "test-feed",
      url: `http://127.0.0.1:${addr.port}/advisories`,
      type: "github" as const
    };

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();

    const first = await monitor.checkFeed(feedSource);
    assert.equal(first.length, 1);

    const second = await monitor.checkFeed(feedSource);
    assert.equal(second.length, 0);

    feedServer.close();
    vault.lock();
  });
});

test("AdvisoryMonitor persists seen IDs across reloads", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const advisories = [
      { ghsa_id: "GHSA-persist-test", severity: "low", summary: "Persistence test" }
    ];

    const feedServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(advisories));
    });

    await new Promise<void>((resolve) => {
      feedServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = feedServer.address() as { port: number };
    const feedSource = {
      name: "test-feed",
      url: `http://127.0.0.1:${addr.port}/advisories`,
      type: "github" as const
    };

    const monitor1 = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor1.load();
    await monitor1.checkFeed(feedSource);
    assert.equal(monitor1.getSeenCount(), 1);

    const monitor2 = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor2.load();
    assert.equal(monitor2.getSeenCount(), 1);

    const result = await monitor2.checkFeed(feedSource);
    assert.equal(result.length, 0);

    feedServer.close();
    vault.lock();
  });
});

test("AdvisoryMonitor handles network errors gracefully", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();

    const result = await monitor.checkFeed({
      name: "broken-feed",
      url: "http://127.0.0.1:1/nonexistent",
      type: "github"
    });

    assert.equal(result.length, 0);
    vault.lock();
  });
});

test("AdvisoryMonitor start and stop polling", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();

    assert.equal(monitor.isPolling(), false);

    monitor.startPolling(60_000, [{ name: "test", url: "https://example.com", type: "github" }]);
    assert.equal(monitor.isPolling(), true);

    monitor.stopPolling();
    assert.equal(monitor.isPolling(), false);

    vault.lock();
  });
});

test("AdvisoryMonitor handles empty feed response", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const feedServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("[]");
    });

    await new Promise<void>((resolve) => {
      feedServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = feedServer.address() as { port: number };

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();

    const result = await monitor.checkFeed({
      name: "empty-feed",
      url: `http://127.0.0.1:${addr.port}/empty`,
      type: "github"
    });

    assert.equal(result.length, 0);

    feedServer.close();
    vault.lock();
  });
});

test("AdvisoryMonitor fetchFeed supports dry-run without mutating seen state", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const advisories = [
      { ghsa_id: "GHSA-dry-run-1", severity: "high", summary: "Dry run advisory" }
    ];

    const feedServer = http.createServer((_, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(advisories));
    });

    await new Promise<void>((resolve) => {
      feedServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = feedServer.address() as { port: number };

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();
    const feed = {
      name: "dry-run-feed",
      url: `http://127.0.0.1:${addr.port}/advisories`,
      type: "github" as const
    };

    const fetched = await monitor.fetchFeed(feed);
    assert.equal(fetched.length, 1);
    assert.equal(monitor.getSeenCount(), 0);
    assert.equal(monitor.isSeen("GHSA-dry-run-1"), false);

    const checked = await monitor.checkFeed(feed);
    assert.equal(checked.length, 1);
    assert.equal(monitor.isSeen("GHSA-dry-run-1"), true);
    assert.equal(monitor.getSeenCount(), 1);

    feedServer.close();
    vault.lock();
  });
});

test("AdvisoryMonitor maps multi-package advisories to provider revocation targets", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();
    const scopes = new ScopeEngine();
    await scopes.load();

    await scopes.grant({
      skillId: "skill.alpha",
      provider: "github",
      scope: "github:read"
    });
    await scopes.grant({
      skillId: "skill.alpha",
      provider: "slack",
      scope: "slack:read"
    });
    await scopes.grant({
      skillId: "skill.alpha",
      provider: "discord",
      scope: "discord:read"
    });

    await vault.storeCredential({
      handle: "github-main",
      provider: "github",
      secret: "ghp_test"
    });
    await vault.storeCredential({
      handle: "slack-main",
      provider: "slack",
      secret: "xoxb-test"
    });
    await vault.storeCredential({
      handle: "discord-main",
      provider: "discord",
      secret: "disc-test"
    });

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await monitor.load();
    monitor.setScopeEngine(scopes);

    await monitor.processAdvisory({
      id: "GHSA-multi-provider",
      source: "github",
      severity: "critical",
      summary: "Critical advisory affecting actions and slack package ecosystems",
      affectedPackage: "actions/toolkit",
      affectedPackages: ["actions/toolkit", "slack/web-api"],
      publishedAt: new Date().toISOString()
    });

    const activeGrants = scopes.listGrants({ activeOnly: true });
    assert.equal(activeGrants.some((grant) => grant.provider === "github"), false);
    assert.equal(activeGrants.some((grant) => grant.provider === "slack"), false);
    assert.equal(activeGrants.some((grant) => grant.provider === "discord"), true);

    await assert.rejects(async () => {
      await vault.getCredential("github-main", "github");
    }, NotFoundError);

    await assert.rejects(async () => {
      await vault.getCredential("slack-main", "slack");
    }, NotFoundError);

    const discord = await vault.getCredential("discord-main", "discord");
    assert.equal(discord.secret, "disc-test");

    vault.lock();
  });
});

test("AdvisoryMonitor load fails closed for malformed persisted state", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);
    await writeFile(resolveClauthPaths().advisoryStateFile, "{broken-json", "utf8");

    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");
    const audit = new AuditLogger();
    await audit.load();
    const alertRouter = new AlertRouter(config);
    await alertRouter.load();

    const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
    await assert.rejects(async () => {
      await monitor.load();
    });

    vault.lock();
  });
});
