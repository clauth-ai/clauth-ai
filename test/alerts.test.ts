import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { AlertRouter } from "../src/core/alerts.js";

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-alerts-test-"));
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

test("AlertRouter dispatches to matching webhook channels", async () => {
  await withTempHome(async () => {
    const received: unknown[] = [];
    const webhookServer = http.createServer((req, res) => {
      let body = "";
      req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
      req.on("end", () => {
        received.push(JSON.parse(body));
        res.writeHead(200);
        res.end();
      });
    });

    await new Promise<void>((resolve) => {
      webhookServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = webhookServer.address() as { port: number };
    const url = `http://127.0.0.1:${addr.port}/hook`;

    const config = {
      ...defaultConfig(),
      alertChannels: [{ type: "webhook" as const, url, minSeverity: "warning" as const }]
    };
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const result = await router.dispatch({
      severity: "critical",
      category: "firewall",
      message: "Burst limit exceeded",
      timestamp: new Date().toISOString(),
      metadata: { skillId: "test-skill" }
    });

    assert.equal(result.sent, 1);
    assert.equal(result.failed, 0);
    assert.equal(received.length, 1);
    assert.equal((received[0] as { severity: string }).severity, "critical");

    webhookServer.close();
  });
});

test("AlertRouter filters by minimum severity", async () => {
  await withTempHome(async () => {
    let callCount = 0;
    const webhookServer = http.createServer((_, res) => {
      callCount++;
      res.writeHead(200);
      res.end();
    });

    await new Promise<void>((resolve) => {
      webhookServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = webhookServer.address() as { port: number };
    const url = `http://127.0.0.1:${addr.port}/hook`;

    const config = {
      ...defaultConfig(),
      alertChannels: [{ type: "webhook" as const, url, minSeverity: "critical" as const }]
    };
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const result = await router.dispatch({
      severity: "info",
      category: "test",
      message: "Should not be sent",
      timestamp: new Date().toISOString()
    });

    assert.equal(result.sent, 0);
    assert.equal(callCount, 0);

    webhookServer.close();
  });
});

test("AlertRouter handles webhook failure gracefully", async () => {
  await withTempHome(async () => {
    const config = {
      ...defaultConfig(),
      alertChannels: [{ type: "webhook" as const, url: "http://127.0.0.1:1/fail", minSeverity: "info" as const }]
    };
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const result = await router.dispatch({
      severity: "critical",
      category: "test",
      message: "Should fail",
      timestamp: new Date().toISOString()
    });

    assert.equal(result.sent, 0);
    assert.equal(result.failed, 1);
  });
});

test("AlertRouter with no channels dispatches zero", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const result = await router.dispatch({
      severity: "critical",
      category: "test",
      message: "No channels",
      timestamp: new Date().toISOString()
    });

    assert.equal(result.sent, 0);
    assert.equal(result.failed, 0);
  });
});

test("AlertRouter.testWebhook sends test payload", async () => {
  await withTempHome(async () => {
    let received = false;
    const webhookServer = http.createServer((_, res) => {
      received = true;
      res.writeHead(200);
      res.end();
    });

    await new Promise<void>((resolve) => {
      webhookServer.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = webhookServer.address() as { port: number };
    const url = `http://127.0.0.1:${addr.port}/test`;

    const config = defaultConfig();
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const ok = await router.testWebhook(url);
    assert.ok(ok);
    assert.ok(received);

    webhookServer.close();
  });
});

test("AlertRouter.getChannels returns configured channels", async () => {
  await withTempHome(async () => {
    const config = {
      ...defaultConfig(),
      alertChannels: [
        { type: "webhook" as const, url: "https://hooks.example.com/a", minSeverity: "info" as const },
        { type: "webhook" as const, url: "https://hooks.example.com/b", minSeverity: "critical" as const }
      ]
    };
    await saveConfig(config);

    const router = new AlertRouter(config);
    await router.load();

    const channels = router.getChannels();
    assert.equal(channels.length, 2);
  });
});
