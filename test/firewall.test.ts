import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig } from "../src/core/config.js";
import { BehavioralFirewall } from "../src/core/firewall.js";
import type { RequestContext } from "../src/types/index.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-firewall-test-"));
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

function makeContext(overrides?: Partial<RequestContext>): RequestContext {
  return {
    skillId: "skill.test",
    provider: "github",
    scope: "github:read",
    endpoint: "https://api.github.com/user",
    method: "GET",
    timestamp: Date.now(),
    ...overrides,
  };
}

test("firewall allows normal requests during warmup period", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    // Disable off-hours so the test is not time-of-day dependent
    config.firewall.offHoursStart = 0;
    config.firewall.offHoursEnd = 0;
    const fw = new BehavioralFirewall(config);
    await fw.load();

    const decision = await fw.evaluate(makeContext());
    assert.equal(decision.allowed, true);
    assert.equal(decision.severity, "info");
    assert.equal(decision.reasons.length, 0);
  });
});

test("firewall detects burst threshold exceeded", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.burstLimit = 5;
    config.firewall.burstWindowMs = 10_000;

    const fw = new BehavioralFirewall(config);
    await fw.load();

    const now = Date.now();

    // Send requests up to the limit (should be fine)
    for (let i = 0; i < 5; i++) {
      const d = await fw.evaluate(makeContext({ timestamp: now + i }));
      assert.equal(d.allowed, true);
    }

    // Next request exceeds burst limit
    const decision = await fw.evaluate(makeContext({ timestamp: now + 5 }));
    assert.equal(decision.allowed, false);
    assert.equal(decision.severity, "critical");
    assert.ok(decision.reasons.some((r) => r.includes("Burst threshold")));
  });
});

test("firewall detects rate spike after warmup", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.minWarmupRequests = 5;
    config.firewall.rateSpikeMultiplier = 2;
    config.firewall.burstLimit = 200; // high burst limit so it doesn't interfere

    const fw = new BehavioralFirewall(config);
    await fw.load();

    // Build a baseline: 5 requests spread over 5 minutes
    const startTime = Date.now() - 5 * 60_000;
    for (let i = 0; i < 5; i++) {
      await fw.evaluate(
        makeContext({ timestamp: startTime + i * 60_000 })
      );
    }

    // Now send a burst of requests in the last minute (way above 1/min baseline * 2)
    const now = Date.now();
    let spikeDetected = false;
    for (let i = 0; i < 10; i++) {
      const d = await fw.evaluate(makeContext({ timestamp: now + i * 100 }));
      if (d.reasons.some((r) => r.includes("Rate spike"))) {
        spikeDetected = true;
        break;
      }
    }
    assert.ok(spikeDetected, "Expected rate spike detection after warmup");
  });
});

test("firewall flags new endpoint after warmup", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.minWarmupRequests = 3;
    config.firewall.burstLimit = 200;

    const fw = new BehavioralFirewall(config);
    await fw.load();

    // Warmup with known endpoint
    const baseTime = Date.now() - 3 * 60_000;
    for (let i = 0; i < 3; i++) {
      await fw.evaluate(
        makeContext({
          endpoint: "https://api.github.com/user",
          timestamp: baseTime + i * 60_000,
        })
      );
    }

    // Hit a never-before-seen endpoint
    const decision = await fw.evaluate(
      makeContext({
        endpoint: "https://api.github.com/admin/keys",
        timestamp: Date.now(),
      })
    );
    assert.ok(decision.reasons.some((r) => r.includes("New endpoint")));
    assert.equal(decision.severity, "warn");
  });
});

test("firewall flags off-hours activity", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.offHoursStart = 1;
    config.firewall.offHoursEnd = 5;

    const fw = new BehavioralFirewall(config);
    await fw.load();

    // Create a timestamp at 2 AM local time
    const now = new Date();
    now.setHours(2, 0, 0, 0);

    const decision = await fw.evaluate(
      makeContext({ timestamp: now.getTime() })
    );
    assert.ok(decision.reasons.some((r) => r.includes("Off-hours")));
  });
});

test("firewall does not flag off-hours during business hours", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    config.firewall.offHoursStart = 1;
    config.firewall.offHoursEnd = 5;

    const fw = new BehavioralFirewall(config);
    await fw.load();

    // Create a timestamp at 10 AM local time
    const now = new Date();
    now.setHours(10, 0, 0, 0);

    const decision = await fw.evaluate(
      makeContext({ timestamp: now.getTime() })
    );
    assert.ok(!decision.reasons.some((r) => r.includes("Off-hours")));
  });
});

test("firewall marks scope creep as critical and blocks", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const fw = new BehavioralFirewall(config);
    await fw.load();

    const decision = await fw.evaluate(makeContext(), { scopeDenied: true });
    assert.equal(decision.allowed, false);
    assert.equal(decision.severity, "critical");
    assert.ok(decision.reasons.some((r) => r.includes("Scope creep")));
  });
});

test("firewall persists and restores skill baselines", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();

    // First session: build some baseline
    const fw1 = new BehavioralFirewall(config);
    await fw1.load();
    await fw1.evaluate(makeContext({ endpoint: "https://api.github.com/user" }));
    await fw1.evaluate(makeContext({ endpoint: "https://api.github.com/repos" }));

    // Second session: load from disk
    const fw2 = new BehavioralFirewall(config);
    await fw2.load();

    // The second instance should recognize the existing endpoints (no "new endpoint" flag during warmup)
    // But after warmup, a truly new endpoint should still be flagged
    // We can verify persistence by checking that warmup requests count carries over
    config.firewall.minWarmupRequests = 2;
    const fw3 = new BehavioralFirewall(config);
    await fw3.load();

    const decision = await fw3.evaluate(
      makeContext({ endpoint: "https://api.github.com/admin/danger" })
    );
    assert.ok(
      decision.reasons.some((r) => r.includes("New endpoint")),
      "Expected new endpoint detection after restored baseline"
    );
  });
});
