import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { AccessDeniedError } from "../src/core/errors.js";
import { ScopeEngine } from "../src/core/scopes.js";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-scopes-test-"));
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

test("scope engine enforces wildcard match and rate limits", async () => {
  await withTempHome(async () => {
    const scopes = new ScopeEngine();
    await scopes.load();

    await scopes.grant({
      skillId: "skill.alpha",
      provider: "twitter",
      scope: "twitter:*",
      rateLimitPerMinute: 2
    });

    const now = Date.now();

    scopes.authorize({
      skillId: "skill.alpha",
      provider: "twitter",
      scope: "twitter:read",
      endpoint: "https://api.twitter.com/2/users/me",
      method: "GET",
      timestamp: now
    });

    scopes.authorize({
      skillId: "skill.alpha",
      provider: "twitter",
      scope: "twitter:post",
      endpoint: "https://api.twitter.com/2/tweets",
      method: "POST",
      timestamp: now + 1
    });

    assert.throws(() => {
      scopes.authorize({
        skillId: "skill.alpha",
        provider: "twitter",
        scope: "twitter:post",
        endpoint: "https://api.twitter.com/2/tweets",
        method: "POST",
        timestamp: now + 2
      });
    }, AccessDeniedError);
  });
});

test("scope revoke disables previously active grant", async () => {
  await withTempHome(async () => {
    const scopes = new ScopeEngine();
    await scopes.load();

    await scopes.grant({
      skillId: "skill.beta",
      provider: "github",
      scope: "github:read"
    });

    const revoked = await scopes.revoke({
      skillId: "skill.beta",
      provider: "github",
      scope: "github:read"
    });

    assert.equal(revoked, 1);

    assert.throws(() => {
      scopes.authorize({
        skillId: "skill.beta",
        provider: "github",
        scope: "github:read",
        endpoint: "https://api.github.com/user",
        method: "GET",
        timestamp: Date.now()
      });
    }, AccessDeniedError);
  });
});
