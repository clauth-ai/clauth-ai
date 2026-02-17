import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import type http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import type { ClauthConfig } from "../src/core/config.js";
import { AuditLogger } from "../src/core/audit.js";
import { ClauthError } from "../src/core/errors.js";
import { SessionEngine } from "../src/core/sessions.js";
import { SkillAuthEngine } from "../src/core/skill-auth.js";
import { Vault } from "../src/core/vault.js";
import type { ClauthRuntime } from "../src/daemon/runtime.js";
import { parseProofMethod, requireSkillPrincipal, resolveIdentityAccess } from "../src/daemon/app.js";

const PASSPHRASE = "correct horse battery staple";

async function withTempHome(run: () => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-daemon-auth-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  const originalAdmin = process.env.CLAUTH_ADMIN_TOKEN;
  process.env.CLAUTH_HOME = temp;

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

function asRequest(headers: http.IncomingHttpHeaders): http.IncomingMessage {
  return { headers } as unknown as http.IncomingMessage;
}

async function buildAuthRuntime(config: ClauthConfig): Promise<{
  runtime: ClauthRuntime;
  vault: Vault;
  skillAuth: SkillAuthEngine;
  sessions: SessionEngine;
}> {
  await saveConfig(config);

  const vault = new Vault(config);
  await vault.unlock(PASSPHRASE);
  const audit = new AuditLogger();
  await audit.load();
  const skillAuth = new SkillAuthEngine(config);
  await skillAuth.load();
  const sessions = new SessionEngine(vault, config.hardening.sessionTtlSeconds);

  const runtime = {
    config,
    sessions,
    skillAuth,
    audit
  } as unknown as ClauthRuntime;

  return { runtime, vault, skillAuth, sessions };
}

test("requireSkillPrincipal resolves owning skill from token when expected skill is omitted", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault, skillAuth } = await buildAuthRuntime(config);
    const issued = await skillAuth.issue("skill.alpha");

    const principal = await requireSkillPrincipal(
      asRequest({ "x-clauth-skill-token": issued.token }),
      runtime
    );

    assert.equal(principal.skillId, "skill.alpha");
    assert.equal(principal.method, "skill-token");
    vault.lock();
  });
});

test("requireSkillPrincipal rejects mismatched declared skill", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault, skillAuth } = await buildAuthRuntime(config);
    const issued = await skillAuth.issue("skill.alpha");

    await assert.rejects(
      () =>
        requireSkillPrincipal(
          asRequest({ "x-clauth-skill-token": issued.token }),
          runtime,
          "skill.beta"
        ),
      (error: unknown) => error instanceof ClauthError && error.code === "UNAUTHORIZED"
    );

    vault.lock();
  });
});

test("requireSkillPrincipal accepts JWT principal when subject matches expected skill", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault, sessions } = await buildAuthRuntime(config);

    const jwt = sessions.issue({ sub: "skill.alpha" });
    const principal = await requireSkillPrincipal(
      asRequest({ authorization: `Bearer ${jwt}` }),
      runtime,
      "skill.alpha"
    );

    assert.equal(principal.skillId, "skill.alpha");
    assert.equal(principal.method, "jwt");
    vault.lock();
  });
});

test("resolveIdentityAccess enforces admin token when hardening flag is enabled", async () => {
  await withTempHome(async () => {
    process.env.CLAUTH_ADMIN_TOKEN = "test-admin-token";
    const config = defaultConfig();
    config.hardening.requireAdminTokenForIdentity = true;
    const { runtime, vault } = await buildAuthRuntime(config);

    const granted = await resolveIdentityAccess(
      asRequest({ "x-clauth-admin-token": "test-admin-token" }),
      runtime,
      "skill.alpha"
    );
    assert.equal(granted.isAdmin, true);
    assert.equal(granted.skillId, "skill.alpha");

    await assert.rejects(
      () => resolveIdentityAccess(asRequest({}), runtime),
      (error: unknown) => error instanceof ClauthError && error.code === "UNAUTHORIZED"
    );

    vault.lock();
  });
});

test("resolveIdentityAccess derives skill from token for identity routes", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault, skillAuth } = await buildAuthRuntime(config);
    const issued = await skillAuth.issue("skill.identity");

    const access = await resolveIdentityAccess(
      asRequest({ "x-clauth-skill-token": issued.token }),
      runtime
    );

    assert.equal(access.isAdmin, false);
    assert.equal(access.skillId, "skill.identity");
    vault.lock();
  });
});

test("resolveIdentityAccess requires authenticated skill principal", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault } = await buildAuthRuntime(config);

    await assert.rejects(
      () => resolveIdentityAccess(asRequest({}), runtime),
      (error: unknown) => error instanceof ClauthError && error.code === "UNAUTHORIZED"
    );

    vault.lock();
  });
});

test("requireSkillPrincipal always requires authentication", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    const { runtime, vault } = await buildAuthRuntime(config);

    await assert.rejects(
      () => requireSkillPrincipal(asRequest({}), runtime, "skill.alpha"),
      (error: unknown) => error instanceof ClauthError && error.code === "UNAUTHORIZED"
    );

    vault.lock();
  });
});

test("parseProofMethod enforces supported values", () => {
  assert.equal(parseProofMethod(undefined), "signed-challenge");
  assert.equal(parseProofMethod("oauth"), "oauth");
  assert.equal(parseProofMethod("email"), "email");
  assert.throws(
    () => parseProofMethod("dns"),
    (error: unknown) => error instanceof ClauthError && error.code === "VALIDATION_ERROR"
  );
});
