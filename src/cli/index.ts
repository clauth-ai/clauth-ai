#!/usr/bin/env node

import readline from "node:readline";
import process from "node:process";
import os from "node:os";
import path from "node:path";
import { promises as fs } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadConfig, saveConfig } from "../core/config.js";
import { ClauthError, ValidationError } from "../core/errors.js";
import { ensureDir, ensureFile, resolveClauthPaths } from "../core/fs.js";
import { ScopeEngine } from "../core/scopes.js";
import { Vault } from "../core/vault.js";
import { AuditLogger } from "../core/audit.js";
import { SkillAuthEngine } from "../core/skill-auth.js";
import { IdentityBrokerEngine } from "../core/identity-broker.js";
import { AlertRouter } from "../core/alerts.js";
import { SessionEngine } from "../core/sessions.js";
import { AdvisoryMonitor } from "../core/advisory.js";
import { renderServiceTemplate } from "./service-templates.js";
import type { ServiceTarget } from "./service-templates.js";
import type { ProofMethod } from "../types/index.js";
import {
  buildActivationCommands,
  buildServicePlan,
  defaultDestinationPath,
  defaultGeneratedPath,
  defaultServiceName,
  formatProcessCommand
} from "./service-utils.js";
import type { ProcessCommand } from "./service-utils.js";

const execFileAsync = promisify(execFile);

const [, , command, ...args] = process.argv;

run().catch((error) => {
  if (error instanceof ClauthError) {
    console.error(`[${error.code}] ${error.message}`);
    process.exit(1);
  }

  if (error instanceof Error) {
    console.error(error.message);
    process.exit(1);
  }

  console.error(String(error));
  process.exit(1);
});

async function run(): Promise<void> {
  switch (command) {
    case "init":
      await cmdInit(args);
      return;
    case "store":
      await cmdStore(args);
      return;
    case "grant":
      await cmdGrant(args);
      return;
    case "revoke":
      await cmdRevoke(args);
      return;
    case "emergency-revoke":
      await cmdEmergencyRevoke();
      return;
    case "status":
      await cmdStatus();
      return;
    case "daemon":
    case "serve":
      await cmdDaemon(args);
      return;
    case "doctor":
      await cmdDoctor();
      return;
    case "migrate":
      await cmdMigrate(args);
      return;
    case "skill-token":
      await cmdSkillToken(args);
      return;
    case "session-token":
      await cmdSessionToken(args);
      return;
    case "service":
      await cmdService(args);
      return;
    case "identity":
      await cmdIdentity(args);
      return;
    case "advisory":
      await cmdAdvisory(args);
      return;
    default:
      printHelp();
      process.exit(command ? 1 : 0);
  }
}

async function cmdInit(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const config = await loadConfig();

  if (flags.transport !== undefined) {
    if (typeof flags.transport !== "string") {
      throw new ValidationError("--transport must be followed by tcp or unix.");
    }
    if (flags.transport !== "tcp" && flags.transport !== "unix") {
      throw new ValidationError("--transport must be either tcp or unix.");
    }
    config.transport = flags.transport;
  }

  if (flags.host !== undefined && typeof flags.host !== "string") {
    throw new ValidationError("--host must be followed by a hostname.");
  }
  if (typeof flags.host === "string") {
    config.host = flags.host;
  }

  if (flags.port !== undefined && typeof flags.port !== "string") {
    throw new ValidationError("--port must be followed by a number.");
  }
  if (typeof flags.port === "string") {
    const parsedPort = Number(flags.port);
    if (!Number.isFinite(parsedPort) || parsedPort <= 0) {
      throw new ValidationError("--port must be a positive number.");
    }
    config.port = parsedPort;
  }

  if (flags.socket !== undefined && typeof flags.socket !== "string") {
    throw new ValidationError("--socket must be followed by a path.");
  }
  if (typeof flags.socket === "string") {
    config.socketPath = flags.socket;
  }

  if (flags.requireSkillToken !== undefined) {
    throw new ValidationError("--requireSkillToken is deprecated. Skill authentication is always required.");
  }

  if (config.transport === "unix" && !config.socketPath.trim()) {
    throw new ValidationError("socketPath is required when transport is unix.");
  }

  await saveConfig(config);

  const passphrase = await resolvePassphrase({ promptIfMissing: true, promptLabel: "Create vault passphrase" });
  const vault = new Vault(config);
  await vault.unlock(passphrase);
  vault.lock();

  const paths = resolveClauthPaths();
  await ensureDir(paths.homeDir);
  await ensureFile(paths.scopeFile, JSON.stringify({ grants: [] }, null, 2));
  await ensureFile(paths.auditFile, "");
  await ensureFile(paths.firewallFile, JSON.stringify({ skills: {} }, null, 2));
  await ensureFile(paths.skillAuthFile, JSON.stringify({ tokens: [] }, null, 2));
  await ensureFile(paths.sessionRevocationsFile, JSON.stringify({ revoked: [] }, null, 2));
  await ensureFile(paths.oauthTokensFile, JSON.stringify({ tokens: {} }, null, 2));
  await ensureFile(paths.advisoryStateFile, JSON.stringify({ seenIds: [] }, null, 2));
  await ensureFile(paths.identityStateFile, JSON.stringify({ challenges: {}, proofs: [] }, null, 2));

  console.log("Clauth initialized.");
  console.log(`Home: ${paths.homeDir}`);
  console.log(`Daemon: ${formatDaemonAddress(config)}`);
}

async function cmdStore(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const handle = requireString(flags.handle, "--handle is required");
  const provider = requireString(flags.provider, "--provider is required");
  const secret = await resolveStoreSecret(flags);
  const ttl = parseOptionalNumber(flags.ttl, "--ttl");

  const config = await loadConfig();
  const passphrase = await resolvePassphrase({ promptIfMissing: true });
  const vault = new Vault(config);
  const audit = new AuditLogger();
  await audit.load();

  await vault.unlock(passphrase);
  const credential = await vault.storeCredential({
    handle,
    provider,
    secret,
    ttlSeconds: ttl,
    metadata: parseMetadata(flags.metadata)
  });
  vault.lock();
  await audit.append({
    ts: new Date().toISOString(),
    event: "credential.store",
    provider: credential.provider,
    outcome: "ok",
    details: {
      handle: credential.handle,
      expiresAt: credential.expiresAt ?? null
    }
  });

  console.log(
    JSON.stringify(
      {
        handle: credential.handle,
        provider: credential.provider,
        createdAt: credential.createdAt,
        expiresAt: credential.expiresAt ?? null
      },
      null,
      2
    )
  );
}

async function cmdGrant(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const skillId = requireString(flags.skill, "--skill is required");
  const provider = requireString(flags.provider, "--provider is required");
  const scope = requireString(flags.scope, "--scope is required");
  const rpm = parseOptionalNumber(flags.rpm, "--rpm");

  const scopes = new ScopeEngine();
  const audit = new AuditLogger();
  await audit.load();
  await scopes.load();
  const grant = await scopes.grant({
    skillId,
    provider,
    scope,
    rateLimitPerMinute: rpm
  });
  await audit.append({
    ts: new Date().toISOString(),
    event: "grant.create",
    skillId: grant.skillId,
    provider: grant.provider,
    scope: grant.scope,
    outcome: "ok",
    details: { rateLimitPerMinute: grant.rateLimitPerMinute }
  });

  console.log(JSON.stringify(grant, null, 2));
}

async function cmdRevoke(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const skillId = requireString(flags.skill, "--skill is required");
  const provider = optionalString(flags.provider, "--provider");
  const scope = optionalString(flags.scope, "--scope");

  const scopes = new ScopeEngine();
  const audit = new AuditLogger();
  await audit.load();
  await scopes.load();
  const revoked = await scopes.revoke({
    skillId,
    provider,
    scope
  });
  await audit.append({
    ts: new Date().toISOString(),
    event: "grant.revoke",
    skillId,
    provider,
    scope,
    outcome: "ok",
    details: { revoked }
  });

  console.log(JSON.stringify({ revoked }, null, 2));
}

async function cmdEmergencyRevoke(): Promise<void> {
  const scopes = new ScopeEngine();
  const audit = new AuditLogger();
  await Promise.all([scopes.load(), audit.load()]);

  const revoked = await scopes.emergencyRevokeAll();
  await audit.append({
    ts: new Date().toISOString(),
    event: "grant.emergency_revoke",
    outcome: "ok",
    details: { revoked }
  });

  console.log(JSON.stringify({ revoked }, null, 2));
}

async function cmdStatus(): Promise<void> {
  const config = await loadConfig();
  const scopes = new ScopeEngine();
  const audit = new AuditLogger();
  const skillAuth = new SkillAuthEngine(config);
  await Promise.all([scopes.load(), audit.load(), skillAuth.load()]);

  let credentialCount: number | null = null;
  let maybePassphrase: string | null = null;
  try {
    maybePassphrase = await resolvePassphrase();
  } catch {
    maybePassphrase = null;
  }
  if (maybePassphrase) {
    const vault = new Vault(config);
    await vault.unlock(maybePassphrase);
    credentialCount = (await vault.listCredentialMetadata()).length;
    vault.lock();
  }

  const integrity = await audit.verifyIntegrity();

  console.log(
    JSON.stringify(
      {
        daemon: formatDaemonAddress(config),
        transport: config.transport,
        provisionedSkillTokens: skillAuth.list().filter((entry) => entry.active).length,
        activeGrants: scopes.listGrants({ activeOnly: true }).length,
        credentialCount,
        auditIntegrity: integrity
      },
      null,
      2
    )
  );
}

async function cmdDaemon(_args: string[]): Promise<void> {
  // Prefer non-interactive env/file configuration, but allow interactive startup
  // when running the daemon from a terminal.
  if (!process.env.CLAUTH_PASSPHRASE && !process.env.CLAUTH_PASSPHRASE_FILE) {
    const passphrase = await resolvePassphrase({ promptIfMissing: true, promptLabel: "Vault passphrase" });
    process.env.CLAUTH_PASSPHRASE = passphrase;
  }

  // `../daemon/server.js` is a self-starting entrypoint. In dev it resolves to
  // `server.ts` via the local loader; in production it resolves to compiled JS.
  await import("../daemon/server.js");
}

async function cmdDoctor(): Promise<void> {
  const paths = resolveClauthPaths();
  const checks: Array<{ check: string; ok: boolean; detail?: string }> = [];

  const config = await loadConfig();
  checks.push({
    check: "config",
    ok: Boolean((config.transport === "tcp" && config.host && config.port) || (config.transport === "unix" && config.socketPath)),
    detail: formatDaemonAddress(config)
  });
  checks.push({
    check: "hardening.loopback-host",
    ok: config.transport !== "tcp" || isLoopbackHost(config.host),
    detail: config.transport === "tcp" ? config.host : "n/a (unix transport)"
  });
  checks.push({
    check: "hardening.remote-access",
    ok: process.env.CLAUTH_ALLOW_REMOTE !== "1",
    detail:
      process.env.CLAUTH_ALLOW_REMOTE === "1"
        ? "CLAUTH_ALLOW_REMOTE=1 is enabled (unsafe for production)"
        : "disabled"
  });
  checks.push({
    check: "hardening.insecure-http",
    ok: process.env.CLAUTH_ALLOW_INSECURE_HTTP !== "1",
    detail:
      process.env.CLAUTH_ALLOW_INSECURE_HTTP === "1"
        ? "CLAUTH_ALLOW_INSECURE_HTTP=1 is enabled (unsafe for production)"
        : "disabled"
  });
  const hasAdminToken = Boolean(process.env.CLAUTH_ADMIN_TOKEN?.trim());
  checks.push({
    check: "hardening.admin-token",
    ok: hasAdminToken,
    detail: hasAdminToken ? "configured" : "missing CLAUTH_ADMIN_TOKEN"
  });
  checks.push({
    check: "hardening.identity-admin-gate",
    ok: !config.hardening.requireAdminTokenForIdentity || hasAdminToken,
    detail: config.hardening.requireAdminTokenForIdentity
      ? "requireAdminTokenForIdentity=true"
      : "requireAdminTokenForIdentity=false"
  });

  const scopes = new ScopeEngine();
  await scopes.load();
  checks.push({ check: "scope-store", ok: true, detail: `${scopes.listGrants().length} grants loaded` });

  const audit = new AuditLogger();
  await audit.load();
  const integrity = await audit.verifyIntegrity();
  checks.push({
    check: "audit-integrity",
    ok: integrity.valid,
    detail: integrity.valid ? "valid" : `${integrity.reason ?? "invalid"} at line ${integrity.brokenAtLine ?? "?"}`
  });

  checks.push({ check: "paths", ok: true, detail: paths.homeDir });

  const skillAuth = new SkillAuthEngine(config);
  await skillAuth.load();
  checks.push({
    check: "skill-auth-store",
    ok: true,
    detail: `${skillAuth.list().length} skill token record(s) loaded`
  });

  const passed = checks.every((entry) => entry.ok);
  console.log(JSON.stringify({ passed, checks }, null, 2));
}

async function cmdSkillToken(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  const flags = parseFlags(rest);
  const config = await loadConfig();
  const skillAuth = new SkillAuthEngine(config);
  const audit = new AuditLogger();
  await Promise.all([skillAuth.load(), audit.load()]);

  if (subcommand === "issue") {
    const skill = requireString(flags.skill, "--skill is required");
    const issued = await skillAuth.issue(skill);
    await audit.append({
      ts: new Date().toISOString(),
      event: "skill_token.issue",
      skillId: issued.skillId,
      outcome: "ok"
    });
    console.log(
      JSON.stringify(
        {
          skillId: issued.skillId,
          token: issued.token,
          note: "Store this token securely; it is shown only once."
        },
        null,
        2
      )
    );
    return;
  }

  if (subcommand === "revoke") {
    const skill = requireString(flags.skill, "--skill is required");
    const revoked = await skillAuth.revoke(skill);
    await audit.append({
      ts: new Date().toISOString(),
      event: "skill_token.revoke",
      skillId: skill,
      outcome: revoked ? "ok" : "not_found"
    });
    console.log(JSON.stringify({ skillId: skill, revoked }, null, 2));
    return;
  }

  if (subcommand === "list") {
    console.log(JSON.stringify({ tokens: skillAuth.list() }, null, 2));
    return;
  }

  throw new ValidationError("Usage: skill-token <issue|revoke|list> [--skill <skillId>]");
}

async function cmdSessionToken(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  const flags = parseFlags(rest);
  const config = await loadConfig();
  const passphrase = await resolvePassphrase({ promptIfMissing: true });
  const vault = new Vault(config);
  await vault.unlock(passphrase);

  const sessions = new SessionEngine(vault, config.hardening.sessionTtlSeconds);
  await sessions.load();
  const audit = new AuditLogger();
  await audit.load();

  if (subcommand === "issue") {
    const skillId = requireString(flags.skill, "--skill is required");
    const scope = optionalString(flags.scope, "--scope");
    const ttlSeconds = parseOptionalNumber(flags.ttl, "--ttl");
    const issued = sessions.issueWithMetadata(
      {
        sub: skillId,
        ...(scope ? { scope } : {})
      },
      ttlSeconds
    );

    await audit.append({
      ts: new Date().toISOString(),
      event: "session_token.issue",
      skillId,
      outcome: "ok",
      details: {
        jti: issued.jti,
        exp: issued.exp,
        iat: issued.iat
      }
    });

    vault.lock();
    console.log(
      JSON.stringify(
        {
          skillId,
          token: issued.token,
          jti: issued.jti,
          issuedAt: new Date(issued.iat * 1000).toISOString(),
          expiresAt: new Date(issued.exp * 1000).toISOString()
        },
        null,
        2
      )
    );
    return;
  }

  if (subcommand === "revoke") {
    const token = optionalString(flags.token, "--token");
    const jti = optionalString(flags.jti, "--jti");

    if (!token && !jti) {
      vault.lock();
      throw new ValidationError("Provide --token <jwt> or --jti <session-id>.");
    }

    let revoked = false;
    let revokedJti: string | undefined;
    let expiresAt: number | undefined;

    if (token) {
      const result = await sessions.revokeToken(token, "cli");
      revoked = result.revoked;
      revokedJti = result.jti;
      expiresAt = result.expiresAt;
    } else if (jti) {
      const exp =
        parseOptionalNumber(flags.exp, "--exp") ??
        Math.floor(Date.now() / 1000) + config.hardening.sessionTtlSeconds;
      revoked = await sessions.revokeJti(jti, exp, "cli");
      revokedJti = jti;
      expiresAt = exp;
    }

    await audit.append({
      ts: new Date().toISOString(),
      event: "session_token.revoke",
      outcome: revoked ? "ok" : "not_found",
      details: {
        jti: revokedJti,
        exp: expiresAt
      }
    });

    vault.lock();
    console.log(
      JSON.stringify(
        {
          revoked,
          jti: revokedJti,
          expiresAt: expiresAt ? new Date(expiresAt * 1000).toISOString() : undefined
        },
        null,
        2
      )
    );
    return;
  }

  if (subcommand === "list") {
    const revocations = sessions.listRevocations();
    vault.lock();
    console.log(JSON.stringify({ revocations }, null, 2));
    return;
  }

  vault.lock();
  throw new ValidationError(
    "Usage: session-token <issue|revoke|list> [--skill <skillId>] [--scope <scope>] [--ttl <seconds>] [--token <jwt>] [--jti <id>] [--exp <epoch-seconds>]"
  );
}

async function cmdMigrate(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const fromPath =
    optionalString(flags.from, "--from") ?? path.join(os.homedir(), ".openclaw", "openclaw.json");
  const writeMode = flags.write === true;

  const raw = await fs.readFile(fromPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new ValidationError("Input config must be a JSON object.");
  }

  const config = await loadConfig();
  const passphrase = await resolvePassphrase({ promptIfMissing: true });
  const vault = new Vault(config);
  const audit = new AuditLogger();
  await audit.load();
  await vault.unlock(passphrase);

  const replaced: Array<{ path: string; handle: string; provider: string }> = [];
  const seenSecrets = new Map<string, string>();
  let counter = 0;

  async function walk(node: unknown, breadcrumb: string[], providerHint?: string): Promise<void> {
    if (Array.isArray(node)) {
      for (let idx = 0; idx < node.length; idx += 1) {
        await walk(node[idx], [...breadcrumb, String(idx)], providerHint);
      }
      return;
    }

    if (!node || typeof node !== "object") {
      return;
    }

    const obj = node as Record<string, unknown>;
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      const nextBreadcrumb = [...breadcrumb, key];
      const nextProviderHint = detectProviderHint(nextBreadcrumb, providerHint);

      if (typeof value === "string" && isLikelySecretKey(lowerKey)) {
        const provider = nextProviderHint ?? "unknown";
        const secret = value.trim();
        if (!secret) {
          continue;
        }

        const existingHandle = seenSecrets.get(secret);
        const handle = existingHandle ?? `migrated-${provider}-${counter++}`;
        if (!existingHandle) {
          await vault.storeCredential({
            handle,
            provider,
            secret
          });
          seenSecrets.set(secret, handle);
        }

        obj[key] = `clauth://${handle}`;
        replaced.push({
          path: nextBreadcrumb.join("."),
          handle,
          provider
        });
        continue;
      }

      await walk(value, nextBreadcrumb, nextProviderHint);
    }
  }

  await walk(parsed, []);
  vault.lock();

  if (replaced.length === 0) {
    await audit.append({
      ts: new Date().toISOString(),
      event: "credential.store",
      outcome: "ok",
      details: { migrated: 0, fromPath }
    });
    console.log(JSON.stringify({ replaced: 0, message: "No credential-like keys found." }, null, 2));
    return;
  }

  if (!writeMode) {
    await audit.append({
      ts: new Date().toISOString(),
      event: "credential.store",
      outcome: "ok",
      details: { migrated: replaced.length, fromPath, dryRun: true }
    });
    console.log(
      JSON.stringify(
        {
          replaced: replaced.length,
          dryRun: true,
          fromPath,
          sample: replaced.slice(0, 10),
          next: "Re-run with --write to persist rewritten config and backup original."
        },
        null,
        2
      )
    );
    return;
  }

  const backupPath = `${fromPath}.bak.${Date.now()}`;
  await fs.copyFile(fromPath, backupPath);
  await fs.writeFile(fromPath, JSON.stringify(parsed, null, 2), "utf8");
  await audit.append({
    ts: new Date().toISOString(),
    event: "credential.store",
    outcome: "ok",
    details: { migrated: replaced.length, fromPath, backupPath, dryRun: false }
  });

  console.log(
    JSON.stringify(
      {
        replaced: replaced.length,
        fromPath,
        backupPath
      },
      null,
      2
    )
  );
}

async function cmdService(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  const flags = parseFlags(rest);

  if (subcommand === "install") {
    const layout = resolveServiceLayout(flags);
    const content = renderServiceTemplate(layout.target, {
      name: layout.name,
      cwd: layout.cwd,
      nodeBin: layout.nodeBin,
      daemonScript: layout.daemonScript,
      clauthHome: layout.clauthHome,
      envFile: layout.envFile,
      passphraseFile: layout.passphraseFile
    });

    await ensureDir(path.dirname(layout.outputPath));
    await fs.writeFile(layout.outputPath, content, { encoding: "utf8", mode: 0o600 });

    if (layout.target === "systemd") {
      await ensureFile(
        layout.envFile,
        [
          "CLAUTH_PASSPHRASE=replace-with-secure-passphrase",
          "CLAUTH_ADMIN_TOKEN=replace-with-admin-token",
          `CLAUTH_HOME=${layout.clauthHome}`,
          ""
        ].join("\n")
      );
    } else {
      await ensureFile(layout.passphraseFile, "replace-with-secure-passphrase\n");
    }

    const plan = buildServicePlan({
      target: layout.target,
      name: layout.name,
      sourcePath: layout.outputPath,
      destinationPath: layout.destinationPath,
      envFile: layout.envFile,
      passphraseFile: layout.passphraseFile
    });

    console.log(
      JSON.stringify(
        {
          target: layout.target,
          outputPath: layout.outputPath,
          daemonScript: layout.daemonScript,
          envFile: layout.envFile,
          passphraseFile: layout.passphraseFile,
          destinationPath: layout.destinationPath,
          commands: plan.commands
        },
        null,
        2
      )
    );
    return;
  }

  if (subcommand === "doctor") {
    const layout = resolveServiceLayout(flags);
    const plan = buildServicePlan({
      target: layout.target,
      name: layout.name,
      sourcePath: layout.outputPath,
      destinationPath: layout.destinationPath,
      envFile: layout.envFile,
      passphraseFile: layout.passphraseFile
    });

    const checks: Array<{ check: string; ok: boolean; detail: string }> = [];
    checks.push(await fileCheck("generated-unit", layout.outputPath));
    checks.push(await fileCheck("daemon-script", layout.daemonScript));
    checks.push(await fileCheck("service-parent-dir", path.dirname(layout.destinationPath), true));

    if (layout.target === "systemd") {
      checks.push(await fileCheck("env-file", layout.envFile));
    } else {
      checks.push(await fileCheck("passphrase-file", layout.passphraseFile));
      checks.push({
        check: "platform",
        ok: process.platform === "darwin",
        detail: process.platform === "darwin" ? "launchd available" : `running on ${process.platform}`
      });
    }

    console.log(
      JSON.stringify(
        {
          target: layout.target,
          passed: checks.every((entry) => entry.ok),
          checks,
          commands: plan.commands
        },
        null,
        2
      )
    );
    return;
  }

  if (subcommand === "apply") {
    const layout = resolveServiceLayout(flags);
    const write = parseBooleanFlag(flags.write, "--write", false);
    const run = parseBooleanFlag(flags.run, "--run", false);
    const useSudo = parseBooleanFlag(flags.sudo, "--sudo", false);
    const ackSystem = parseBooleanFlag(flags.ackSystem, "--ackSystem", false);
    const plan = buildServicePlan({
      target: layout.target,
      name: layout.name,
      sourcePath: layout.outputPath,
      destinationPath: layout.destinationPath,
      envFile: layout.envFile,
      passphraseFile: layout.passphraseFile
    });

    const result: Record<string, unknown> = {
      target: layout.target,
      sourcePath: layout.outputPath,
      destinationPath: layout.destinationPath,
      commands: plan.commands,
      write,
      run,
      sudo: useSudo
    };

    if (!write) {
      result.next = "Re-run with --write true to copy generated service file to destination path.";
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    try {
      await fs.access(layout.outputPath);
    } catch {
      throw new ValidationError(`Generated service file is missing at ${layout.outputPath}. Run 'service install' first.`);
    }

    try {
      await ensureDir(path.dirname(layout.destinationPath));
      await fs.copyFile(layout.outputPath, layout.destinationPath);
    } catch (error) {
      throw new ValidationError(
        `Failed to copy service file to ${layout.destinationPath}. Re-run with sufficient permissions or run commands manually: ${plan.commands.join(
          " && "
        )}`
      );
    }

    if (layout.target === "systemd") {
      result.next = "Service file copied. Run remaining sudo systemctl commands from 'commands'.";
    } else {
      result.next = "Service file copied. Run launchctl commands from 'commands'.";
    }

    if (run) {
      if (layout.target === "systemd" && !ackSystem) {
        throw new ValidationError("Running system-level commands requires --ackSystem true.");
      }
      if (layout.target === "launchd" && process.platform !== "darwin") {
        throw new ValidationError(`launchd command execution is only available on macOS (current: ${process.platform}).`);
      }

      const activationSteps = buildActivationCommands(layout.target, layout.name, layout.destinationPath);
      const runtimeSteps = useSudo ? activationSteps.map((step) => toSudoStep(step)) : activationSteps;

      const execution = await executeActivationSteps(runtimeSteps);
      result.execution = execution;
      result.next = "Activation commands executed.";
    }

    console.log(JSON.stringify(result, null, 2));
    return;
  }

  throw new ValidationError(
    "Usage: service <install|doctor|apply> [--target systemd|launchd] [--output <path>] [--name <label>] [--envFile <path>] [--passphraseFile <path>] [--dest <path>] [--write true|false] [--run true|false] [--sudo true|false] [--ackSystem true|false]"
  );
}

async function cmdIdentity(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  const flags = parseFlags(rest);
  const config = await loadConfig();
  const passphrase = await resolvePassphrase({ promptIfMissing: true });
  const vault = new Vault(config);
  const audit = new AuditLogger();
  await Promise.all([audit.load()]);
  await vault.unlock(passphrase);

  const alertRouter = new AlertRouter(config);
  await alertRouter.load();
  const sessions = new SessionEngine(vault);
  const broker = new IdentityBrokerEngine({ vault, audit, alertRouter, sessions });
  await broker.load();

  if (subcommand === "challenge") {
    const provider = requireString(flags.provider, "--provider is required");
    const accountId = requireString(flags.accountId, "--accountId is required");
    const skill = optionalString(flags.skill, "--skill") ?? "cli";
    const method = parseIdentityMethod(optionalString(flags.method, "--method"));
    const challenge = await broker.createChallenge({ skillId: skill, provider, accountId, method });
    const output: Record<string, unknown> = {
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt
    };
    if (method === "email") {
      output.delivery = "webhook";
    } else {
      output.challenge = challenge.challenge;
    }
    if (method === "oauth") {
      output.oauthUrl = broker.generateOAuthUrl(challenge.id);
    }
    vault.lock();
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  if (subcommand === "verify") {
    const challengeId = requireString(flags.challengeId, "--challengeId is required");
    const proof = requireString(flags.proof, "--proof is required");
    const result = await broker.verifyChallenge(challengeId, proof);
    vault.lock();
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  if (subcommand === "list") {
    const skill = optionalString(flags.skill, "--skill");
    const proofs = broker.listProofs(skill);
    vault.lock();
    console.log(JSON.stringify({ proofs }, null, 2));
    return;
  }

  if (subcommand === "revoke") {
    const proofId = requireString(flags.proofId, "--proofId is required");
    const revoked = await broker.revokeProof(proofId);
    vault.lock();
    console.log(JSON.stringify({ revoked }, null, 2));
    return;
  }

  vault.lock();
  throw new ValidationError("Usage: identity <challenge|verify|list|revoke> [--provider <name>] [--accountId <id>] [--method signed-challenge|oauth|email] [--challengeId <id>] [--proof <proof>] [--proofId <id>]");
}

async function cmdAdvisory(args: string[]): Promise<void> {
  const [subcommand, ...rest] = args;
  const flags = parseFlags(rest);

  if (subcommand !== "check") {
    throw new ValidationError(
      "Usage: advisory check [--feed <name-or-url>] [--limit <count>] [--apply true|false]"
    );
  }

  const apply = parseBooleanFlag(flags.apply, "--apply", false);
  const limit = parseOptionalNumber(flags.limit, "--limit") ?? 20;
  if (!Number.isFinite(limit) || limit <= 0) {
    throw new ValidationError("--limit must be a positive number.");
  }
  const feedFilter = optionalString(flags.feed, "--feed");

  const config = await loadConfig();
  if (config.advisoryFeeds.length === 0) {
    throw new ValidationError("No advisory feeds are configured.");
  }

  const feeds = feedFilter
    ? config.advisoryFeeds.filter((feed) => feed.name === feedFilter || feed.url === feedFilter)
    : config.advisoryFeeds;
  if (feeds.length === 0) {
    throw new ValidationError(`No advisory feed matched '${feedFilter}'.`);
  }

  const passphrase = await resolvePassphrase({ promptIfMissing: true });
  const vault = new Vault(config);
  await vault.unlock(passphrase);

  const scopes = new ScopeEngine();
  await scopes.load();
  const audit = new AuditLogger();
  await audit.load();
  const alertRouter = new AlertRouter(config);
  await alertRouter.load();
  const monitor = new AdvisoryMonitor({ vault, audit, alertRouter });
  await monitor.load();
  monitor.setScopeEngine(scopes);

  if (apply) {
    const applied = [];
    for (const feed of feeds) {
      const processed = await monitor.checkFeed(feed);
      applied.push({
        feed: feed.name,
        url: feed.url,
        processed: processed.length,
        advisoryIds: processed.map((advisory) => advisory.id)
      });
    }
    vault.lock();
    console.log(
      JSON.stringify(
        {
          mode: "apply",
          feeds: applied
        },
        null,
        2
      )
    );
    return;
  }

  const dryRun: Array<{
    feed: string;
    url: string;
    totalFetched: number;
    newUnseen: number;
    advisories: Array<{
      id: string;
      severity: string;
      summary: string;
      affectedPackage?: string;
      affectedProviders: string[];
      activeGrantMatches: number;
      credentialMatches: number;
    }>;
  }> = [];

  for (const feed of feeds) {
    const fetched = await monitor.fetchFeed(feed);
    const unseen = fetched.filter((advisory) => !monitor.isSeen(advisory.id));
    const selected = unseen.slice(0, Math.floor(limit));
    const advisories = [];
    for (const advisory of selected) {
      const impact = await monitor.previewAdvisoryImpact(advisory);
      advisories.push({
        id: advisory.id,
        severity: advisory.severity,
        summary: advisory.summary,
        affectedPackage: advisory.affectedPackage,
        affectedProviders: impact.affectedProviders,
        activeGrantMatches: impact.activeGrantMatches,
        credentialMatches: impact.credentialMatches
      });
    }
    dryRun.push({
      feed: feed.name,
      url: feed.url,
      totalFetched: fetched.length,
      newUnseen: unseen.length,
      advisories
    });
  }

  vault.lock();
  console.log(
    JSON.stringify(
      {
        mode: "dry-run",
        limit: Math.floor(limit),
        feeds: dryRun,
        next: "Re-run with --apply true to process unseen advisories."
      },
      null,
      2
    )
  );
}

function parseIdentityMethod(method: string | undefined): ProofMethod {
  if (!method) {
    return "signed-challenge";
  }
  if (method === "signed-challenge" || method === "oauth" || method === "email") {
    return method;
  }
  throw new ValidationError("--method must be one of: signed-challenge, oauth, email.");
}

function resolveServiceLayout(flags: Record<string, string | boolean>): {
  target: ServiceTarget;
  name: string;
  cwd: string;
  clauthHome: string;
  nodeBin: string;
  daemonScript: string;
  outputPath: string;
  envFile: string;
  passphraseFile: string;
  destinationPath: string;
} {
  const target = parseServiceTarget(flags.target);
  const name = optionalString(flags.name, "--name") ?? defaultServiceName(target);
  const cwd = process.cwd();
  const clauthHome = resolveClauthPaths().homeDir;
  const nodeBin = process.execPath;
  const daemonScript = path.join(cwd, "dist", "daemon", "server.js");
  const outputPath = optionalString(flags.output, "--output") ?? defaultGeneratedPath(target, clauthHome, name);
  const envFile = optionalString(flags.envFile, "--envFile") ?? path.join(clauthHome, "clauth.env");
  const passphraseFile = optionalString(flags.passphraseFile, "--passphraseFile") ?? path.join(clauthHome, "passphrase");
  const destinationPath =
    optionalString(flags.dest, "--dest") ?? defaultDestinationPath(target, name, os.homedir());

  return {
    target,
    name,
    cwd,
    clauthHome,
    nodeBin,
    daemonScript,
    outputPath,
    envFile,
    passphraseFile,
    destinationPath
  };
}

async function fileCheck(check: string, filePath: string, directory = false): Promise<{ check: string; ok: boolean; detail: string }> {
  try {
    const stat = await fs.stat(filePath);
    if (directory && !stat.isDirectory()) {
      return { check, ok: false, detail: `${filePath} exists but is not a directory` };
    }
    return { check, ok: true, detail: filePath };
  } catch {
    return { check, ok: false, detail: `${filePath} is missing` };
  }
}

function toSudoStep(step: ProcessCommand): ProcessCommand {
  return {
    command: "sudo",
    args: [step.command, ...step.args],
    allowFailure: step.allowFailure
  };
}

async function executeActivationSteps(steps: ProcessCommand[]): Promise<Array<{ command: string; ok: boolean; exitCode: number; stdout: string; stderr: string; allowFailure: boolean }>> {
  const results: Array<{ command: string; ok: boolean; exitCode: number; stdout: string; stderr: string; allowFailure: boolean }> = [];

  for (const step of steps) {
    const commandText = formatProcessCommand(step);

    try {
      const output = await execFileAsync(step.command, step.args, {
        timeout: 20_000,
        maxBuffer: 1024 * 1024
      });

      results.push({
        command: commandText,
        ok: true,
        exitCode: 0,
        stdout: output.stdout,
        stderr: output.stderr,
        allowFailure: Boolean(step.allowFailure)
      });
      continue;
    } catch (error) {
      const err = error as {
        code?: number | string;
        stdout?: string;
        stderr?: string;
        message?: string;
      };

      const exitCode = typeof err.code === "number" ? err.code : -1;
      const stdout = err.stdout ?? "";
      const stderr = err.stderr ?? err.message ?? "unknown error";
      const allowFailure = Boolean(step.allowFailure);

      results.push({
        command: commandText,
        ok: false,
        exitCode,
        stdout,
        stderr,
        allowFailure
      });

      if (!allowFailure) {
        throw new ValidationError(`Activation command failed: ${commandText}\n${stderr}`);
      }
    }
  }

  return results;
}

function parseFlags(args: string[]): Record<string, string | boolean> {
  const flags: Record<string, string | boolean> = {};

  for (let idx = 0; idx < args.length; idx += 1) {
    const token = args[idx];
    if (!token.startsWith("--")) {
      continue;
    }

    const key = token.slice(2);
    const next = args[idx + 1];
    if (!next || next.startsWith("--")) {
      flags[key] = true;
      continue;
    }

    flags[key] = next;
    idx += 1;
  }

  return flags;
}

function parseMetadata(value: string | boolean | undefined): Record<string, string> | undefined {
  if (!value || typeof value !== "string") {
    return undefined;
  }

  const pairs = value.split(",").map((part) => part.trim()).filter(Boolean);
  if (pairs.length === 0) {
    return undefined;
  }

  const metadata: Record<string, string> = {};
  for (const pair of pairs) {
    const [key, ...rest] = pair.split("=");
    if (!key || rest.length === 0) {
      continue;
    }
    metadata[key.trim()] = rest.join("=").trim();
  }

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

async function resolveStoreSecret(flags: Record<string, string | boolean>): Promise<string> {
  if (flags.secret !== undefined) {
    throw new ValidationError("--secret is no longer supported. Use --secret-env <ENV_VAR> or --secret-stdin.");
  }

  const secretEnvName = optionalString(flags["secret-env"], "--secret-env");
  const useSecretStdin = parseBooleanFlag(flags["secret-stdin"], "--secret-stdin", false);

  const sourceCount = Number(secretEnvName !== undefined) + Number(useSecretStdin);
  if (sourceCount === 0) {
    throw new ValidationError("One secret source is required: --secret-env or --secret-stdin.");
  }
  if (sourceCount > 1) {
    throw new ValidationError("Use exactly one secret source: --secret-env or --secret-stdin.");
  }

  if (secretEnvName !== undefined) {
    const fromEnv = process.env[secretEnvName];
    if (fromEnv === undefined) {
      throw new ValidationError(`Environment variable '${secretEnvName}' is not set.`);
    }
    if (!fromEnv.length) {
      throw new ValidationError(`Environment variable '${secretEnvName}' is empty.`);
    }
    return fromEnv;
  }

  if (process.stdin.isTTY) {
    throw new ValidationError("--secret-stdin requires piped stdin.");
  }

  const fromStdin = await readStdinAll();
  const normalized = fromStdin.replace(/\r?\n$/, "");
  if (!normalized.length) {
    throw new ValidationError("Secret from stdin is empty.");
  }
  return normalized;
}

function requireString(value: string | boolean | undefined, message: string): string {
  if (!value || typeof value !== "string" || !value.trim()) {
    throw new ValidationError(message);
  }
  return value;
}

function parseOptionalNumber(value: string | boolean | undefined, flagName: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new ValidationError(`${flagName} must be followed by a numeric value.`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new ValidationError(`${flagName} must be a non-negative number.`);
  }
  return parsed;
}

function parseBooleanFlag(value: string | boolean | undefined, flagName: string, defaultValue: boolean): boolean {
  if (value === undefined) {
    return defaultValue;
  }
  if (typeof value === "boolean") {
    return value;
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  throw new ValidationError(`${flagName} must be true or false.`);
}

function optionalString(value: string | boolean | undefined, flagName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || !value.trim()) {
    throw new ValidationError(`${flagName} must be followed by a value.`);
  }
  return value.trim();
}

async function resolvePassphrase(input?: { promptIfMissing?: boolean; promptLabel?: string }): Promise<string> {
  const fromEnv = process.env.CLAUTH_PASSPHRASE;
  if (fromEnv) {
    return fromEnv;
  }

  const fromFile = process.env.CLAUTH_PASSPHRASE_FILE;
  if (fromFile) {
    const raw = await fs.readFile(fromFile, "utf8");
    const trimmed = raw.trim();
    if (trimmed) {
      return trimmed;
    }
  }

  if (!input?.promptIfMissing) {
    throw new ValidationError("Passphrase not provided. Set CLAUTH_PASSPHRASE or CLAUTH_PASSPHRASE_FILE.");
  }

  return promptHidden(`${input.promptLabel ?? "Vault passphrase"}: `);
}

function printHelp(): void {
  console.log(`
clauth commands:
  init [--transport tcp|unix] [--host 127.0.0.1] [--port 4317] [--socket <path>]
  store --handle <id> --provider <name> (--secret-env <ENV_VAR> | --secret-stdin) [--ttl <seconds>] [--metadata key=value,key2=value2]
  grant --skill <skillId> --provider <name> --scope <provider:action> [--rpm <count>]
  revoke --skill <skillId> [--provider <name>] [--scope <provider:action>]
  emergency-revoke
  status
  daemon
  serve
  doctor
  migrate [--from <path>] [--write]
  skill-token issue --skill <skillId>
  skill-token revoke --skill <skillId>
  skill-token list
  session-token issue --skill <skillId> [--scope <scope>] [--ttl <seconds>]
  session-token revoke (--token <jwt> | --jti <id>) [--exp <epoch-seconds>]
  session-token list
  identity challenge --provider <name> --accountId <id> [--skill <skillId>] [--method signed-challenge|oauth|email]
  identity verify --challengeId <id> --proof <proof>
  identity list [--skill <skillId>]
  identity revoke --proofId <id>
  advisory check [--feed <name-or-url>] [--limit <count>] [--apply true|false]
  service install [--target systemd|launchd] [--output <path>] [--name <label>] [--envFile <path>] [--passphraseFile <path>] [--dest <path>]
  service doctor [--target systemd|launchd] [--output <path>] [--name <label>] [--envFile <path>] [--passphraseFile <path>] [--dest <path>]
  service apply [--target systemd|launchd] [--output <path>] [--name <label>] [--dest <path>] [--write true|false] [--run true|false] [--sudo true|false] [--ackSystem true|false]

Environment:
  CLAUTH_HOME
  CLAUTH_PASSPHRASE
  CLAUTH_PASSPHRASE_FILE
  CLAUTH_ADMIN_TOKEN
  CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL
`);
}

function formatDaemonAddress(config: { transport: string; host: string; port: number; socketPath: string }): string {
  if (config.transport === "unix") {
    return `unix://${config.socketPath}`;
  }
  return `http://${config.host}:${config.port}`;
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

function promptHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    }) as readline.Interface & { _writeToOutput?: (value: string) => void };

    rl._writeToOutput = function writeToOutput(_value: string): void {
      process.stdout.write("*");
    };

    rl.question("", (answer) => {
      rl.close();
      process.stdout.write("\n");
      resolve(answer.trim());
    });
  });
}

async function readStdinAll(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    if (typeof chunk === "string") {
      chunks.push(Buffer.from(chunk));
    } else {
      chunks.push(chunk);
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

function isLikelySecretKey(key: string): boolean {
  return /(api.?key|token|secret|password)/i.test(key);
}

function detectProviderHint(parts: string[], currentHint?: string): string | undefined {
  const deny = new Set(["config", "settings", "credentials", "auth", "secrets", "accounts", "providers", "default"]);
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    const candidate = parts[index].toLowerCase();
    if (/^[a-z0-9_-]{2,40}$/.test(candidate) && !deny.has(candidate) && !candidate.match(/^\\d+$/)) {
      return candidate;
    }
  }
  return currentHint;
}

function parseServiceTarget(value: string | boolean | undefined): ServiceTarget {
  if (!value) {
    return process.platform === "darwin" ? "launchd" : "systemd";
  }
  if (typeof value !== "string") {
    throw new ValidationError("--target must be followed by systemd or launchd.");
  }
  if (value !== "systemd" && value !== "launchd") {
    throw new ValidationError("--target must be systemd or launchd.");
  }
  return value;
}
