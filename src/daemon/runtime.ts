import { AuditLogger } from "../core/audit.js";
import { loadConfig } from "../core/config.js";
import type { ClauthConfig } from "../core/config.js";
import { CredentialProxy } from "../core/proxy.js";
import { OAuthRefresher } from "../core/oauth-refresh.js";
import { ScopeEngine } from "../core/scopes.js";
import { Vault } from "../core/vault.js";
import { BehavioralFirewall } from "../core/firewall.js";
import { SkillAuthEngine } from "../core/skill-auth.js";
import { AlertRouter } from "../core/alerts.js";
import { AdvisoryMonitor } from "../core/advisory.js";
import { SessionEngine } from "../core/sessions.js";
import { IdentityBrokerEngine } from "../core/identity-broker.js";

export interface ClauthRuntime {
  config: ClauthConfig;
  vault: Vault;
  scopes: ScopeEngine;
  firewall: BehavioralFirewall;
  audit: AuditLogger;
  skillAuth: SkillAuthEngine;
  proxy: CredentialProxy;
  oauthRefresher: OAuthRefresher;
  alertRouter: AlertRouter;
  advisoryMonitor: AdvisoryMonitor;
  sessions: SessionEngine;
  identityBroker: IdentityBrokerEngine;
}

export async function buildRuntime(passphrase: string): Promise<ClauthRuntime> {
  const config = await loadConfig();
  const vault = new Vault(config);
  const scopes = new ScopeEngine();
  const firewall = new BehavioralFirewall(config);
  const audit = new AuditLogger();
  const skillAuth = new SkillAuthEngine(config);

  await Promise.all([scopes.load(), firewall.load(), audit.load(), skillAuth.load()]);
  await vault.unlock(passphrase);

  const oauthRefresher = new OAuthRefresher({ vault, audit });
  await oauthRefresher.load();

  const alertRouter = new AlertRouter(config);
  await alertRouter.load();

  const advisoryMonitor = new AdvisoryMonitor({ vault, audit, alertRouter });
  await advisoryMonitor.load();
  advisoryMonitor.setScopeEngine(scopes);

  const sessions = new SessionEngine(vault, config.hardening.sessionTtlSeconds);
  await sessions.load();

  const identityBroker = new IdentityBrokerEngine({
    vault, audit, alertRouter, sessions,
    challengeTtlMs: config.hardening.challengeTtlSeconds * 1000,
    maxVerifyAttempts: config.hardening.identityMaxVerifyAttempts
  });
  await identityBroker.load();

  const proxy = new CredentialProxy({
    vault,
    scopeEngine: scopes,
    firewall,
    audit,
    oauthRefresher,
    enforceHttps: config.hardening.enforceHttps && process.env.CLAUTH_ALLOW_INSECURE_HTTP !== "1"
  });

  await audit.append({
    ts: new Date().toISOString(),
    event: "daemon.start",
    outcome: "ok",
    details: {
      transport: config.transport
    }
  });

  return {
    config,
    vault,
    scopes,
    firewall,
    audit,
    skillAuth,
    proxy,
    oauthRefresher,
    alertRouter,
    advisoryMonitor,
    sessions,
    identityBroker
  };
}
