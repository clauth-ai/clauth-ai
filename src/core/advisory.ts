import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import type { AuditLogger } from "./audit.js";
import type { AlertRouter } from "./alerts.js";
import type { ScopeEngine } from "./scopes.js";
import type { Vault } from "./vault.js";
import type { Advisory, AdvisorySource } from "../types/index.js";

interface AdvisoryState {
  seenIds: string[];
}

const EMPTY_STATE: AdvisoryState = { seenIds: [] };
const PROVIDER_ALIASES: Record<string, string[]> = {
  github: ["github", "actions"],
  twitter: ["twitter", "x"],
  x: ["twitter", "x"],
  slack: ["slack"],
  discord: ["discord", "discordapp"],
  google: ["google", "googleapis"],
  moltbook: ["moltbook"]
};

export class AdvisoryMonitor {
  private seen: Set<string> = new Set();
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly vault: Vault;
  private readonly audit: AuditLogger;
  private readonly alertRouter: AlertRouter;
  private scopeEngine?: ScopeEngine;

  constructor(input: { vault: Vault; audit: AuditLogger; alertRouter: AlertRouter }) {
    this.vault = input.vault;
    this.audit = input.audit;
    this.alertRouter = input.alertRouter;
  }

  public setScopeEngine(engine: ScopeEngine): void {
    this.scopeEngine = engine;
  }

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    const state = await readJsonFile<AdvisoryState>(paths.advisoryStateFile, structuredClone(EMPTY_STATE));
    this.seen = new Set(state.seenIds);
  }

  public async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.advisoryStateFile, { seenIds: [...this.seen] });
  }

  public startPolling(intervalMs: number, feeds: AdvisorySource[]): void {
    this.stopPolling();
    if (feeds.length === 0) {
      return;
    }
    this.timer = setInterval(async () => {
      for (const feed of feeds) {
        await this.checkFeed(feed).catch(() => {});
      }
    }, intervalMs);
    this.timer.unref?.();
  }

  public stopPolling(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  public isPolling(): boolean {
    return this.timer !== null;
  }

  public async checkFeed(source: AdvisorySource): Promise<Advisory[]> {
    const advisories = await this.fetchFeed(source);
    const newAdvisories: Advisory[] = [];
    for (const advisory of advisories) {
      if (this.seen.has(advisory.id)) {
        continue;
      }
      this.seen.add(advisory.id);
      newAdvisories.push(advisory);
      await this.processAdvisory(advisory);
    }

    if (newAdvisories.length > 0) {
      await this.persist();
    }

    return newAdvisories;
  }

  public async fetchFeed(source: AdvisorySource): Promise<Advisory[]> {
    try {
      const response = await fetch(source.url, {
        headers: { accept: "application/json" }
      });
      if (!response.ok) {
        return [];
      }

      const data = (await response.json()) as unknown;
      const items = Array.isArray(data) ? data : [];
      const advisories: Advisory[] = [];
      for (const item of items) {
        const advisory = parseAdvisory(item, source);
        if (advisory) {
          advisories.push(advisory);
        }
      }
      return advisories;
    } catch {
      // Network error; silently skip this poll cycle.
      return [];
    }
  }

  public isSeen(advisoryId: string): boolean {
    return this.seen.has(advisoryId);
  }

  public async previewAdvisoryImpact(advisory: Advisory): Promise<{
    affectedProviders: string[];
    activeGrantMatches: number;
    credentialMatches: number;
  }> {
    const affectedProviders = resolveAffectedProviders(advisory);
    const affectedProviderSet = new Set(affectedProviders);

    let activeGrantMatches = 0;
    if (affectedProviderSet.size > 0 && this.scopeEngine) {
      const grants = this.scopeEngine.listGrants({ activeOnly: true });
      activeGrantMatches = grants.filter((grant) => {
        const scopeProvider = grant.scope.split(":")[0]?.trim().toLowerCase();
        return (
          affectedProviderSet.has(grant.provider) ||
          (scopeProvider !== undefined && affectedProviderSet.has(scopeProvider))
        );
      }).length;
    }

    let credentialMatches = 0;
    if (affectedProviderSet.size > 0) {
      try {
        const metadata = await this.vault.listCredentialMetadata();
        credentialMatches = metadata.filter((credential) =>
          affectedProviderSet.has(credential.provider)
        ).length;
      } catch {
        credentialMatches = 0;
      }
    }

    return {
      affectedProviders,
      activeGrantMatches,
      credentialMatches
    };
  }

  public async processAdvisory(advisory: Advisory): Promise<void> {
    let revokedCount = 0;
    const affectedProviders = resolveAffectedProviders(advisory);
    const affectedProviderSet = new Set(affectedProviders);

    if (advisory.severity === "critical" && affectedProviderSet.size > 0 && this.scopeEngine) {
      const grants = this.scopeEngine.listGrants({ activeOnly: true });
      const matching = grants.filter(
        (g) => {
          const scopeProvider = g.scope.split(":")[0]?.trim().toLowerCase();
          return (
            affectedProviderSet.has(g.provider) ||
            (scopeProvider !== undefined && affectedProviderSet.has(scopeProvider))
          );
        }
      );

      for (const grant of matching) {
        try {
          const count = await this.scopeEngine.revoke({
            skillId: grant.skillId,
            provider: grant.provider,
            scope: grant.scope
          });
          revokedCount += count;
        } catch {
          // Grant may already be revoked; continue.
        }
      }
    }

    if (advisory.severity === "critical" && affectedProviderSet.size > 0) {
      try {
        const metadata = await this.vault.listCredentialMetadata();
        const affected = metadata.filter((c) => affectedProviderSet.has(c.provider));
        for (const cred of affected) {
          await this.vault.deleteCredential(cred.handle);
        }
      } catch {
        // Vault may be locked or credential already gone.
      }
    }

    await this.alertRouter.dispatch({
      severity: advisory.severity,
      category: "advisory",
      message: `Security advisory ${advisory.id}: ${advisory.summary}`,
      timestamp: new Date().toISOString(),
      metadata: {
        advisoryId: advisory.id,
        source: advisory.source,
        affectedPackage: advisory.affectedPackage,
        affectedPackages: advisory.affectedPackages,
        affectedProviders,
        url: advisory.url,
        revokedGrants: revokedCount
      }
    });

    await this.audit.append({
      ts: new Date().toISOString(),
      event: "firewall.alert",
      outcome: "advisory_processed",
      details: {
        advisoryId: advisory.id,
        severity: advisory.severity,
        source: advisory.source,
        affectedProviders,
        revokedGrants: revokedCount
      }
    });
  }

  public getSeenCount(): number {
    return this.seen.size;
  }
}

export function parseAdvisory(item: unknown, source: AdvisorySource): Advisory | null {
  if (!item || typeof item !== "object") {
    return null;
  }

  const obj = item as Record<string, unknown>;
  const id = typeof obj.ghsa_id === "string" ? obj.ghsa_id : typeof obj.id === "string" ? obj.id : null;
  if (!id) {
    return null;
  }

  const severityRaw = typeof obj.severity === "string" ? obj.severity.toLowerCase() : "info";
  const severity = severityRaw === "critical" || severityRaw === "high" ? "critical" : severityRaw === "moderate" || severityRaw === "medium" ? "warning" : "info";
  const affectedPackages = extractAffectedPackages(obj);
  const affectedPackage = affectedPackages[0];

  return {
    id,
    source: source.name,
    severity,
    summary: typeof obj.summary === "string" ? obj.summary : String(obj.description ?? id),
    affectedPackage,
    affectedPackages: affectedPackages.length > 0 ? affectedPackages : undefined,
    publishedAt: typeof obj.published_at === "string" ? obj.published_at : new Date().toISOString(),
    url: typeof obj.html_url === "string" ? obj.html_url : undefined
  };
}

function extractAffectedPackages(obj: Record<string, unknown>): string[] {
  const packages: string[] = [];
  const seen = new Set<string>();
  const addPackage = (value: unknown): void => {
    if (typeof value !== "string" || !value.trim()) {
      return;
    }
    const normalized = normalizePackageName(value);
    if (!normalized || seen.has(normalized)) {
      return;
    }
    seen.add(normalized);
    packages.push(normalized);
  };

  addPackage(obj.package);
  addPackage(obj.affectedPackage);
  addPackage(obj.affected_package);

  if (obj.package && typeof obj.package === "object") {
    addPackage((obj.package as Record<string, unknown>).name);
    addPackage((obj.package as Record<string, unknown>).slug);
  }

  const vulnerabilities = Array.isArray(obj.vulnerabilities) ? obj.vulnerabilities : [];
  for (const vuln of vulnerabilities) {
    if (!vuln || typeof vuln !== "object") {
      continue;
    }
    const vulnObj = vuln as Record<string, unknown>;
    addPackage(vulnObj.package);
    if (vulnObj.package && typeof vulnObj.package === "object") {
      addPackage((vulnObj.package as Record<string, unknown>).name);
      addPackage((vulnObj.package as Record<string, unknown>).slug);
    }
    addPackage(vulnObj.name);
  }

  const affected = Array.isArray(obj.affected) ? obj.affected : [];
  for (const entry of affected) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const affectedObj = entry as Record<string, unknown>;
    addPackage(affectedObj.package);
    if (affectedObj.package && typeof affectedObj.package === "object") {
      addPackage((affectedObj.package as Record<string, unknown>).name);
      addPackage((affectedObj.package as Record<string, unknown>).slug);
    }
    addPackage(affectedObj.name);
  }

  return packages;
}

function normalizePackageName(value: string): string {
  return value.trim().toLowerCase();
}

function resolveAffectedProviders(advisory: Advisory): string[] {
  const providerSet = new Set<string>();
  const packages =
    advisory.affectedPackages && advisory.affectedPackages.length > 0
      ? advisory.affectedPackages
      : advisory.affectedPackage
        ? [advisory.affectedPackage]
        : [];

  for (const pkg of packages) {
    const normalizedPackage = normalizePackageName(pkg);
    for (const [provider, aliases] of Object.entries(PROVIDER_ALIASES)) {
      if (aliases.some((alias) => hasAliasToken(normalizedPackage, alias))) {
        providerSet.add(provider);
      }
    }
  }

  return [...providerSet];
}

function hasAliasToken(packageName: string, alias: string): boolean {
  const normalizedAlias = normalizePackageName(alias);
  if (packageName === normalizedAlias) {
    return true;
  }
  if (
    packageName.startsWith(`${normalizedAlias}/`) ||
    packageName.endsWith(`/${normalizedAlias}`) ||
    packageName.includes(`/${normalizedAlias}/`)
  ) {
    return true;
  }
  const tokens = packageName.split(/[^a-z0-9]+/).filter(Boolean);
  return tokens.includes(normalizedAlias);
}
