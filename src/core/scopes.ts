import { DEFAULT_GRANT_RATE_LIMIT } from "./constants.js";
import { AccessDeniedError, NotFoundError, ValidationError } from "./errors.js";
import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import type { RequestContext, ScopeGrant } from "../types/index.js";

interface ScopeStore {
  grants: ScopeGrant[];
}

const EMPTY_SCOPE_STORE: ScopeStore = { grants: [] };

function normalizeScope(scope: string): string {
  return scope.trim().toLowerCase();
}

function splitScope(scope: string): [string, string] {
  const [provider, action] = normalizeScope(scope).split(":");
  if (!provider || !action) {
    throw new ValidationError("Scope must follow provider:action format.");
  }
  return [provider, action];
}

function matchScope(grantScope: string, requestedScope: string): boolean {
  const [gProvider, gAction] = splitScope(grantScope);
  const [rProvider, rAction] = splitScope(requestedScope);

  const providerMatch = gProvider === "*" || gProvider === rProvider;
  const actionMatch = gAction === "*" || gAction === rAction;

  return providerMatch && actionMatch;
}

export class ScopeEngine {
  private store: ScopeStore = structuredClone(EMPTY_SCOPE_STORE);
  private readonly requestTimestamps = new Map<string, number[]>();

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    this.store = await readJsonFile<ScopeStore>(paths.scopeFile, structuredClone(EMPTY_SCOPE_STORE));
  }

  public async reload(): Promise<void> {
    await this.load();
  }

  public async grant(input: {
    skillId: string;
    provider: string;
    scope: string;
    rateLimitPerMinute?: number;
  }): Promise<ScopeGrant> {
    const now = new Date().toISOString();
    if (!input.skillId.trim()) {
      throw new ValidationError("skillId is required.");
    }

    const normalizedProvider = input.provider.trim().toLowerCase();
    if (!normalizedProvider) {
      throw new ValidationError("provider is required.");
    }

    const normalizedScope = normalizeScope(input.scope);
    const [scopeProvider] = splitScope(normalizedScope);
    if (scopeProvider !== "*" && scopeProvider !== normalizedProvider) {
      throw new ValidationError("Scope provider must match provider or wildcard.");
    }

    const existing = this.store.grants.find(
      (grant) =>
        grant.skillId === input.skillId && grant.provider === normalizedProvider && grant.scope === normalizedScope
    );

    if (existing) {
      existing.active = true;
      existing.rateLimitPerMinute = input.rateLimitPerMinute ?? existing.rateLimitPerMinute;
      existing.updatedAt = now;
      await this.persist();
      return { ...existing };
    }

    const grant: ScopeGrant = {
      skillId: input.skillId,
      provider: normalizedProvider,
      scope: normalizedScope,
      rateLimitPerMinute: input.rateLimitPerMinute ?? DEFAULT_GRANT_RATE_LIMIT,
      active: true,
      createdAt: now,
      updatedAt: now
    };

    this.store.grants.push(grant);
    await this.persist();
    return { ...grant };
  }

  public async revoke(input: { skillId: string; provider?: string; scope?: string }): Promise<number> {
    const { skillId, scope } = input;
    const provider = input.provider?.trim().toLowerCase();
    let revoked = 0;

    for (const grant of this.store.grants) {
      if (grant.skillId !== skillId) {
        continue;
      }
      if (provider && grant.provider !== provider) {
        continue;
      }
      if (scope && grant.scope !== normalizeScope(scope)) {
        continue;
      }
      if (grant.active) {
        grant.active = false;
        grant.updatedAt = new Date().toISOString();
        revoked += 1;
      }
    }

    if (revoked === 0) {
      throw new NotFoundError("No matching active grant found.");
    }

    await this.persist();
    return revoked;
  }

  public async emergencyRevokeAll(): Promise<number> {
    let revoked = 0;
    for (const grant of this.store.grants) {
      if (grant.active) {
        grant.active = false;
        grant.updatedAt = new Date().toISOString();
        revoked += 1;
      }
    }

    if (revoked > 0) {
      await this.persist();
    }
    return revoked;
  }

  public listGrants(filter?: { skillId?: string; activeOnly?: boolean }): ScopeGrant[] {
    return this.store.grants
      .filter((grant) => {
        if (filter?.skillId && grant.skillId !== filter.skillId) {
          return false;
        }
        if (filter?.activeOnly && !grant.active) {
          return false;
        }
        return true;
      })
      .map((grant) => ({ ...grant }));
  }

  public authorize(context: RequestContext): { grant: ScopeGrant; remaining: number } {
    const requestedScope = normalizeScope(context.scope);
    const requestedProvider = context.provider.trim().toLowerCase();

    const candidates = this.store.grants.filter(
      (grant) =>
        grant.active &&
        grant.skillId === context.skillId &&
        grant.provider === requestedProvider &&
        matchScope(grant.scope, requestedScope)
    );

    if (candidates.length === 0) {
      throw new AccessDeniedError(
        `No active grant for skill '${context.skillId}' provider '${context.provider}' scope '${requestedScope}'.`
      );
    }

    // Prefer most specific scope (fewest wildcards).
    candidates.sort((a, b) => wildcardCount(a.scope) - wildcardCount(b.scope));
    const selected = candidates[0];

    const key = `${context.skillId}|${selected.provider}|${selected.scope}`;
    const now = context.timestamp;
    const cutoff = now - 60_000;
    const timestamps = this.requestTimestamps.get(key) ?? [];
    const recent = timestamps.filter((ts) => ts >= cutoff);

    if (recent.length >= selected.rateLimitPerMinute) {
      throw new AccessDeniedError(
        `Rate limit exceeded for skill '${context.skillId}' (${selected.rateLimitPerMinute}/min).`
      );
    }

    recent.push(now);
    this.requestTimestamps.set(key, recent);

    return {
      grant: { ...selected },
      remaining: Math.max(0, selected.rateLimitPerMinute - recent.length)
    };
  }

  private async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.scopeFile, this.store);
  }
}

function wildcardCount(scope: string): number {
  return scope.split("").filter((char) => char === "*").length;
}
