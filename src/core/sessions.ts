import crypto from "node:crypto";
import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import type { Vault } from "./vault.js";
import type { SessionClaims } from "../types/index.js";

const DEFAULT_TTL_SECONDS = 3600;
const HKDF_INFO = "clauth-session-v1";

interface SessionRevocationRecord {
  jti: string;
  revokedAt: string;
  expiresAt: number;
  reason?: string;
}

interface SessionRevocationStore {
  revoked: SessionRevocationRecord[];
}

const EMPTY_REVOCATION_STORE: SessionRevocationStore = { revoked: [] };

export class SessionEngine {
  private readonly vault: Vault;
  private readonly defaultTtlSeconds: number;
  private secretCache: Buffer | null = null;
  private revocationStore: SessionRevocationStore = structuredClone(EMPTY_REVOCATION_STORE);
  private revokedJtis: Set<string> = new Set();
  private loaded = false;
  private persistQueue: Promise<void> = Promise.resolve();

  constructor(vault: Vault, defaultTtlSeconds?: number) {
    this.vault = vault;
    this.defaultTtlSeconds = defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
  }

  public async load(): Promise<void> {
    if (this.loaded) {
      return;
    }

    await this.loadStore();
    this.loaded = true;
  }

  public async reload(): Promise<void> {
    await this.loadStore();
    this.loaded = true;
  }

  private async loadStore(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    this.revocationStore = await readJsonFile<SessionRevocationStore>(
      paths.sessionRevocationsFile,
      structuredClone(EMPTY_REVOCATION_STORE)
    );
    this.pruneExpired();
    this.rebuildRevocationIndex();
  }

  private getSecret(): Buffer {
    if (this.secretCache) {
      return this.secretCache;
    }
    const masterKey = this.vault.getMasterKey();
    this.secretCache = crypto.hkdfSync("sha256", masterKey, Buffer.alloc(0), HKDF_INFO, 32) as unknown as Buffer;
    if (!(this.secretCache instanceof Buffer)) {
      this.secretCache = Buffer.from(this.secretCache);
    }
    return this.secretCache;
  }

  public issue(claims: Pick<SessionClaims, "sub" | "scope">, ttlSeconds?: number): string {
    return this.issueWithMetadata(claims, ttlSeconds).token;
  }

  public issueWithMetadata(
    claims: Pick<SessionClaims, "sub" | "scope">,
    ttlSeconds?: number
  ): { token: string; jti: string; iat: number; exp: number } {
    const now = Math.floor(Date.now() / 1000);
    const ttl = ttlSeconds ?? this.defaultTtlSeconds;
    const jti = crypto.randomUUID();

    const payload: SessionClaims = {
      sub: claims.sub,
      iss: "clauth",
      iat: now,
      exp: now + ttl,
      jti,
      scope: claims.scope
    };

    const header = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = base64url(JSON.stringify(payload));
    const sigInput = `${header}.${body}`;
    const signature = this.sign(sigInput);

    return {
      token: `${sigInput}.${signature}`,
      jti,
      iat: now,
      exp: payload.exp
    };
  }

  public verify(token: string): SessionClaims | null {
    return this.verifyToken(token, { ignoreExpiry: false, ignoreRevocation: false });
  }

  public verifyAllowExpired(token: string): SessionClaims | null {
    return this.verifyToken(token, { ignoreExpiry: true, ignoreRevocation: true });
  }

  public async revokeJti(jti: string, expiresAt: number, reason?: string): Promise<boolean> {
    await this.load();
    const normalizedJti = jti.trim();
    if (!normalizedJti) {
      return false;
    }
    if (!Number.isFinite(expiresAt)) {
      return false;
    }
    if (this.revokedJtis.has(normalizedJti)) {
      return false;
    }

    this.revocationStore.revoked.push({
      jti: normalizedJti,
      revokedAt: new Date().toISOString(),
      expiresAt,
      reason
    });
    this.rebuildRevocationIndex();
    await this.persist();
    return true;
  }

  public async revokeToken(token: string, reason?: string): Promise<{
    revoked: boolean;
    jti?: string;
    expiresAt?: number;
  }> {
    const claims = this.verifyAllowExpired(token);
    if (!claims?.jti || typeof claims.exp !== "number") {
      return { revoked: false };
    }
    const revoked = await this.revokeJti(claims.jti, claims.exp, reason);
    return {
      revoked,
      jti: claims.jti,
      expiresAt: claims.exp
    };
  }

  public listRevocations(): SessionRevocationRecord[] {
    const now = Math.floor(Date.now() / 1000);
    return this.revocationStore.revoked
      .filter((entry) => entry.expiresAt > now)
      .map((entry) => ({ ...entry }));
  }

  private verifyToken(
    token: string,
    options: { ignoreExpiry: boolean; ignoreRevocation: boolean }
  ): SessionClaims | null {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return null;
    }

    const [header, body, signature] = parts;
    const sigInput = `${header}.${body}`;
    const expected = this.sign(sigInput);

    if (!timingSafeCompare(signature, expected)) {
      return null;
    }

    try {
      const headerObj = JSON.parse(base64urlDecode(header));
      if (headerObj.alg !== "HS256") {
        return null;
      }
    } catch {
      return null;
    }

    try {
      const claims = JSON.parse(base64urlDecode(body)) as SessionClaims;

      if (claims.iss !== "clauth") {
        return null;
      }

      const now = Math.floor(Date.now() / 1000);
      if (!options.ignoreExpiry && claims.exp <= now) {
        return null;
      }

      if (!options.ignoreRevocation && claims.jti && this.revokedJtis.has(claims.jti)) {
        return null;
      }

      return claims;
    } catch {
      return null;
    }
  }

  public invalidateCache(): void {
    if (this.secretCache) {
      this.secretCache.fill(0);
      this.secretCache = null;
    }
  }

  private async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    this.persistQueue = this.persistQueue.catch(() => undefined).then(async () => {
      this.pruneExpired();
      await writeJsonFileAtomic(paths.sessionRevocationsFile, this.revocationStore);
    });
    await this.persistQueue;
  }

  private pruneExpired(): void {
    const now = Math.floor(Date.now() / 1000);
    this.revocationStore.revoked = this.revocationStore.revoked.filter(
      (entry) => entry.expiresAt > now && entry.jti.trim()
    );
  }

  private rebuildRevocationIndex(): void {
    this.pruneExpired();
    this.revokedJtis = new Set(this.revocationStore.revoked.map((entry) => entry.jti));
  }

  private sign(input: string): string {
    const secret = this.getSecret();
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(input, "utf8");
    return hmac.digest("base64url");
  }
}

function base64url(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

function base64urlDecode(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

function timingSafeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
