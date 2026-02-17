import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import { ensureDir, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import { AuditLogger } from "./audit.js";
import { ValidationError } from "./errors.js";
import { Vault } from "./vault.js";
import type { OAuthTokenSet } from "../types/index.js";

interface OAuthTokenStore {
  tokens: Record<string, OAuthTokenSet>;
}

interface OAuthTokenEnvelope {
  version: 1;
  cipher: "aes-256-gcm";
  iv: string;
  tag: string;
  ciphertext: string;
  updatedAt: string;
}

const EMPTY_STORE: OAuthTokenStore = { tokens: {} };
const EXPIRY_BUFFER_MS = 60_000;

export class OAuthRefresher {
  private store: OAuthTokenStore = structuredClone(EMPTY_STORE);
  private readonly vault: Vault;
  private readonly audit: AuditLogger;

  constructor(input: { vault: Vault; audit: AuditLogger }) {
    this.vault = input.vault;
    this.audit = input.audit;
  }

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    let parsed: unknown = null;
    try {
      const raw = await fs.readFile(paths.oauthTokensFile, "utf8");
      parsed = JSON.parse(raw) as unknown;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === "ENOENT") {
        this.store = structuredClone(EMPTY_STORE);
        return;
      }
      if (error instanceof SyntaxError) {
        throw new ValidationError("OAuth token store is invalid JSON.");
      }
      throw error;
    }

    if (!parsed) {
      this.store = structuredClone(EMPTY_STORE);
      return;
    }

    if (isOAuthTokenEnvelope(parsed)) {
      try {
        this.store = this.decryptEnvelope(parsed);
      } catch {
        throw new ValidationError("OAuth token store failed integrity validation.");
      }
      return;
    }

    if (isOAuthTokenStore(parsed)) {
      this.store = structuredClone(parsed);
      // Migrate legacy plaintext store to encrypted envelope at load.
      await this.persist();
      return;
    }

    throw new ValidationError("OAuth token store has unsupported format.");
  }

  public async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.oauthTokensFile, this.encryptStore());
  }

  public async registerToken(handle: string, tokenSet: OAuthTokenSet): Promise<void> {
    this.store.tokens[handle] = { ...tokenSet };
    await this.persist();
  }

  public getTokenSet(handle: string): OAuthTokenSet | undefined {
    const ts = this.store.tokens[handle];
    return ts ? { ...ts } : undefined;
  }

  public async removeToken(handle: string): Promise<void> {
    delete this.store.tokens[handle];
    await this.persist();
  }

  public isExpired(handle: string): boolean {
    const tokenSet = this.store.tokens[handle];
    if (!tokenSet) {
      return false;
    }
    return Date.now() >= Date.parse(tokenSet.expiresAt) - EXPIRY_BUFFER_MS;
  }

  public async refreshIfNeeded(handle: string): Promise<boolean> {
    const tokenSet = this.store.tokens[handle];
    if (!tokenSet) {
      return false;
    }
    if (!this.isExpired(handle)) {
      return false;
    }
    return this.forceRefresh(handle);
  }

  public async forceRefresh(handle: string): Promise<boolean> {
    const tokenSet = this.store.tokens[handle];
    if (!tokenSet) {
      return false;
    }

    try {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokenSet.refreshToken
      });
      if (tokenSet.clientId) {
        body.set("client_id", tokenSet.clientId);
      }
      if (tokenSet.clientSecret) {
        body.set("client_secret", tokenSet.clientSecret);
      }

      const response = await fetch(tokenSet.tokenUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: body.toString()
      });

      if (!response.ok) {
        await this.audit.append({
          ts: new Date().toISOString(),
          event: "credential.store",
          outcome: "oauth_refresh_failed",
          details: { handle, status: response.status }
        });
        return false;
      }

      const result = (await response.json()) as {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
      };

      const newExpiresAt = new Date(
        Date.now() + (result.expires_in ?? 3600) * 1000
      ).toISOString();

      tokenSet.accessToken = result.access_token;
      if (result.refresh_token) {
        tokenSet.refreshToken = result.refresh_token;
      }
      tokenSet.expiresAt = newExpiresAt;

      this.store.tokens[handle] = tokenSet;
      await this.persist();

      await this.vault.updateCredentialSecret(handle, result.access_token);

      await this.audit.append({
        ts: new Date().toISOString(),
        event: "credential.store",
        outcome: "oauth_refresh_ok",
        details: { handle, expiresAt: newExpiresAt }
      });

      return true;
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        event: "credential.store",
        outcome: "oauth_refresh_error",
        details: {
          handle,
          message: error instanceof Error ? error.message : String(error)
        }
      });
      return false;
    }
  }

  public listTokenHandles(): string[] {
    return Object.keys(this.store.tokens);
  }

  private encryptStore(): OAuthTokenEnvelope {
    const key = this.vault.getMasterKey().subarray(0, 32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const plaintext = Buffer.from(JSON.stringify(this.store), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      version: 1,
      cipher: "aes-256-gcm",
      iv: iv.toString("base64url"),
      tag: tag.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      updatedAt: new Date().toISOString()
    };
  }

  private decryptEnvelope(envelope: OAuthTokenEnvelope): OAuthTokenStore {
    if (envelope.version !== 1 || envelope.cipher !== "aes-256-gcm") {
      throw new ValidationError("OAuth token store envelope format is unsupported.");
    }

    const key = this.vault.getMasterKey().subarray(0, 32);
    const iv = Buffer.from(envelope.iv, "base64url");
    const tag = Buffer.from(envelope.tag, "base64url");
    const ciphertext = Buffer.from(envelope.ciphertext, "base64url");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const decoded = JSON.parse(plaintext.toString("utf8")) as unknown;

    if (!isOAuthTokenStore(decoded)) {
      throw new ValidationError("OAuth token store payload has invalid structure.");
    }
    return structuredClone(decoded);
  }
}

function isOAuthTokenStore(value: unknown): value is OAuthTokenStore {
  if (!value || typeof value !== "object") {
    return false;
  }
  const obj = value as Record<string, unknown>;
  if (!obj.tokens || typeof obj.tokens !== "object") {
    return false;
  }
  return true;
}

function isOAuthTokenEnvelope(value: unknown): value is OAuthTokenEnvelope {
  if (!value || typeof value !== "object") {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return (
    obj.version === 1 &&
    obj.cipher === "aes-256-gcm" &&
    typeof obj.iv === "string" &&
    typeof obj.tag === "string" &&
    typeof obj.ciphertext === "string"
  );
}
