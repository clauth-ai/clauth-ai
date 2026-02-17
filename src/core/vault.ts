import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import type { ClauthConfig } from "./config.js";
import { AccessDeniedError, NotFoundError, ValidationError } from "./errors.js";
import { atomicWrite, ensureDir, resolveClauthPaths } from "./fs.js";
import { deriveKey } from "./kdf.js";
import type { KdfDescriptor } from "./kdf.js";
import type { StoredCredential, VaultRecord } from "../types/index.js";

interface VaultEnvelope {
  version: 1;
  cipher: "aes-256-gcm";
  iv: string;
  tag: string;
  ciphertext: string;
  kdf: KdfDescriptor;
  updatedAt: string;
}

const EMPTY_RECORD: VaultRecord = { credentials: {} };

export class Vault {
  private readonly config: ClauthConfig;
  private unlocked = false;
  private key?: Buffer;
  private record: VaultRecord = structuredClone(EMPTY_RECORD);
  private activeKdf: KdfDescriptor;

  constructor(config: ClauthConfig) {
    this.config = config;
    this.activeKdf = resolveActiveKdf(undefined, config);
  }

  public isUnlocked(): boolean {
    return this.unlocked;
  }

  public async unlock(passphrase: string): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);

    let envelope: VaultEnvelope | undefined;
    try {
      const raw = await fs.readFile(paths.vaultFile, "utf8");
      envelope = JSON.parse(raw) as VaultEnvelope;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === "ENOENT") {
        envelope = undefined;
      } else if (error instanceof SyntaxError) {
        throw new ValidationError("Vault file contains invalid JSON.");
      } else {
        throw error;
      }
    }

    const kdf = resolveActiveKdf(envelope?.kdf, this.config);
    const salt = Buffer.from(kdf.salt, "base64url");
    const derived = deriveKey(passphrase, salt, kdf.params, kdf.algorithm);

    if (!envelope) {
      this.key = derived.key;
      this.record = structuredClone(EMPTY_RECORD);
      this.unlocked = true;
      this.activeKdf = {
        ...kdf,
        algorithm: derived.algorithm
      };
      await this.persist();
      return;
    }

    try {
      this.record = this.decryptEnvelope(envelope, derived.key);
      this.key = derived.key;
      this.unlocked = true;
      this.activeKdf = {
        ...kdf,
        algorithm: derived.algorithm
      };
      await this.pruneExpired();
    } catch (error) {
      derived.key.fill(0);
      if (error instanceof ValidationError) {
        throw error;
      }
      throw new AccessDeniedError("Failed to unlock vault. Check passphrase.");
    }
  }

  public async reload(): Promise<void> {
    this.assertUnlocked();

    const paths = resolveClauthPaths();
    let envelope: VaultEnvelope;
    try {
      const raw = await fs.readFile(paths.vaultFile, "utf8");
      envelope = JSON.parse(raw) as VaultEnvelope;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === "ENOENT") {
        this.record = structuredClone(EMPTY_RECORD);
        return;
      }
      if (error instanceof SyntaxError) {
        throw new ValidationError("Vault file contains invalid JSON.");
      }
      throw error;
    }

    this.record = this.decryptEnvelope(envelope, this.key!);
    this.activeKdf = resolveActiveKdf(envelope.kdf, this.config);
    await this.pruneExpired();
  }

  public lock(): void {
    if (this.key) {
      this.key.fill(0);
    }
    this.key = undefined;
    this.record = structuredClone(EMPTY_RECORD);
    this.unlocked = false;
  }

  public async storeCredential(input: {
    handle: string;
    provider: string;
    secret: string;
    ttlSeconds?: number;
    metadata?: Record<string, string>;
  }): Promise<StoredCredential> {
    this.assertUnlocked();
    if (!input.handle || !input.provider || !input.secret) {
      throw new ValidationError("handle, provider, and secret are required.");
    }

    const provider = input.provider.trim().toLowerCase();
    const handle = input.handle.trim();
    if (!provider || !handle) {
      throw new ValidationError("handle and provider cannot be empty.");
    }

    const now = new Date();
    const expiresAt =
      typeof input.ttlSeconds === "number" && input.ttlSeconds > 0
        ? new Date(now.getTime() + input.ttlSeconds * 1000).toISOString()
        : undefined;

    const cred: StoredCredential = {
      handle,
      provider,
      secret: input.secret,
      createdAt: now.toISOString(),
      expiresAt,
      metadata: input.metadata
    };

    this.record.credentials[handle] = cred;
    await this.persist();
    return { ...cred };
  }

  public async deleteCredential(handle: string): Promise<void> {
    this.assertUnlocked();
    const normalizedHandle = handle.trim();
    if (!this.record.credentials[normalizedHandle]) {
      throw new NotFoundError(`Credential handle '${normalizedHandle}' does not exist.`);
    }
    delete this.record.credentials[normalizedHandle];
    await this.persist();
  }

  public async getCredential(handle: string, provider?: string): Promise<StoredCredential> {
    this.assertUnlocked();
    const normalizedHandle = handle.trim();
    const credential = this.record.credentials[normalizedHandle];
    if (!credential) {
      throw new NotFoundError(`Credential handle '${normalizedHandle}' not found.`);
    }

    if (credential.expiresAt && Date.parse(credential.expiresAt) <= Date.now()) {
      delete this.record.credentials[normalizedHandle];
      await this.persist();
      throw new NotFoundError(`Credential handle '${normalizedHandle}' has expired.`);
    }

    if (provider && credential.provider !== provider.trim().toLowerCase()) {
      throw new AccessDeniedError(`Credential handle '${handle}' does not match provider '${provider}'.`);
    }

    return { ...credential };
  }

  public async updateCredentialSecret(handle: string, newSecret: string): Promise<StoredCredential> {
    this.assertUnlocked();
    const normalizedHandle = handle.trim();
    const credential = this.record.credentials[normalizedHandle];
    if (!credential) {
      throw new NotFoundError(`Credential handle '${normalizedHandle}' not found.`);
    }
    credential.secret = newSecret;
    await this.persist();
    return { ...credential };
  }

  public getMasterKey(): Buffer {
    this.assertUnlocked();
    return this.key!;
  }

  public async listCredentialMetadata(): Promise<Array<Omit<StoredCredential, "secret">>> {
    this.assertUnlocked();
    await this.pruneExpired();
    return Object.values(this.record.credentials).map(({ secret, ...meta }) => ({ ...meta }));
  }

  private async pruneExpired(): Promise<void> {
    let mutated = false;
    for (const [handle, credential] of Object.entries(this.record.credentials)) {
      if (credential.expiresAt && Date.parse(credential.expiresAt) <= Date.now()) {
        delete this.record.credentials[handle];
        mutated = true;
      }
    }

    if (mutated) {
      await this.persist();
    }
  }

  private encryptRecord(): VaultEnvelope {
    if (!this.key) {
      throw new AccessDeniedError("Vault is locked.");
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key.subarray(0, 32), iv);
    const plaintext = Buffer.from(JSON.stringify(this.record), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
      version: 1,
      cipher: "aes-256-gcm",
      iv: iv.toString("base64url"),
      tag: tag.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      kdf: {
        algorithm: this.activeKdf.algorithm,
        params: this.activeKdf.params,
        salt: this.activeKdf.salt
      },
      updatedAt: new Date().toISOString()
    };
  }

  private decryptEnvelope(envelope: VaultEnvelope, key: Buffer): VaultRecord {
    if (envelope.version !== 1 || envelope.cipher !== "aes-256-gcm") {
      throw new ValidationError("Unsupported vault format.");
    }

    const iv = Buffer.from(envelope.iv, "base64url");
    const tag = Buffer.from(envelope.tag, "base64url");
    const ciphertext = Buffer.from(envelope.ciphertext, "base64url");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key.subarray(0, 32), iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    const decoded = JSON.parse(plaintext.toString("utf8")) as VaultRecord;
    if (!decoded.credentials || typeof decoded.credentials !== "object") {
      throw new ValidationError("Invalid vault payload.");
    }

    return decoded;
  }

  private async persist(): Promise<void> {
    this.assertUnlocked();
    const path = resolveClauthPaths().vaultFile;
    const envelope = this.encryptRecord();
    await atomicWrite(path, JSON.stringify(envelope, null, 2));
  }

  private assertUnlocked(): void {
    if (!this.unlocked || !this.key) {
      throw new AccessDeniedError("Vault is locked.");
    }
  }
}

function resolveActiveKdf(
  descriptor: KdfDescriptor | undefined,
  config: ClauthConfig
): KdfDescriptor {
  const argon2Available = typeof (crypto as unknown as { argon2Sync?: Function }).argon2Sync === "function";
  const algorithm = descriptor
    ? descriptor.algorithm
    : argon2Available
      ? "argon2id"
      : "scrypt";
  const salt =
    typeof descriptor?.salt === "string" && descriptor.salt.trim()
      ? descriptor.salt
      : config.vaultSalt;
  const params = descriptor?.params
    ? {
        ...config.kdf,
        ...descriptor.params
      }
    : { ...config.kdf };

  return {
    algorithm,
    params,
    salt
  };
}
