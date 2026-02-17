import crypto from "node:crypto";
import { ensureDir, ensureFile, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import type { ClauthConfig } from "./config.js";
import { ValidationError } from "./errors.js";

interface SkillTokenRecord {
  skillId: string;
  tokenHash: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

interface SkillTokenStore {
  tokens: SkillTokenRecord[];
}

const EMPTY_STORE: SkillTokenStore = { tokens: [] };

export class SkillAuthEngine {
  private readonly config: ClauthConfig;
  private store: SkillTokenStore = structuredClone(EMPTY_STORE);

  constructor(config: ClauthConfig) {
    this.config = config;
  }

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await ensureFile(paths.skillAuthFile, JSON.stringify(EMPTY_STORE, null, 2));
    this.store = await readJsonFile<SkillTokenStore>(paths.skillAuthFile, structuredClone(EMPTY_STORE));
  }

  public async reload(): Promise<void> {
    await this.load();
  }

  public async issue(skillId: string): Promise<{ skillId: string; token: string }> {
    const normalizedSkillId = normalizeSkillId(skillId);
    const token = crypto.randomBytes(32).toString("base64url");
    const tokenHash = this.hashToken(token);
    const now = new Date().toISOString();

    const existing = this.store.tokens.find((entry) => entry.skillId === normalizedSkillId);
    if (existing) {
      existing.tokenHash = tokenHash;
      existing.active = true;
      existing.updatedAt = now;
    } else {
      this.store.tokens.push({
        skillId: normalizedSkillId,
        tokenHash,
        active: true,
        createdAt: now,
        updatedAt: now
      });
    }

    await this.persist();
    return {
      skillId: normalizedSkillId,
      token
    };
  }

  public async revoke(skillId: string): Promise<boolean> {
    const normalizedSkillId = normalizeSkillId(skillId);
    const entry = this.store.tokens.find((record) => record.skillId === normalizedSkillId);
    if (!entry || !entry.active) {
      return false;
    }

    entry.active = false;
    entry.updatedAt = new Date().toISOString();
    await this.persist();
    return true;
  }

  public list(): Array<Omit<SkillTokenRecord, "tokenHash">> {
    return this.store.tokens.map(({ tokenHash, ...rest }) => ({ ...rest }));
  }

  public identify(token: string): string | null {
    const normalizedToken = token.trim();
    if (!normalizedToken) {
      return null;
    }

    for (const entry of this.store.tokens) {
      if (!entry.active) {
        continue;
      }
      if (this.tokenHashMatches(entry.tokenHash, normalizedToken)) {
        return entry.skillId;
      }
    }

    return null;
  }

  public verify(skillId: string, token: string): boolean {
    const normalizedSkillId = normalizeSkillId(skillId);
    const normalizedToken = token.trim();
    if (!normalizedToken) {
      return false;
    }
    const entry = this.store.tokens.find((record) => record.skillId === normalizedSkillId && record.active);
    if (!entry) {
      return false;
    }

    return this.tokenHashMatches(entry.tokenHash, normalizedToken);
  }

  private hashToken(token: string): string {
    const peppered = `${this.config.skillTokenSalt}:${token}`;
    return crypto.createHash("sha256").update(peppered, "utf8").digest("hex");
  }

  private tokenHashMatches(expectedHash: string, token: string): boolean {
    const incomingHash = this.hashToken(token);
    const expected = Buffer.from(expectedHash, "hex");
    const actual = Buffer.from(incomingHash, "hex");
    if (expected.length !== actual.length) {
      return false;
    }
    return crypto.timingSafeEqual(expected, actual);
  }

  private async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.skillAuthFile, this.store);
  }
}

function normalizeSkillId(skillId: string): string {
  const normalized = skillId.trim();
  if (!normalized) {
    throw new ValidationError("skillId is required.");
  }
  return normalized;
}
