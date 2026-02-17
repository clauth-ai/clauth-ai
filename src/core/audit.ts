import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import { ensureDir, resolveClauthPaths } from "./fs.js";
import type { AuditEntry } from "../types/index.js";

type AuditPayload = Omit<AuditEntry, "prevHash" | "hash">;
const AUDIT_GENESIS = "GENESIS";
const AUDIT_LOCK_TIMEOUT_MS = 5000;
const AUDIT_LOCK_RETRY_MS = 20;

export class AuditLogger {
  private lastHash = AUDIT_GENESIS;
  private loaded = false;
  private appendQueue: Promise<void> = Promise.resolve();

  public async load(): Promise<void> {
    if (this.loaded) {
      return;
    }

    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);

    this.lastHash = await this.readLastHashFromDisk(paths.auditFile);

    this.loaded = true;
  }

  public async append(payload: AuditPayload): Promise<AuditEntry> {
    await this.load();

    let writtenEntry!: AuditEntry;

    this.appendQueue = this.appendQueue.catch(() => undefined).then(() =>
      this.withLock(async () => {
        const paths = resolveClauthPaths();
        await ensureDir(paths.homeDir);

        const prevHash = await this.readLastHashFromDisk(paths.auditFile);
        const entryData = {
          ...payload,
          prevHash
        };
        const canonical = JSON.stringify(entryData);
        const hash = crypto.createHash("sha256").update(canonical, "utf8").digest("hex");

        const entry: AuditEntry = {
          ...entryData,
          hash
        };

        await fs.appendFile(paths.auditFile, `${JSON.stringify(entry)}\n`, {
          encoding: "utf8",
          mode: 0o600
        });

        this.lastHash = hash;
        writtenEntry = entry;
      })
    );

    await this.appendQueue;
    return writtenEntry;
  }

  public async verifyIntegrity(): Promise<{ valid: boolean; brokenAtLine?: number; reason?: string }> {
    const paths = resolveClauthPaths();

    let raw = "";
    try {
      raw = await fs.readFile(paths.auditFile, "utf8");
    } catch {
      return { valid: true };
    }

    const lines = raw.split("\n").filter(Boolean);
    let lastHash = AUDIT_GENESIS;

    for (let index = 0; index < lines.length; index += 1) {
      const lineNo = index + 1;
      let parsed: AuditEntry;
      try {
        parsed = parseAuditLine(lines[index], lineNo);
      } catch {
        return {
          valid: false,
          brokenAtLine: lineNo,
          reason: "invalid_json"
        };
      }

      if (parsed.prevHash !== lastHash) {
        return {
          valid: false,
          brokenAtLine: lineNo,
          reason: "prevHash mismatch"
        };
      }

      const { hash, ...payload } = parsed;
      const expected = crypto.createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
      if (expected !== hash) {
        return {
          valid: false,
          brokenAtLine: lineNo,
          reason: "hash mismatch"
        };
      }

      lastHash = hash;
    }

    return { valid: true };
  }

  private async readLastHashFromDisk(auditFile: string): Promise<string> {
    try {
      const raw = await fs.readFile(auditFile, "utf8");
      const lines = raw.split("\n").filter(Boolean);
      if (lines.length === 0) {
        return AUDIT_GENESIS;
      }
      const last = parseAuditLine(lines[lines.length - 1], lines.length);
      return last.hash;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code === "ENOENT") {
        return AUDIT_GENESIS;
      }
      throw error;
    }
  }

  private async withLock<T>(work: () => Promise<T>): Promise<T> {
    const paths = resolveClauthPaths();
    const lockPath = `${paths.auditFile}.lock`;
    const handle = await acquireLock(lockPath);
    try {
      return await work();
    } finally {
      await handle.close().catch(() => undefined);
      await fs.unlink(lockPath).catch(() => undefined);
    }
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function acquireLock(lockPath: string): Promise<fs.FileHandle> {
  const startedAt = Date.now();
  while (true) {
    try {
      return await fs.open(lockPath, "wx", 0o600);
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (code !== "EEXIST") {
        throw error;
      }
      if (Date.now() - startedAt >= AUDIT_LOCK_TIMEOUT_MS) {
        throw new Error("Timed out waiting for audit log lock.");
      }
      await sleep(AUDIT_LOCK_RETRY_MS);
    }
  }
}

function parseAuditLine(line: string, lineNo: number): AuditEntry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line) as unknown;
  } catch {
    throw new Error(`Audit log line ${lineNo} is not valid JSON.`);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Audit log line ${lineNo} is not an object.`);
  }

  const entry = parsed as Partial<AuditEntry>;
  if (typeof entry.hash !== "string" || typeof entry.prevHash !== "string") {
    throw new Error(`Audit log line ${lineNo} is missing required hash fields.`);
  }

  return entry as AuditEntry;
}
