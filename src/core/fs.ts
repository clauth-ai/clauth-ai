import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

export interface ClauthPaths {
  homeDir: string;
  configFile: string;
  vaultFile: string;
  scopeFile: string;
  auditFile: string;
  firewallFile: string;
  skillAuthFile: string;
  sessionRevocationsFile: string;
  oauthTokensFile: string;
  advisoryStateFile: string;
  identityStateFile: string;
}

export function resolveClauthPaths(): ClauthPaths {
  const homeDir = process.env.CLAUTH_HOME ?? path.join(os.homedir(), ".clauth");
  return {
    homeDir,
    configFile: path.join(homeDir, "config.json"),
    vaultFile: path.join(homeDir, "vault.enc"),
    scopeFile: path.join(homeDir, "scopes.json"),
    auditFile: path.join(homeDir, "audit.ndjson"),
    firewallFile: path.join(homeDir, "firewall.json"),
    skillAuthFile: path.join(homeDir, "skill-auth.json"),
    sessionRevocationsFile: path.join(homeDir, "session-revocations.json"),
    oauthTokensFile: path.join(homeDir, "oauth-tokens.json"),
    advisoryStateFile: path.join(homeDir, "advisory-state.json"),
    identityStateFile: path.join(homeDir, "identity-state.json")
  };
}

export async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
}

export async function ensureFile(filePath: string, defaultContent: string): Promise<void> {
  try {
    await fs.access(filePath);
  } catch {
    await atomicWrite(filePath, defaultContent);
    await chmodSafe(filePath, 0o600);
  }
}

export async function chmodSafe(filePath: string, mode: number): Promise<void> {
  try {
    await fs.chmod(filePath, mode);
  } catch {
    // chmod can fail on some platforms/filesystems; not fatal for local dev.
  }
}

export async function atomicWrite(filePath: string, content: string): Promise<void> {
  const temp = `${filePath}.${randomUUID()}.tmp`;
  await fs.writeFile(temp, content, { encoding: "utf8", mode: 0o600 });
  await fs.rename(temp, filePath);
}

export async function readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === "ENOENT") {
      return fallback;
    }
    throw error;
  }
}

export async function writeJsonFileAtomic(filePath: string, value: unknown): Promise<void> {
  await atomicWrite(filePath, JSON.stringify(value, null, 2));
  await chmodSafe(filePath, 0o600);
}
