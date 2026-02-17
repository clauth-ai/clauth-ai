import { randomBytes } from "node:crypto";
import { DEFAULT_FIREWALL, DEFAULT_HOST, DEFAULT_KDF, DEFAULT_PORT } from "./constants.js";
import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";

export type TransportMode = "tcp" | "unix";

export interface ClauthConfig {
  transport: TransportMode;
  host: string;
  port: number;
  socketPath: string;
  skillTokenSalt: string;
  vaultSalt: string;
  kdf: {
    memory: number;
    parallelism: number;
    iterations: number;
    tagLength: number;
  };
  firewall: {
    minWarmupRequests: number;
    rateSpikeMultiplier: number;
    burstWindowMs: number;
    burstLimit: number;
    offHoursStart: number;
    offHoursEnd: number;
  };
  alertChannels: Array<{
    type: "webhook";
    url: string;
    minSeverity: "info" | "warning" | "critical";
  }>;
  advisoryFeeds: Array<{
    name: string;
    url: string;
    type: "github" | "custom";
  }>;
  advisoryPollIntervalMs: number;
  hardening: {
    enforceHttps: boolean;
    maxRequestBodyBytes: number;
    sessionTtlSeconds: number;
    challengeTtlSeconds: number;
    identityMaxVerifyAttempts: number;
    identityVerifyPerSkillPerMinute: number;
    identityVerifyPerIpPerMinute: number;
    requireAdminTokenForIdentity: boolean;
  };
}

const DEFAULT_ADVISORY_FEEDS: ClauthConfig["advisoryFeeds"] = [
  {
    name: "github",
    url: "https://api.github.com/advisories",
    type: "github"
  }
];

export const defaultConfig = (): ClauthConfig => ({
  transport: "tcp",
  host: DEFAULT_HOST,
  port: DEFAULT_PORT,
  socketPath: `${resolveClauthPaths().homeDir}/clauth.sock`,
  skillTokenSalt: randomBytes(16).toString("base64url"),
  vaultSalt: randomBytes(16).toString("base64url"),
  kdf: { ...DEFAULT_KDF },
  firewall: { ...DEFAULT_FIREWALL },
  alertChannels: [],
  advisoryFeeds: DEFAULT_ADVISORY_FEEDS.map((feed) => ({ ...feed })),
  advisoryPollIntervalMs: 3_600_000,
  hardening: {
    enforceHttps: true,
    maxRequestBodyBytes: 1_048_576,
    sessionTtlSeconds: 3600,
    challengeTtlSeconds: 600,
    identityMaxVerifyAttempts: 5,
    identityVerifyPerSkillPerMinute: 30,
    identityVerifyPerIpPerMinute: 60,
    requireAdminTokenForIdentity: false
  }
});

export async function loadConfig(): Promise<ClauthConfig> {
  const paths = resolveClauthPaths();
  await ensureDir(paths.homeDir);
  const defaults = defaultConfig();
  const loaded = await readJsonFile<Partial<ClauthConfig>>(paths.configFile, defaults);

  const transport: TransportMode = loaded.transport === "unix" ? "unix" : "tcp";
  const host = typeof loaded.host === "string" && loaded.host.trim() ? loaded.host : defaults.host;
  const port = typeof loaded.port === "number" && Number.isFinite(loaded.port) ? loaded.port : defaults.port;
  const socketPath =
    typeof loaded.socketPath === "string" && loaded.socketPath.trim() ? loaded.socketPath : defaults.socketPath;
  const skillTokenSalt =
    typeof loaded.skillTokenSalt === "string" && loaded.skillTokenSalt.trim()
      ? loaded.skillTokenSalt
      : defaults.skillTokenSalt;

  return {
    transport,
    host,
    port,
    socketPath,
    skillTokenSalt,
    vaultSalt:
      typeof loaded.vaultSalt === "string" && loaded.vaultSalt.trim() ? loaded.vaultSalt : defaults.vaultSalt,
    kdf: {
      ...defaults.kdf,
      ...(loaded.kdf ?? {})
    },
    firewall: {
      ...defaults.firewall,
      ...(loaded.firewall ?? {})
    },
    alertChannels: Array.isArray(loaded.alertChannels) ? loaded.alertChannels : defaults.alertChannels,
    advisoryFeeds: Array.isArray(loaded.advisoryFeeds) ? loaded.advisoryFeeds : defaults.advisoryFeeds,
    advisoryPollIntervalMs:
      typeof loaded.advisoryPollIntervalMs === "number" && loaded.advisoryPollIntervalMs > 0
        ? loaded.advisoryPollIntervalMs
        : defaults.advisoryPollIntervalMs,
    hardening: {
      ...defaults.hardening,
      ...(loaded.hardening && typeof loaded.hardening === "object" ? loaded.hardening : {})
    }
  };
}

export async function saveConfig(config: ClauthConfig): Promise<void> {
  const paths = resolveClauthPaths();
  await ensureDir(paths.homeDir);
  await writeJsonFileAtomic(paths.configFile, config);
}
