export const CLAUTH_VERSION = "0.1.0";
export const DEFAULT_PORT = 4317;
export const DEFAULT_HOST = "127.0.0.1";

export const DEFAULT_KDF = {
  memory: 64 * 1024,
  parallelism: 1,
  iterations: 3,
  tagLength: 32
};

export const DEFAULT_FIREWALL = {
  minWarmupRequests: 10,
  rateSpikeMultiplier: 3,
  burstWindowMs: 10_000,
  burstLimit: 20,
  offHoursStart: 1,
  offHoursEnd: 5
};

export const DEFAULT_GRANT_RATE_LIMIT = 60;
