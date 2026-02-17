import { ValidationError } from "../core/errors.js";
import type { StoredCredential } from "../types/index.js";

const DEFAULT_ALLOWED_HOSTS: Record<string, string[]> = {
  github: ["api.github.com"],
  openai: ["api.openai.com"],
  stripe: ["api.stripe.com"],
  twitter: ["api.twitter.com", "api.x.com"],
  x: ["api.x.com", "api.twitter.com"],
  slack: ["*.slack.com", "slack.com"],
  discord: ["discord.com", "*.discord.com", "discordapp.com", "*.discordapp.com"],
  google: ["*.googleapis.com", "accounts.google.com"],
  moltbook: ["api.moltbook.com", "moltbook.com"]
};

const ALLOW_UNKNOWN_PROVIDER_HOSTS = process.env.CLAUTH_ALLOW_UNKNOWN_PROVIDER_HOSTS === "1";

export function assertEndpointAllowed(provider: string, endpoint: string, credential: StoredCredential): void {
  const url = new URL(endpoint);
  const endpointHost = url.hostname.toLowerCase();

  const explicitHosts = parseAllowedHosts(credential.metadata?.allowedHosts);
  const defaultHosts = DEFAULT_ALLOWED_HOSTS[provider] ?? [];
  const allowedHosts = explicitHosts.length > 0 ? explicitHosts : defaultHosts;

  if (allowedHosts.length === 0 && ALLOW_UNKNOWN_PROVIDER_HOSTS) {
    return;
  }

  if (allowedHosts.length === 0) {
    throw new ValidationError(
      `No endpoint policy for provider '${provider}'. Set credential metadata allowedHosts (comma-separated host list).`
    );
  }

  const allowed = allowedHosts.some((pattern) => hostMatchesPattern(endpointHost, pattern));
  if (!allowed) {
    throw new ValidationError(
      `Endpoint host '${endpointHost}' is not allowed for provider '${provider}'. Allowed: ${allowedHosts.join(", ")}`
    );
  }
}

function parseAllowedHosts(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function hostMatchesPattern(host: string, pattern: string): boolean {
  const normalizedPattern = pattern.toLowerCase();
  if (normalizedPattern.startsWith("*.")) {
    const suffix = normalizedPattern.slice(2);
    return host === suffix || host.endsWith(`.${suffix}`);
  }
  return host === normalizedPattern;
}
