import type { StoredCredential } from "../types/index.js";

const BEARER_PROVIDERS = new Set([
  "github",
  "twitter",
  "x",
  "slack",
  "discord",
  "google",
  "moltbook",
  "openai",
  "stripe"
]);

export function buildAuthHeaders(provider: string, credential: StoredCredential): Record<string, string> {
  const authType = credential.metadata?.authType ?? inferDefaultAuthType(provider);

  if (authType === "api-key") {
    const headerName = credential.metadata?.headerName ?? "x-api-key";
    return {
      [headerName]: credential.secret
    };
  }

  if (authType === "bearer") {
    return {
      authorization: `Bearer ${credential.secret}`
    };
  }

  if (authType === "basic") {
    return {
      authorization: `Basic ${credential.secret}`
    };
  }

  // Safe fallback to bearer for unknown auth types.
  return {
    authorization: `Bearer ${credential.secret}`
  };
}

function inferDefaultAuthType(provider: string): "bearer" | "api-key" {
  const normalized = provider.toLowerCase();
  if (BEARER_PROVIDERS.has(normalized)) {
    return "bearer";
  }
  return "api-key";
}
