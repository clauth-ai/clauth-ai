/**
 * Clauth client SDK for skill developers.
 *
 * Usage:
 *
 *   import { ClauthClient } from "clauth-ai/client";
 *
 *   const clauth = new ClauthClient();
 *
 *   const res = await clauth.fetch("github", "github-main", "github:read",
 *     "https://api.github.com/user"
 *   );
 *   console.log(res.status, res.body);
 *
 * Environment variables (auto-discovered):
 *   CLAUTH_DAEMON_URL   - daemon base URL (default: http://127.0.0.1:4317)
 *   CLAUTH_SKILL_ID     - this skill's identifier
 *   CLAUTH_SKILL_TOKEN  - issued skill token
 */

export interface ClauthClientOptions {
  /** Daemon base URL. Defaults to CLAUTH_DAEMON_URL or http://127.0.0.1:4317 */
  daemonUrl?: string;
  /** Skill identifier. Defaults to CLAUTH_SKILL_ID env var. */
  skillId?: string;
  /** Skill token. Defaults to CLAUTH_SKILL_TOKEN env var. */
  skillToken?: string;
}

export interface ClauthResponse<T = unknown> {
  /** HTTP status code from the upstream provider. */
  status: number;
  /** Response headers from the upstream provider. */
  headers: Record<string, string>;
  /** Parsed response body. */
  body: T;
}

export interface ClauthFetchOptions {
  /** HTTP method. Defaults to GET. */
  method?: string;
  /** Additional headers to forward (auth headers are stripped by the proxy). */
  headers?: Record<string, string>;
  /** Request body. Objects are JSON-serialized automatically. */
  body?: unknown;
}

export class ClauthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(code: string, message: string, statusCode: number) {
    super(message);
    this.name = "ClauthError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class ClauthClient {
  private readonly daemonUrl: string;
  private readonly skillId: string;
  private readonly skillToken: string;

  constructor(options?: ClauthClientOptions) {
    this.daemonUrl = strip(options?.daemonUrl ?? process.env.CLAUTH_DAEMON_URL ?? "http://127.0.0.1:4317", "/");
    this.skillId = options?.skillId ?? process.env.CLAUTH_SKILL_ID ?? "";
    this.skillToken = options?.skillToken ?? process.env.CLAUTH_SKILL_TOKEN ?? "";

    if (!this.skillId) {
      throw new ClauthError("CONFIG_ERROR", "skillId is required. Set CLAUTH_SKILL_ID or pass it in options.", 0);
    }
    if (!this.skillToken) {
      throw new ClauthError("CONFIG_ERROR", "skillToken is required. Set CLAUTH_SKILL_TOKEN or pass it in options.", 0);
    }
  }

  /**
   * Execute a brokered request through the clauth proxy.
   *
   * @param provider     - Provider name (e.g. "github", "slack")
   * @param credential   - Credential handle stored in the vault
   * @param scope        - Required scope (e.g. "github:read")
   * @param endpoint     - Full upstream URL
   * @param options      - Method, headers, body
   */
  async fetch<T = unknown>(
    provider: string,
    credential: string,
    scope: string,
    endpoint: string,
    options?: ClauthFetchOptions
  ): Promise<ClauthResponse<T>> {
    const payload = {
      skillId: this.skillId,
      provider,
      credentialHandle: credential,
      scope,
      endpoint,
      method: options?.method ?? "GET",
      headers: options?.headers,
      body: options?.body,
    };

    const response = await globalThis.fetch(`${this.daemonUrl}/clauth/v1/proxy`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-clauth-skill-token": this.skillToken,
      },
      body: JSON.stringify(payload),
    });

    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }

    if (!response.ok) {
      const err = parsed as { error?: { code?: string; message?: string } };
      throw new ClauthError(
        err?.error?.code ?? "PROXY_ERROR",
        err?.error?.message ?? `Proxy returned ${response.status}`,
        response.status
      );
    }

    const result = parsed as { status: number; headers: Record<string, string>; body: T };
    return {
      status: result.status,
      headers: result.headers,
      body: result.body,
    };
  }

  /**
   * Check if the daemon is reachable.
   */
  async health(): Promise<boolean> {
    try {
      const response = await globalThis.fetch(`${this.daemonUrl}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Get daemon status.
   */
  async status(): Promise<Record<string, unknown>> {
    const response = await globalThis.fetch(`${this.daemonUrl}/clauth/v1/status`);
    return (await response.json()) as Record<string, unknown>;
  }

  /**
   * Create an identity verification challenge.
   */
  async createIdentityChallenge(
    provider: string,
    accountId: string
  ): Promise<{ challengeId: string; challenge: string; expiresAt: string }> {
    const response = await globalThis.fetch(`${this.daemonUrl}/clauth/v1/identity/challenge`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-clauth-skill-token": this.skillToken,
      },
      body: JSON.stringify({ skillId: this.skillId, provider, accountId }),
    });

    const data = await response.json();
    if (!response.ok) {
      const err = data as { error?: { code?: string; message?: string } };
      throw new ClauthError(
        err?.error?.code ?? "IDENTITY_ERROR",
        err?.error?.message ?? `Challenge creation failed with ${response.status}`,
        response.status
      );
    }

    return data as { challengeId: string; challenge: string; expiresAt: string };
  }

  /**
   * Submit proof for an identity challenge.
   */
  async verifyIdentity(
    challengeId: string,
    proof: string
  ): Promise<{ status: string; verifiedAt?: string }> {
    const response = await globalThis.fetch(`${this.daemonUrl}/clauth/v1/identity/verify`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-clauth-skill-token": this.skillToken,
      },
      body: JSON.stringify({ skillId: this.skillId, challengeId, proof }),
    });

    const data = await response.json();
    if (!response.ok) {
      const err = data as { error?: { code?: string; message?: string } };
      throw new ClauthError(
        err?.error?.code ?? "IDENTITY_ERROR",
        err?.error?.message ?? `Verification failed with ${response.status}`,
        response.status
      );
    }

    return data as { status: string; verifiedAt?: string };
  }

  /**
   * Build a signed-challenge proof payload.
   */
  buildSignedChallengeProof(
    credentialHandle: string,
    challenge: string,
    accountId?: string
  ): string {
    return JSON.stringify({
      credentialHandle,
      challenge,
      ...(accountId ? { accountId } : {})
    });
  }

  /**
   * Get the status of an identity challenge.
   */
  async getIdentityStatus(
    challengeId: string
  ): Promise<{ status: string; verifiedAt?: string }> {
    const response = await globalThis.fetch(
      `${this.daemonUrl}/clauth/v1/identity/challenge/${encodeURIComponent(challengeId)}/status`,
      {
        headers: { "x-clauth-skill-token": this.skillToken },
      }
    );

    const data = await response.json();
    if (!response.ok) {
      const err = data as { error?: { code?: string; message?: string } };
      throw new ClauthError(
        err?.error?.code ?? "IDENTITY_ERROR",
        err?.error?.message ?? `Status check failed with ${response.status}`,
        response.status
      );
    }

    return data as { status: string; verifiedAt?: string };
  }

  /**
   * List verified identity proofs.
   */
  async listIdentityProofs(): Promise<Array<Record<string, unknown>>> {
    const response = await globalThis.fetch(
      `${this.daemonUrl}/clauth/v1/identity/proofs?skillId=${encodeURIComponent(this.skillId)}`,
      {
        headers: { "x-clauth-skill-token": this.skillToken },
      }
    );

    const data = await response.json();
    if (!response.ok) {
      const err = data as { error?: { code?: string; message?: string } };
      throw new ClauthError(
        err?.error?.code ?? "IDENTITY_ERROR",
        err?.error?.message ?? `List proofs failed with ${response.status}`,
        response.status
      );
    }

    return (data as { proofs: Array<Record<string, unknown>> }).proofs;
  }
}

function strip(value: string, suffix: string): string {
  return value.endsWith(suffix) ? value.slice(0, -suffix.length) : value;
}
