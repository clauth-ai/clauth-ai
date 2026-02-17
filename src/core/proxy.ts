import { AuditLogger } from "./audit.js";
import { BehavioralFirewall } from "./firewall.js";
import { AccessDeniedError, ClauthError, ValidationError } from "./errors.js";
import { OAuthRefresher } from "./oauth-refresh.js";
import { ScopeEngine } from "./scopes.js";
import { Vault } from "./vault.js";
import { buildAuthHeaders } from "../providers/auth.js";
import { assertEndpointAllowed } from "../providers/policy.js";
import type { ProxyRequest, ProxyResponse, RequestContext } from "../types/index.js";

export class CredentialProxy {
  private readonly vault: Vault;
  private readonly scopeEngine: ScopeEngine;
  private readonly firewall: BehavioralFirewall;
  private readonly audit: AuditLogger;
  private readonly oauthRefresher?: OAuthRefresher;
  private readonly enforceHttps: boolean;

  constructor(input: {
    vault: Vault;
    scopeEngine: ScopeEngine;
    firewall: BehavioralFirewall;
    audit: AuditLogger;
    oauthRefresher?: OAuthRefresher;
    enforceHttps?: boolean;
  }) {
    this.vault = input.vault;
    this.scopeEngine = input.scopeEngine;
    this.firewall = input.firewall;
    this.audit = input.audit;
    this.oauthRefresher = input.oauthRefresher;
    this.enforceHttps = input.enforceHttps ?? true;
  }

  public async execute(req: ProxyRequest): Promise<ProxyResponse> {
    validateProxyRequest(req, this.enforceHttps);
    const provider = req.provider.trim().toLowerCase();
    const timestamp = Date.now();
    const context: RequestContext = {
      skillId: req.skillId,
      provider,
      scope: req.scope,
      endpoint: req.endpoint,
      method: req.method,
      timestamp
    };

    try {
      this.scopeEngine.authorize(context);
    } catch (error) {
      const fwDecision = await this.firewall.evaluate(context, { scopeDenied: true });
      await this.audit.append({
        ts: new Date(timestamp).toISOString(),
        event: "proxy.deny",
        skillId: req.skillId,
        provider,
        scope: req.scope,
        endpoint: req.endpoint,
        method: req.method,
        outcome: "scope_denied",
        details: {
          firewall: fwDecision
        }
      });

      if (error instanceof ClauthError) {
        throw error;
      }
      throw new AccessDeniedError("Scope denied.");
    }

    const firewallDecision = await this.firewall.evaluate(context);
    if (!firewallDecision.allowed) {
      await this.audit.append({
        ts: new Date(timestamp).toISOString(),
        event: "firewall.alert",
        skillId: req.skillId,
        provider,
        scope: req.scope,
        endpoint: req.endpoint,
        method: req.method,
        outcome: "blocked",
        details: { reasons: firewallDecision.reasons, severity: firewallDecision.severity }
      });
      throw new AccessDeniedError(`Firewall blocked request: ${firewallDecision.reasons.join("; ")}`);
    }

    const credential = await this.vault.getCredential(req.credentialHandle, provider);
    assertEndpointAllowed(provider, req.endpoint, credential);

    const authHeaders = buildAuthHeaders(provider, credential);
    const mergedHeaders = mergeHeaders(req.headers, authHeaders);

    const fetchOptions: RequestInit = {
      method: req.method.toUpperCase(),
      headers: mergedHeaders
    };

    if (req.body !== undefined && req.body !== null) {
      if (typeof req.body === "string") {
        fetchOptions.body = req.body;
      } else {
        fetchOptions.body = JSON.stringify(req.body);
      }
      if (!hasHeader(mergedHeaders, "content-type")) {
        (fetchOptions.headers as Record<string, string>)["content-type"] = "application/json";
      }
    }

    try {
      let response = await fetch(req.endpoint, fetchOptions);

      if (response.status === 401 && this.oauthRefresher) {
        let refreshed = await this.oauthRefresher.refreshIfNeeded(req.credentialHandle);
        if (!refreshed && this.oauthRefresher.getTokenSet(req.credentialHandle)) {
          refreshed = await this.oauthRefresher.forceRefresh(req.credentialHandle);
        }
        if (refreshed) {
          const refreshedCredential = await this.vault.getCredential(req.credentialHandle, provider);
          const refreshedAuthHeaders = buildAuthHeaders(provider, refreshedCredential);
          const refreshedMergedHeaders = mergeHeaders(req.headers, refreshedAuthHeaders);
          const retryOptions: RequestInit = {
            method: req.method.toUpperCase(),
            headers: refreshedMergedHeaders
          };
          if (req.body !== undefined && req.body !== null) {
            retryOptions.body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
            if (!hasHeader(refreshedMergedHeaders, "content-type")) {
              (retryOptions.headers as Record<string, string>)["content-type"] = "application/json";
            }
          }
          response = await fetch(req.endpoint, retryOptions);
        }
      }

      const responseHeaders = mapHeaders(response.headers);
      const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
      const body = await parseResponseBody(response, contentType);

      await this.audit.append({
        ts: new Date().toISOString(),
        event: "proxy.allow",
        skillId: req.skillId,
        provider,
        scope: req.scope,
        endpoint: req.endpoint,
        method: req.method,
        outcome: "ok",
        statusCode: response.status,
        details: {
          firewall: firewallDecision
        }
      });

      return {
        status: response.status,
        headers: responseHeaders,
        body
      };
    } catch (error) {
      await this.audit.append({
        ts: new Date().toISOString(),
        event: "proxy.error",
        skillId: req.skillId,
        provider,
        scope: req.scope,
        endpoint: req.endpoint,
        method: req.method,
        outcome: "error",
        details: {
          message: error instanceof Error ? error.message : String(error)
        }
      });
      throw new ClauthError("UPSTREAM_ERROR", "Failed to execute provider request", 502);
    }
  }
}

function validateProxyRequest(req: ProxyRequest, enforceHttps: boolean): void {
  if (!req.skillId || !req.provider || !req.credentialHandle || !req.scope || !req.endpoint || !req.method) {
    throw new ValidationError("skillId, provider, credentialHandle, scope, endpoint, and method are required.");
  }

  let url: URL;
  try {
    url = new URL(req.endpoint);
  } catch {
    throw new ValidationError("endpoint must be a valid URL.");
  }
  if (enforceHttps && url.protocol !== "https:") {
    throw new ValidationError("Only HTTPS endpoints are allowed. Set hardening.enforceHttps to false to allow HTTP.");
  }
}

function mergeHeaders(
  callerHeaders: Record<string, string> | undefined,
  authHeaders: Record<string, string>
): Record<string, string> {
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(callerHeaders ?? {})) {
    const lower = key.toLowerCase();
    if (lower === "authorization" || lower === "proxy-authorization") {
      continue;
    }
    sanitized[lower] = value;
  }

  for (const [key, value] of Object.entries(authHeaders)) {
    sanitized[key.toLowerCase()] = value;
  }

  return sanitized;
}

function hasHeader(headers: Record<string, string>, headerName: string): boolean {
  return Object.keys(headers).some((name) => name.toLowerCase() === headerName.toLowerCase());
}

function mapHeaders(headers: Headers): Record<string, string> {
  const output: Record<string, string> = {};
  headers.forEach((value, key) => {
    output[key.toLowerCase()] = value;
  });
  return output;
}

async function parseResponseBody(response: Response, contentType: string): Promise<unknown> {
  const text = await response.text();
  if (!text) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  return text;
}
