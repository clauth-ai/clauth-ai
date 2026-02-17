import http from "node:http";
import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { URL, fileURLToPath } from "node:url";
import { ClauthError } from "../core/errors.js";
import { CLAUTH_VERSION } from "../core/constants.js";
import type { ProxyRequest, Capabilities } from "../types/index.js";
import type { ClauthRuntime } from "./runtime.js";
import { renderDashboardHtml } from "./dashboard.js";

export interface ListenOverride {
  transport?: "tcp" | "unix";
  host?: string;
  port?: number;
  socketPath?: string;
}

export function createClauthServer(runtime: ClauthRuntime): http.Server {
  const capabilities: Capabilities = {
    product: "clauth",
    version: CLAUTH_VERSION,
    brokeredExecution: true,
    endpointPolicyEnforced: true,
    transport: runtime.config.transport,
    requireSkillToken: true,
    supportsIdentityBroker: true,
    supportedProofMethods: ["signed-challenge", "oauth", "email"]
  };

  const maxBodyBytes = runtime.config.hardening.maxRequestBodyBytes;
  const identityVerifyRateLimiter = createIdentityVerifyRateLimiter(runtime);

  runtime.firewall.setAlertRouter(runtime.alertRouter);

  if (runtime.config.advisoryFeeds.length > 0) {
    runtime.advisoryMonitor.startPolling(
      runtime.config.advisoryPollIntervalMs,
      runtime.config.advisoryFeeds
    );
  }

  return http.createServer(async (req, res) => {
    const method = req.method ?? "GET";
    const requestUrl = new URL(req.url ?? "/", "http://localhost");

    try {
      assertLocalRequest(req, runtime);

      if (method === "GET" && requestUrl.pathname === "/health") {
        return json(res, 200, { ok: true, service: "clauth", version: CLAUTH_VERSION });
      }

      if (method === "GET" && (requestUrl.pathname === "/" || requestUrl.pathname === "/dashboard")) {
        return html(res, 200, renderDashboardHtml());
      }

      if (method === "GET" && STATIC_FILES[requestUrl.pathname]) {
        return serveStatic(res, requestUrl.pathname);
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/capabilities") {
        return json(res, 200, capabilities);
      }

      if (requestUrl.pathname.startsWith("/clauth/v1/") && requestUrl.pathname !== "/clauth/v1/capabilities") {
        await refreshRuntimeState(runtime);
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/status") {
        const integrity = await runtime.audit.verifyIntegrity();
        return json(res, 200, {
          vaultUnlocked: runtime.vault.isUnlocked(),
          transport: runtime.config.transport,
          daemon:
            runtime.config.transport === "unix"
              ? `unix://${runtime.config.socketPath}`
              : `http://${runtime.config.host}:${runtime.config.port}`,
          requireSkillToken: true,
          activeSkillTokens: runtime.skillAuth.list().filter((entry) => entry.active).length,
          activeGrants: runtime.scopes.listGrants({ activeOnly: true }).length,
          auditIntegrity: integrity
        });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/proxy") {
        const payload = (await parseJsonBody(req, maxBodyBytes)) as Partial<ProxyRequest>;
        const principal = await requireSkillPrincipal(req, runtime, payload.skillId);
        const response = await runtime.proxy.execute({
          ...payload,
          skillId: principal.skillId
        } as ProxyRequest);
        return json(res, 200, response);
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/emergency-revoke") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const revoked = await runtime.scopes.emergencyRevokeAll();
        await runtime.audit.append({
          ts: new Date().toISOString(),
          event: "grant.emergency_revoke",
          outcome: "ok",
          details: { revoked }
        });
        return json(res, 200, { revoked });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/admin/skill-token/issue") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const payload = (await parseJsonBody(req, maxBodyBytes)) as { skillId?: string };
        if (!payload.skillId || !payload.skillId.trim()) {
          throw new ClauthError("VALIDATION_ERROR", "skillId is required", 422);
        }

        const issued = await runtime.skillAuth.issue(payload.skillId);
        await runtime.audit.append({
          ts: new Date().toISOString(),
          event: "skill_token.issue",
          skillId: issued.skillId,
          outcome: "ok"
        });
        return json(res, 200, {
          skillId: issued.skillId,
          token: issued.token
        });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/admin/skill-token/revoke") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const payload = (await parseJsonBody(req, maxBodyBytes)) as { skillId?: string };
        if (!payload.skillId || !payload.skillId.trim()) {
          throw new ClauthError("VALIDATION_ERROR", "skillId is required", 422);
        }

        const revoked = await runtime.skillAuth.revoke(payload.skillId);
        await runtime.audit.append({
          ts: new Date().toISOString(),
          event: "skill_token.revoke",
          skillId: payload.skillId,
          outcome: revoked ? "ok" : "not_found"
        });
        return json(res, 200, {
          skillId: payload.skillId,
          revoked
        });
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/admin/skill-token/list") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        return json(res, 200, {
          tokens: runtime.skillAuth.list()
        });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/admin/session-token/issue") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const payload = (await parseJsonBody(req, maxBodyBytes)) as {
          skillId?: string;
          scope?: string;
          ttlSeconds?: number;
        };
        if (!payload.skillId || !payload.skillId.trim()) {
          throw new ClauthError("VALIDATION_ERROR", "skillId is required", 422);
        }

        const issued = runtime.sessions.issueWithMetadata(
          {
            sub: payload.skillId.trim(),
            ...(payload.scope && payload.scope.trim() ? { scope: payload.scope.trim() } : {})
          },
          payload.ttlSeconds
        );

        await runtime.audit.append({
          ts: new Date().toISOString(),
          event: "session_token.issue",
          skillId: payload.skillId.trim(),
          outcome: "ok",
          details: {
            jti: issued.jti,
            iat: issued.iat,
            exp: issued.exp
          }
        });

        return json(res, 200, {
          skillId: payload.skillId.trim(),
          token: issued.token,
          jti: issued.jti,
          issuedAt: new Date(issued.iat * 1000).toISOString(),
          expiresAt: new Date(issued.exp * 1000).toISOString()
        });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/admin/session-token/revoke") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const payload = (await parseJsonBody(req, maxBodyBytes)) as {
          token?: string;
          jti?: string;
          exp?: number;
        };

        const token = payload.token?.trim();
        const jti = payload.jti?.trim();
        if (!token && !jti) {
          throw new ClauthError("VALIDATION_ERROR", "token or jti is required", 422);
        }

        let revoked = false;
        let revokedJti: string | undefined;
        let expiresAt: number | undefined;

        if (token) {
          const result = await runtime.sessions.revokeToken(token, "admin-api");
          revoked = result.revoked;
          revokedJti = result.jti;
          expiresAt = result.expiresAt;
        } else if (jti) {
          expiresAt =
            typeof payload.exp === "number" && Number.isFinite(payload.exp)
              ? payload.exp
              : Math.floor(Date.now() / 1000) + runtime.config.hardening.sessionTtlSeconds;
          revoked = await runtime.sessions.revokeJti(jti, expiresAt, "admin-api");
          revokedJti = jti;
        }

        await runtime.audit.append({
          ts: new Date().toISOString(),
          event: "session_token.revoke",
          outcome: revoked ? "ok" : "not_found",
          details: {
            jti: revokedJti,
            exp: expiresAt
          }
        });

        return json(res, 200, {
          revoked,
          jti: revokedJti,
          expiresAt: typeof expiresAt === "number" ? new Date(expiresAt * 1000).toISOString() : undefined
        });
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/admin/session-token/revocations") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        return json(res, 200, {
          revocations: runtime.sessions.listRevocations()
        });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/admin/alerts/test") {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const payload = (await parseJsonBody(req, maxBodyBytes)) as { url?: string };
        if (!payload.url) {
          throw new ClauthError("VALIDATION_ERROR", "url is required", 422);
        }
        const ok = await runtime.alertRouter.testWebhook(payload.url);
        return json(res, 200, { ok, url: payload.url });
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/identity/challenge") {
        const payload = (await parseJsonBody(req, maxBodyBytes)) as {
          provider?: string;
          accountId?: string;
          skillId?: string;
          method?: string;
        };
        const access = await resolveIdentityAccess(req, runtime, payload.skillId);
        if (!payload.provider || !payload.accountId) {
          throw new ClauthError("VALIDATION_ERROR", "provider and accountId are required", 422);
        }
        const method = parseProofMethod(payload.method);
        const skillId = access.isAdmin ? access.skillId ?? "admin" : access.skillId;
        if (!skillId) {
          throw new ClauthError("VALIDATION_ERROR", "skillId is required for identity challenge", 422);
        }
        const challenge = await runtime.identityBroker.createChallenge({
          skillId,
          provider: payload.provider,
          accountId: payload.accountId,
          method
        });
        const responseBody: Record<string, unknown> = {
          challengeId: challenge.id,
          expiresAt: challenge.expiresAt
        };
        if (method === "email") {
          responseBody.delivery = "webhook";
        } else {
          responseBody.challenge = challenge.challenge;
        }
        if (method === "oauth") {
          const oauthUrl = runtime.identityBroker.generateOAuthUrl(challenge.id);
          if (oauthUrl) {
            responseBody.oauthUrl = oauthUrl;
          }
        }
        return json(res, 200, responseBody);
      }

      if (method === "POST" && requestUrl.pathname === "/clauth/v1/identity/verify") {
        const payload = (await parseJsonBody(req, maxBodyBytes)) as {
          challengeId?: string;
          proof?: string;
          skillId?: string;
        };
        const access = await resolveIdentityAccess(req, runtime, payload.skillId);
        await enforceIdentityVerifyRateLimits(req, runtime, access, identityVerifyRateLimiter);
        if (!payload.challengeId || !payload.proof) {
          throw new ClauthError("VALIDATION_ERROR", "challengeId and proof are required", 422);
        }
        const result = await runtime.identityBroker.verifyChallenge(payload.challengeId, payload.proof, {
          requesterSkillId: access.skillId,
          allowAnySkill: access.isAdmin
        });
        return json(res, 200, result);
      }

      if (method === "GET" && requestUrl.pathname.startsWith("/clauth/v1/identity/challenge/") && requestUrl.pathname.endsWith("/status")) {
        const access = await resolveIdentityAccess(req, runtime);
        const parts = requestUrl.pathname.split("/");
        const challengeId = parts[5];
        if (!challengeId) {
          throw new ClauthError("VALIDATION_ERROR", "challengeId is required", 422);
        }
        const challenge = runtime.identityBroker.getChallengeForSkill(challengeId, {
          requesterSkillId: access.skillId,
          allowAnySkill: access.isAdmin
        });
        if (!challenge) {
          throw new ClauthError("NOT_FOUND", "Challenge not found", 404);
        }
        return json(res, 200, { status: challenge.status, verifiedAt: challenge.verifiedAt });
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/identity/proofs") {
        const requestedSkillId = requestUrl.searchParams.get("skillId") ?? undefined;
        const access = await resolveIdentityAccess(req, runtime, requestedSkillId);
        const proofs = runtime.identityBroker.listProofs(access.skillId);
        return json(res, 200, { proofs });
      }

      if (method === "GET" && requestUrl.pathname === "/clauth/v1/identity/oauth/callback") {
        const state = requestUrl.searchParams.get("state") ?? "";
        const code = requestUrl.searchParams.get("code") ?? "";
        if (!state || !code) {
          throw new ClauthError("VALIDATION_ERROR", "state and code are required", 422);
        }
        const result = await runtime.identityBroker.completeOAuthCallback(state, code);
        const statusMessage = result.status === "verified"
          ? "Identity verified successfully. You may close this window."
          : `Verification ${result.status}. Please try again or contact support.`;
        return html(res, result.status === "verified" ? 200 : 400, `<!doctype html>
<html><head><meta charset="utf-8"><title>Clauth OAuth Verification</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0a0e17;color:#e2e8f0;}
.card{text-align:center;padding:40px;border-radius:12px;border:1px solid #1e293b;background:#111827;max-width:400px;}
h1{font-size:20px;margin-bottom:12px;}p{color:#94a3b8;font-size:14px;}</style>
</head><body><div class="card"><h1>${result.status === "verified" ? "Verified" : "Failed"}</h1><p>${statusMessage}</p></div></body></html>`);
      }

      if (method === "DELETE" && requestUrl.pathname.startsWith("/clauth/v1/admin/identity/proofs/")) {
        assertAdminToken(req.headers["x-clauth-admin-token"]);
        const proofId = requestUrl.pathname.split("/").pop();
        if (!proofId) {
          throw new ClauthError("VALIDATION_ERROR", "proofId is required", 422);
        }
        const revoked = await runtime.identityBroker.revokeProof(proofId);
        return json(res, 200, { revoked });
      }

      return json(res, 404, {
        error: {
          code: "NOT_FOUND",
          message: "Route not found"
        }
      });
    } catch (error) {
      if (error instanceof ClauthError) {
        return json(res, error.statusCode, {
          error: {
            code: error.code,
            message: error.message
          }
        });
      }

      return json(res, 500, {
        error: {
          code: "INTERNAL_ERROR",
          message: error instanceof Error ? error.message : String(error)
        }
      });
    }
  });
}

export async function listenClauthServer(
  server: http.Server,
  runtime: ClauthRuntime,
  override?: ListenOverride
): Promise<{ endpoint: string; address: string }> {
  const transport = override?.transport ?? runtime.config.transport;
  const host = override?.host ?? runtime.config.host;
  const port = override?.port ?? runtime.config.port;
  const socketPath = override?.socketPath ?? runtime.config.socketPath;

  if (transport === "unix") {
    await fs.unlink(socketPath).catch((error: unknown) => {
      if ((error as { code?: string }).code !== "ENOENT") {
        throw error;
      }
    });
  }

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);

    if (transport === "unix") {
      server.listen(socketPath, () => onListening());
      return;
    }

    server.listen(port, host, () => onListening());
  });

  if (transport === "unix") {
    await fs.chmod(socketPath, 0o600).catch(() => {
      // Not fatal on filesystems that do not support chmod.
    });
    return {
      endpoint: `unix://${socketPath}`,
      address: socketPath
    };
  }

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new ClauthError("INTERNAL_ERROR", "Failed to resolve listening address", 500);
  }
  return {
    endpoint: `http://${host}:${address.port}`,
    address: `${host}:${address.port}`
  };
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload)
  });
  res.end(payload);
}

function html(res: http.ServerResponse, status: number, body: string): void {
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(body)
  });
  res.end(body);
}

async function parseJsonBody(req: http.IncomingMessage, maxBytes?: number): Promise<unknown> {
  const limit = maxBytes ?? 1_048_576;
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buf.length;
    if (totalBytes > limit) {
      throw new ClauthError("VALIDATION_ERROR", `Request body exceeds maximum size of ${limit} bytes`, 413);
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    return {};
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new ClauthError("INVALID_JSON", "Request body must be valid JSON", 422);
  }
}

export interface SkillPrincipal {
  skillId: string;
  method: "jwt" | "skill-token";
}

export interface IdentityAccess {
  isAdmin: boolean;
  skillId?: string;
}

interface IdentityVerifyRateLimiter {
  readonly windowMs: number;
  readonly perSkillLimit: number;
  readonly perIpLimit: number;
  readonly skillBuckets: Map<string, number[]>;
  readonly ipBuckets: Map<string, number[]>;
}

export async function requireSkillPrincipal(
  req: http.IncomingMessage,
  runtime: ClauthRuntime,
  expectedSkillId?: string
): Promise<SkillPrincipal> {
  const expected = expectedSkillId?.trim() ? expectedSkillId.trim() : undefined;
  if (expectedSkillId !== undefined && !expected) {
    throw new ClauthError("UNAUTHORIZED", "skillId is required when skill token auth is enabled", 401);
  }

  // Check for session JWT first (Authorization: Bearer <jwt>).
  const authHeader = req.headers["authorization"];
  const bearer = typeof authHeader === "string" && authHeader.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : null;

  if (bearer) {
    const claims = runtime.sessions.verify(bearer);
    if (claims && (!expected || claims.sub === expected)) {
      return { skillId: claims.sub, method: "jwt" };
    }
  }

  // Fall back to skill token header.
  const tokenHeader = req.headers["x-clauth-skill-token"];
  const token = (Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader)?.trim();
  if (!token) {
    await runtime.audit.append({
      ts: new Date().toISOString(),
      event: "proxy.deny",
      skillId: expected,
      outcome: "skill_auth_failed",
      details: {
        reason: "missing_skill_token"
      }
    });
    throw new ClauthError("UNAUTHORIZED", "Missing skill token", 401);
  }

  const resolvedSkillId = expected ?? runtime.skillAuth.identify(token) ?? undefined;
  if (!resolvedSkillId || !runtime.skillAuth.verify(resolvedSkillId, token)) {
    await runtime.audit.append({
      ts: new Date().toISOString(),
      event: "proxy.deny",
      skillId: expected ?? resolvedSkillId,
      outcome: "skill_auth_failed",
      details: {
        reason: "invalid_skill_token"
      }
    });
    throw new ClauthError("UNAUTHORIZED", "Invalid skill token", 401);
  }

  return { skillId: resolvedSkillId, method: "skill-token" };
}

export async function resolveIdentityAccess(
  req: http.IncomingMessage,
  runtime: ClauthRuntime,
  providedSkillId?: string
): Promise<IdentityAccess> {
  const normalizedProvidedSkillId = providedSkillId?.trim() ? providedSkillId.trim() : undefined;

  if (runtime.config.hardening.requireAdminTokenForIdentity) {
    assertAdminToken(req.headers["x-clauth-admin-token"]);
    return {
      isAdmin: true,
      skillId: normalizedProvidedSkillId
    };
  }

  const principal = await requireSkillPrincipal(req, runtime, normalizedProvidedSkillId);
  return {
    isAdmin: false,
    skillId: principal.skillId
  };
}

function assertLocalRequest(req: http.IncomingMessage, runtime: ClauthRuntime): void {
  if (runtime.config.transport !== "tcp") {
    return;
  }
  if (process.env.CLAUTH_ALLOW_REMOTE === "1") {
    return;
  }

  const remoteAddress = req.socket.remoteAddress ?? "";
  if (isLoopback(remoteAddress)) {
    return;
  }

  throw new ClauthError("FORBIDDEN", `Remote address '${remoteAddress}' is not allowed`, 403);
}

function isLoopback(address: string): boolean {
  return (
    address === "::1" ||
    address === "127.0.0.1" ||
    address.startsWith("127.") ||
    address === "::ffff:127.0.0.1" ||
    address.startsWith("::ffff:127.")
  );
}

const STATIC_FILES: Record<string, string> = {
  "/favicon.png": "image/png",
  "/favicon-32.png": "image/png",
  "/apple-touch-icon.png": "image/png",
  "/icon-192.png": "image/png",
  "/icon-512.png": "image/png",
  "/logo.png": "image/png"
};

function resolvePublicDir(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return path.resolve(path.dirname(thisFile), "..", "..", "public");
}

async function serveStatic(res: http.ServerResponse, pathname: string): Promise<void> {
  const contentType = STATIC_FILES[pathname];
  if (!contentType) {
    return json(res, 404, { error: { code: "NOT_FOUND", message: "Not found" } });
  }
  const filename = pathname.slice(1);
  const filePath = path.join(resolvePublicDir(), filename);
  try {
    const content = await fs.readFile(filePath);
    res.writeHead(200, {
      "content-type": contentType,
      "content-length": content.length,
      "cache-control": "public, max-age=86400"
    });
    res.end(content);
  } catch {
    return json(res, 404, { error: { code: "NOT_FOUND", message: "Static file not found" } });
  }
}

export function assertAdminToken(tokenHeader: string | string[] | undefined): void {
  const configured = process.env.CLAUTH_ADMIN_TOKEN;
  if (!configured) {
    throw new ClauthError("ADMIN_AUTH_DISABLED", "CLAUTH_ADMIN_TOKEN is not configured", 503);
  }

  const token = Array.isArray(tokenHeader) ? tokenHeader[0] : tokenHeader;
  if (!token) {
    throw new ClauthError("UNAUTHORIZED", "Invalid admin token", 401);
  }

  const expected = Buffer.from(configured, "utf8");
  const actual = Buffer.from(token, "utf8");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new ClauthError("UNAUTHORIZED", "Invalid admin token", 401);
  }
}

export function parseProofMethod(method: string | undefined): "signed-challenge" | "oauth" | "email" {
  if (!method || !method.trim()) {
    return "signed-challenge";
  }
  if (method === "signed-challenge" || method === "oauth" || method === "email") {
    return method;
  }
  throw new ClauthError("VALIDATION_ERROR", "method must be one of: signed-challenge, oauth, email", 422);
}

function createIdentityVerifyRateLimiter(runtime: ClauthRuntime): IdentityVerifyRateLimiter {
  const perSkillLimit = Math.max(1, Math.floor(runtime.config.hardening.identityVerifyPerSkillPerMinute));
  const perIpLimit = Math.max(1, Math.floor(runtime.config.hardening.identityVerifyPerIpPerMinute));
  return {
    windowMs: 60_000,
    perSkillLimit,
    perIpLimit,
    skillBuckets: new Map<string, number[]>(),
    ipBuckets: new Map<string, number[]>()
  };
}

async function enforceIdentityVerifyRateLimits(
  req: http.IncomingMessage,
  runtime: ClauthRuntime,
  access: IdentityAccess,
  limiter: IdentityVerifyRateLimiter
): Promise<void> {
  const now = Date.now();
  const skillKey = access.skillId?.trim() ? access.skillId : "admin";
  const ipKey = normalizeRemoteAddress(req.socket.remoteAddress);

  const skillLimited = consumeRateLimit(
    limiter.skillBuckets,
    skillKey,
    limiter.perSkillLimit,
    now,
    limiter.windowMs
  );
  const ipLimited = consumeRateLimit(
    limiter.ipBuckets,
    ipKey,
    limiter.perIpLimit,
    now,
    limiter.windowMs
  );

  if (!skillLimited && !ipLimited) {
    return;
  }

  await runtime.audit.append({
    ts: new Date().toISOString(),
    event: "identity.verify",
    skillId: access.skillId,
    outcome: "rate_limited",
    details: {
      skillKey,
      ip: ipKey,
      skillLimited,
      ipLimited,
      perSkillLimit: limiter.perSkillLimit,
      perIpLimit: limiter.perIpLimit
    }
  });

  throw new ClauthError("RATE_LIMITED", "Identity verification rate limit exceeded", 429);
}

function consumeRateLimit(
  buckets: Map<string, number[]>,
  key: string,
  limit: number,
  now: number,
  windowMs: number
): boolean {
  const cutoff = now - windowMs;
  const current = buckets.get(key) ?? [];
  const recent = current.filter((ts) => ts >= cutoff);
  recent.push(now);
  buckets.set(key, recent);
  return recent.length > limit;
}

function normalizeRemoteAddress(address: string | undefined): string {
  if (!address || !address.trim()) {
    return "unknown";
  }
  return address.trim();
}

async function refreshRuntimeState(runtime: ClauthRuntime): Promise<void> {
  await Promise.all([
    runtime.vault.reload(),
    runtime.scopes.reload(),
    runtime.skillAuth.reload(),
    runtime.sessions.reload(),
    runtime.identityBroker.reload()
  ]);
}
