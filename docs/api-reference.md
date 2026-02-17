# API Reference

Base URL: `http://127.0.0.1:4317` (default)

## Authentication

### Skill Token
Include in request header:
```
x-clauth-skill-token: <issued-token>
```

### Session JWT
Alternative to skill token. Include as Bearer token:
```
Authorization: Bearer <jwt>
```

The JWT `sub` claim must match the request `skillId` when provided. If `skillId` is omitted, Clauth derives it from the authenticated principal.
Session JWTs include a `jti` and can be revoked by admin endpoints.

### Admin Token
For admin-only endpoints:
```
x-clauth-admin-token: <configured-token>
```

Set via `CLAUTH_ADMIN_TOKEN` environment variable.

---

## Health & Status

### `GET /health`

**Auth**: None

**Response**:
```json
{
  "ok": true,
  "service": "clauth",
  "version": "0.1.0"
}
```

### `GET /clauth/v1/capabilities`

**Auth**: None

**Response**:
```json
{
  "product": "clauth",
  "version": "0.1.0",
  "brokeredExecution": true,
  "endpointPolicyEnforced": true,
  "transport": "tcp",
  "requireSkillToken": true,
  "supportsIdentityBroker": true,
  "supportedProofMethods": ["signed-challenge", "oauth", "email"]
}
```

### `GET /clauth/v1/status`

**Auth**: None

**Response**:
```json
{
  "vaultUnlocked": true,
  "transport": "tcp",
  "daemon": "http://127.0.0.1:4317",
  "requireSkillToken": true,
  "activeSkillTokens": 2,
  "activeGrants": 5,
  "auditIntegrity": {
    "valid": true,
    "entries": 42
  }
}
```

---

## Proxy

### `POST /clauth/v1/proxy`

**Auth**: Skill token or JWT

Execute a brokered API request. Clauth validates scope, runs firewall checks, resolves credentials, injects auth headers, and returns the provider response.
Proxy authentication is always required.

**Request**:
```json
{
  "skillId": "my-agent",
  "provider": "github",
  "credentialHandle": "github-main",
  "scope": "github:read",
  "method": "GET",
  "endpoint": "https://api.github.com/user",
  "headers": {},
  "body": null
}
```

**Response** (success):
```json
{
  "status": 200,
  "headers": {
    "content-type": "application/json"
  },
  "body": {
    "login": "octocat",
    "id": 1
  }
}
```

**Response** (scope denied):
```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "No active grant for skill 'my-agent' provider 'github' scope 'github:write'."
  }
}
```

**Response** (firewall blocked):
```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "Firewall blocked request: Burst threshold exceeded (21 in 10000ms)."
  }
}
```

---

## Grants & Revocation

### `POST /clauth/v1/emergency-revoke`

**Auth**: Admin token

Revoke all active grants immediately.

**Response**:
```json
{
  "revoked": 5
}
```

---

## Skill Tokens

### `POST /clauth/v1/admin/skill-token/issue`

**Auth**: Admin token

**Request**:
```json
{
  "skillId": "my-agent"
}
```

**Response**:
```json
{
  "skillId": "my-agent",
  "token": "clauth_sk_..."
}
```

### `POST /clauth/v1/admin/skill-token/revoke`

**Auth**: Admin token

**Request**:
```json
{
  "skillId": "my-agent"
}
```

**Response**:
```json
{
  "skillId": "my-agent",
  "revoked": true
}
```

### `GET /clauth/v1/admin/skill-token/list`

**Auth**: Admin token

**Response**:
```json
{
  "tokens": [
    {
      "skillId": "my-agent",
      "active": true,
      "createdAt": "2025-01-15T10:00:00.000Z"
    }
  ]
}
```

---

## Session Tokens

### `POST /clauth/v1/admin/session-token/issue`

**Auth**: Admin token

Issue an HMAC-signed JWT for a skill principal.

**Request**:
```json
{
  "skillId": "my-agent",
  "scope": "github:read",
  "ttlSeconds": 900
}
```

**Response**:
```json
{
  "skillId": "my-agent",
  "token": "<jwt>",
  "jti": "uuid",
  "issuedAt": "2025-01-15T10:00:00.000Z",
  "expiresAt": "2025-01-15T10:15:00.000Z"
}
```

### `POST /clauth/v1/admin/session-token/revoke`

**Auth**: Admin token

Revoke by token or by explicit `jti`.

**Request** (token):
```json
{
  "token": "<jwt>"
}
```

**Request** (jti):
```json
{
  "jti": "uuid",
  "exp": 1736957700
}
```

**Response**:
```json
{
  "revoked": true,
  "jti": "uuid",
  "expiresAt": "2025-01-15T10:15:00.000Z"
}
```

### `GET /clauth/v1/admin/session-token/revocations`

**Auth**: Admin token

**Response**:
```json
{
  "revocations": [
    {
      "jti": "uuid",
      "revokedAt": "2025-01-15T10:02:00.000Z",
      "expiresAt": 1736957700,
      "reason": "admin-api"
    }
  ]
}
```

---

## Alerts

### `POST /clauth/v1/admin/alerts/test`

**Auth**: Admin token

Test webhook delivery.

**Request**:
```json
{
  "url": "https://hooks.slack.com/services/xxx"
}
```

**Response**:
```json
{
  "ok": true,
  "url": "https://hooks.slack.com/services/xxx"
}
```

---

## Identity Broker

### `POST /clauth/v1/identity/challenge`

**Auth**: Skill token or JWT  
When `hardening.requireAdminTokenForIdentity=true`, requires admin token instead.

Create an identity verification challenge.

**Request**:
```json
{
  "skillId": "my-agent",
  "provider": "github",
  "accountId": "octocat",
  "method": "signed-challenge"
}
```

Supported methods: `signed-challenge`, `oauth`, `email`

**Response**:
```json
{
  "challengeId": "550e8400-e29b-41d4-a716-446655440000",
  "challenge": "base64url-random-token",
  "expiresAt": "2025-01-15T10:10:00.000Z"
}
```

When `method` is `oauth`, the response includes:
```json
{
  "challengeId": "...",
  "challenge": "...",
  "expiresAt": "...",
  "oauthUrl": "https://github.com/login/oauth/authorize?client_id=...&state=..."
}
```

When `method` is `email`, response includes:
```json
{
  "challengeId": "...",
  "expiresAt": "...",
  "delivery": "webhook"
}
```
Email code delivery requires `CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL`.

### `POST /clauth/v1/identity/verify`

**Auth**: Skill token or JWT  
When `hardening.requireAdminTokenForIdentity=true`, requires admin token instead.

Identity verification attempts are rate-limited per skill and per source IP.
When exceeded, response is:

```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Identity verification rate limit exceeded"
  }
}
```

Submit proof for a challenge.

**Request**:
```json
{
  "challengeId": "550e8400-e29b-41d4-a716-446655440000",
  "proof": "{\"credentialHandle\":\"github-main\",\"challenge\":\"base64url-random-token\",\"accountId\":\"octocat\"}",
  "skillId": "my-agent"
}
```

For `signed-challenge`: `proof` is a JSON string with `credentialHandle` and `challenge` (optional `accountId`). Clauth validates challenge binding, then uses the stored credential to call the provider API and verify account ownership.

For `email`: `proof` is the one-time code delivered by the configured webhook flow.

**Response** (success):
```json
{
  "status": "verified",
  "verifiedAt": "2025-01-15T10:05:00.000Z"
}
```

**Response** (failure):
```json
{
  "status": "failed"
}
```

### `GET /clauth/v1/identity/challenge/:id/status`

**Auth**: Skill token or JWT  
When `hardening.requireAdminTokenForIdentity=true`, requires admin token instead.

Poll challenge status.

**Response**:
```json
{
  "status": "pending",
  "verifiedAt": null
}
```

Status values: `pending`, `verified`, `expired`, `failed`

### `GET /clauth/v1/identity/proofs`

**Auth**: Skill token or JWT  
When `hardening.requireAdminTokenForIdentity=true`, requires admin token instead.

Lists verified identity proofs for the caller skill.  
Admin-authenticated requests may optionally filter with `?skillId=`.

**Response**:
```json
{
  "proofs": [
    {
      "challengeId": "550e8400-...",
      "provider": "github",
      "accountId": "octocat",
      "method": "signed-challenge",
      "verifiedAt": "2025-01-15T10:05:00.000Z",
      "signature": "hex-hmac-signature"
    }
  ]
}
```

### `GET /clauth/v1/identity/oauth/callback`

**Auth**: None (uses HMAC-signed state parameter)

OAuth provider callback. Automatically exchanges authorization code for access token, verifies identity, and marks the challenge as verified.
This callback remains unauthenticated even when `hardening.requireAdminTokenForIdentity=true`.

Query parameters: `state`, `code`

Returns HTML page indicating verification result.

### `DELETE /clauth/v1/admin/identity/proofs/:id`

**Auth**: Admin token

Revoke a verified identity proof.

**Response**:
```json
{
  "revoked": true
}
```

---

## Pages

### `GET /`
Landing page with architecture overview, request flow visualization, identity verification methods, and before/after comparison.

### `GET /dashboard`
Operator dashboard for status and admin operations.

---

## Error Format

All errors follow:
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description"
  }
}
```

Common error codes:
- `UNAUTHORIZED` — Missing or invalid auth token (401)
- `ACCESS_DENIED` — Scope denied or firewall blocked (403)
- `FORBIDDEN` — Remote address not allowed (403)
- `NOT_FOUND` — Resource not found (404)
- `VALIDATION_ERROR` — Invalid request format (422)
- `ADMIN_AUTH_DISABLED` — `CLAUTH_ADMIN_TOKEN` not configured (503)
- `UPSTREAM_ERROR` — Provider request failed (502)
- `INTERNAL_ERROR` — Unexpected server error (500)
