# Clauth — Credential Proxy for Agents

You are interacting with **Clauth**, a credential proxy and behavioral firewall. You do not have direct access to API credentials. Instead, you make brokered requests through Clauth, which injects credentials on your behalf and enforces security policies.

## Why This Exists

You never see raw API keys, OAuth tokens, or secrets. Clauth holds them in an encrypted vault and injects authentication headers at request time. This means:

- You cannot accidentally leak credentials
- You can only access providers and scopes you've been granted
- Your request patterns are monitored for anomalies
- All your API calls are logged in a tamper-evident audit chain

## Setup

### Prerequisites

The human operator must have:

1. Installed and initialized clauth:
   ```bash
   npm install -g clauth-ai
   clauth init
   ```

2. Stored credentials in the vault:
   ```bash
   export GITHUB_PAT='ghp_xxx'
   clauth store --handle github-main --provider github --secret-env GITHUB_PAT
   ```

3. Granted you access to specific scopes:
   ```bash
   clauth grant --skill <your-skill-id> --provider github --scope github:read --rpm 60
   ```

4. Issued you a skill token:
   ```bash
   clauth skill-token issue --skill <your-skill-id>
   ```

5. Started the daemon:
   ```bash
   clauth daemon
   ```

### Your Configuration

You need three values (typically set as environment variables):

```
CLAUTH_DAEMON_URL=http://127.0.0.1:4317
CLAUTH_SKILL_ID=<your-skill-id>
CLAUTH_SKILL_TOKEN=<issued-token>
```

## Making API Calls

### Using the SDK (TypeScript/JavaScript)

```typescript
import { ClauthClient } from "clauth-ai/client";

const clauth = new ClauthClient(); // reads from env vars

// GET request
const user = await clauth.fetch(
  "github",        // provider
  "github-main",   // credential handle (ask operator for this)
  "github:read",   // scope you need
  "https://api.github.com/user"
);
// user.status = 200
// user.body = { login: "octocat", ... }

// POST request
const issue = await clauth.fetch(
  "github", "github-main", "github:write",
  "https://api.github.com/repos/owner/repo/issues",
  {
    method: "POST",
    body: { title: "Bug report", body: "Details here" }
  }
);
```

### Using HTTP Directly

If you're not in a TypeScript environment, call the daemon HTTP API:

```
POST http://127.0.0.1:4317/clauth/v1/proxy
x-clauth-skill-token: <your-token>
Content-Type: application/json

{
  "skillId": "<your-skill-id>",
  "provider": "github",
  "credentialHandle": "github-main",
  "scope": "github:read",
  "method": "GET",
  "endpoint": "https://api.github.com/user"
}
```

Response:
```json
{
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": { "login": "octocat" }
}
```

## What You Need to Know

### You reference credentials by handle, not by value

You never see `ghp_xxx` or `sk-xxx`. You reference credentials by their **handle** (e.g., `github-main`). The operator tells you which handles exist for which providers. If you don't know the handle, ask the operator.

### You must specify the scope you need

Every request requires a `scope` in `provider:action` format:
- `github:read` — read GitHub data
- `github:write` — create/modify GitHub data
- `slack:messages` — send Slack messages
- `twitter:post` — post tweets

If you request a scope you haven't been granted, the request is denied.

### Endpoints must match the provider

You can only call URLs that are on the provider's allowlist. For example, with `provider: "github"`, you can only call `api.github.com` URLs. Requests to other hosts are blocked.

### Rate limits apply

Each grant has a per-minute rate limit (default: 60/min). If you exceed it, requests are denied until the window resets.

### The firewall monitors your behavior

After a warmup period, the firewall learns your normal patterns. Sudden changes trigger alerts:
- Burst of requests in a short window
- Request rate much higher than your baseline
- Calling an endpoint you've never called before
- Activity during off-hours (1-5 AM by default)

Critical anomalies (burst threshold, scope creep) block the request. Others generate alerts but still allow it.

## Error Handling

When a request fails, you get an error with a code and message:

```json
{
  "error": {
    "code": "ACCESS_DENIED",
    "message": "No active grant for skill 'my-agent' provider 'github' scope 'github:write'."
  }
}
```

| Error Code | What It Means | What To Do |
|------------|---------------|------------|
| `ACCESS_DENIED` | Scope not granted or firewall blocked | Ask operator to grant the scope |
| `UNAUTHORIZED` | Missing or invalid skill token | Check your CLAUTH_SKILL_TOKEN |
| `NOT_FOUND` | Credential handle doesn't exist | Ask operator for correct handle |
| `VALIDATION_ERROR` | Bad request format | Check your request parameters |
| `UPSTREAM_ERROR` | Provider API returned an error | Check endpoint URL and method |

## Identity Verification

You can prove you control an account on a provider without the operator posting anything publicly.

### Signed Challenge (zero friction)

```typescript
// 1. Create a challenge
const challenge = await clauth.createIdentityChallenge("github", "octocat");

// 2. Prove ownership using your stored credential
const result = await clauth.verifyIdentity(challenge.challengeId, "github-main");
// result.status === "verified"
```

This works because Clauth uses your stored GitHub credential to call `GET /user` and confirms the `login` matches `octocat`.

### Email Challenge

```typescript
const challenge = await clauth.createIdentityChallenge("email", "user@example.com");
// The calling app sends the challenge.challenge code to the email
// User submits the code back
const result = await clauth.verifyIdentity(challenge.challengeId, challenge.challenge);
```

### List Your Verified Proofs

```typescript
const proofs = await clauth.listIdentityProofs();
```

## Checking Daemon Status

```typescript
const ok = await clauth.health();     // true if daemon is running
const info = await clauth.status();   // detailed status
```

Or via HTTP:
```
GET http://127.0.0.1:4317/health
GET http://127.0.0.1:4317/clauth/v1/status
GET http://127.0.0.1:4317/clauth/v1/capabilities
```

## Available Providers

Common providers with built-in endpoint policies:

| Provider | Example Scope | Allowed Hosts |
|----------|--------------|---------------|
| `github` | `github:read`, `github:write` | `api.github.com` |
| `slack` | `slack:messages`, `slack:channels` | `slack.com` |
| `twitter` | `twitter:read`, `twitter:post` | `api.twitter.com`, `api.x.com` |
| custom | `custom:read` | Set via credential `allowedHosts` metadata |

## Quick Reference

| Action | SDK Method | HTTP Endpoint |
|--------|-----------|---------------|
| API call | `clauth.fetch(provider, handle, scope, url)` | `POST /clauth/v1/proxy` |
| Health check | `clauth.health()` | `GET /health` |
| Status | `clauth.status()` | `GET /clauth/v1/status` |
| Create identity challenge | `clauth.createIdentityChallenge(provider, accountId)` | `POST /clauth/v1/identity/challenge` |
| Submit identity proof | `clauth.verifyIdentity(challengeId, proof)` | `POST /clauth/v1/identity/verify` |
| Poll challenge status | `clauth.getIdentityStatus(challengeId)` | `GET /clauth/v1/identity/challenge/:id/status` |
| List identity proofs | `clauth.listIdentityProofs()` | `GET /clauth/v1/identity/proofs` |

## If Something Isn't Working

1. **"UNAUTHORIZED"** — Your skill token is wrong or missing. Ask the operator to re-issue it.
2. **"ACCESS_DENIED" with scope message** — You need a grant for that scope. Ask the operator: `clauth grant --skill <you> --provider <x> --scope <x:action>`
3. **"ACCESS_DENIED" with firewall message** — You hit the burst limit or the firewall flagged your behavior. Slow down and retry.
4. **"NOT_FOUND" for credential** — The handle you're using doesn't exist. Ask the operator which handles are available.
5. **"UPSTREAM_ERROR"** — The provider API itself failed. Check the URL and method.
6. **Daemon not responding** — Ask the operator to start the daemon: `clauth daemon`
