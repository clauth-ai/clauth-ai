# Agent Integration Guide

This guide explains how to integrate skills and agents with Clauth using the client SDK.

## Installation

```bash
npm install clauth-ai
```

Skills import from the `clauth-ai/client` export:

```typescript
import { ClauthClient } from "clauth-ai/client";
```

## Quick Start

```typescript
import { ClauthClient } from "clauth-ai/client";

// Auto-discovers from CLAUTH_DAEMON_URL, CLAUTH_SKILL_ID, CLAUTH_SKILL_TOKEN
const clauth = new ClauthClient();

// Make a brokered API call
const res = await clauth.fetch(
  "github",           // provider name
  "github-main",      // credential handle
  "github:read",      // required scope
  "https://api.github.com/user"
);

console.log(res.status);  // 200
console.log(res.body);    // { login: "octocat", ... }
```

## Configuration

### Environment Variables (recommended)

```bash
export CLAUTH_DAEMON_URL=http://127.0.0.1:4317
export CLAUTH_SKILL_ID=my-agent
export CLAUTH_SKILL_TOKEN=clauth_sk_xxx
```

The client auto-discovers these:

```typescript
const clauth = new ClauthClient();  // reads from env vars
```

### Explicit Options

```typescript
const clauth = new ClauthClient({
  daemonUrl: "http://127.0.0.1:4317",
  skillId: "my-agent",
  skillToken: "clauth_sk_xxx"
});
```

## API

### `clauth.fetch(provider, credential, scope, endpoint, options?)`

Execute a brokered API request through the proxy.

**Parameters**:

| Param | Type | Description |
|-------|------|-------------|
| `provider` | string | Provider name (e.g., `"github"`, `"slack"`) |
| `credential` | string | Credential handle stored in the vault |
| `scope` | string | Required scope (e.g., `"github:read"`) |
| `endpoint` | string | Full upstream URL |
| `options.method` | string | HTTP method (default: `"GET"`) |
| `options.headers` | object | Additional headers (auth headers stripped) |
| `options.body` | any | Request body (objects JSON-serialized) |

**Returns**: `{ status: number, headers: object, body: any }`

**Examples**:

```typescript
// GET request
const user = await clauth.fetch(
  "github", "github-main", "github:read",
  "https://api.github.com/user"
);

// POST request with body
const issue = await clauth.fetch(
  "github", "github-main", "github:write",
  "https://api.github.com/repos/owner/repo/issues",
  {
    method: "POST",
    body: { title: "Bug report", body: "Description here" }
  }
);

// Custom headers
const res = await clauth.fetch(
  "custom", "custom-api", "custom:read",
  "https://api.custom.example.com/data",
  {
    headers: { "x-custom-header": "value" }
  }
);
```

### `clauth.health()`

Check if the daemon is reachable.

```typescript
const ok = await clauth.health();
console.log(ok);  // true
```

### `clauth.status()`

Get daemon status information.

```typescript
const info = await clauth.status();
console.log(info.vaultUnlocked);     // true
console.log(info.activeGrants);       // 5
console.log(info.auditIntegrity);     // { valid: true, entries: 42 }
```

### `clauth.createIdentityChallenge(provider, accountId)`

Create an identity verification challenge.

```typescript
const challenge = await clauth.createIdentityChallenge("github", "octocat");
console.log(challenge.challengeId);  // UUID
console.log(challenge.challenge);    // base64url token
console.log(challenge.expiresAt);    // ISO timestamp
```

### `clauth.verifyIdentity(challengeId, proof)`

Submit proof for a challenge.

```typescript
// For signed-challenge: proof is a challenge-bound JSON payload
const proof = clauth.buildSignedChallengeProof("github-main", challenge.challenge, "octocat");
const result = await clauth.verifyIdentity(challenge.challengeId, proof);
console.log(result.status);     // "verified"
console.log(result.verifiedAt); // ISO timestamp

// For email: proof is the one-time code delivered by your webhook/email channel
const emailResult = await clauth.verifyIdentity(challenge.challengeId, "<email-code>");
```

### `clauth.getIdentityStatus(challengeId)`

Poll challenge status.

```typescript
const status = await clauth.getIdentityStatus(challenge.challengeId);
console.log(status.status);  // "pending" | "verified" | "expired" | "failed"
```

### `clauth.listIdentityProofs()`

List verified identity proofs for this skill.

```typescript
const proofs = await clauth.listIdentityProofs();
for (const proof of proofs) {
  console.log(`${proof.provider}/${proof.accountId}: ${proof.method}`);
}
```

## Error Handling

All client methods throw `ClauthError` on failure:

```typescript
import { ClauthClient, ClauthError } from "clauth-ai/client";

try {
  await clauth.fetch("github", "handle", "github:write", "https://api.github.com/user");
} catch (error) {
  if (error instanceof ClauthError) {
    console.error(error.code);       // "ACCESS_DENIED"
    console.error(error.message);    // "No active grant..."
    console.error(error.statusCode); // 403
  }
}
```

Common error codes:

| Code | Meaning |
|------|---------|
| `ACCESS_DENIED` | Scope not granted or firewall blocked |
| `UNAUTHORIZED` | Missing or invalid skill token |
| `NOT_FOUND` | Credential handle or challenge not found |
| `VALIDATION_ERROR` | Invalid request format |
| `UPSTREAM_ERROR` | Provider API call failed |

## Integration Patterns

### Basic Agent Pattern

```typescript
import { ClauthClient, ClauthError } from "clauth-ai/client";

const clauth = new ClauthClient();

async function fetchGitHubRepos(): Promise<any[]> {
  try {
    const res = await clauth.fetch(
      "github", "github-main", "github:read",
      "https://api.github.com/user/repos"
    );
    return res.body as any[];
  } catch (error) {
    if (error instanceof ClauthError && error.code === "ACCESS_DENIED") {
      console.log("Insufficient permissions for this operation");
      return [];
    }
    throw error;
  }
}
```

### Multi-Provider Agent

```typescript
const clauth = new ClauthClient();

// GitHub API
const repos = await clauth.fetch(
  "github", "github-main", "github:read",
  "https://api.github.com/user/repos"
);

// Slack API
const channels = await clauth.fetch(
  "slack", "slack-bot", "slack:channels",
  "https://slack.com/api/conversations.list"
);

// Post to Slack
await clauth.fetch(
  "slack", "slack-bot", "slack:messages",
  "https://slack.com/api/chat.postMessage",
  {
    method: "POST",
    body: { channel: "C123", text: `Found ${repos.body.length} repos` }
  }
);
```

### Identity-Aware Agent

```typescript
const clauth = new ClauthClient();

// Verify GitHub identity before performing sensitive operations
async function ensureVerified(): Promise<boolean> {
  const proofs = await clauth.listIdentityProofs();
  if (proofs.some(p => p.provider === "github")) {
    return true;
  }

  const challenge = await clauth.createIdentityChallenge("github", "octocat");
  const proof = clauth.buildSignedChallengeProof("github-main", challenge.challenge, "octocat");
  const result = await clauth.verifyIdentity(challenge.challengeId, proof);
  return result.status === "verified";
}
```

### Polling Pattern for Identity

```typescript
async function waitForVerification(challengeId: string, timeoutMs = 300000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const status = await clauth.getIdentityStatus(challengeId);
    if (status.status === "verified") return true;
    if (status.status === "failed" || status.status === "expired") return false;
    await new Promise(r => setTimeout(r, 2000));
  }
  return false;
}
```

## Setup Checklist

For a new skill/agent to work with Clauth:

1. **Admin issues a skill token**:
   ```bash
   clauth skill-token issue --skill my-agent
   ```

2. **Admin stores required credentials**:
   ```bash
   export GITHUB_PAT='ghp_xxx'
   clauth store --handle github-main --provider github --secret-env GITHUB_PAT
   ```

3. **Admin grants scopes**:
   ```bash
   clauth grant --skill my-agent --provider github --scope github:read --rpm 60
   clauth grant --skill my-agent --provider github --scope github:write --rpm 30
   ```

4. **Skill configures environment**:
   ```bash
   export CLAUTH_SKILL_ID=my-agent
   export CLAUTH_SKILL_TOKEN=<issued-token>
   export CLAUTH_DAEMON_URL=http://127.0.0.1:4317
   ```

5. **Skill uses the client SDK** to make brokered requests.

## What Skills Cannot Do

- Read raw credentials (only the daemon resolves them)
- Bypass scope enforcement (grants checked before credential resolution)
- Send credentials to unauthorized hosts (endpoint allowlist enforced)
- Exceed rate limits (per-grant RPM ceiling)
- Hide abnormal behavior (firewall detects anomalies after warmup)
- Forge audit entries (hash chain prevents tampering)
- Forge identity proofs (HMAC-signed with vault master key)
