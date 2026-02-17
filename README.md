# Clauth

Credential proxy and behavioral firewall for [OpenClaw](https://github.com/openclaw).

Skills and agents never see raw credentials. Clauth brokers every outbound API request, enforces per-skill scopes, detects abnormal behavior, auto-refreshes OAuth tokens, monitors security advisories, and verifies identities — all with zero external dependencies.

## Why Clauth?

| Without Clauth | With Clauth |
|----------------|-------------|
| Plaintext credentials in `~/.openclaw/openclaw.json` | AES-256-GCM encrypted vault with scrypt KDF (Argon2id when available) |
| Any skill reads every credential | Skills receive scoped handles, never raw tokens |
| No least-privilege boundaries | Granular `provider:action` grants per skill |
| No behavioral detection | Per-skill baselines with anomaly blocking |
| No tamper-evident audit trail | Hash-chained append-only event stream |
| Manual cleanup on breach | Emergency revoke + advisory-driven auto-revocation |
| Public post identity verification | Private verification (OAuth, email, signed challenge) |

## Requirements

- Node.js 22 LTS (22.x)
- No external npm dependencies at runtime

## Quick Start

```bash
# Install globally (keeps the command name `clauth`)
npm install -g clauth-ai

# Initialize clauth (creates ~/.clauth/ and encrypted vault)
clauth init

# Store a credential
export GITHUB_PAT='ghp_xxx'
clauth store --handle github-main --provider github --secret-env GITHUB_PAT

# Grant a skill access
clauth grant --skill my-agent --provider github --scope github:read --rpm 60

# Issue a skill token
clauth skill-token issue --skill my-agent

# Start the daemon
export CLAUTH_ADMIN_TOKEN='set-admin-token'
clauth daemon

# Open the landing page
open http://127.0.0.1:4317/
```

### Developer Quick Start (from source)

```bash
npm install
npm run cli -- init
export CLAUTH_ADMIN_TOKEN='set-admin-token'
npm run dev
```

## Architecture

```
Skills/Agents (untrusted code)
        |
        | POST /clauth/v1/proxy { skillId, provider, scope, endpoint }
        v
  ┌─────────────────────────────────────┐
  │         Clauth Daemon               │
  │                                     │
  │  Skill Token Auth ──► Scope Engine  │
  │         │                  │        │
  │         v                  v        │
  │  Behavioral Firewall   OAuth Auto   │
  │         │              Refresh      │
  │         v                  │        │
  │  Encrypted Vault ◄────────┘        │
  │         │                           │
  │  Alert Router + Advisory Monitor    │
  │  Identity Broker + Session JWTs     │
  │  Hash-Chained Audit Log            │
  └──────────┬──────────────────────────┘
             │
             v
    External Provider APIs
    (GitHub, Slack, Twitter, etc.)
```

## Core Subsystems

### Encrypted Vault
AES-256-GCM at rest, scrypt key derivation by default (Argon2id when available). Credentials stored with provider, handle, optional TTL, and metadata. Vault is unlocked once at daemon start; key held in memory.

### Scope Engine
Per-skill grants in `provider:action` format with wildcard support (`github:*`, `*:read`). Each grant has a per-minute rate limit. Revocation is instant and audited.

### Behavioral Firewall
Silent baseline learning per skill. Detects: burst threshold violations, rate spikes vs baseline, new endpoints after warmup, off-hours activity, and scope creep attempts. Critical anomalies block the request. Alerts dispatched to configured webhooks.

### Credential Proxy
Intercepts every outbound request. Validates scope grants, runs firewall evaluation, resolves credentials from vault, injects auth headers, strips caller-supplied auth headers, enforces provider endpoint allowlists, and returns only the provider response. On 401, attempts automatic OAuth token refresh and retries once.

### OAuth Token Refresh
Manages `refresh_token` lifecycle. On proxy 401 response, automatically refreshes the access token via the provider's token endpoint and retries the request. Token metadata is persisted in `oauth-tokens.json` encrypted with the vault master key, and tampered metadata fails closed on load.

### Alert Router
Webhook-based alert dispatch with severity filtering (`info`, `warning`, `critical`). Fire-and-forget delivery via `Promise.allSettled`. Firewall anomalies and advisory events dispatched automatically.

### Advisory Monitor
Polls configured security advisory feeds (default: GitHub Advisory Database). On critical advisory matching a stored provider, auto-revokes scope grants and deletes affected credentials. Idempotent via seen-ID tracking.

### Session Engine
Zero-dependency JWT implementation (HS256). Signing key derived from vault master key via HKDF. Used for browser-based flows and as an alternative to skill tokens in HTTP routes.

### Identity Broker
Identity verification without public posting. Three proof methods:
- **Signed Challenge**: Challenge-bound proof payload verified via stored credential against provider API
- **OAuth Flow**: Standard OAuth2 authorization with identity verification
- **Email Challenge**: One-time code delivered through out-of-band webhook flow

### Audit Logger
Hash-chained NDJSON event stream. Every credential store, proxy call, grant change, firewall alert, and identity verification is logged with tamper-evident hash chain. Integrity verifiable at any time.

The daemon hot-reloads file-backed vault, scope, skill-token, session-revocation, and identity state on every API request, so CLI changes take effect immediately without restarting.

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `GET` | `/health` | none | Health check |
| `GET` | `/` | none | Landing page |
| `GET` | `/dashboard` | none | Operator dashboard |
| `GET` | `/clauth/v1/capabilities` | none | Feature capabilities |
| `GET` | `/clauth/v1/status` | none | Daemon status |
| `POST` | `/clauth/v1/proxy` | skill-token or JWT | Brokered proxy request |
| `POST` | `/clauth/v1/emergency-revoke` | admin-token | Revoke all grants |
| `POST` | `/clauth/v1/admin/skill-token/issue` | admin-token | Issue skill token |
| `POST` | `/clauth/v1/admin/skill-token/revoke` | admin-token | Revoke skill token |
| `GET` | `/clauth/v1/admin/skill-token/list` | admin-token | List skill tokens |
| `POST` | `/clauth/v1/admin/session-token/issue` | admin-token | Issue session JWT |
| `POST` | `/clauth/v1/admin/session-token/revoke` | admin-token | Revoke session JWT (`jti`) |
| `GET` | `/clauth/v1/admin/session-token/revocations` | admin-token | List active session revocations |
| `POST` | `/clauth/v1/admin/alerts/test` | admin-token | Test webhook delivery |
| `POST` | `/clauth/v1/identity/challenge` | skill-token or JWT | Create identity challenge |
| `POST` | `/clauth/v1/identity/verify` | skill-token or JWT | Submit identity proof |
| `GET` | `/clauth/v1/identity/challenge/:id/status` | skill-token or JWT | Poll challenge status |
| `GET` | `/clauth/v1/identity/proofs` | skill-token or JWT | List verified proofs for caller skill |
| `GET` | `/clauth/v1/identity/oauth/callback` | none (state param) | OAuth verification callback |
| `DELETE` | `/clauth/v1/admin/identity/proofs/:id` | admin-token | Revoke identity proof |

## CLI Commands

```
clauth init          Initialize state directory and vault
clauth store         Store a credential in the vault
clauth grant         Grant a skill access to a scope
clauth revoke        Revoke a grant
clauth emergency-revoke  Revoke all grants immediately
clauth status        Show daemon and system status
clauth daemon        Start the daemon (uses CLAUTH_PASSPHRASE/CLAUTH_PASSPHRASE_FILE)
clauth doctor        Run diagnostic checks
clauth migrate       Import credentials from OpenClaw config
clauth skill-token   Issue, revoke, or list skill tokens
clauth session-token Issue, revoke, or list session JWT revocations
clauth identity      Create challenges, verify, list proofs, revoke
clauth advisory      Manual advisory dry-run and apply workflow
clauth service       Generate, validate, and apply service templates
```

## Client SDK

```typescript
import { ClauthClient } from "clauth-ai/client";

const clauth = new ClauthClient({
  skillId: "my-agent",
  skillToken: "issued-token"
});

// Brokered API call — credential never exposed to skill
const res = await clauth.fetch(
  "github",           // provider
  "github-main",      // credential handle
  "github:read",      // required scope
  "https://api.github.com/user"
);
console.log(res.status, res.body);

// Identity verification
const challenge = await clauth.createIdentityChallenge("github", "myuser");
const proof = clauth.buildSignedChallengeProof("github-main", challenge.challenge, "myuser");
const result = await clauth.verifyIdentity(challenge.challengeId, proof);
```

## Deployment

### Docker

```bash
docker build -t clauth .
docker compose up -d
```

### systemd

```bash
clauth service install --target systemd
clauth service apply --target systemd --write true
```

### launchd (macOS)

```bash
clauth service install --target launchd
clauth service apply --target launchd --write true
```

## Security Notes

- Default requires HTTPS for all outbound provider calls
- Provider endpoint allowlists prevent credential exfiltration to arbitrary hosts
- Proxy and identity routes require authenticated skill principal (skill token or JWT)
- Vault passphrase must be at least 12 characters
- Daemon binds to `127.0.0.1` only (loopback enforcement)
- All state files written with `0o600` permissions in `0o700` directory
- OAuth refresh token state is encrypted at rest with the vault master key
- Email proof delivery requires `CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL`
- Set `hardening.requireAdminTokenForIdentity=true` to require admin token on identity routes
- `CLAUTH_ALLOW_INSECURE_HTTP=1` is development-only

## Documentation

- [Setup Guide](docs/setup-guide.md) — Step-by-step installation and configuration
- [Security Model](docs/security-model.md) — Threat model, encryption, and design rationale
- [API Reference](docs/api-reference.md) — Complete endpoint documentation
- [Identity Broker](docs/identity-broker.md) — Identity verification flows
- [Configuration](docs/configuration.md) — All configuration options
- [Agent Integration](docs/agent-integration.md) — SDK guide for skill developers
- [Real-World Testing](docs/real-world-testing.md) — End-to-end operational and security validation runbook

## Tests

```bash
npm test
```

156 tests covering vault encryption, scope enforcement, firewall anomaly detection, proxy security, session JWTs, identity verification, OAuth refresh, alerts, advisories, service templates, client SDK, and daemon HTTP routes.

## License

See [LICENSE](LICENSE).
