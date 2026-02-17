# Security Model

## Threat Model

Clauth assumes that skills and agents are **untrusted code** running alongside a human operator's credentials. The threat scenarios:

1. **Malicious skill installation**: A compromised or intentionally malicious skill attempts to exfiltrate credentials
2. **Credential theft via environment**: A skill reads environment variables, files, or process memory to extract tokens
3. **Scope escalation**: A skill with limited access attempts to access unauthorized providers or actions
4. **Behavioral manipulation**: A skill gradually changes its request patterns to mask data exfiltration
5. **Supply chain compromise**: A provider's OAuth tokens are compromised via upstream vulnerability

## Defense Layers

### Layer 1: Credential Isolation

**Problem**: OpenClaw stores credentials in plaintext JSON (`~/.openclaw/openclaw.json`). Any skill can read every credential.

**Solution**: Clauth encrypts all credentials at rest using AES-256-GCM. The vault is unlocked once at daemon start with a passphrase-derived key (scrypt by default; Argon2id when the runtime supports it). Skills never see raw credentials — they reference handles like `github-main`, and the daemon injects auth headers at request-time.

**Why AES-256-GCM**: Authenticated encryption prevents both reading and tampering. GCM mode provides integrity via authentication tags. Each vault write uses a fresh IV.

**Why Memory-Hard KDFs**: Clauth prefers Argon2id when available, but uses Node.js built-in scrypt on runtimes that do not expose `crypto.argon2Sync`. Both are designed to make offline brute-force attacks more expensive than simple hashing.

### Layer 2: Scope Enforcement

**Problem**: No least-privilege boundaries — any skill can use any credential for any purpose.

**Solution**: Granular `provider:action` grants per skill. Each grant has:
- A specific `skillId` (e.g., `my-github-agent`)
- A `provider` (e.g., `github`)
- A `scope` (e.g., `github:read`)
- A `rateLimitPerMinute` ceiling

Wildcards (`github:*`, `*:read`) allow flexibility while maintaining boundaries. Scope authorization happens before any credential is resolved.

### Layer 3: Behavioral Firewall

**Problem**: Even with scope enforcement, a compromised skill could abuse its granted access (e.g., mass data exfiltration within allowed scope).

**Solution**: Silent baseline learning with anomaly detection:

| Check | Severity | Action |
|-------|----------|--------|
| Burst threshold (>20 in 10s) | Critical | Block request |
| Rate spike (>3x baseline) | Warning | Alert |
| New endpoint after warmup | Warning | Alert |
| Off-hours activity (1-5 AM) | Warning | Alert |
| Scope creep (unauthorized scope) | Critical | Block + alert |

The firewall learns per-skill baselines automatically. After a warmup period (10 requests), new patterns trigger alerts. Critical anomalies block the request immediately.

### Layer 4: Endpoint Policy

**Problem**: A skill with valid scope could redirect requests to an attacker-controlled server to capture injected credentials.

**Solution**: Provider endpoint allowlists. Known providers (GitHub, Slack, Twitter, etc.) have hardcoded allowed hostnames. Custom providers require explicit `allowedHosts` metadata on the credential. Every request's target URL is validated against the allowlist before credential injection.

### Layer 5: OAuth Auto-Refresh

**Problem**: Expired tokens cause silent failures. Manual token rotation creates windows of vulnerability.

**Solution**: Clauth manages `refresh_token` lifecycle automatically. On proxy 401 response:
1. Refresh the access token via the provider's token endpoint
2. Update the vault atomically
3. Retry the original request with the new token
4. If still failing, return the original 401

This ensures tokens are always fresh without operator intervention.
OAuth refresh metadata is stored in an encrypted envelope keyed by the vault master key. If the envelope is malformed or tampered, load fails closed instead of silently accepting it.

### Layer 6: Advisory-Driven Revocation

**Problem**: When a provider is compromised (e.g., GitHub token leak), manual response is slow and error-prone.

**Solution**: Advisory monitor polls security feeds (GitHub Advisory Database). On critical advisory matching a stored provider:
1. Auto-revokes all scope grants for the affected provider
2. Deletes affected credentials from the vault
3. Dispatches critical alert to configured webhooks
4. Logs the event in the audit chain

### Layer 7: Tamper-Evident Audit

**Problem**: An attacker who gains access could cover their tracks by editing logs.

**Solution**: Hash-chained NDJSON audit log. Each entry includes:
- Previous entry's hash
- Current entry's hash (SHA-256 of content + previous hash)

Append operations are serialized with an inter-process lock so daemon and CLI writers cannot fork the chain. Any modification to any entry still breaks integrity, and verification is available at any time via `audit.verifyIntegrity()`.

### Layer 8: Identity Verification

**Problem**: Proving identity ownership typically requires public posting (e.g., tweeting a verification code), which is both privacy-invasive and insecure.

**Solution**: Three private verification methods:
- **Signed Challenge**: Clauth generates a nonce and requires proof payloads bound to that nonce before verifying ownership via stored credential against provider API (e.g., `GET /user` on GitHub)
- **OAuth Flow**: Standard OAuth2 authorization with HMAC-signed state parameter
- **Email Challenge**: One-time code delivered out-of-band via webhook and verified with constant-time comparison

## Encryption Details

### Vault Envelope

```json
{
  "version": 1,
  "cipher": "aes-256-gcm",
  "iv": "<base64url>",
    "tag": "<base64url>",
    "ciphertext": "<base64url>",
    "kdf": {
    "algorithm": "scrypt",
    "params": {
      "memory": 65536,
      "parallelism": 1,
      "iterations": 3,
      "tagLength": 32
    },
    "salt": "<base64url>"
  }
}
```

- Fresh random IV (12 bytes) on every write
- GCM authentication tag (16 bytes) prevents tampering
- KDF algorithm and parameters are stored alongside ciphertext for forward compatibility
- Salt is per-vault, generated at initialization

### Session JWTs

- HS256 (HMAC-SHA256) signing
- Key derived from vault master key via HKDF (`node:crypto` `hkdfSync`)
- Standard JWT format: `header.payload.signature`
- Timing-safe signature comparison (`crypto.timingSafeEqual`)
- Configurable TTL (default: 3600 seconds)

### Identity Proof Signatures

- HMAC-SHA256 of `challengeId:provider:accountId:method`
- Signed with vault master key
- Prevents proof forgery even if state file is compromised

### OAuth State Parameter

- Format: `challengeId:hmac`
- HMAC-SHA256 of challengeId using vault master key (truncated to 16 hex chars)
- Prevents CSRF and state injection attacks

## File Permissions

| Path | Mode | Purpose |
|------|------|---------|
| `~/.clauth/` | `0o700` | State directory (owner only) |
| `~/.clauth/*.json` | `0o600` | State files (owner read/write only) |
| `~/.clauth/vault.enc` | `0o600` | Encrypted vault |
| `~/.clauth/audit.ndjson` | `0o600` | Audit log |

All writes are atomic (write to temp file, rename) to prevent corruption.

## Comparison with Alternatives

### vs. Environment Variables

Environment variables are readable by any process in the same session. Clauth isolates credentials in an encrypted vault accessible only through the daemon.

### vs. HashiCorp Vault

HashiCorp Vault is a production-grade secrets management system, but it's a heavy dependency with its own infrastructure requirements. Clauth is zero-dependency, local-first, and purpose-built for the agent/skill trust model.

### vs. OS Keychain

OS keychains (macOS Keychain, GNOME Keyring) store secrets but don't provide scope enforcement, behavioral monitoring, or brokered execution. Clauth adds the proxy and firewall layers on top of at-rest encryption.

### vs. OAuth Token Files

Storing OAuth tokens in files requires each skill to handle refresh logic, expiry, and rotation. Clauth centralizes this in the daemon with automatic refresh on 401 responses.

## Hardening Configuration

```json
{
  "hardening": {
    "enforceHttps": true,
    "maxRequestBodyBytes": 1048576,
    "sessionTtlSeconds": 3600,
    "challengeTtlSeconds": 600,
    "requireAdminTokenForIdentity": false
  }
}
```

- `enforceHttps`: Require HTTPS for outbound calls (default: true)
- `maxRequestBodyBytes`: Maximum proxy request body size (default: 1 MiB)
- `sessionTtlSeconds`: JWT session token lifetime (default: 1 hour)
- `challengeTtlSeconds`: Identity challenge expiry (default: 10 minutes)
- `requireAdminTokenForIdentity`: Require admin token for identity endpoints (except OAuth callback)
