# Identity Broker

The identity broker enables private identity verification without public posting. It supports three proof methods and integrates with the audit log, alert router, and session engine.

## Why?

OpenClaw verification often depends on public posting (e.g., tweeting a verification code). This is:

- **Privacy-invasive**: Account ownership becomes public knowledge
- **Friction-heavy**: Requires posting and then deleting content
- **Insecure**: Verification codes visible to anyone watching the feed

Clauth provides private alternatives with lower friction and stronger assurance.

## Proof Methods

### Signed Challenge

The primary method for agent-driven flows. Zero user friction.

**Flow**:

1. Third-party site calls `POST /clauth/v1/identity/challenge`:
   ```json
   {
     "skillId": "my-agent",
     "provider": "github",
     "accountId": "octocat",
     "method": "signed-challenge"
   }
   ```

2. Clauth generates a random 32-byte challenge token and returns:
   ```json
   {
     "challengeId": "uuid",
     "challenge": "base64url-token",
     "expiresAt": "2025-01-15T10:10:00Z"
   }
   ```

3. Agent calls `POST /clauth/v1/identity/verify` with a structured proof payload:
   ```json
   {
     "challengeId": "uuid",
     "proof": "{\"credentialHandle\":\"github-main\",\"challenge\":\"base64url-token\",\"accountId\":\"octocat\"}"
   }
   ```

4. Clauth uses the stored credential to call the provider's identity endpoint:
   - **GitHub**: `GET https://api.github.com/user` — checks `login` field
   - **Twitter**: `GET https://api.twitter.com/2/users/me` — checks `data.username`
   - **Slack**: `POST https://slack.com/api/auth.test` — checks `user_id`

5. If the provider confirms the account matches `accountId`, the challenge is marked `verified`.

6. Third-party polls `GET /clauth/v1/identity/challenge/:id/status`:
   ```json
   {
     "status": "verified",
     "verifiedAt": "2025-01-15T10:05:00Z"
   }
   ```

**Security**: The credential never leaves the daemon. Ownership is proved by demonstrating the ability to authenticate against the provider API, and proof is bound to the per-challenge nonce.

### OAuth Flow

Standard OAuth2 authorization flow with identity verification.

**Flow**:

1. Create challenge with `method: "oauth"`:
   ```json
   {
     "skillId": "my-agent",
     "provider": "github",
     "accountId": "octocat",
     "method": "oauth"
   }
   ```

2. Response includes an `oauthUrl`:
   ```json
   {
     "challengeId": "uuid",
     "challenge": "base64url-token",
     "expiresAt": "2025-01-15T10:10:00Z",
     "oauthUrl": "https://github.com/login/oauth/authorize?client_id=...&state=uuid:hmac&..."
   }
   ```

3. User opens the `oauthUrl` in a browser and authorizes the OAuth app.

4. Provider redirects to `GET /clauth/v1/identity/oauth/callback?state=uuid:hmac&code=xxx`.

5. Clauth:
   - Validates the HMAC-signed state parameter
   - Exchanges the authorization code for an access token
   - Calls the provider's identity endpoint with the new token
   - Verifies the account matches `accountId`
   - Marks the challenge as `verified`

6. User sees a confirmation page in the browser.

**Prerequisites**: Requires OAuth app credentials:
- `CLAUTH_GITHUB_CLIENT_ID` / `CLAUTH_GITHUB_CLIENT_SECRET`
- `CLAUTH_TWITTER_CLIENT_ID` / `CLAUTH_TWITTER_CLIENT_SECRET`
- `CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL` (required for `email` method)

**Security**: State parameter is HMAC-signed with the vault master key to prevent CSRF attacks.

### Email Challenge

Simple code-based verification.

**Flow**:

1. Create challenge with `method: "email"`:
   ```json
   {
     "skillId": "my-agent",
     "provider": "email",
     "accountId": "user@example.com",
     "method": "email"
   }
   ```

2. Clauth generates a one-time challenge code and dispatches it to `CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL`.

3. The webhook receiver sends the code to the user's email (or equivalent out-of-band channel).

4. User submits the code via `POST /clauth/v1/identity/verify`:
   ```json
   {
     "challengeId": "uuid",
     "proof": "the-challenge-code"
   }
   ```

5. Clauth verifies exact match of code and marks as `verified`.

**Security**: The code is never returned in the challenge response. Clauth stores only an HMAC-bound representation and compares proofs in constant time.

## Verified Proofs

Successfully verified challenges produce identity proofs. Each proof contains:

```json
{
  "challengeId": "uuid",
  "provider": "github",
  "accountId": "octocat",
  "method": "signed-challenge",
  "verifiedAt": "2025-01-15T10:05:00Z",
  "signature": "hmac-hex"
}
```

The `signature` is an HMAC-SHA256 of `challengeId:provider:accountId:method` using the vault master key. This prevents proof forgery even if the state file is compromised.

## Listing Proofs

```
GET /clauth/v1/identity/proofs
```

Requires skill token or JWT and returns proofs for the authenticated skill.
If `hardening.requireAdminTokenForIdentity=true`, admin token is required.
Admin-authenticated requests can optionally filter with `?skillId=my-agent`.

## Revoking Proofs

Admin-only:
```
DELETE /clauth/v1/admin/identity/proofs/:challengeId
```

## CLI Usage

```bash
# Create a challenge
clauth identity challenge --provider github --accountId octocat

# Submit proof
# signed-challenge proof payload:
clauth identity verify --challengeId <id> --proof '{"credentialHandle":"github-main","challenge":"<challenge>","accountId":"octocat"}'
# email proof: one-time code delivered by webhook
clauth identity verify --challengeId <id> --proof <email-code>

# List verified proofs
clauth identity list
clauth identity list --skill my-agent

# Revoke a proof
clauth identity revoke --proofId <challengeId>
```

## Client SDK

```typescript
import { ClauthClient } from "clauth-ai/client";

const clauth = new ClauthClient({
  skillId: "my-agent",
  skillToken: "issued-token"
});

// Create challenge
const challenge = await clauth.createIdentityChallenge("github", "octocat");

// Submit proof (signed-challenge method)
const proof = clauth.buildSignedChallengeProof("github-main", challenge.challenge, "octocat");
const result = await clauth.verifyIdentity(challenge.challengeId, proof);
console.log(result.status); // "verified"

// Poll status
const status = await clauth.getIdentityStatus(challenge.challengeId);

// List proofs
const proofs = await clauth.listIdentityProofs();
```

## Supported Providers

| Provider | Signed Challenge | OAuth | Verification Endpoint |
|----------|-----------------|-------|----------------------|
| GitHub | Yes | Yes | `GET /user` (checks `login`) |
| Twitter | Yes | Yes | `GET /2/users/me` (checks `data.username`) |
| Slack | Yes | No | `POST auth.test` (checks `user_id`) |
| Email | No | No | Code match only |

## Audit Events

All identity operations are logged:

- `identity.challenge` — Challenge created
- `identity.verify` — Verification attempted (outcome: `identity_verified` or `failed`)
- `identity.revoke` — Proof revoked

## Alert Integration

On successful verification, an `info`-level alert is dispatched:
```json
{
  "severity": "info",
  "category": "identity",
  "message": "Identity verified: github/octocat",
  "metadata": {
    "challengeId": "uuid",
    "method": "signed-challenge"
  }
}
```
