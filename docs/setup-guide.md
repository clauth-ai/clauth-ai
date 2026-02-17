# Setup Guide

## Prerequisites

- Node.js 22 LTS (22.x)
- npm (included with Node.js)

## Installation

```bash
npm install -g clauth-ai
```

### From source (contributors)

```bash
git clone <repo-url> clauth
cd clauth
npm install
```

## Initialize

```bash
clauth init
```

This creates `~/.clauth/` with all necessary state files and prompts for a vault passphrase (minimum 12 characters).

### Custom transport

TCP (default):
```bash
clauth init --transport tcp --host 127.0.0.1 --port 4317
```

Unix socket:
```bash
clauth init --transport unix --socket "$HOME/.clauth/clauth.sock"
```

## Store Credentials

Clauth will prompt for the vault passphrase when required. For non-interactive usage, set `CLAUTH_PASSPHRASE` or `CLAUTH_PASSPHRASE_FILE`.

Store a GitHub token:
```bash
export GITHUB_PAT='ghp_xxx'
clauth store --handle github-main --provider github --secret-env GITHUB_PAT
```

Store with metadata (auth type, custom host policy):
```bash
export CUSTOM_API_TOKEN='sk_xxx'
clauth store --handle custom-api --provider custom --secret-env CUSTOM_API_TOKEN \
  --metadata authType=bearer,allowedHosts=api.custom.example.com
```

Store with TTL (auto-expiry):
```bash
export TEMP_GITHUB_PAT='ghp_yyy'
clauth store --handle temp-token --provider github --secret-env TEMP_GITHUB_PAT --ttl 3600
```

Store from stdin (no secret in shell history or process args):
```bash
printf '%s' "$GITHUB_PAT" | clauth store --handle github-main --provider github --secret-stdin
```

When the daemon is already running, credential updates are picked up automatically on the next API request (no restart required).

## Grant Skill Access

```bash
clauth grant --skill my-agent --provider github --scope github:read --rpm 60
```

Scope format is `provider:action`. Wildcards supported:
- `github:*` — all actions on GitHub
- `*:read` — read on any provider

Rate limit (`--rpm`) defaults to 60 requests/minute per grant.

Grant and revoke changes are applied live by the running daemon on the next request.

## Issue Skill Tokens

Skills authenticate via tokens issued by an admin:

```bash
clauth skill-token issue --skill my-agent
```

Save the token — it is shown only once. Skills include it as `x-clauth-skill-token` header.

Skill token rotation/revocation, session-token revocations, and identity proof updates are also applied live by the running daemon on the next request.

## Start the Daemon

```bash
export CLAUTH_ADMIN_TOKEN='set-admin-token'
clauth daemon
```

From source (dev mode):
```bash
export CLAUTH_ADMIN_TOKEN='set-admin-token'
npm run dev
```

The daemon listens on `http://127.0.0.1:4317` by default.

## Verify Setup

```bash
clauth doctor
```

Check daemon health:
```bash
curl http://127.0.0.1:4317/health
```

View status:
```bash
clauth status
```

## Configure Alert Webhooks

Edit `~/.clauth/config.json`:

```json
{
  "alertChannels": [
    {
      "type": "webhook",
      "url": "https://hooks.slack.com/services/xxx",
      "minSeverity": "warning"
    }
  ]
}
```

Test delivery:
```bash
curl -X POST http://127.0.0.1:4317/clauth/v1/admin/alerts/test \
  -H "x-clauth-admin-token: $CLAUTH_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/xxx"}'
```

## Configure Advisory Feeds

Edit `~/.clauth/config.json`:

```json
{
  "advisoryFeeds": [
    {
      "name": "github",
      "url": "https://api.github.com/advisories",
      "type": "github"
    }
  ],
  "advisoryPollIntervalMs": 3600000
}
```

On critical advisory matching a stored provider, clauth auto-revokes grants and deletes affected credentials.

Manual dry-run check (no state mutation):

```bash
clauth advisory check --limit 20
```

Apply unseen advisories immediately:

```bash
clauth advisory check --apply true
```

## Docker Deployment

```bash
docker build -t clauth .
```

Or use Docker Compose:

```bash
# Create .env file
echo "CLAUTH_PASSPHRASE=your-long-passphrase-here" > .env
echo "CLAUTH_ADMIN_TOKEN=set-admin-token" >> .env

docker compose up -d
```

The compose file mounts `~/.clauth` as a volume and runs the container as a non-root user with a read-only filesystem.

## systemd Service

```bash
# Generate the service file
clauth service install --target systemd

# Review and edit the generated env file
# ~/.clauth/clauth.env contains CLAUTH_PASSPHRASE and CLAUTH_ADMIN_TOKEN placeholders

# Copy to systemd directory
clauth service apply --target systemd --write true

# Or apply and start (requires --ackSystem for system-level commands)
clauth service apply --target systemd --write true --run true --sudo true --ackSystem true
```

## launchd Service (macOS)

```bash
clauth service install --target launchd
clauth service apply --target launchd --write true
```

## OpenClaw Migration

Import credentials from an existing OpenClaw configuration:

```bash
# Dry run — shows what would be migrated
clauth migrate

# From a custom path
clauth migrate --from /path/to/openclaw.json

# Write mode — stores credentials and rewrites config
clauth migrate --write
```

The original config is backed up before rewriting. Secret values are replaced with `clauth://handle` references.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLAUTH_HOME` | No | `~/.clauth` | State directory path |
| `CLAUTH_PASSPHRASE` | Yes (daemon) | — | Vault unlock passphrase |
| `CLAUTH_PASSPHRASE_FILE` | Alt | — | Path to passphrase file |
| `CLAUTH_ADMIN_TOKEN` | Yes (admin API) | — | Admin endpoint auth token |
| `CLAUTH_ALLOW_INSECURE_HTTP` | No | `0` | Allow HTTP provider endpoints (dev only) |
| `CLAUTH_ALLOW_REMOTE` | No | `0` | Allow non-loopback connections |
| `CLAUTH_ALLOW_UNKNOWN_PROVIDER_HOSTS` | No | `0` | Relax host allowlist |
| `CLAUTH_OAUTH_REDIRECT_URI` | No | `http://127.0.0.1:4317/clauth/v1/identity/oauth/callback` | OAuth callback URL |
| `CLAUTH_GITHUB_CLIENT_ID` | No | — | GitHub OAuth client ID |
| `CLAUTH_GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth client secret |
| `CLAUTH_TWITTER_CLIENT_ID` | No | — | Twitter OAuth client ID |
| `CLAUTH_TWITTER_CLIENT_SECRET` | No | — | Twitter OAuth client secret |
| `CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL` | No | — | Webhook target for out-of-band email challenge code delivery |
