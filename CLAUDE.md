# Clauth - Project Instructions

## What is this?

Clauth is a credential proxy and behavioral firewall for OpenClaw. It brokers every outbound API request so that skills/agents never see raw credentials. Zero external dependencies — everything uses Node.js built-in modules.

## Architecture

```
Skills/Agents (untrusted)
    |
    v
HTTP Daemon (src/daemon/)
    |
    v
Credential Proxy (src/core/proxy.ts)
    |-- Scope Engine (src/core/scopes.ts) — per-skill grants
    |-- Behavioral Firewall (src/core/firewall.ts) — anomaly detection
    |-- Encrypted Vault (src/core/vault.ts) — AES-256-GCM secrets
    |-- OAuth Refresher (src/core/oauth-refresh.ts) — automatic token refresh
    |-- Alert Router (src/core/alerts.ts) — webhook notifications
    |-- Advisory Monitor (src/core/advisory.ts) — security feed polling
    |-- Session Engine (src/core/sessions.ts) — JWT session tokens
    |-- Identity Broker (src/core/identity-broker.ts) — identity verification
    |-- Audit Logger (src/core/audit.ts) — hash-chained event log
    v
External Provider APIs
```

## Key Patterns

- **Zero-dependency**: No npm packages beyond dev tooling. All crypto uses `node:crypto`.
- **Class lifecycle**: Every subsystem follows `constructor() -> async load() -> async persist()`.
- **JSON state files**: All state stored in `~/.clauth/` as JSON files with atomic writes.
- **Composition via runtime**: `src/daemon/runtime.ts` builds and wires all subsystems.
- **ESM with .js extensions**: All TypeScript imports use `.js` extensions for Node ESM compatibility.
- **Node.js 22+**: Uses `--experimental-strip-types` for dev, `tsc` for production builds.

## Commands

```bash
npm test          # Run all tests (uses custom loader for .ts ESM)
npm run build     # TypeScript compilation to dist/
npm run dev       # Start daemon in dev mode (strip-types)
npm run cli       # Run CLI in dev mode
npm run lint      # TypeScript type check (tsc --noEmit)
```

## File Layout

```
src/
  core/       # Business logic (vault, scopes, firewall, proxy, etc.)
  daemon/     # HTTP server, app routes, runtime composition, landing page, dashboard
  cli/        # CLI entry point and service template helpers
  client/     # SDK for skill developers (ClauthClient class)
  providers/  # Provider auth headers and endpoint policy
  types/      # Shared TypeScript interfaces
test/         # Tests using node:test runner
deploy/       # Systemd service template
docs/         # Documentation
```

## State Files (~/.clauth/)

| File | Purpose |
|------|---------|
| `config.json` | Daemon configuration |
| `vault.enc` | AES-256-GCM encrypted credentials |
| `scopes.json` | Per-skill scope grants |
| `audit.ndjson` | Hash-chained audit log |
| `firewall.json` | Per-skill behavioral baselines |
| `skill-auth.json` | Issued skill tokens |
| `oauth-tokens.json` | OAuth refresh token metadata |
| `advisory-state.json` | Seen advisory IDs |
| `identity-state.json` | Identity challenges and proofs |

## Testing

- Tests use Node.js built-in `node:test` runner.
- Each test uses `withTempHome()` to isolate state via `CLAUTH_HOME` env var.
- Run a single test: `node --experimental-strip-types --import ./scripts/register-loader.mjs --test test/vault.test.ts`

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `CLAUTH_HOME` | Override state directory (default: `~/.clauth`) |
| `CLAUTH_PASSPHRASE` | Vault unlock passphrase |
| `CLAUTH_PASSPHRASE_FILE` | Path to file containing passphrase |
| `CLAUTH_ADMIN_TOKEN` | Admin API authentication token |
| `CLAUTH_ALLOW_INSECURE_HTTP` | Allow HTTP endpoints (dev only) |
| `CLAUTH_ALLOW_REMOTE` | Allow non-loopback connections |
| `CLAUTH_ALLOW_UNKNOWN_PROVIDER_HOSTS` | Relax provider host policy |
| `CLAUTH_OAUTH_REDIRECT_URI` | Override OAuth callback URL |
| `CLAUTH_GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `CLAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth app client secret |
| `CLAUTH_TWITTER_CLIENT_ID` | Twitter OAuth app client ID |
| `CLAUTH_TWITTER_CLIENT_SECRET` | Twitter OAuth app client secret |

## When Making Changes

- Always run `npx tsc --noEmit` before considering work complete.
- Always run `npm test` to verify all tests pass.
- Maintain the zero-dependency constraint — do not add npm packages.
- Use `.js` extensions in all TypeScript import paths.
- Follow the existing `async load()` / `async persist()` pattern for new subsystems.
- Wire new subsystems through `runtime.ts` and test in isolation.
- Atomic writes via `writeJsonFileAtomic()` for all state files.
- Files in `~/.clauth/` should be created with `0o600` permissions.
