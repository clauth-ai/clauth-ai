export type ProviderName = string;

export interface StoredCredential {
  handle: string;
  provider: ProviderName;
  secret: string;
  createdAt: string;
  expiresAt?: string;
  metadata?: Record<string, string>;
}

export interface VaultRecord {
  credentials: Record<string, StoredCredential>;
}

export interface ScopeGrant {
  skillId: string;
  provider: ProviderName;
  scope: string;
  rateLimitPerMinute: number;
  active: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface RequestContext {
  skillId: string;
  provider: ProviderName;
  scope: string;
  endpoint: string;
  method: string;
  timestamp: number;
}

export type FirewallSeverity = "info" | "warn" | "critical";

export interface FirewallDecision {
  allowed: boolean;
  severity: FirewallSeverity;
  reasons: string[];
}

export interface AuditEntry {
  ts: string;
  event:
    | "credential.store"
    | "credential.delete"
    | "proxy.allow"
    | "proxy.deny"
    | "proxy.error"
    | "grant.create"
    | "grant.revoke"
    | "grant.emergency_revoke"
    | "skill_token.issue"
    | "skill_token.revoke"
    | "session_token.issue"
    | "session_token.revoke"
    | "firewall.alert"
    | "daemon.start"
    | "identity.challenge"
    | "identity.verify"
    | "identity.revoke"
    | "advisory.processed";
  skillId?: string;
  provider?: string;
  scope?: string;
  endpoint?: string;
  method?: string;
  outcome?: string;
  statusCode?: number;
  details?: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

export interface ProxyRequest {
  skillId: string;
  provider: ProviderName;
  credentialHandle: string;
  scope: string;
  method: string;
  endpoint: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface OAuthTokenSet {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  tokenUrl: string;
  clientId?: string;
  clientSecret?: string;
  scopes?: string[];
}

export type AlertSeverity = "info" | "warning" | "critical";

export interface AlertChannel {
  type: "webhook";
  url: string;
  minSeverity: AlertSeverity;
}

export interface AlertEvent {
  severity: AlertSeverity;
  category: string;
  message: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface Advisory {
  id: string;
  source: string;
  severity: AlertSeverity;
  summary: string;
  affectedPackage?: string;
  affectedPackages?: string[];
  publishedAt: string;
  url?: string;
}

export interface AdvisorySource {
  name: string;
  url: string;
  type: "github" | "custom";
}

export interface SessionClaims {
  sub: string;
  iss: string;
  iat: number;
  exp: number;
  jti?: string;
  scope?: string;
}

export type ProofMethod = "signed-challenge" | "oauth" | "email";
export type ChallengeStatus = "pending" | "verified" | "expired" | "failed";

export interface IdentityChallenge {
  id: string;
  skillId: string;
  provider: string;
  accountId: string;
  method: ProofMethod;
  challenge: string;
  status: ChallengeStatus;
  createdAt: string;
  expiresAt: string;
  verifiedAt?: string;
  attempts?: number;
  lastAttemptAt?: string;
}

export interface IdentityProof {
  challengeId: string;
  provider: string;
  accountId: string;
  method: ProofMethod;
  verifiedAt: string;
  signature: string;
}

export interface Capabilities {
  product: "clauth";
  version: string;
  brokeredExecution: true;
  endpointPolicyEnforced: true;
  transport: "tcp" | "unix";
  requireSkillToken: boolean;
  supportsIdentityBroker: boolean;
  supportedProofMethods: string[];
}
