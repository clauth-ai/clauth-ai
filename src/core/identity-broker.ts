import crypto from "node:crypto";
import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import { ValidationError } from "./errors.js";
import type { Vault } from "./vault.js";
import type { AuditLogger } from "./audit.js";
import type { AlertRouter } from "./alerts.js";
import type { SessionEngine } from "./sessions.js";
import type {
  IdentityChallenge,
  IdentityProof,
  ProofMethod,
  ChallengeStatus
} from "../types/index.js";

interface IdentityState {
  challenges: Record<string, IdentityChallenge>;
  proofs: IdentityProof[];
}

interface ChallengeAccess {
  requesterSkillId?: string;
  allowAnySkill?: boolean;
}

interface SignedChallengeProof {
  credentialHandle: string;
  challenge: string;
  accountId?: string;
}

const EMPTY_STATE: IdentityState = { challenges: {}, proofs: [] };
const DEFAULT_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_MAX_VERIFY_ATTEMPTS = 5;

export class IdentityBrokerEngine {
  private state: IdentityState = structuredClone(EMPTY_STATE);
  private readonly vault: Vault;
  private readonly audit: AuditLogger;
  private readonly alertRouter: AlertRouter;
  private readonly sessions: SessionEngine;
  private readonly challengeTtlMs: number;
  private readonly maxVerifyAttempts: number;

  constructor(input: {
    vault: Vault;
    audit: AuditLogger;
    alertRouter: AlertRouter;
    sessions: SessionEngine;
    challengeTtlMs?: number;
    maxVerifyAttempts?: number;
  }) {
    this.vault = input.vault;
    this.audit = input.audit;
    this.alertRouter = input.alertRouter;
    this.sessions = input.sessions;
    this.challengeTtlMs = input.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    this.maxVerifyAttempts = input.maxVerifyAttempts ?? DEFAULT_MAX_VERIFY_ATTEMPTS;
  }

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    this.state = await readJsonFile<IdentityState>(paths.identityStateFile, structuredClone(EMPTY_STATE));
  }

  public async reload(): Promise<void> {
    await this.load();
  }

  public async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.identityStateFile, this.state);
  }

  public async createChallenge(input: {
    skillId: string;
    provider: string;
    accountId: string;
    method?: ProofMethod;
  }): Promise<IdentityChallenge> {
    const id = crypto.randomUUID();
    const now = new Date();
    const method = input.method ?? "signed-challenge";
    const expiresAt = new Date(now.getTime() + this.challengeTtlMs).toISOString();
    let challenge = crypto.randomBytes(32).toString("base64url");

    if (method === "email") {
      const code = generateEmailCode();
      challenge = this.signEmailCode(id, input.accountId, code);
      await this.dispatchEmailChallenge({
        challengeId: id,
        skillId: input.skillId,
        accountId: input.accountId,
        code,
        expiresAt
      });
    }

    const entry: IdentityChallenge = {
      id,
      skillId: input.skillId,
      provider: input.provider,
      accountId: input.accountId,
      method,
      challenge,
      status: "pending",
      createdAt: now.toISOString(),
      expiresAt,
      attempts: 0
    };

    this.state.challenges[id] = entry;
    await this.persist();

    await this.audit.append({
      ts: new Date().toISOString(),
      event: "identity.challenge",
      skillId: entry.skillId,
      provider: entry.provider,
      outcome: "ok",
      details: {
        challengeId: entry.id,
        accountId: entry.accountId,
        method: entry.method
      }
    });

    return { ...entry };
  }

  public getChallenge(id: string): IdentityChallenge | null {
    const challenge = this.state.challenges[id];
    if (!challenge) {
      return null;
    }

    if (challenge.status === "pending" && Date.parse(challenge.expiresAt) <= Date.now()) {
      challenge.status = "expired";
    }

    return { ...challenge };
  }

  public getChallengeForSkill(id: string, access?: ChallengeAccess): IdentityChallenge | null {
    const challenge = this.getChallenge(id);
    if (!challenge) {
      return null;
    }
    if (access?.allowAnySkill) {
      return challenge;
    }
    if (access?.requesterSkillId && challenge.skillId !== access.requesterSkillId) {
      return null;
    }
    return challenge;
  }

  public async verifyChallenge(
    challengeId: string,
    proof: string,
    access?: ChallengeAccess
  ): Promise<{ status: ChallengeStatus; verifiedAt?: string }> {
    const challenge = this.state.challenges[challengeId];
    if (!challenge) {
      return { status: "failed" };
    }

    if (!canAccessChallenge(challenge, access)) {
      return { status: "failed" };
    }

    if (challenge.status !== "pending") {
      return { status: challenge.status };
    }

    if (Date.parse(challenge.expiresAt) <= Date.now()) {
      challenge.status = "expired";
      await this.persist();
      return { status: "expired" };
    }

    const attemptsSoFar = challenge.attempts ?? 0;
    if (attemptsSoFar >= this.maxVerifyAttempts) {
      challenge.status = "failed";
      await this.persist();
      return { status: "failed" };
    }

    challenge.attempts = attemptsSoFar + 1;
    challenge.lastAttemptAt = new Date().toISOString();

    const verified = await this.executeVerification(challenge, proof);

    if (verified) {
      const now = new Date().toISOString();
      challenge.status = "verified";
      challenge.verifiedAt = now;

      const signature = this.signProof(challenge);
      this.state.proofs.push({
        challengeId: challenge.id,
        provider: challenge.provider,
        accountId: challenge.accountId,
        method: challenge.method,
        verifiedAt: now,
        signature
      });

      await this.persist();

      this.alertRouter.dispatch({
        severity: "info",
        category: "identity",
        message: `Identity verified: ${challenge.provider}/${challenge.accountId}`,
        timestamp: now,
        metadata: { challengeId: challenge.id, method: challenge.method }
      }).catch(() => {});

      await this.audit.append({
        ts: now,
        event: "identity.verify",
        skillId: challenge.skillId,
        provider: challenge.provider,
        outcome: "identity_verified",
        details: {
          challengeId: challenge.id,
          provider: challenge.provider,
          accountId: challenge.accountId,
          method: challenge.method
        }
      });

      return { status: "verified", verifiedAt: now };
    }

    challenge.status = (challenge.attempts ?? 0) >= this.maxVerifyAttempts ? "failed" : "pending";
    await this.persist();

    await this.audit.append({
      ts: new Date().toISOString(),
      event: "identity.verify",
      skillId: challenge.skillId,
      provider: challenge.provider,
      outcome: "failed",
      details: {
        challengeId: challenge.id,
        accountId: challenge.accountId,
        method: challenge.method,
        attempts: challenge.attempts ?? 0,
        maxVerifyAttempts: this.maxVerifyAttempts,
        status: challenge.status
      }
    });

    return { status: challenge.status };
  }

  public listProofs(skillId?: string): IdentityProof[] {
    if (!skillId) {
      return this.state.proofs.map((p) => ({ ...p }));
    }

    const challengeIds = new Set(
      Object.values(this.state.challenges)
        .filter((c) => c.skillId === skillId && c.status === "verified")
        .map((c) => c.id)
    );

    return this.state.proofs
      .filter((p) => challengeIds.has(p.challengeId))
      .map((p) => ({ ...p }));
  }

  public async revokeProof(proofId: string): Promise<boolean> {
    const index = this.state.proofs.findIndex((p) => p.challengeId === proofId);
    if (index === -1) {
      await this.audit.append({
        ts: new Date().toISOString(),
        event: "identity.revoke",
        outcome: "not_found",
        details: { proofId }
      });
      return false;
    }
    this.state.proofs.splice(index, 1);
    await this.persist();

    await this.audit.append({
      ts: new Date().toISOString(),
      event: "identity.revoke",
      outcome: "ok",
      details: { proofId }
    });

    return true;
  }

  public async completeOAuthCallback(
    stateParam: string,
    code: string
  ): Promise<{ status: ChallengeStatus; challengeId: string; verifiedAt?: string }> {
    const challengeId = this.decodeOAuthState(stateParam);
    if (!challengeId) {
      return { status: "failed", challengeId: stateParam };
    }

    const challenge = this.state.challenges[challengeId];
    if (!challenge || challenge.status !== "pending" || challenge.method !== "oauth") {
      return { status: "failed", challengeId };
    }

    if (Date.parse(challenge.expiresAt) <= Date.now()) {
      challenge.status = "expired";
      await this.persist();
      return { status: "expired", challengeId };
    }

    const providerOAuth = OAUTH_PROVIDERS[challenge.provider];
    if (!providerOAuth) {
      challenge.status = "failed";
      await this.persist();
      return { status: "failed", challengeId };
    }

    try {
      const tokenResponse = await fetch(providerOAuth.tokenUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json"
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: providerOAuth.clientId(),
          client_secret: providerOAuth.clientSecret(),
          redirect_uri: this.getOAuthRedirectUri()
        }).toString()
      });

      if (!tokenResponse.ok) {
        challenge.status = "failed";
        await this.persist();
        return { status: "failed", challengeId };
      }

      const tokenData = (await tokenResponse.json()) as { access_token?: string };
      if (!tokenData.access_token) {
        challenge.status = "failed";
        await this.persist();
        return { status: "failed", challengeId };
      }

      const ownershipVerified = await providerOAuth.verifyIdentity(
        tokenData.access_token,
        challenge.accountId
      );

      if (!ownershipVerified) {
        challenge.status = "failed";
        await this.persist();
        return { status: "failed", challengeId };
      }

      const now = new Date().toISOString();
      challenge.status = "verified";
      challenge.verifiedAt = now;

      const signature = this.signProof(challenge);
      this.state.proofs.push({
        challengeId: challenge.id,
        provider: challenge.provider,
        accountId: challenge.accountId,
        method: challenge.method,
        verifiedAt: now,
        signature
      });

      await this.persist();

      this.alertRouter.dispatch({
        severity: "info",
        category: "identity",
        message: `OAuth identity verified: ${challenge.provider}/${challenge.accountId}`,
        timestamp: now,
        metadata: { challengeId: challenge.id, method: "oauth" }
      }).catch(() => {});

      await this.audit.append({
        ts: now,
        event: "identity.verify",
        skillId: challenge.skillId,
        provider: challenge.provider,
        outcome: "identity_verified",
        details: {
          challengeId: challenge.id,
          provider: challenge.provider,
          accountId: challenge.accountId,
          method: "oauth"
        }
      });

      return { status: "verified", challengeId, verifiedAt: now };
    } catch {
      challenge.status = "failed";
      await this.persist();
      return { status: "failed", challengeId };
    }
  }

  public generateOAuthUrl(challengeId: string): string | null {
    const challenge = this.state.challenges[challengeId];
    if (!challenge || challenge.method !== "oauth") {
      return null;
    }

    const providerOAuth = OAUTH_PROVIDERS[challenge.provider];
    if (!providerOAuth) {
      return null;
    }

    const state = this.encodeOAuthState(challengeId);
    const params = new URLSearchParams({
      client_id: providerOAuth.clientId(),
      redirect_uri: this.getOAuthRedirectUri(),
      scope: providerOAuth.scope,
      state,
      response_type: "code"
    });

    return `${providerOAuth.authorizeUrl}?${params.toString()}`;
  }

  private encodeOAuthState(challengeId: string): string {
    const masterKey = this.vault.getMasterKey();
    const hmac = crypto.createHmac("sha256", masterKey).update(challengeId, "utf8").digest("hex").slice(0, 16);
    return `${challengeId}:${hmac}`;
  }

  private decodeOAuthState(state: string): string | null {
    const sep = state.lastIndexOf(":");
    if (sep <= 0 || sep >= state.length - 1) {
      return null;
    }
    const challengeId = state.slice(0, sep);
    const hmac = state.slice(sep + 1);
    const masterKey = this.vault.getMasterKey();
    const expected = crypto.createHmac("sha256", masterKey).update(challengeId, "utf8").digest("hex").slice(0, 16);
    const actual = Buffer.from(hmac, "utf8");
    const expectedBuf = Buffer.from(expected, "utf8");
    if (actual.length !== expectedBuf.length || !crypto.timingSafeEqual(actual, expectedBuf)) {
      return null;
    }
    return challengeId;
  }

  private getOAuthRedirectUri(): string {
    return process.env.CLAUTH_OAUTH_REDIRECT_URI ?? "http://127.0.0.1:4317/clauth/v1/identity/oauth/callback";
  }

  private async executeVerification(
    challenge: IdentityChallenge,
    proof: string
  ): Promise<boolean> {
    if (challenge.method === "signed-challenge") {
      return this.verifySignedChallenge(challenge, proof);
    }
    if (challenge.method === "email") {
      return this.verifyEmailCode(challenge, proof);
    }
    return false;
  }

  private verifyEmailCode(challenge: IdentityChallenge, proof: string): boolean {
    const normalized = proof.trim();
    if (!normalized) {
      return false;
    }
    const expected = this.signEmailCode(challenge.id, challenge.accountId, normalized);
    return timingSafeStringEqual(expected, challenge.challenge);
  }

  private async verifySignedChallenge(
    challenge: IdentityChallenge,
    proof: string
  ): Promise<boolean> {
    const endpoints = IDENTITY_ENDPOINTS[challenge.provider];
    if (!endpoints) {
      return false;
    }

    try {
      const parsedProof = parseSignedChallengeProof(proof);
      if (!parsedProof) {
        return false;
      }
      if (!timingSafeStringEqual(parsedProof.challenge, challenge.challenge)) {
        return false;
      }
      if (
        parsedProof.accountId &&
        parsedProof.accountId.trim().toLowerCase() !== challenge.accountId.trim().toLowerCase()
      ) {
        return false;
      }

      const credential = await this.vault.getCredential(
        parsedProof.credentialHandle,
        challenge.provider
      );

      const result = await endpoints.verifyOwnership(
        credential.secret,
        challenge.accountId,
        challenge.challenge
      );

      return result;
    } catch {
      return false;
    }
  }

  private async dispatchEmailChallenge(input: {
    challengeId: string;
    skillId: string;
    accountId: string;
    code: string;
    expiresAt: string;
  }): Promise<void> {
    const webhookUrl = process.env.CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL?.trim();
    if (!webhookUrl) {
      throw new ValidationError(
        "Email verification requires CLAUTH_EMAIL_CHALLENGE_WEBHOOK_URL to deliver challenge codes."
      );
    }

    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        challengeId: input.challengeId,
        skillId: input.skillId,
        provider: "email",
        accountId: input.accountId,
        code: input.code,
        expiresAt: input.expiresAt
      })
    });

    if (!response.ok) {
      throw new ValidationError(`Email challenge delivery failed (HTTP ${response.status}).`);
    }
  }

  private signEmailCode(challengeId: string, accountId: string, code: string): string {
    const masterKey = this.vault.getMasterKey();
    const message = `${challengeId}:${accountId.trim().toLowerCase()}:${code.trim()}`;
    return crypto.createHmac("sha256", masterKey).update(message, "utf8").digest("hex");
  }

  private signProof(challenge: IdentityChallenge): string {
    const masterKey = this.vault.getMasterKey();
    const data = `${challenge.id}:${challenge.provider}:${challenge.accountId}:${challenge.method}`;
    return crypto.createHmac("sha256", masterKey).update(data, "utf8").digest("hex");
  }
}

function canAccessChallenge(challenge: IdentityChallenge, access?: ChallengeAccess): boolean {
  if (!access || access.allowAnySkill) {
    return true;
  }
  if (!access.requesterSkillId) {
    return true;
  }
  return challenge.skillId === access.requesterSkillId;
}

function parseSignedChallengeProof(value: string): SignedChallengeProof | null {
  let decoded: unknown;
  try {
    decoded = JSON.parse(value) as unknown;
  } catch {
    return null;
  }

  if (!decoded || typeof decoded !== "object") {
    return null;
  }
  const obj = decoded as Record<string, unknown>;
  const credentialHandle =
    typeof obj.credentialHandle === "string" ? obj.credentialHandle.trim() : "";
  const challenge = typeof obj.challenge === "string" ? obj.challenge.trim() : "";
  const accountId = typeof obj.accountId === "string" ? obj.accountId.trim() : undefined;

  if (!credentialHandle || !challenge) {
    return null;
  }

  return {
    credentialHandle,
    challenge,
    accountId
  };
}

function generateEmailCode(): string {
  return crypto.randomInt(0, 1_000_000).toString().padStart(6, "0");
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

const OAUTH_PROVIDERS: Record<
  string,
  {
    authorizeUrl: string;
    tokenUrl: string;
    scope: string;
    clientId: () => string;
    clientSecret: () => string;
    verifyIdentity: (accessToken: string, accountId: string) => Promise<boolean>;
  }
> = {
  github: {
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scope: "read:user",
    clientId: () => process.env.CLAUTH_GITHUB_CLIENT_ID ?? "",
    clientSecret: () => process.env.CLAUTH_GITHUB_CLIENT_SECRET ?? "",
    async verifyIdentity(accessToken, accountId) {
      try {
        const response = await fetch("https://api.github.com/user", {
          headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" }
        });
        if (!response.ok) return false;
        const data = (await response.json()) as { login?: string };
        return data.login?.toLowerCase() === accountId.toLowerCase();
      } catch {
        return false;
      }
    }
  },
  twitter: {
    authorizeUrl: "https://twitter.com/i/oauth2/authorize",
    tokenUrl: "https://api.twitter.com/2/oauth2/token",
    scope: "users.read tweet.read",
    clientId: () => process.env.CLAUTH_TWITTER_CLIENT_ID ?? "",
    clientSecret: () => process.env.CLAUTH_TWITTER_CLIENT_SECRET ?? "",
    async verifyIdentity(accessToken, accountId) {
      try {
        const response = await fetch("https://api.twitter.com/2/users/me", {
          headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" }
        });
        if (!response.ok) return false;
        const data = (await response.json()) as { data?: { username?: string } };
        return data.data?.username?.toLowerCase() === accountId.toLowerCase();
      } catch {
        return false;
      }
    }
  }
};

const IDENTITY_ENDPOINTS: Record<
  string,
  {
    verifyOwnership: (
      credential: string,
      accountId: string,
      challenge: string
    ) => Promise<boolean>;
  }
> = {
  github: {
    async verifyOwnership(credential, accountId) {
      try {
        const response = await fetch("https://api.github.com/user", {
          headers: { authorization: `Bearer ${credential}`, accept: "application/json" }
        });
        if (!response.ok) {
          return false;
        }
        const data = (await response.json()) as { login?: string };
        return data.login?.toLowerCase() === accountId.toLowerCase();
      } catch {
        return false;
      }
    }
  },
  twitter: {
    async verifyOwnership(credential, accountId) {
      try {
        const response = await fetch("https://api.twitter.com/2/users/me", {
          headers: { authorization: `Bearer ${credential}`, accept: "application/json" }
        });
        if (!response.ok) {
          return false;
        }
        const data = (await response.json()) as { data?: { username?: string } };
        return data.data?.username?.toLowerCase() === accountId.toLowerCase();
      } catch {
        return false;
      }
    }
  },
  slack: {
    async verifyOwnership(credential, accountId) {
      try {
        const response = await fetch("https://slack.com/api/auth.test", {
          headers: { authorization: `Bearer ${credential}`, accept: "application/json" }
        });
        if (!response.ok) {
          return false;
        }
        const data = (await response.json()) as { ok?: boolean; user_id?: string };
        return data.ok === true && data.user_id === accountId;
      } catch {
        return false;
      }
    }
  }
};
