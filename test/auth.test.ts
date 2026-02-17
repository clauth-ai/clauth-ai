import test from "node:test";
import assert from "node:assert/strict";
import { buildAuthHeaders } from "../src/providers/auth.js";
import type { StoredCredential } from "../src/types/index.js";

function makeCred(overrides?: Partial<StoredCredential>): StoredCredential {
  return {
    handle: "test-cred",
    provider: "github",
    secret: "test-secret-value",
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

test("bearer auth for known providers", () => {
  const providers = ["github", "openai", "stripe", "twitter", "x", "slack", "discord", "google", "moltbook"];
  for (const provider of providers) {
    const headers = buildAuthHeaders(provider, makeCred({ provider }));
    assert.equal(headers.authorization, "Bearer test-secret-value");
    assert.equal(Object.keys(headers).length, 1);
  }
});

test("api-key fallback for unknown providers", () => {
  const headers = buildAuthHeaders("custom-service", makeCred({ provider: "custom-service" }));
  assert.equal(headers["x-api-key"], "test-secret-value");
  assert.equal(Object.keys(headers).length, 1);
});

test("explicit authType=bearer overrides inference", () => {
  const headers = buildAuthHeaders(
    "custom-service",
    makeCred({
      provider: "custom-service",
      metadata: { authType: "bearer" },
    })
  );
  assert.equal(headers.authorization, "Bearer test-secret-value");
});

test("explicit authType=api-key with default header name", () => {
  const headers = buildAuthHeaders(
    "github",
    makeCred({
      metadata: { authType: "api-key" },
    })
  );
  assert.equal(headers["x-api-key"], "test-secret-value");
});

test("explicit authType=api-key with custom header name", () => {
  const headers = buildAuthHeaders(
    "openai",
    makeCred({
      provider: "openai",
      metadata: { authType: "api-key", headerName: "Authorization" },
    })
  );
  assert.equal(headers["Authorization"], "test-secret-value");
});

test("explicit authType=basic produces Basic header", () => {
  const encoded = Buffer.from("user:pass").toString("base64");
  const headers = buildAuthHeaders(
    "jira",
    makeCred({
      provider: "jira",
      secret: encoded,
      metadata: { authType: "basic" },
    })
  );
  assert.equal(headers.authorization, `Basic ${encoded}`);
});

test("unknown authType falls back to bearer", () => {
  const headers = buildAuthHeaders(
    "github",
    makeCred({
      metadata: { authType: "carrier-pigeon" },
    })
  );
  assert.equal(headers.authorization, "Bearer test-secret-value");
});

test("provider name is case-insensitive for inference", () => {
  // buildAuthHeaders receives an already-lowercased provider from proxy.ts,
  // but the inference function lowercases too
  const headers = buildAuthHeaders("GitHub", makeCred({ provider: "GitHub" }));
  assert.equal(headers.authorization, "Bearer test-secret-value");
});
