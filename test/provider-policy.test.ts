import test from "node:test";
import assert from "node:assert/strict";
import { assertEndpointAllowed } from "../src/providers/policy.js";

const credential = {
  handle: "h",
  provider: "github",
  secret: "s",
  createdAt: new Date().toISOString(),
  metadata: undefined
};

test("known provider allows expected host", () => {
  assert.doesNotThrow(() => {
    assertEndpointAllowed("github", "https://api.github.com/user", credential);
  });
});

test("openai provider allows expected host", () => {
  assert.doesNotThrow(() => {
    assertEndpointAllowed("openai", "https://api.openai.com/v1/models", {
      ...credential,
      provider: "openai"
    });
  });
});

test("stripe provider allows expected host", () => {
  assert.doesNotThrow(() => {
    assertEndpointAllowed("stripe", "https://api.stripe.com/v1/charges", {
      ...credential,
      provider: "stripe"
    });
  });
});

test("known provider rejects unexpected host", () => {
  assert.throws(() => {
    assertEndpointAllowed("github", "https://evil.example.com/collect", credential);
  });
});

test("explicit allowedHosts metadata supports custom provider", () => {
  assert.doesNotThrow(() => {
    assertEndpointAllowed(
      "custom",
      "https://api.custom.example.com/v1",
      {
        ...credential,
        provider: "custom",
        metadata: { allowedHosts: "api.custom.example.com,*.svc.custom.example.com" }
      }
    );
  });
});

test("explicit wildcard host metadata rejects non-matching host", () => {
  assert.throws(() => {
    assertEndpointAllowed(
      "custom",
      "https://api.other.example.com/v1",
      {
        ...credential,
        provider: "custom",
        metadata: { allowedHosts: "*.svc.custom.example.com" }
      }
    );
  });
});
