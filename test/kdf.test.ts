import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { deriveKey } from "../src/core/kdf.js";
import type { KdfParams } from "../src/core/kdf.js";
import { ValidationError } from "../src/core/errors.js";

const TEST_PARAMS: KdfParams = {
  memory: 64 * 1024,
  parallelism: 1,
  iterations: 3,
  tagLength: 32,
};

test("deriveKey rejects empty passphrase", () => {
  const salt = crypto.randomBytes(16);
  assert.throws(
    () => deriveKey("", salt, TEST_PARAMS),
    (err: unknown) => err instanceof ValidationError
  );
});

test("deriveKey rejects passphrase shorter than 12 characters", () => {
  const salt = crypto.randomBytes(16);
  assert.throws(
    () => deriveKey("short", salt, TEST_PARAMS),
    (err: unknown) => err instanceof ValidationError
  );
});

test("deriveKey accepts passphrase of exactly 12 characters", () => {
  const salt = crypto.randomBytes(16);
  const result = deriveKey("exactly12chr", salt, TEST_PARAMS);
  assert.equal(result.key.length, TEST_PARAMS.tagLength);
  assert.ok(["argon2id", "scrypt"].includes(result.algorithm));
});

test("deriveKey produces correct length output", () => {
  const salt = crypto.randomBytes(16);
  const result = deriveKey("correct horse battery staple", salt, TEST_PARAMS);
  assert.equal(result.key.length, 32);
});

test("deriveKey produces deterministic output for same inputs", () => {
  const salt = crypto.randomBytes(16);
  const a = deriveKey("correct horse battery staple", salt, TEST_PARAMS);
  const b = deriveKey("correct horse battery staple", salt, TEST_PARAMS);
  assert.ok(a.key.equals(b.key));
  assert.equal(a.algorithm, b.algorithm);
});

test("deriveKey produces different output for different passphrases", () => {
  const salt = crypto.randomBytes(16);
  const a = deriveKey("correct horse battery staple", salt, TEST_PARAMS);
  const b = deriveKey("another passphrase here!", salt, TEST_PARAMS);
  assert.ok(!a.key.equals(b.key));
});

test("deriveKey produces different output for different salts", () => {
  const saltA = crypto.randomBytes(16);
  const saltB = crypto.randomBytes(16);
  const a = deriveKey("correct horse battery staple", saltA, TEST_PARAMS);
  const b = deriveKey("correct horse battery staple", saltB, TEST_PARAMS);
  assert.ok(!a.key.equals(b.key));
});

test("explicit scrypt algorithm works", () => {
  const salt = crypto.randomBytes(16);
  const result = deriveKey("correct horse battery staple", salt, TEST_PARAMS, "scrypt");
  assert.equal(result.algorithm, "scrypt");
  assert.equal(result.key.length, 32);
});

test(
  "explicit argon2id algorithm rejects when runtime does not support it",
  { skip: typeof (crypto as unknown as { argon2Sync?: Function }).argon2Sync === "function" },
  () => {
  const salt = crypto.randomBytes(16);
    assert.throws(
      () => deriveKey("correct horse battery staple", salt, TEST_PARAMS, "argon2id"),
      (err: unknown) => err instanceof ValidationError
    );
  }
);
