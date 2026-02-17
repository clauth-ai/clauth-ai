import crypto from "node:crypto";
import { ValidationError } from "./errors.js";

export interface KdfParams {
  memory: number;
  parallelism: number;
  iterations: number;
  tagLength: number;
}

export interface KdfDescriptor {
  algorithm: "argon2id" | "scrypt";
  params: KdfParams;
  salt: string;
}

const SCRYPT_MAXMEM = 1024 * 1024 * 1024;

export function deriveKey(
  passphrase: string,
  salt: Buffer,
  params: KdfParams,
  requestedAlgorithm?: "argon2id" | "scrypt"
): { key: Buffer; algorithm: "argon2id" | "scrypt" } {
  if (!passphrase || passphrase.length < 12) {
    throw new ValidationError("Passphrase must be at least 12 characters.");
  }

  if (requestedAlgorithm === "scrypt") {
    const key = crypto.scryptSync(passphrase, salt, params.tagLength, {
      N: 1 << 18,
      r: 8,
      p: Math.max(1, params.parallelism),
      maxmem: SCRYPT_MAXMEM
    });
    return { key, algorithm: "scrypt" };
  }

  const argon2Sync = (crypto as unknown as { argon2Sync?: Function }).argon2Sync;
  if (typeof argon2Sync === "function") {
    const key = argon2Sync("argon2id", {
      message: Buffer.from(passphrase, "utf8"),
      nonce: salt,
      memory: params.memory,
      parallelism: params.parallelism,
      passes: params.iterations,
      tagLength: params.tagLength
    }) as Buffer;

    return { key, algorithm: "argon2id" };
  }

  if (requestedAlgorithm === "argon2id") {
    throw new ValidationError("Vault requires Argon2id but the runtime does not support it.");
  }

  const key = crypto.scryptSync(passphrase, salt, params.tagLength, {
    N: 1 << 18,
    r: 8,
    p: Math.max(1, params.parallelism),
    maxmem: SCRYPT_MAXMEM
  });

  return { key, algorithm: "scrypt" };
}
