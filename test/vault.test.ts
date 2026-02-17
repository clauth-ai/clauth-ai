import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import * as crypto from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { defaultConfig, saveConfig } from "../src/core/config.js";
import { NotFoundError, ValidationError } from "../src/core/errors.js";
import { Vault } from "../src/core/vault.js";
import { resolveClauthPaths } from "../src/core/fs.js";

async function withTempHome(run: (home: string) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-vault-test-"));
  const originalHome = process.env.CLAUTH_HOME;

  process.env.CLAUTH_HOME = temp;

  try {
    await run(temp);
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }

    await rm(temp, { recursive: true, force: true });
  }
}

test("vault encrypts, reads, and prunes expired credentials", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    const vault = new Vault(config);
    await vault.unlock("correct horse battery staple");

    await vault.storeCredential({
      handle: "github-main",
      provider: "github",
      secret: "ghp_example",
      ttlSeconds: 1,
      metadata: { authType: "bearer" }
    });

    const fetched = await vault.getCredential("github-main", "github");
    assert.equal(fetched.secret, "ghp_example");

    const metadata = await vault.listCredentialMetadata();
    assert.equal(metadata.length, 1);
    assert.equal((metadata[0] as { secret?: string }).secret, undefined);

    await new Promise((resolve) => setTimeout(resolve, 1100));

    await assert.rejects(async () => {
      await vault.getCredential("github-main", "github");
    }, NotFoundError);

    vault.lock();
  });
});

test("vault preserves active KDF descriptor across writes", async () => {
  await withTempHome(async () => {
    const baseConfig = defaultConfig();
    await saveConfig(baseConfig);

    const initialVault = new Vault(baseConfig);
    await initialVault.unlock("correct horse battery staple");
    await initialVault.storeCredential({
      handle: "github-main",
      provider: "github",
      secret: "ghp_initial"
    });
    initialVault.lock();

    const vaultFile = resolveClauthPaths().vaultFile;
    const firstEnvelope = JSON.parse(await readFile(vaultFile, "utf8")) as {
      kdf: { algorithm: string; salt: string; params: { iterations: number } };
    };

    const driftedConfig = {
      ...baseConfig,
      vaultSalt: crypto.randomBytes(16).toString("base64url"),
      kdf: {
        ...baseConfig.kdf,
        iterations: baseConfig.kdf.iterations + 5
      }
    };

    const secondVault = new Vault(driftedConfig);
    await secondVault.unlock("correct horse battery staple");
    await secondVault.storeCredential({
      handle: "github-backup",
      provider: "github",
      secret: "ghp_backup"
    });
    secondVault.lock();

    const secondEnvelope = JSON.parse(await readFile(vaultFile, "utf8")) as {
      kdf: { algorithm: string; salt: string; params: { iterations: number } };
    };

    assert.equal(secondEnvelope.kdf.algorithm, firstEnvelope.kdf.algorithm);
    assert.equal(secondEnvelope.kdf.salt, firstEnvelope.kdf.salt);
    assert.equal(secondEnvelope.kdf.params.iterations, firstEnvelope.kdf.params.iterations);

    const restartedVault = new Vault(driftedConfig);
    await restartedVault.unlock("correct horse battery staple");

    const primary = await restartedVault.getCredential("github-main", "github");
    const backup = await restartedVault.getCredential("github-backup", "github");
    assert.equal(primary.secret, "ghp_initial");
    assert.equal(backup.secret, "ghp_backup");

    restartedVault.lock();
  });
});

test("vault unlock fails closed for malformed vault file", async () => {
  await withTempHome(async () => {
    const config = defaultConfig();
    await saveConfig(config);

    await writeFile(resolveClauthPaths().vaultFile, "{broken-json", "utf8");

    const vault = new Vault(config);
    await assert.rejects(
      async () => {
        await vault.unlock("correct horse battery staple");
      },
      (error: unknown) => error instanceof ValidationError
    );
  });
});
