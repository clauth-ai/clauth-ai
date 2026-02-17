import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { loadConfig } from "../src/core/config.js";
import { Vault } from "../src/core/vault.js";

const PASSPHRASE = "correct horse battery staple";
const CLI_ENTRY = [
  "--experimental-strip-types",
  "--import",
  "./scripts/register-loader.mjs",
  "src/cli/index.ts"
];

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function withTempHome(run: (env: NodeJS.ProcessEnv) => Promise<void>): Promise<void> {
  const temp = await mkdtemp(path.join(os.tmpdir(), "clauth-cli-store-test-"));
  const originalHome = process.env.CLAUTH_HOME;
  const originalPassphrase = process.env.CLAUTH_PASSPHRASE;

  process.env.CLAUTH_HOME = temp;
  process.env.CLAUTH_PASSPHRASE = PASSPHRASE;

  try {
    await run({
      ...process.env,
      CLAUTH_HOME: temp,
      CLAUTH_PASSPHRASE: PASSPHRASE
    });
  } finally {
    if (originalHome === undefined) {
      delete process.env.CLAUTH_HOME;
    } else {
      process.env.CLAUTH_HOME = originalHome;
    }
    if (originalPassphrase === undefined) {
      delete process.env.CLAUTH_PASSPHRASE;
    } else {
      process.env.CLAUTH_PASSPHRASE = originalPassphrase;
    }
    await rm(temp, { recursive: true, force: true });
  }
}

function runCli(args: string[], env: NodeJS.ProcessEnv, stdinInput?: string): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...CLI_ENTRY, ...args], {
      cwd: process.cwd(),
      env,
      stdio: ["pipe", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? -1,
        stdout,
        stderr
      });
    });

    if (stdinInput !== undefined) {
      child.stdin.end(stdinInput);
      return;
    }
    child.stdin.end();
  });
}

async function initClauth(env: NodeJS.ProcessEnv): Promise<void> {
  const result = await runCli(["init"], env);
  assert.equal(result.code, 0, `init failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
}

test("cli store supports --secret-env", async () => {
  await withTempHome(async (baseEnv) => {
    await initClauth(baseEnv);
    const env = { ...baseEnv, TEST_SECRET: "env-secret-abc" };

    const store = await runCli(
      ["store", "--handle", "github-main", "--provider", "github", "--secret-env", "TEST_SECRET"],
      env
    );
    assert.equal(store.code, 0, `store failed\nstdout:\n${store.stdout}\nstderr:\n${store.stderr}`);

    const vault = new Vault(await loadConfig());
    await vault.unlock(PASSPHRASE);
    const credential = await vault.getCredential("github-main", "github");
    assert.equal(credential.secret, "env-secret-abc");
    vault.lock();
  });
});

test("cli store supports --secret-stdin", async () => {
  await withTempHome(async (env) => {
    await initClauth(env);

    const store = await runCli(
      ["store", "--handle", "github-main", "--provider", "github", "--secret-stdin"],
      env,
      "stdin-secret-xyz\n"
    );
    assert.equal(store.code, 0, `store failed\nstdout:\n${store.stdout}\nstderr:\n${store.stderr}`);

    const vault = new Vault(await loadConfig());
    await vault.unlock(PASSPHRASE);
    const credential = await vault.getCredential("github-main", "github");
    assert.equal(credential.secret, "stdin-secret-xyz");
    vault.lock();
  });
});

test("cli store rejects multiple secret sources", async () => {
  await withTempHome(async (baseEnv) => {
    await initClauth(baseEnv);
    const env = { ...baseEnv, TEST_SECRET: "env-secret-abc" };

    const store = await runCli(
      [
        "store",
        "--handle",
        "github-main",
        "--provider",
        "github",
        "--secret-env",
        "TEST_SECRET",
        "--secret-stdin"
      ],
      env,
      "stdin-secret"
    );
    assert.notEqual(store.code, 0);
    assert.match(store.stderr, /Use exactly one secret source/);
  });
});

test("cli store rejects deprecated --secret flag", async () => {
  await withTempHome(async (env) => {
    await initClauth(env);

    const store = await runCli(
      ["store", "--handle", "github-main", "--provider", "github", "--secret", "inline-secret"],
      env
    );
    assert.notEqual(store.code, 0);
    assert.match(store.stderr, /--secret is no longer supported/);
  });
});
