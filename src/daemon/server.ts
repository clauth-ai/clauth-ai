import { promises as fs } from "node:fs";
import { buildRuntime } from "./runtime.js";
import { createClauthServer, listenClauthServer } from "./app.js";

let passphrase: string | undefined;
try {
  passphrase = await resolvePassphrase();
} catch (error) {
  console.error(`Failed to resolve passphrase: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
if (!passphrase) {
  console.error("CLAUTH_PASSPHRASE or CLAUTH_PASSPHRASE_FILE is required to start daemon.");
  process.exit(1);
}

const runtime = await buildRuntime(passphrase);
const server = createClauthServer(runtime);
const listening = await listenClauthServer(server, runtime);
console.log(`Clauth daemon listening on ${listening.endpoint}`);

async function resolvePassphrase(): Promise<string | undefined> {
  const direct = process.env.CLAUTH_PASSPHRASE;
  if (direct) {
    return direct;
  }

  const passphraseFile = process.env.CLAUTH_PASSPHRASE_FILE;
  if (!passphraseFile) {
    return undefined;
  }

  const raw = await fs.readFile(passphraseFile, "utf8");
  const trimmed = raw.trim();
  return trimmed || undefined;
}
