import test from "node:test";
import assert from "node:assert/strict";
import { renderServiceTemplate } from "../src/cli/service-templates.js";

test("renders systemd template", () => {
  const rendered = renderServiceTemplate("systemd", {
    name: "clauth",
    cwd: "/opt/clauth",
    nodeBin: "/usr/bin/node",
    daemonScript: "/opt/clauth/dist/daemon/server.js",
    clauthHome: "/home/user/.clauth",
    envFile: "/home/user/.clauth/clauth.env",
    passphraseFile: "/home/user/.clauth/passphrase"
  });

  assert.match(rendered, /\[Unit\]/);
  assert.match(rendered, /EnvironmentFile=\/home\/user\/\.clauth\/clauth\.env/);
});

test("renders launchd template", () => {
  const rendered = renderServiceTemplate("launchd", {
    name: "com.clauth.daemon",
    cwd: "/Users/alice/clauth",
    nodeBin: "/usr/local/bin/node",
    daemonScript: "/Users/alice/clauth/dist/daemon/server.js",
    clauthHome: "/Users/alice/.clauth",
    envFile: "/Users/alice/.clauth/clauth.env",
    passphraseFile: "/Users/alice/.clauth/passphrase"
  });

  assert.match(rendered, /<plist version="1\.0">/);
  assert.match(rendered, /CLAUTH_PASSPHRASE_FILE/);
  assert.match(rendered, /\/Users\/alice\/\.clauth\/passphrase/);
});
