import test from "node:test";
import assert from "node:assert/strict";
import {
  buildActivationCommands,
  buildServicePlan,
  defaultDestinationPath,
  defaultGeneratedPath,
  defaultServiceName,
  formatProcessCommand,
  shellQuote
} from "../src/cli/service-utils.js";

test("default service names are target-specific", () => {
  assert.equal(defaultServiceName("systemd"), "clauth");
  assert.equal(defaultServiceName("launchd"), "com.clauth.daemon");
});

test("default path helpers resolve expected suffixes", () => {
  assert.equal(defaultGeneratedPath("systemd", "/tmp/clauth", "clauth"), "/tmp/clauth/clauth.service");
  assert.equal(defaultGeneratedPath("launchd", "/tmp/clauth", "com.clauth.daemon"), "/tmp/clauth/com.clauth.daemon.plist");

  assert.equal(defaultDestinationPath("systemd", "clauth"), "/etc/systemd/system/clauth.service");
  assert.match(defaultDestinationPath("launchd", "com.clauth.daemon", "/Users/alice"), /\/Users\/alice\/Library\/LaunchAgents\/com\.clauth\.daemon\.plist$/);
});

test("buildServicePlan emits systemd command sequence", () => {
  const plan = buildServicePlan({
    target: "systemd",
    name: "clauth",
    sourcePath: "/tmp/clauth.service",
    destinationPath: "/etc/systemd/system/clauth.service",
    envFile: "/tmp/clauth.env",
    passphraseFile: "/tmp/passphrase"
  });

  assert.equal(plan.commands.length, 3);
  assert.match(plan.commands[0], /sudo cp/);
  assert.match(plan.commands[2], /systemctl enable --now 'clauth\.service'/);
});

test("buildActivationCommands returns expected systemd steps", () => {
  const steps = buildActivationCommands("systemd", "clauth", "/etc/systemd/system/clauth.service");
  assert.equal(steps.length, 2);
  assert.deepEqual(steps[0], { command: "systemctl", args: ["daemon-reload"] });
  assert.deepEqual(steps[1], { command: "systemctl", args: ["enable", "--now", "clauth.service"] });
});

test("buildActivationCommands returns expected launchd steps", () => {
  const destination = "/Users/alice/Library/LaunchAgents/com.clauth.daemon.plist";
  const steps = buildActivationCommands("launchd", "com.clauth.daemon", destination);
  assert.equal(steps.length, 2);
  assert.equal(steps[0].command, "launchctl");
  assert.equal(steps[0].allowFailure, true);
  assert.deepEqual(steps[1], { command: "launchctl", args: ["load", "-w", destination] });
});

test("formatProcessCommand renders quoted shell command", () => {
  const text = formatProcessCommand({ command: "launchctl", args: ["load", "-w", "/tmp/a b.plist"] });
  assert.equal(text, "launchctl 'load' '-w' '/tmp/a b.plist'");
});

test("shellQuote escapes single quotes", () => {
  assert.equal(shellQuote("abc"), "'abc'");
  assert.equal(shellQuote("a'b"), "'a'\\''b'");
});
