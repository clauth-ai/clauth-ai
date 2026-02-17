import test from "node:test";
import assert from "node:assert/strict";
import { parseAdvisory } from "../src/core/advisory.js";
import type { AdvisorySource } from "../src/types/index.js";

const SOURCE: AdvisorySource = {
  name: "github",
  url: "https://api.github.com/advisories",
  type: "github"
};

test("parseAdvisory extracts package from vulnerabilities package object", () => {
  const advisory = parseAdvisory(
    {
      ghsa_id: "GHSA-1234-abcd",
      severity: "high",
      summary: "Critical provider incident",
      vulnerabilities: [
        {
          package: {
            ecosystem: "actions",
            name: "github"
          }
        }
      ]
    },
    SOURCE
  );

  assert.ok(advisory);
  assert.equal(advisory.severity, "critical");
  assert.equal(advisory.affectedPackage, "github");
});

test("parseAdvisory extracts package from affected entries", () => {
  const advisory = parseAdvisory(
    {
      id: "ADV-200",
      severity: "moderate",
      description: "Moderate issue",
      affected: [
        {
          package: {
            name: "slack"
          }
        }
      ]
    },
    SOURCE
  );

  assert.ok(advisory);
  assert.equal(advisory.severity, "warning");
  assert.equal(advisory.affectedPackage, "slack");
});

test("parseAdvisory supports direct package fields and normalizes case", () => {
  const advisory = parseAdvisory(
    {
      id: "ADV-300",
      severity: "critical",
      summary: "Critical incident",
      package: "GitHub"
    },
    SOURCE
  );

  assert.ok(advisory);
  assert.equal(advisory.affectedPackage, "github");
});

test("parseAdvisory returns null for advisory payload without identifier", () => {
  const advisory = parseAdvisory(
    {
      severity: "high",
      summary: "No ID payload"
    },
    SOURCE
  );

  assert.equal(advisory, null);
});

test("parseAdvisory collects multiple affected packages and deduplicates", () => {
  const advisory = parseAdvisory(
    {
      id: "ADV-400",
      severity: "high",
      summary: "Multi-package advisory",
      vulnerabilities: [
        { package: { name: "actions/toolkit" } },
        { package: { name: "SLACK/web-api" } }
      ],
      affected: [
        { package: { name: "actions/toolkit" } },
        { package: { name: "discord.js" } }
      ]
    },
    SOURCE
  );

  assert.ok(advisory);
  assert.equal(advisory.affectedPackage, "actions/toolkit");
  assert.deepEqual(advisory.affectedPackages, [
    "actions/toolkit",
    "slack/web-api",
    "discord.js"
  ]);
});
