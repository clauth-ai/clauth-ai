import os from "node:os";
import path from "node:path";
import type { ServiceTarget } from "./service-templates.js";

export interface ServicePlan {
  target: ServiceTarget;
  name: string;
  sourcePath: string;
  destinationPath: string;
  envFile: string;
  passphraseFile: string;
  commands: string[];
}

export interface ProcessCommand {
  command: string;
  args: string[];
  allowFailure?: boolean;
}

export function defaultServiceName(target: ServiceTarget): string {
  return target === "systemd" ? "clauth" : "com.clauth.daemon";
}

export function defaultGeneratedPath(target: ServiceTarget, clauthHome: string, name: string): string {
  return target === "systemd"
    ? path.join(clauthHome, `${name}.service`)
    : path.join(clauthHome, `${name}.plist`);
}

export function defaultDestinationPath(target: ServiceTarget, name: string, homeDir = os.homedir()): string {
  return target === "systemd"
    ? path.join("/etc/systemd/system", `${name}.service`)
    : path.join(homeDir, "Library", "LaunchAgents", `${name}.plist`);
}

export function buildServicePlan(input: {
  target: ServiceTarget;
  name: string;
  sourcePath: string;
  destinationPath: string;
  envFile: string;
  passphraseFile: string;
}): ServicePlan {
  const { target, name, sourcePath, destinationPath, envFile, passphraseFile } = input;

  const commands =
    target === "systemd"
      ? [
          `sudo cp ${shellQuote(sourcePath)} ${shellQuote(destinationPath)}`,
          `sudo systemctl daemon-reload`,
          `sudo systemctl enable --now ${shellQuote(`${name}.service`)}`
        ]
      : [
          `cp ${shellQuote(sourcePath)} ${shellQuote(destinationPath)}`,
          `launchctl unload -w ${shellQuote(destinationPath)} || true`,
          `launchctl load -w ${shellQuote(destinationPath)}`
        ];

  return {
    target,
    name,
    sourcePath,
    destinationPath,
    envFile,
    passphraseFile,
    commands
  };
}

export function shellQuote(value: string): string {
  if (!value) {
    return "''";
  }

  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function buildActivationCommands(target: ServiceTarget, name: string, destinationPath: string): ProcessCommand[] {
  if (target === "systemd") {
    return [
      {
        command: "systemctl",
        args: ["daemon-reload"]
      },
      {
        command: "systemctl",
        args: ["enable", "--now", `${name}.service`]
      }
    ];
  }

  return [
    {
      command: "launchctl",
      args: ["unload", "-w", destinationPath],
      allowFailure: true
    },
    {
      command: "launchctl",
      args: ["load", "-w", destinationPath]
    }
  ];
}

export function formatProcessCommand(step: ProcessCommand): string {
  return [step.command, ...step.args.map((arg) => shellQuote(arg))].join(" ");
}
