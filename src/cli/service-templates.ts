import path from "node:path";

export type ServiceTarget = "systemd" | "launchd";

interface TemplateInput {
  name: string;
  cwd: string;
  nodeBin: string;
  daemonScript: string;
  clauthHome: string;
  envFile: string;
  passphraseFile: string;
}

export function renderServiceTemplate(target: ServiceTarget, input: TemplateInput): string {
  if (target === "systemd") {
    return renderSystemd(input);
  }
  return renderLaunchd(input);
}

function renderSystemd(input: TemplateInput): string {
  return `[Unit]
Description=Clauth Daemon (${input.name})
After=network.target

[Service]
Type=simple
WorkingDirectory=${input.cwd}
ExecStart=${input.nodeBin} ${input.daemonScript}
Restart=on-failure
RestartSec=3
Environment=CLAUTH_HOME=${input.clauthHome}
EnvironmentFile=${input.envFile}

# Optional hardening flags you can enable if they fit your environment:
# NoNewPrivileges=true
# PrivateTmp=true
# ProtectSystem=strict
# ProtectHome=true

[Install]
WantedBy=multi-user.target
`;
}

function renderLaunchd(input: TemplateInput): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>${input.name}</string>

    <key>ProgramArguments</key>
    <array>
      <string>${input.nodeBin}</string>
      <string>${input.daemonScript}</string>
    </array>

    <key>WorkingDirectory</key>
    <string>${input.cwd}</string>

    <key>EnvironmentVariables</key>
    <dict>
      <key>CLAUTH_HOME</key>
      <string>${input.clauthHome}</string>
      <key>CLAUTH_PASSPHRASE_FILE</key>
      <string>${input.passphraseFile}</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>${path.join(input.clauthHome, "clauth.stdout.log")}</string>
    <key>StandardErrorPath</key>
    <string>${path.join(input.clauthHome, "clauth.stderr.log")}</string>
  </dict>
</plist>
`;
}
