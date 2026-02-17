import type { ClauthConfig } from "./config.js";
import type { AlertChannel, AlertEvent, AlertSeverity } from "../types/index.js";

const SEVERITY_LEVELS: Record<AlertSeverity, number> = {
  info: 0,
  warning: 1,
  critical: 2
};

export class AlertRouter {
  private channels: AlertChannel[] = [];
  private readonly config: ClauthConfig;

  constructor(config: ClauthConfig) {
    this.config = config;
  }

  public async load(): Promise<void> {
    this.channels = (this.config.alertChannels ?? []).map((ch) => ({ ...ch }));
  }

  public getChannels(): AlertChannel[] {
    return this.channels.map((ch) => ({ ...ch }));
  }

  public async dispatch(event: AlertEvent): Promise<{ sent: number; failed: number }> {
    const matching = this.channels.filter(
      (ch) => SEVERITY_LEVELS[event.severity] >= SEVERITY_LEVELS[ch.minSeverity]
    );

    let sent = 0;
    let failed = 0;

    const promises = matching.map(async (channel) => {
      try {
        await fetch(channel.url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            severity: event.severity,
            category: event.category,
            message: event.message,
            timestamp: event.timestamp,
            metadata: event.metadata
          })
        });
        sent += 1;
      } catch {
        failed += 1;
      }
    });

    await Promise.allSettled(promises);

    return { sent, failed };
  }

  public async testWebhook(url: string): Promise<boolean> {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          severity: "info",
          category: "test",
          message: "Clauth alert test",
          timestamp: new Date().toISOString(),
          metadata: { test: true }
        })
      });
      return response.ok;
    } catch {
      return false;
    }
  }
}
