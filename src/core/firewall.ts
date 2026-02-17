import type { ClauthConfig } from "./config.js";
import { ensureDir, readJsonFile, resolveClauthPaths, writeJsonFileAtomic } from "./fs.js";
import type { AlertRouter } from "./alerts.js";
import type { FirewallDecision, RequestContext } from "../types/index.js";

interface SkillBaseline {
  firstSeen: number;
  totalRequests: number;
  recentTimestamps: number[];
  seenEndpoints: string[];
}

interface FirewallStore {
  skills: Record<string, SkillBaseline>;
}

const EMPTY_FIREWALL_STORE: FirewallStore = { skills: {} };

export class BehavioralFirewall {
  private readonly config: ClauthConfig;
  private store: FirewallStore = structuredClone(EMPTY_FIREWALL_STORE);
  private alertRouter?: AlertRouter;

  constructor(config: ClauthConfig) {
    this.config = config;
  }

  public setAlertRouter(router: AlertRouter): void {
    this.alertRouter = router;
  }

  public async load(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    this.store = await readJsonFile<FirewallStore>(paths.firewallFile, structuredClone(EMPTY_FIREWALL_STORE));
  }

  public async evaluate(context: RequestContext, input?: { scopeDenied?: boolean }): Promise<FirewallDecision> {
    const reasons: string[] = [];
    let severity: FirewallDecision["severity"] = "info";
    let allowed = true;

    const skillState = this.getOrCreateSkill(context.skillId, context.timestamp);
    const now = context.timestamp;

    const burstCutoff = now - this.config.firewall.burstWindowMs;
    const rollingCutoff = now - Math.max(this.config.firewall.burstWindowMs, 60_000);
    skillState.recentTimestamps = skillState.recentTimestamps.filter((ts) => ts >= rollingCutoff);
    skillState.recentTimestamps.push(now);

    const burstCount = skillState.recentTimestamps.filter((ts) => ts >= burstCutoff).length;
    if (burstCount > this.config.firewall.burstLimit) {
      reasons.push(`Burst threshold exceeded (${burstCount} in ${this.config.firewall.burstWindowMs}ms).`);
      severity = "critical";
      allowed = false;
    }

    const requestsInLastMinute = skillState.recentTimestamps.filter((ts) => ts >= now - 60_000).length;
    const elapsedMinutes = Math.max((now - skillState.firstSeen) / 60_000, 1);
    const averageRpm = skillState.totalRequests / elapsedMinutes;

    if (
      skillState.totalRequests >= this.config.firewall.minWarmupRequests &&
      requestsInLastMinute > averageRpm * this.config.firewall.rateSpikeMultiplier
    ) {
      reasons.push(`Rate spike detected (${requestsInLastMinute}/min vs baseline ${averageRpm.toFixed(2)}/min).`);
      severity = severity === "critical" ? "critical" : "warn";
    }

    if (
      skillState.totalRequests >= this.config.firewall.minWarmupRequests &&
      !skillState.seenEndpoints.includes(context.endpoint)
    ) {
      reasons.push(`New endpoint detected: ${context.endpoint}`);
      severity = severity === "critical" ? "critical" : "warn";
    }

    const localHour = new Date(now).getHours();
    if (isOffHours(localHour, this.config.firewall.offHoursStart, this.config.firewall.offHoursEnd)) {
      reasons.push(`Off-hours activity detected at ${localHour}:00 local time.`);
      severity = severity === "critical" ? "critical" : "warn";
    }

    if (input?.scopeDenied) {
      reasons.push("Scope creep attempt detected (requested unauthorized scope).");
      severity = "critical";
      allowed = false;
    }

    if (!skillState.seenEndpoints.includes(context.endpoint)) {
      skillState.seenEndpoints.push(context.endpoint);
    }
    skillState.totalRequests += 1;

    await this.persist();

    if (reasons.length > 0 && this.alertRouter) {
      const alertSeverity = severity === "warn" ? "warning" : severity === "critical" ? "critical" : "info";
      this.alertRouter.dispatch({
        severity: alertSeverity,
        category: "firewall",
        message: reasons.join("; "),
        timestamp: new Date(now).toISOString(),
        metadata: { skillId: context.skillId, provider: context.provider, allowed }
      }).catch(() => {});
    }

    return {
      allowed,
      severity,
      reasons
    };
  }

  private getOrCreateSkill(skillId: string, timestamp: number): SkillBaseline {
    let state = this.store.skills[skillId];
    if (!state) {
      state = {
        firstSeen: timestamp,
        totalRequests: 0,
        recentTimestamps: [],
        seenEndpoints: []
      };
      this.store.skills[skillId] = state;
    }
    return state;
  }

  private async persist(): Promise<void> {
    const paths = resolveClauthPaths();
    await ensureDir(paths.homeDir);
    await writeJsonFileAtomic(paths.firewallFile, this.store);
  }
}

function isOffHours(hour: number, start: number, end: number): boolean {
  if (start === end) {
    return false;
  }
  if (start < end) {
    return hour >= start && hour < end;
  }
  return hour >= start || hour < end;
}
