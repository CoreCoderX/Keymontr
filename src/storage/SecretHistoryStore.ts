import { GlobalStateManager, STORAGE_KEYS } from "./GlobalStateManager.js";
import { SecretFinding } from "../core/types/SecretFinding.js";
import { SeverityLevel } from "../core/types/SeverityLevel.js";

/**
 * A lightweight record stored in history (doesn't store the secret value itself).
 */
export interface HistoryRecord {
  id: string;
  /** Stable identity of the finding (fileUri+line+content+rule hash).
   *  Unlike the random `id`, this stays the same across re-scans, which is
   *  what allows detection statistics to be deduplicated. */
  suppressionKey: string;
  fileUri: string;
  fileName: string;
  lineNumber?: number;
  severity: SeverityLevel;
  ruleId?: string;
  matchedGroup?: string;
  detectedAt: Date;
  isFixed: boolean;
  fixedAt?: Date;
}

export interface SecretStatistics {
  totalDetected: number;
  totalFixed: number;
  totalSuppressed: number;
  commitsBlocked: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  byFile: Record<string, number>;
  lastUpdated: Date;
}

const DEFAULT_STATS: SecretStatistics = {
  totalDetected: 0,
  totalFixed: 0,
  totalSuppressed: 0,
  commitsBlocked: 0,
  byType: {},
  bySeverity: {},
  byFile: {},
  lastUpdated: new Date(),
};

// Maximum history entries to keep (to avoid unlimited storage growth)
const MAX_HISTORY_ENTRIES = 500;

/**
 * SecretHistoryStore — Stores detection history and statistics.
 *
 * Never stores secret values — only metadata about findings.
 * This ensures the history log itself does not become a secret leak.
 */
export class SecretHistoryStore {
  private history: HistoryRecord[] = [];
  private stats: SecretStatistics = { ...DEFAULT_STATS };

  constructor(private readonly globalState: GlobalStateManager) {}

  /**
   * Loads history and statistics from GlobalState.
   *
   * If the persisted records predate stable suppression keys, the corrupted /
   * inflated statistics are rebuilt from the (deduplicated) history so the
   * dashboard totals reflect reality instead of accumulated re-scans.
   */
  public load(): void {
    const rawHistory = this.globalState.get<HistoryRecord[]>(
      STORAGE_KEYS.SECRET_HISTORY,
      [],
    );

    this.history = rawHistory.map((r) => ({
      ...r,
      detectedAt: new Date(r.detectedAt),
      ...(r.fixedAt !== undefined ? { fixedAt: new Date(r.fixedAt) } : {}),
    }));

    const rawStats = this.globalState.get<SecretStatistics>(
      STORAGE_KEYS.STATISTICS,
      DEFAULT_STATS,
    );

    this.stats = {
      ...rawStats,
      lastUpdated: new Date(rawStats.lastUpdated),
    };

    // Migration: older history entries had no suppressionKey, so duplicate
    // detections of the same secret were counted repeatedly. Wipe the
    // inflated data once; it will be rebuilt correctly on the next scans.
    const needsMigration = this.history.some((r) => !r.suppressionKey);
    if (needsMigration) {
      this.history = [];
      this.stats = { ...DEFAULT_STATS, lastUpdated: new Date() };
      void this.persist();
      return;
    }

    // Self-heal: rebuild statistics from the deduplicated history so they
    // reflect unique findings even if they were inflated before the fix.
    const rebuilt = this.rebuildStats(this.history);
    this.stats = {
      ...rebuilt,
      totalSuppressed: this.stats.totalSuppressed,
      commitsBlocked: this.stats.commitsBlocked,
      lastUpdated: this.stats.lastUpdated,
    };
  }

  /**
   * Records a new detection event.
   * Called when a finding passes Gate 7 and Gate 8.
   */
  public async recordDetection(finding: SecretFinding): Promise<void> {
    const suppressionKey = finding.suppression.suppressionKey;

    // A live secret is re-scanned on every open/save/typing event. Only the
    // FIRST detection of a given secret should be counted, otherwise the
    // totals inflate (75 total / 74 active for 19 real secrets). If the
    // secret was previously fixed and reappears, count it as a new occurrence
    // without inflating totalDetected.
    let isReappearance = false;
    const existingIndex = this.history.findIndex(
      (r) => r.suppressionKey === suppressionKey,
    );
    if (existingIndex !== -1) {
      const existing = this.history[existingIndex];
      if (!existing.isFixed) {
        return; // Same live secret re-detected — no-op.
      }
      // Reappeared after a fix: drop the old fixed record and count the new
      // occurrence without inflating totalDetected.
      this.history.splice(existingIndex, 1);
      this.stats.totalFixed = Math.max(0, this.stats.totalFixed - 1);
      isReappearance = true;
    }

    const record: HistoryRecord = {
      id: finding.id,
      suppressionKey,
      fileUri: finding.meta.fileUri,
      fileName: finding.meta.fileName,
      ...(finding.candidate.lineNumber !== undefined
        ? { lineNumber: finding.candidate.lineNumber }
        : {}),
      severity: finding.severity,
      ...(finding.detection.matchedRuleId !== undefined
        ? { ruleId: finding.detection.matchedRuleId }
        : {}),
      ...(finding.detection.matchedGroup !== undefined
        ? { matchedGroup: finding.detection.matchedGroup }
        : {}),
      detectedAt: finding.meta.detectedAt,
      isFixed: false,
    };

    // Prepend (newest first), cap at max entries
    this.history.unshift(record);
    if (this.history.length > MAX_HISTORY_ENTRIES) {
      this.history = this.history.slice(0, MAX_HISTORY_ENTRIES);
    }

    // Update statistics (skip on reappearance — same secret, already counted)
    if (!isReappearance) {
      this.stats.totalDetected++;

      const typeKey =
        finding.detection.matchedRuleId ??
        finding.detection.matchedGroup ??
        "unknown";
      this.stats.byType[typeKey] = (this.stats.byType[typeKey] ?? 0) + 1;

      const sevKey = finding.severity as string;
      this.stats.bySeverity[sevKey] = (this.stats.bySeverity[sevKey] ?? 0) + 1;

      const fileKey = finding.meta.fileName;
      this.stats.byFile[fileKey] = (this.stats.byFile[fileKey] ?? 0) + 1;
    }

    this.stats.lastUpdated = new Date();

    await this.persist();
  }

  /**
   * Marks a finding as fixed.
   */
  public async markFixed(findingId: string, suppressionKey?: string): Promise<void> {
    // Prefer the stable suppression key; fall back to the (legacy) random id.
    const matchIndex = suppressionKey
      ? this.history.findIndex(
          (r) => r.suppressionKey === suppressionKey && !r.isFixed,
        )
      : this.history.findIndex((r) => r.id === findingId && !r.isFixed);
    const record = matchIndex !== -1 ? this.history[matchIndex] : undefined;
    if (record !== undefined) {
      record.isFixed = true;
      record.fixedAt = new Date();
      this.stats.totalFixed++;
      this.stats.lastUpdated = new Date();
      await this.persist();
    }
  }

  /**
   * Increments the commit block counter.
   */
  public async recordCommitBlocked(): Promise<void> {
    this.stats.commitsBlocked++;
    this.stats.lastUpdated = new Date();
    await this.globalState.set(STORAGE_KEYS.STATISTICS, this.stats);
  }

  /**
   * Increments the suppression counter.
   */
  public async recordSuppression(): Promise<void> {
    this.stats.totalSuppressed++;
    this.stats.lastUpdated = new Date();
    await this.globalState.set(STORAGE_KEYS.STATISTICS, this.stats);
  }

  /**
   * Returns all history records.
   */
  public getHistory(): HistoryRecord[] {
    return [...this.history];
  }

  /**
   * Returns current statistics.
   */
  public getStatistics(): SecretStatistics {
    return { ...this.stats };
  }

  /**
   * Returns history for a specific file.
   */
  public getHistoryForFile(fileUri: string): HistoryRecord[] {
    return this.history.filter((r) => r.fileUri === fileUri);
  }

  /**
   * Clears all history and resets statistics.
   */
  public async clearAll(): Promise<void> {
    this.history = [];
    this.stats = { ...DEFAULT_STATS, lastUpdated: new Date() };
    await this.persist();
  }

  private async persist(): Promise<void> {
    await this.globalState.set(STORAGE_KEYS.SECRET_HISTORY, this.history);
    await this.globalState.set(STORAGE_KEYS.STATISTICS, this.stats);
  }

  /**
   * Rebuilds statistics from history, counting each unique finding once
   * (deduplicated by suppressionKey).
   */
  private rebuildStats(history: HistoryRecord[]): SecretStatistics {
    const stats: SecretStatistics = {
      ...DEFAULT_STATS,
      lastUpdated: new Date(),
    };
    const seen = new Set<string>();
    for (const r of history) {
      if (seen.has(r.suppressionKey)) {
        continue;
      }
      seen.add(r.suppressionKey);
      stats.totalDetected++;
      if (r.isFixed) {
        stats.totalFixed++;
      }
      const typeKey = r.ruleId ?? r.matchedGroup ?? "unknown";
      stats.byType[typeKey] = (stats.byType[typeKey] ?? 0) + 1;
      const sevKey = r.severity as string;
      stats.bySeverity[sevKey] = (stats.bySeverity[sevKey] ?? 0) + 1;
      const fileKey = r.fileName;
      stats.byFile[fileKey] = (stats.byFile[fileKey] ?? 0) + 1;
    }
    return stats;
  }
}
