import { GlobalStateManager, STORAGE_KEYS } from "./GlobalStateManager.js";
import { SecretFinding } from "../core/types/SecretFinding.js";
import { SeverityLevel } from "../core/types/SeverityLevel.js";

/**
 * A lightweight record stored in history (doesn't store the secret value itself).
 */
export interface HistoryRecord {
  id: string;
  fileUri: string;
  fileName: string;
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
  }

  /**
   * Records a new detection event.
   * Called when a finding passes Gate 7 and Gate 8.
   */
  public async recordDetection(finding: SecretFinding): Promise<void> {
    const record: HistoryRecord = {
      id: finding.id,
      fileUri: finding.meta.fileUri,
      fileName: finding.meta.fileName,
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

    // Update statistics
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

    this.stats.lastUpdated = new Date();

    await this.persist();
  }

  /**
   * Marks a finding as fixed.
   */
  public async markFixed(findingId: string): Promise<void> {
    const record = this.history.find((r) => r.id === findingId);
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
}
