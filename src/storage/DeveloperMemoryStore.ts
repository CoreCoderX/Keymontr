import { GlobalStateManager, STORAGE_KEYS } from "./GlobalStateManager.js";
import { Gate8_DeveloperMemory } from "../core/pipeline/Gate8_DeveloperMemory.js";
import { SuppressionRecord } from "../core/types/SecretFinding.js";
import { SeverityLevel } from "../core/types/SeverityLevel.js";

/**
 * DeveloperMemoryStore — Bridges Gate8_DeveloperMemory (pure logic)
 * with VS Code GlobalState (persistence layer).
 *
 * Responsibilities:
 * - Load suppressions from GlobalState on extension activate
 * - Save suppressions to GlobalState when changed
 * - Expose add/remove/query operations to VS Code commands
 */
export class DeveloperMemoryStore {
  constructor(
    private readonly gate8: Gate8_DeveloperMemory,
    private readonly globalState: GlobalStateManager,
  ) {}

  /**
   * Loads all persisted suppressions from GlobalState into Gate8.
   * Must be called during extension activation.
   */
  public loadFromStorage(): void {
    const raw = this.globalState.get<SuppressionRecord[]>(
      STORAGE_KEYS.PERMANENT_SUPPRESSIONS,
      [],
    );

    // Rehydrate Date objects (JSON.parse returns strings for Date fields)
    const records: SuppressionRecord[] = raw.map((r) => ({
      ...r,
      suppressedAt: new Date(r.suppressedAt),
      ...(r.expiresAt !== undefined
        ? { expiresAt: new Date(r.expiresAt) }
        : {}),
    }));

    this.gate8.loadFromPersistence(records);
  }

  /**
   * Saves all current suppressions to GlobalState.
   */
  public async saveToStorage(): Promise<void> {
    const records = this.gate8.toPersistenceRecords();
    await this.globalState.set(STORAGE_KEYS.PERMANENT_SUPPRESSIONS, records);
  }

  /**
   * Adds a permanent suppression and persists it immediately.
   */
  public async addPermanentSuppression(
    fileUri: string,
    lineNumber: number,
    lineContent: string,
    severity: SeverityLevel,
    ruleId?: string,
    reason?: string,
  ): Promise<SuppressionRecord> {
    const record = this.gate8.suppressPermanently(
      fileUri,
      lineNumber,
      lineContent,
      severity,
      ruleId,
      reason,
    );
    await this.saveToStorage();
    return record;
  }

  /**
   * Removes a suppression by its key and persists the change.
   */
  public async removeSuppression(suppressionKey: string): Promise<boolean> {
    const removed = this.gate8.unsuppress(suppressionKey);
    if (removed) {
      await this.saveToStorage();
    }
    return removed;
  }

  /**
   * Returns all active permanent suppression records.
   */
  public getAllSuppressions(): SuppressionRecord[] {
    return this.gate8.toPersistenceRecords();
  }

  /**
   * Returns ALL currently ignored keys — permanent suppressions plus
   * session-only suppressions (which do not survive a restart).
   */
  public getAllIgnored(): Array<SuppressionRecord & { kind: "permanent" | "session" }> {
    const permanent = this.gate8
      .toPersistenceRecords()
      .map((r) => ({ ...r, kind: "permanent" as const }));
    const session = this.gate8
      .getSessionSuppressions()
      .map((r) => ({ ...r, kind: "session" as const }));
    return [...permanent, ...session];
  }

  /**
   * Returns the total count of permanent suppressions.
   */
  public get suppressionCount(): number {
    return this.gate8.permanentCount;
  }

  /**
   * Clears all suppressions permanently.
   */
  public async clearAll(): Promise<void> {
    const records = this.gate8.toPersistenceRecords();
    for (const record of records) {
      this.gate8.unsuppress(record.suppressionKey);
    }
    await this.saveToStorage();
  }
}
