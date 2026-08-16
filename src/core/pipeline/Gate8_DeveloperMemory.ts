import { SuppressionRecord } from "../types/SecretFinding.js";
import { SeverityLevel } from "../types/SeverityLevel.js";
import { generateSuppressionKey } from "../utils/HashUtils.js";

/**
 * Gate 8 — Developer Memory
 *
 * Tracks which findings the developer has previously acknowledged or suppressed.
 * Prevents repeated warnings for findings the developer has intentionally
 * dismissed as safe.
 *
 * Two suppression types:
 * 1. Permanent: stored persistently (survives VS Code restarts)
 * 2. Session: stored in-memory only (cleared on restart)
 *
 * The actual persistence layer (VS Code GlobalState) is handled by
 * DeveloperMemoryStore. This class is the pure logic layer.
 */

export interface Gate8Result {
  isSuppressed: boolean;
  suppressionType: "permanent" | "session" | "none";
  suppressionKey: string;
  record?: SuppressionRecord;
}

export class Gate8_DeveloperMemory {
  // Permanent suppressions: key → record
  private permanentSuppressions: Map<string, SuppressionRecord> = new Map();
  // Session suppressions: just the keys
  private sessionSuppressions: Set<string> = new Set();

  /**
   * Checks whether a finding is suppressed.
   *
   * @param fileUri - File containing the finding
   * @param lineNumber - Line number of the finding
   * @param lineContent - Full line content
   * @param ruleId - Matched rule ID (if any)
   */
  public check(
    fileUri: string,
    lineNumber: number,
    lineContent: string,
    ruleId?: string,
  ): Gate8Result {
    const key = generateSuppressionKey(
      fileUri,
      lineNumber,
      lineContent,
      ruleId,
    );

    // Check permanent suppressions first
    const permanent = this.permanentSuppressions.get(key);
    if (permanent !== undefined) {
      // Check if it has expired
      if (
        permanent.expiresAt !== undefined &&
        permanent.expiresAt < new Date()
      ) {
        this.permanentSuppressions.delete(key);
      } else {
        return {
          isSuppressed: true,
          suppressionType: "permanent",
          suppressionKey: key,
          record: permanent,
        };
      }
    }

    // Check session suppressions
    if (this.sessionSuppressions.has(key)) {
      return {
        isSuppressed: true,
        suppressionType: "session",
        suppressionKey: key,
      };
    }

    return {
      isSuppressed: false,
      suppressionType: "none",
      suppressionKey: key,
    };
  }

  /**
   * Adds a permanent suppression.
   */
  public suppressPermanently(
    fileUri: string,
    lineNumber: number,
    lineContent: string,
    severity: SeverityLevel,
    ruleId?: string,
    reason?: string,
    expiresAt?: Date,
  ): SuppressionRecord {
    const key = generateSuppressionKey(
      fileUri,
      lineNumber,
      lineContent,
      ruleId,
    );

    const record: SuppressionRecord = {
      suppressionKey: key,
      fileUri,
      lineContent,
      severity,
      suppressedAt: new Date(),
      ...(ruleId !== undefined ? { ruleId } : {}),
      ...(reason !== undefined ? { reason } : {}),
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    };

    this.permanentSuppressions.set(key, record);
    return record;
  }

  /**
   * Adds a session suppression (cleared on restart).
   */
  public suppressForSession(
    fileUri: string,
    lineNumber: number,
    lineContent: string,
    ruleId?: string,
  ): string {
    const key = generateSuppressionKey(
      fileUri,
      lineNumber,
      lineContent,
      ruleId,
    );
    this.sessionSuppressions.add(key);
    return key;
  }

  /**
   * Removes a permanent suppression.
   */
  public unsuppress(suppressionKey: string): boolean {
    return this.permanentSuppressions.delete(suppressionKey);
  }

  /**
   * Loads permanent suppressions from persistent storage.
   * Called during extension activation.
   */
  public loadFromPersistence(records: SuppressionRecord[]): void {
    this.permanentSuppressions.clear();
    for (const record of records) {
      // Skip expired records
      if (record.expiresAt !== undefined && record.expiresAt < new Date()) {
        continue;
      }
      this.permanentSuppressions.set(record.suppressionKey, record);
    }
  }

  /**
   * Returns all permanent suppression records for persistence.
   */
  public toPersistenceRecords(): SuppressionRecord[] {
    return Array.from(this.permanentSuppressions.values());
  }

  /**
   * Returns the number of permanent suppressions.
   */
  public get permanentCount(): number {
    return this.permanentSuppressions.size;
  }

  /**
   * Returns the number of session suppressions.
   */
  public get sessionCount(): number {
    return this.sessionSuppressions.size;
  }

  /**
   * Clears all session suppressions.
   */
  public clearSession(): void {
    this.sessionSuppressions.clear();
  }
}
