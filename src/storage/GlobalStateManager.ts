import * as vscode from "vscode";

/**
 * GlobalStateManager — Typed wrapper around VS Code's GlobalState API.
 *
 * Provides type-safe get/set/delete operations with automatic JSON
 * serialization and error handling. All data persists across VS Code
 * restarts (stored in user's global extension storage).
 */
export class GlobalStateManager {
  constructor(private readonly context: vscode.ExtensionContext) {}

  /**
   * Retrieves a value by key. Returns the default value if not found
   * or if deserialization fails.
   */
  public get<T>(key: string, defaultValue: T): T {
    try {
      const stored = this.context.globalState.get<string>(key);
      if (stored === undefined || stored === null) {
        return defaultValue;
      }
      return JSON.parse(stored) as T;
    } catch {
      return defaultValue;
    }
  }

  /**
   * Stores a value by key. Serializes to JSON automatically.
   * Returns true on success, false on failure.
   */
  public async set<T>(key: string, value: T): Promise<boolean> {
    try {
      const serialized = JSON.stringify(value);
      await this.context.globalState.update(key, serialized);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Deletes a key from global state.
   */
  public async delete(key: string): Promise<boolean> {
    try {
      await this.context.globalState.update(key, undefined);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Checks whether a key exists in global state.
   */
  public has(key: string): boolean {
    return this.context.globalState.get(key) !== undefined;
  }

  /**
   * Clears all keys managed by Keymontr.
   * Iterates known keys and removes them.
   */
  public async clearAll(knownKeys: string[]): Promise<void> {
    for (const key of knownKeys) {
      await this.delete(key);
    }
  }
}

/**
 * All storage keys used by Keymontr.
 * Centralized to avoid typos and enable easy clearing.
 */
export const STORAGE_KEYS = {
  PERMANENT_SUPPRESSIONS: "keymontr.permanentSuppressions",
  SECRET_HISTORY: "keymontr.secretHistory",
  STATISTICS: "keymontr.statistics",
  GIT_HOOK_INSTALLED: "keymontr.gitHookInstalled",
  FIRST_ACTIVATION: "keymontr.firstActivation",
  LAST_FULL_SCAN: "keymontr.lastFullScan",
} as const;
