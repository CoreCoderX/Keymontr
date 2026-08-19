import * as path from "path";
import { GitleaksDatabase } from "./GitleaksDatabase.js";
import { StringGroupDatabase } from "./StringGroupDatabase.js";
import { CollisionResolver } from "./CollisionResolver.js";
import { LazyLoader } from "./LazyLoader.js";

/**
 * Singleton that manages all database instances.
 *
 * Provides a single access point for all database operations.
 * Handles initialization order and error recovery.
 */
export class DatabaseManager {
  private static instance: DatabaseManager | null = null;

  private gitleaksDb!: GitleaksDatabase;
  private stringGroupDb!: StringGroupDatabase;
  private collisionResolver!: CollisionResolver;
  private db1LazyLoader!: LazyLoader;
  private db2LazyLoader!: LazyLoader;

  private initialized = false;
  private initError: string | null = null;

  private constructor() {}

  /**
   * Returns the singleton instance.
   */
  public static getInstance(): DatabaseManager {
    DatabaseManager.instance ??= new DatabaseManager();
    return DatabaseManager.instance;
  }

  /**
   * Initializes all databases from the extension root path.
   * Safe to call multiple times — only initializes once.
   *
   * @param extensionRootPath - Absolute path to the extension root (where regex/ and stringgroup/ live)
   */
  public async initialize(extensionRootPath: string): Promise<void> {
    if (this.initialized) {
      return;
    }

    const db1AssetsPath = path.join(extensionRootPath, "regex", "assets");
    const db2AssetsPath = path.join(extensionRootPath, "stringgroup", "assets");

    this.gitleaksDb = new GitleaksDatabase(db1AssetsPath);
    this.stringGroupDb = new StringGroupDatabase(db2AssetsPath);
    this.collisionResolver = new CollisionResolver();
    this.db1LazyLoader = new LazyLoader(db1AssetsPath);
    this.db2LazyLoader = new LazyLoader(db2AssetsPath);

    const errors: string[] = [];

    try {
      await this.gitleaksDb.load();
    } catch (err) {
      errors.push(`DB1 (Gitleaks): ${String(err)}`);
    }

    try {
      await this.stringGroupDb.load();
    } catch (err) {
      errors.push(`DB2 (StringGroup): ${String(err)}`);
    }

    if (errors.length > 0) {
      this.initError = errors.join("; ");
      throw new Error(
        `DatabaseManager: Failed to initialize databases:\n${this.initError}`,
      );
    }

    this.initialized = true;
  }

  /**
   * Returns the Gitleaks (DB1) database instance.
   */
  public getGitleaksDb(): GitleaksDatabase {
    this.assertInitialized();
    return this.gitleaksDb;
  }

  /**
   * Returns the StringGroup (DB2) database instance.
   */
  public getStringGroupDb(): StringGroupDatabase {
    this.assertInitialized();
    return this.stringGroupDb;
  }

  /**
   * Returns the collision resolver.
   */
  public getCollisionResolver(): CollisionResolver {
    this.assertInitialized();
    return this.collisionResolver;
  }

  /**
   * Returns the DB1 lazy loader (for per-rule group files).
   */
  public getDb1LazyLoader(): LazyLoader {
    this.assertInitialized();
    return this.db1LazyLoader;
  }

  /**
   * Returns the DB2 lazy loader (for per-group identifier files).
   */
  public getDb2LazyLoader(): LazyLoader {
    this.assertInitialized();
    return this.db2LazyLoader;
  }

  /**
   * Returns a health report of both databases.
   */
  public getHealthReport(): DatabaseHealthReport {
    return {
      initialized: this.initialized,
      initError: this.initError,
      db1: {
        loaded: this.initialized && this.gitleaksDb.loaded,
        ruleCount: this.initialized ? this.gitleaksDb.getRuleCount() : 0,
        error: this.initialized ? this.gitleaksDb.error : null,
      },
      db2: {
        loaded: this.initialized && this.stringGroupDb.loaded,
        keywordCount: this.initialized
          ? this.stringGroupDb.getKeywordCount()
          : 0,
        error: this.initialized ? this.stringGroupDb.error : null,
      },
    };
  }

  /**
   * Resets the singleton (useful for testing).
   */
  public static reset(): void {
    DatabaseManager.instance = null;
  }

  private assertInitialized(): void {
    if (!this.initialized) {
      throw new Error(
        "DatabaseManager: Not initialized. Call initialize() first.",
      );
    }
  }
}

export interface DatabaseHealthReport {
  initialized: boolean;
  initError: string | null;
  db1: {
    loaded: boolean;
    ruleCount: number;
    error: string | null;
  };
  db2: {
    loaded: boolean;
    keywordCount: number;
    error: string | null;
  };
}
