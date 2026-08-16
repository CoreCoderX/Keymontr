import * as fs from "fs";
import * as path from "path";

/**
 * Provides lazy loading for per-group JSON files.
 * Only loads a group file when it is specifically requested.
 * Caches results to avoid repeated disk reads.
 */
export class LazyLoader {
  private cache: Map<string, unknown> = new Map();
  private readonly groupsPath: string;

  constructor(assetsPath: string) {
    this.groupsPath = path.join(assetsPath, "groups");
  }

  /**
   * Loads a group file by its name (slug).
   * Returns the parsed JSON or null if not found/invalid.
   */
  public loadGroup<T>(groupSlug: string): T | null {
    const cacheKey = groupSlug;

    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey) as T;
    }

    const filePath = path.join(this.groupsPath, `${groupSlug}.json`);

    if (!fs.existsSync(filePath)) {
      return null;
    }

    try {
      const raw = fs.readFileSync(filePath, "utf-8");
      const parsed = JSON.parse(raw) as T;
      this.cache.set(cacheKey, parsed);
      return parsed;
    } catch {
      return null;
    }
  }

  /**
   * Checks whether a group file exists without loading it.
   */
  public groupExists(groupSlug: string): boolean {
    const filePath = path.join(this.groupsPath, `${groupSlug}.json`);
    return fs.existsSync(filePath);
  }

  /**
   * Returns all available group slugs by scanning the groups directory.
   */
  public listGroupSlugs(): string[] {
    if (!fs.existsSync(this.groupsPath)) {
      return [];
    }

    return fs
      .readdirSync(this.groupsPath)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.replace(".json", ""));
  }

  /**
   * Clears the in-memory cache.
   */
  public clearCache(): void {
    this.cache.clear();
  }

  /**
   * Returns the number of cached entries.
   */
  public get cacheSize(): number {
    return this.cache.size;
  }
}
