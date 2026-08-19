import * as fs from "fs";
import * as path from "path";
import { DB2IdentifierIndex } from "../core/types/RuleDefinition.js";

/**
 * Manages the DB2 StringGroup identifier database.
 *
 * Responsibilities:
 * - Load the keyword-index.json for O(1) identifier lookup
 * - Provide group lookup by identifier
 * - Support variant-aware lookup (apiKey, api_key, API_KEY)
 * - Lazy-load per-group files only when needed
 */
export class StringGroupDatabase {
  private identifierIndex: DB2IdentifierIndex = new Map();
  private groupNames: Set<string> = new Set();
  private isLoaded = false;
  private loadError: string | null = null;
  private readonly assetsPath: string;

  constructor(db2AssetsPath: string) {
    this.assetsPath = db2AssetsPath;
  }

  /**
   * Loads the keyword index from keyword-index.json.
   * This is the only file we load eagerly — ~2MB, loads in milliseconds.
   */
  public async load(): Promise<void> {
    const indexFilePath = path.join(this.assetsPath, "keyword-index.json");

    let raw: string;
    try {
      raw = await fs.promises.readFile(indexFilePath, "utf-8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") {
        this.loadError = `DB2 keyword index not found: ${indexFilePath}`;
      } else {
        this.loadError = `Failed to read DB2 keyword index: ${String(err)}`;
      }
      throw new Error(this.loadError, { cause: err });
    }

    let parsed: Record<string, string>;
    try {
      parsed = JSON.parse(raw) as Record<string, string>;
    } catch (err) {
      this.loadError = `Failed to parse DB2 keyword index JSON: ${String(err)}`;
      throw new Error(this.loadError, { cause: err });
    }

    this.validateIndex(parsed);
    this.buildIndex(parsed);

    this.isLoaded = true;
  }

  /**
   * Validates the keyword index structure.
   */
  private validateIndex(parsed: Record<string, string>): void {
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("DB2: keyword-index.json must be a plain object");
    }

    const entries = Object.entries(parsed);
    if (entries.length === 0) {
      throw new Error("DB2: keyword-index.json is empty");
    }

    // Spot check a sample of entries
    const sample = entries.slice(0, 10);
    for (const [key, value] of sample) {
      if (typeof key !== "string" || typeof value !== "string") {
        throw new Error(
          `DB2: Invalid entry in keyword-index — key="${key}" value="${value}"`,
        );
      }
    }
  }

  /**
   * Builds the in-memory index from the parsed JSON.
   */
  private buildIndex(parsed: Record<string, string>): void {
    for (const [keyword, group] of Object.entries(parsed)) {
      this.identifierIndex.set(keyword, group);
      this.groupNames.add(group);
    }
  }

  /**
   * Looks up a single identifier and returns its group, or undefined.
   * O(1) hash map lookup.
   */
  public getGroup(identifier: string): string | undefined {
    this.assertLoaded();
    return this.identifierIndex.get(identifier);
  }

  /**
   * Looks up an identifier trying all common casing variants.
   * Returns the first matching group and which variant matched.
   */
  public getGroupWithVariants(
    identifier: string,
  ): { group: string; matchedVariant: string } | undefined {
    this.assertLoaded();

    // Some identifiers are wrapped in accessor prefixes (get/set/is).
    // getDbPassword → DbPassword → db_password, which IS in the index.
    const strippedForms = [identifier];
    for (const prefix of ["get", "set", "is"]) {
      if (
        identifier.length > prefix.length + 1 &&
        identifier.toLowerCase().startsWith(prefix) &&
        /[A-Z]/.test(identifier[prefix.length])
      ) {
        strippedForms.push(identifier.slice(prefix.length));
      }
    }

    for (const base of strippedForms) {
      const match = this.matchVariants(base);
      if (match !== undefined) {
        return match;
      }
    }

    return undefined;
  }

  /**
   * Looks up a single base identifier trying all common casing variants.
   */
  private matchVariants(
    identifier: string,
  ): { group: string; matchedVariant: string } | undefined {
    // Try exact match first (most common, fastest path)
    const exact = this.identifierIndex.get(identifier);
    if (exact !== undefined) {
      return { group: exact, matchedVariant: identifier };
    }

    // Try lowercase
    const lower = identifier.toLowerCase();
    const lowerMatch = this.identifierIndex.get(lower);
    if (lowerMatch !== undefined) {
      return { group: lowerMatch, matchedVariant: lower };
    }

    // Try uppercase
    const upper = identifier.toUpperCase();
    const upperMatch = this.identifierIndex.get(upper);
    if (upperMatch !== undefined) {
      return { group: upperMatch, matchedVariant: upper };
    }

    // Try snake_case from camelCase
    const snake = identifier
      .replace(/([A-Z])/g, "_$1")
      .toLowerCase()
      .replace(/^_/, "");
    const snakeMatch = this.identifierIndex.get(snake);
    if (snakeMatch !== undefined) {
      return { group: snakeMatch, matchedVariant: snake };
    }

    const snakeUpper = snake.toUpperCase();
    const snakeUpperMatch = this.identifierIndex.get(snakeUpper);
    if (snakeUpperMatch !== undefined) {
      return { group: snakeUpperMatch, matchedVariant: snakeUpper };
    }

    // Try camelCase from snake_case
    if (identifier.includes("_")) {
      const camel = identifier
        .toLowerCase()
        .replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
      const camelMatch = this.identifierIndex.get(camel);
      if (camelMatch !== undefined) {
        return { group: camelMatch, matchedVariant: camel };
      }
    }

    // Try kebab-case
    const kebab = snake.replace(/_/g, "-");
    const kebabMatch = this.identifierIndex.get(kebab);
    if (kebabMatch !== undefined) {
      return { group: kebabMatch, matchedVariant: kebab };
    }

    return undefined;
  }

  /**
   * Looks up multiple identifiers and returns all matching groups.
   */
  public getGroupsForIdentifiers(
    identifiers: string[],
  ): Array<{ identifier: string; group: string }> {
    this.assertLoaded();

    const results: Array<{ identifier: string; group: string }> = [];

    for (const id of identifiers) {
      const match = this.getGroupWithVariants(id);
      if (match !== undefined) {
        results.push({ identifier: id, group: match.group });
      }
    }

    return results;
  }

  /**
   * Returns all unique group names in the database.
   */
  public getAllGroupNames(): string[] {
    this.assertLoaded();
    return Array.from(this.groupNames);
  }

  /**
   * Returns total number of indexed keywords.
   */
  public getKeywordCount(): number {
    return this.identifierIndex.size;
  }

  /**
   * Returns true if the database has been loaded successfully.
   */
  public get loaded(): boolean {
    return this.isLoaded;
  }

  /**
   * Returns the load error if any.
   */
  public get error(): string | null {
    return this.loadError;
  }

  private assertLoaded(): void {
    if (!this.isLoaded) {
      throw new Error(
        "StringGroupDatabase: Database not loaded. Call load() first.",
      );
    }
  }
}
