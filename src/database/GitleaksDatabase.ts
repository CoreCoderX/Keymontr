import * as fs from "fs";
import * as path from "path";
import {
  GitleaksRule,
  GitleaksRulesFile,
  CompiledRule,
  CompiledAllowlist,
  DB1KeywordIndex,
} from "../core/types/RuleDefinition.js";

/**
 * Manages the DB1 Gitleaks rules database.
 *
 * Responsibilities:
 * - Load and validate gitleaks-rules.json
 * - Pre-compile all regexes for performance
 * - Build the keyword index with collision handling
 * - Provide fast rule lookup by keyword or ID
 */
export class GitleaksDatabase {
  private compiledRules: Map<string, CompiledRule> = new Map();
  private keywordIndex: DB1KeywordIndex = new Map();
  private globalAllowlistRegexes: RegExp[] = [];
  private globalAllowlistStopwords: string[] = [];
  private globalAllowlistPaths: RegExp[] = [];
  private isLoaded = false;
  private loadError: string | null = null;

  constructor(private readonly db1AssetsPath: string) {}

  /**
   * Loads and compiles all rules from the database.
   * Must be called before any lookup operations.
   */
  public async load(): Promise<void> {
    const rulesFilePath = path.join(this.db1AssetsPath, "gitleaks-rules.json");

    let raw: string;
    try {
      raw = await fs.promises.readFile(rulesFilePath, "utf-8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException | null)?.code === "ENOENT") {
        this.loadError = `DB1 rules file not found: ${rulesFilePath}`;
      } else {
        this.loadError = `Failed to read DB1 rules file: ${String(err)}`;
      }
      throw new Error(this.loadError, { cause: err });
    }

    let parsed: GitleaksRulesFile;
    try {
      parsed = JSON.parse(raw) as GitleaksRulesFile;
    } catch (err) {
      this.loadError = `Failed to parse DB1 rules JSON: ${String(err)}`;
      throw new Error(this.loadError, { cause: err });
    }

    this.validateStructure(parsed);
    this.compileGlobalAllowlist(parsed);
    this.compileRules(parsed.rules);
    this.buildKeywordIndex();

    this.isLoaded = true;
  }

  /**
   * Validates the top-level structure of the rules file.
   */
  private validateStructure(parsed: GitleaksRulesFile): void {
    if (parsed === null || typeof parsed !== "object") {
      throw new Error("DB1: Rules file is not a valid JSON object");
    }
    if (!Array.isArray(parsed.rules)) {
      throw new Error("DB1: Rules file missing 'rules' array");
    }
    if (parsed.rules.length === 0) {
      throw new Error("DB1: Rules array is empty");
    }
  }

  /**
   * Compiles the global allowlist from the top-level config.
   */
  private compileGlobalAllowlist(parsed: GitleaksRulesFile): void {
    if (!parsed.allowlist) {
      return;
    }

    for (const pattern of parsed.allowlist.regexes ?? []) {
      try {
        this.globalAllowlistRegexes.push(new RegExp(pattern, "i"));
      } catch {
        // Skip invalid global allowlist regexes
      }
    }

    this.globalAllowlistStopwords = (parsed.allowlist.stopwords ?? []).map(
      (w) => w.toLowerCase(),
    );

    for (const pattern of parsed.allowlist.paths ?? []) {
      try {
        this.globalAllowlistPaths.push(new RegExp(pattern, "i"));
      } catch {
        // Skip invalid path regexes
      }
    }
  }

  /**
   * Compiles all rules — pre-compiles regexes for runtime performance.
   */
  private compileRules(rules: GitleaksRule[]): void {
    for (const rule of rules) {
      const compiled = this.compileRule(rule);
      if (compiled !== null) {
        this.compiledRules.set(rule.id, compiled);
      }
    }
  }

  /**
   * Compiles a single rule. Returns null if the rule's regex is invalid.
   */
  private compileRule(rule: GitleaksRule): CompiledRule | null {
    if (!rule.id || typeof rule.id !== "string") {
      return null;
    }

    if (!rule.regex || typeof rule.regex !== "string") {
      return null;
    }

    let pattern = rule.regex;
    let flags = "g";

    // JavaScript RegExp does NOT support (?i) inline. We must strip it and use the 'i' flag.
    const hasGlobalCaseInsensitive = pattern.includes("(?i)");
    if (hasGlobalCaseInsensitive) {
      pattern = pattern.replace(/\(\?i\)/g, "");
      flags += "i";
    }
    // Also handle (?-i) if present (turn off case insensitive)
    if (pattern.includes("(?-i)")) {
      pattern = pattern.replace(/\(\?-i\)/g, "");
    }
    // Inline modifier groups (?-i:X) / (?i:X) are ES2025-only. Rewrite them
    // to plain non-capturing groups so rules compile on every Node runtime
    // (otherwise the whole rule is silently dropped — losing detection).
    if (pattern.includes("(?-i:")) {
      pattern = pattern.replace(/\(\?-i:/g, "(?:");
    }
    if (pattern.includes("(?i:")) {
      if (!hasGlobalCaseInsensitive && !flags.includes("i")) {
        flags += "i";
      }
      pattern = pattern.replace(/\(\?i:/g, "(?:");
    }
    // PCRE named groups (?P<name>) are Go/PCRE syntax — convert to JS named
    // groups (?<name>) which preserve the capture index used by secretGroup.
    if (pattern.includes("(?P<")) {
      pattern = pattern.replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g, "(?<$1>");
    }
    // PCRE dotall group (?s:.) — JS has no inline s flag; any-character is [\s\S].
    if (pattern.includes("(?s:.)")) {
      pattern = pattern.replace(/\(\?s:\.\)/g, "[\\s\\S]");
    }

    let compiledRegex: RegExp;
    try {
      compiledRegex = new RegExp(pattern, flags);
    } catch (_err) {
      // Rule has invalid regex — skip it
      return null;
    }

    let compiledPathRegex: RegExp | undefined;
    if (rule.path !== undefined && rule.path.length > 0) {
      try {
        compiledPathRegex = new RegExp(rule.path, "i");
      } catch {
        compiledPathRegex = undefined;
      }
    }

    const compiledAllowlists: CompiledAllowlist[] = [];
    for (const al of rule.allowlists ?? []) {
      const compiled = this.compileAllowlist(al);
      compiledAllowlists.push(compiled);
    }

    return {
      id: rule.id,
      description: rule.description ?? rule.id,
      regex: compiledRegex,
      rawRegex: rule.regex,
      entropy: rule.entropy ?? 0,
      keywords: (rule.keywords ?? []).map((k) => k.toLowerCase()),
      ...(compiledPathRegex !== undefined
        ? { pathRegex: compiledPathRegex }
        : {}),
      secretGroup: rule.secretGroup ?? 0,
      allowlists: compiledAllowlists,
    };
  }

  /**
   * Compiles a single allowlist entry.
   */
  private compileAllowlist(al: {
    description?: string;
    paths?: string[];
    regexes?: string[];
    regexTarget?: "match" | "line";
    stopwords?: string[];
    condition?: "AND" | "OR";
  }): CompiledAllowlist {
    const paths: RegExp[] = [];
    const regexes: RegExp[] = [];

    for (const p of al.paths ?? []) {
      try {
        paths.push(new RegExp(p, "i"));
      } catch {
        // Skip invalid
      }
    }

    for (const r of al.regexes ?? []) {
      try {
        // Normalize ES2025-only inline modifier groups so allowlist regexes
        // compile on every Node runtime (see compileRule for details).
        let normalized = r.replace(/\(\?-i\)/g, "");
        normalized = normalized.replace(/\(\?-i:/g, "(?:");
        normalized = normalized.replace(/\(\?i:/g, "(?:");
        if (normalized.includes("(?i)")) {
          normalized = normalized.replace(/\(\?i\)/g, "");
        }
        regexes.push(new RegExp(normalized, "i"));
      } catch {
        // Skip invalid
      }
    }

    return {
      ...(al.description !== undefined ? { description: al.description } : {}),
      paths,
      regexes,
      regexTarget: al.regexTarget ?? "match",
      stopwords: (al.stopwords ?? []).map((w) => w.toLowerCase()),
      condition: al.condition ?? "OR",
    };
  }

  /**
   * Builds the keyword-to-rule-ids index.
   * Handles collisions by mapping keywords to ALL matching rule IDs.
   */
  private buildKeywordIndex(): void {
    for (const [ruleId, rule] of this.compiledRules) {
      for (const keyword of rule.keywords) {
        const existing = this.keywordIndex.get(keyword);
        if (existing === undefined) {
          this.keywordIndex.set(keyword, [ruleId]);
        } else {
          // Collision — add this rule to the list
          if (!existing.includes(ruleId)) {
            existing.push(ruleId);
          }
        }
      }
    }
  }

  /**
   * Returns all rule IDs that match a given keyword.
   * Returns an empty array if no match.
   */
  public getRuleIdsForKeyword(keyword: string): string[] {
    this.assertLoaded();
    return this.keywordIndex.get(keyword.toLowerCase()) ?? [];
  }

  /**
   * Returns a compiled rule by its ID.
   */
  public getRule(ruleId: string): CompiledRule | undefined {
    this.assertLoaded();
    return this.compiledRules.get(ruleId);
  }

  /**
   * Returns all compiled rules.
   */
  public getAllRules(): CompiledRule[] {
    this.assertLoaded();
    return Array.from(this.compiledRules.values());
  }

  /**
   * Returns all keywords in the index (for pre-filter construction).
   */
  public getAllKeywords(): string[] {
    this.assertLoaded();
    return Array.from(this.keywordIndex.keys());
  }

  /**
   * Returns the global allowlist regexes.
   */
  public getGlobalAllowlistRegexes(): RegExp[] {
    return this.globalAllowlistRegexes;
  }

  /**
   * Returns the global allowlist stopwords.
   */
  public getGlobalAllowlistStopwords(): string[] {
    return this.globalAllowlistStopwords;
  }

  /**
   * Returns the global allowlist path patterns.
   */
  public getGlobalAllowlistPaths(): RegExp[] {
    return this.globalAllowlistPaths;
  }

  /**
   * Returns the total number of loaded rules.
   */
  public getRuleCount(): number {
    return this.compiledRules.size;
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
        "GitleaksDatabase: Database not loaded. Call load() first.",
      );
    }
  }
}
