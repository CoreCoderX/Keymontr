import { GitleaksDatabase } from "../../database/GitleaksDatabase.js";
import { SecretCandidate, AllowlistResult } from "../types/DetectionResult.js";
import { ConfigurationManager } from "../../config/ConfigurationManager.js";
import { CompiledAllowlist } from "../types/RuleDefinition.js";

/**
 * Gate 5 — Allowlist Engine
 *
 * Checks a candidate against three levels of allowlists:
 *
 * Level 1: DB1 rule-level allowlists (from Gitleaks — very precise)
 * Level 2: Global built-in allowlists (common false positive patterns)
 * Level 3: Developer-defined allowlists (from .keymontr.json + inline comments)
 *
 * If any allowlist matches, the multiplier drops to 0.02 (effectively suppressed).
 */

// Level 2: Built-in global allowlist regexes
const GLOBAL_ALLOWLIST_REGEXES: RegExp[] = [
  // localhost references
  /\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b/i,
  // Example domains
  /\b(example\.com|example\.org|example\.net|example\.io)\b/i,
  // Common placeholder domains
  /\b(test\.example|dev\.example|staging\.example)\b/i,
  // Template variable syntax
  /\$\{[^}]+\}/,
  /\{\{[^}]+\}\}/,
  /%\([^)]+\)s/,
  /<[A-Z_]+>/,
];

// Level 2: Built-in global stopwords
const GLOBAL_STOPWORDS: string[] = [
  "example",
  "sample",
  "placeholder",
  "dummy",
  "fake",
  "test",
  "demo",
  "mock",
  "stub",
  "fixture",
  "changeme",
  "replaceme",
  "fillme",
  "setme",
  "todo",
  "fixme",
  "xxx",
  "yyy",
  "aaa",
  "insert",
  "enter",
  "put",
];

// Inline suppression comment patterns
const INLINE_IGNORE_PATTERNS: RegExp[] = [
  /keymontr-ignore/i,
  /nosec\b/i,
  /noqa\b/i,
  /pragma:\s*allowlist\s+secret/i,
  /gitleaks:allow/i,
];

export class Gate5_Allowlist {
  private readonly developerStopwords: string[];
  private readonly developerPatterns: RegExp[];
  private readonly developerIgnorePaths: RegExp[];

  constructor(
    private readonly gitleaksDb: GitleaksDatabase,
    config: ConfigurationManager,
  ) {
    const cfg = config.getConfig();
    this.developerStopwords = config.getEffectiveStopwords();
    this.developerPatterns = (cfg.ignore.patterns ?? [])
      .map((p) => {
        try {
          return new RegExp(p, "i");
        } catch {
          return null;
        }
      })
      .filter((r): r is RegExp => r !== null);
    this.developerIgnorePaths = [];
  }

  /**
   * Checks a candidate against all allowlist levels.
   *
   * @param candidate - The candidate to check
   * @param fileUri - File path for path-based allowlist checks
   * @param matchedRuleId - The Gitleaks rule that matched (if any)
   */
  public evaluate(
    candidate: SecretCandidate,
    fileUri: string,
    matchedRuleId?: string,
  ): AllowlistResult {
    const value = candidate.value;
    const line = candidate.line;
    const filePath = fileUri.replace(/\\/g, "/");

    // ── Check inline suppression first ────────────────────────────────────
    for (const pattern of INLINE_IGNORE_PATTERNS) {
      if (pattern.test(line)) {
        return this.allowlisted("Inline suppression comment");
      }
    }

    // ── Level 1: DB1 rule-level allowlists ────────────────────────────────
    if (matchedRuleId !== undefined) {
      const rule = this.gitleaksDb.getRule(matchedRuleId);
      if (rule !== undefined) {
        for (const allowlist of rule.allowlists) {
          const result = this.checkAllowlist(allowlist, value, line, filePath);
          if (result !== null) {
            return this.allowlisted(`DB1 rule allowlist: ${result}`);
          }
        }
      }
    }

    // ── Level 2: Global built-in allowlists ───────────────────────────────
    for (const regex of GLOBAL_ALLOWLIST_REGEXES) {
      if (regex.test(value) || regex.test(line)) {
        return this.allowlisted("Global allowlist pattern");
      }
    }

    // Stopwords are matched as whole tokens (word boundaries), not raw
    // substrings. A real key like "sk-proj-AbCdEf..." or "AKIA...EXAMPLE"
    // contains "abcd"/"example" as a substring, but is clearly not a
    // placeholder — substring matching would silently suppress real secrets.
    for (const stopword of GLOBAL_STOPWORDS) {
      if (this.matchesStopword(value, stopword)) {
        return this.allowlisted(`Global stopword: "${stopword}"`);
      }
    }

    // ── Level 3: Developer-defined allowlists ─────────────────────────────
    for (const stopword of this.developerStopwords) {
      if (this.matchesStopword(value, stopword)) {
        return this.allowlisted(`Developer stopword: "${stopword}"`);
      }
    }

    for (const pattern of this.developerPatterns) {
      if (pattern.test(value) || pattern.test(line)) {
        return this.allowlisted(`Developer pattern: ${pattern.source}`);
      }
    }

    for (const pathPattern of this.developerIgnorePaths) {
      if (pathPattern.test(filePath)) {
        return this.allowlisted(`Developer ignored path`);
      }
    }

    return {
      isAllowlisted: false,
      multiplier: 1.0,
    };
  }

  /**
   * Checks a single compiled allowlist entry.
   * Returns the reason string if matched, null if not matched.
   */
  private checkAllowlist(
    allowlist: CompiledAllowlist,
    value: string,
    line: string,
    filePath: string,
  ): string | null {
    const target = allowlist.regexTarget === "line" ? line : value;

    // Stopword check
    const targetLower = target.toLowerCase();
    for (const stopword of allowlist.stopwords) {
      if (targetLower.includes(stopword)) {
        return `stopword match: "${stopword}"`;
      }
    }

    // Regex check
    let regexMatched = false;
    for (const regex of allowlist.regexes) {
      regex.lastIndex = 0;
      if (regex.test(target)) {
        regexMatched = true;
        break;
      }
    }

    // Path check
    let pathMatched = allowlist.paths.length === 0; // No path restrictions = any path
    for (const pathRegex of allowlist.paths) {
      if (pathRegex.test(filePath)) {
        pathMatched = true;
        break;
      }
    }

    if (allowlist.condition === "AND") {
      if (regexMatched && pathMatched) {
        return "AND condition met (regex + path)";
      }
    } else {
      // OR
      if (regexMatched || (allowlist.paths.length > 0 && pathMatched)) {
        return "OR condition met";
      }
    }

    return null;
  }

  /**
   * Checks whether a stopword appears as a standalone token in the value.
   * Uses word boundaries so placeholder words like "example" or "abcd"
   * only match when they are separate tokens, not when embedded inside a
   * longer credential-looking string.
   */
  private matchesStopword(value: string, stopword: string): boolean {
    const escaped = stopword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`\\b${escaped}\\b`, "i").test(value);
  }

  private allowlisted(reason: string): AllowlistResult {
    return {
      isAllowlisted: true,
      matchedAllowlist: reason,
      multiplier: 0.02,
    };
  }
}
