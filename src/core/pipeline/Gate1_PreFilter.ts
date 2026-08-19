import { GitleaksDatabase } from "../../database/GitleaksDatabase.js";
import { StringGroupDatabase } from "../../database/StringGroupDatabase.js";
import {
  extractIdentifiers,
  extractStringLiteralsWithPosition,
  extractEnvStyleValue,
} from "../utils/Tokenizer.js";
import { SecretCandidate } from "../types/DetectionResult.js";

/**
 * Gate 1 — Pre-Filter Layer
 *
 * Performs O(1) keyword lookup to determine if a line contains anything
 * worth investigating. Lines with zero hits are skipped with zero
 * further processing cost.
 *
 * Two sources:
 * - DB1 keywords: value-side prefixes ("AKIA", "sk-", "ghp_")
 * - DB2 identifiers: variable/key names ("api_key", "password", "token")
 *
 * Only lines that hit at least one source proceed to Gate 2.
 */

export interface Gate1Result {
  passed: boolean;
  candidates: SecretCandidate[];
  db1Hits: string[];
  db2Hits: string[];
  reason: string;
}

// Minimum length for a string literal to be considered a candidate
const MIN_CANDIDATE_LENGTH = 8;

// Maximum length to avoid scanning entire file contents stored in variables
const MAX_CANDIDATE_LENGTH = 512;

export class Gate1_PreFilter {
  // Flat set of all DB1 keywords (lowercased) for O(1) lookup
  private readonly db1KeywordSet: Set<string> = new Set();

  constructor(
    private readonly gitleaksDb: GitleaksDatabase,
    private readonly stringGroupDb: StringGroupDatabase,
  ) {
    this.buildDB1KeywordSet();
  }

  /**
   * Builds a flat set of all DB1 keywords for instant substring checking.
   */
  private buildDB1KeywordSet(): void {
    const keywords = this.gitleaksDb.getAllKeywords();
    for (const kw of keywords) {
      this.db1KeywordSet.add(kw.toLowerCase());
    }
  }

  /**
   * Evaluates a single line and extracts candidates if any keyword hits.
   *
   * @param line - The source code line to evaluate
   * @param lineNumber - 0-based line number
   * @param surroundingLines - ±5 surrounding lines for context
   * @param isInComment - Whether this line is inside a comment block
   */
  public evaluateLine(
    line: string,
    lineNumber: number,
    surroundingLines: string[],
    _isInComment: boolean,
  ): Gate1Result {
    if (line.trim().length === 0) {
      return this.notPassed("Empty line");
    }

    const lineLower = line.toLowerCase();

    // ── DB1 keyword check ───────────────────────────────────────────────────
    // Check if the raw line text contains any DB1 keyword as a substring.
    // This is intentionally broad — false negatives here mean missed secrets.
    const db1Hits: string[] = [];
    for (const keyword of this.db1KeywordSet) {
      if (lineLower.includes(keyword)) {
        db1Hits.push(keyword);
      }
    }

    // ── DB2 identifier check ────────────────────────────────────────────────
    // Extract identifier tokens and look them up in the DB2 index.
    const identifiers = extractIdentifiers(line);
    const db2Hits: string[] = [];

    for (const identifier of identifiers) {
      const match = this.stringGroupDb.getGroupWithVariants(identifier);
      if (match !== undefined) {
        db2Hits.push(identifier);
      }
    }

    // If no hits from either source, this line is clean
    if (db1Hits.length === 0 && db2Hits.length === 0) {
      // Context pass-through: a secret VALUE is often isolated on its own
      // line (e.g. `return "P@ssw0rd!2024";`) while the secret-carrying
      // identifier sits on the line above/below. If an adjacent line (±1)
      // contains a DB1 keyword hit, still evaluate this line's literals —
      // deeper layers decide whether it really is a secret.
      if (!this.hasAdjacentDb1Hit(surroundingLines)) {
        return this.notPassed("No keyword hits");
      }
    }

    // ── Extract string literal candidates ───────────────────────────────────
    let stringLiterals = extractStringLiteralsWithPosition(line);

    if (stringLiterals.length === 0) {
      // No quoted literals — this may be an unquoted .env-style assignment
      // (e.g. `AWS_ACCESS_KEY_ID=AKIA...`), which the quoted-literal extractor
      // cannot see. Treat the value after `=` as a candidate.
      stringLiterals = extractEnvStyleValue(line);
    }

    if (stringLiterals.length === 0) {
      // Hits found but no string literals — could be an assignment without value yet
      // or a configuration key reference. Still return passed so deeper layers can
      // evaluate the line's identifier context for future lines.
      return this.notPassed("Keyword hit but no string literals to evaluate");
    }

    // Filter to candidates within acceptable length bounds
    const validLiterals = stringLiterals.filter(
      (lit) =>
        lit.value.length >= MIN_CANDIDATE_LENGTH &&
        lit.value.length <= MAX_CANDIDATE_LENGTH,
    );

    if (validLiterals.length === 0) {
      return this.notPassed("String literals too short or too long");
    }

    // Build SecretCandidate objects
    const candidates: SecretCandidate[] = validLiterals.map((lit) => ({
      value: lit.value,
      lineNumber,
      startChar: lit.start,
      endChar: lit.end,
      line,
      surroundingLines,
      db1KeywordHits: db1Hits,
      db2IdentifierHits: db2Hits,
    }));

    return {
      passed: true,
      candidates,
      db1Hits,
      db2Hits,
      reason: `DB1 hits: [${db1Hits.slice(0, 3).join(", ")}] DB2 hits: [${db2Hits.slice(0, 3).join(", ")}]`,
    };
  }

  /**
   * Checks whether either adjacent line (±1) contains a DB1 keyword hit.
   * surroundingLines layout: first half = lines BEFORE, second half = AFTER.
   */
  private hasAdjacentDb1Hit(surroundingLines: string[]): boolean {
    if (surroundingLines.length === 0) {
      return false;
    }
    const half = Math.floor(surroundingLines.length / 2);
    const adjacent = [surroundingLines[half - 1], surroundingLines[half]];
    for (const adj of adjacent) {
      if (adj === undefined) {
        continue;
      }
      const adjLower = adj.toLowerCase();
      for (const keyword of this.db1KeywordSet) {
        if (adjLower.includes(keyword)) {
          return true;
        }
      }
    }
    return false;
  }

  private notPassed(reason: string): Gate1Result {
    return {
      passed: false,
      candidates: [],
      db1Hits: [],
      db2Hits: [],
      reason,
    };
  }
}
