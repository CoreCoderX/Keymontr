import { CompiledRule } from "../core/types/RuleDefinition.js";

/**
 * Rule IDs that are broad catch-alls. When multiple rules tie at the same
 * score, these must LOSE the tie-breaker so that specific provider rules
 * (e.g. openai-api-key, sendgrid-api-token) win over generic-api-key.
 */
const GENERIC_RULE_PREFIXES = ["generic-"];

export function isGenericRule(ruleId: string): boolean {
  return GENERIC_RULE_PREFIXES.some((prefix) =>
    ruleId.toLowerCase().startsWith(prefix),
  );
}

/**
 * Generic catch-all rules (generic-api-key, generic-secret) are only
 * "shape" matches — a keyword plus a high-entropy-looking value. They are
 * strictly weaker evidence than a specific provider regex, so they score
 * lower and never receive the known-provider confidence floor.
 */

/**
 * Handles keyword collisions in DB1 where multiple rules share the same keyword.
 *
 * Gitleaks has 37 known keyword collisions (e.g., "twitter" × 5 rules).
 * Instead of first-occurrence-wins, we run ALL matching rules and return
 * the highest confidence match plus secondary findings.
 */
export class CollisionResolver {
  /**
   * Given multiple rules that matched for the same keyword,
   * runs all their regexes against the candidate value and
   * returns results sorted by match quality.
   */
  public resolveCollisions(
    candidateValue: string,
    fullLine: string,
    rules: CompiledRule[],
  ): CollisionResolution[] {
    const results: CollisionResolution[] = [];

    for (const rule of rules) {
      const resolution = this.testRule(candidateValue, fullLine, rule);
      if (resolution !== null) {
        results.push(resolution);
      }
    }

    // Sort by score descending (best match first), then break ties so that
    // specific provider rules beat generic catch-all rules (generic-api-key).
    results.sort((a, b) => {
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      const aGeneric = isGenericRule(a.ruleId) ? 1 : 0;
      const bGeneric = isGenericRule(b.ruleId) ? 1 : 0;
      if (aGeneric !== bGeneric) {
        return aGeneric - bGeneric;
      }
      // Deterministic tie-break regardless of insertion order
      return a.ruleId.localeCompare(b.ruleId);
    });

    return results;
  }

  /**
   * Tests a single rule against the candidate.
   * Returns null if no match.
   */
  private testRule(
    candidateValue: string,
    fullLine: string,
    rule: CompiledRule,
  ): CollisionResolution | null {
    // Reset regex state (important for global flag)
    rule.regex.lastIndex = 0;

    // Try to match against the full line (Gitleaks style)
    const match = rule.regex.exec(fullLine);

    if (match === null) {
      // Also try just the candidate value directly
      rule.regex.lastIndex = 0;
      const valueMatch = rule.regex.exec(candidateValue);

      if (valueMatch === null) {
        return null;
      }

      return {
        ruleId: rule.id,
        ruleName: rule.description,
        matchedValue:
          valueMatch[rule.secretGroup] ?? valueMatch[0] ?? candidateValue,
        score: isGenericRule(rule.id) ? 0.6 : 0.85, // Partial match — value only, not full line
        isFullLineMatch: false,
        entropy: rule.entropy,
      };
    }

    // Only accept a full-line match if it actually overlaps the candidate
    // value. Otherwise a rule matching one literal on a multi-literal line
    // (e.g. a PEM block) would also label an unrelated literal (e.g. the
    // identifier "private_key") as the same secret.
    const matchStart = match.index;
    const matchEnd = match.index + match[0].length;
    const valueIndex = fullLine.indexOf(candidateValue);
    if (valueIndex !== -1) {
      const valueStart = valueIndex;
      const valueEnd = valueIndex + candidateValue.length;
      if (valueEnd <= matchStart || valueStart >= matchEnd) {
        return null;
      }
    }

    // Full line match — highest confidence
    const matchedValue = match[rule.secretGroup] ?? match[0] ?? candidateValue;

    return {
      ruleId: rule.id,
      ruleName: rule.description,
      matchedValue,
      score: isGenericRule(rule.id) ? 0.8 : 0.92, // Full line regex match = very high confidence
      isFullLineMatch: true,
      entropy: rule.entropy,
    };
  }

  /**
   * Returns the single best resolution from a set of collision resolutions.
   * If no resolutions, returns null.
   */
  public getBestResolution(
    resolutions: CollisionResolution[],
  ): CollisionResolution | null {
    if (resolutions.length === 0) {
      return null;
    }
    return resolutions[0] ?? null;
  }
}

export interface CollisionResolution {
  ruleId: string;
  ruleName: string;
  matchedValue: string;
  score: number;
  isFullLineMatch: boolean;
  entropy: number;
}
