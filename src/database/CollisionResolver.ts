import { CompiledRule } from "../core/types/RuleDefinition.js";

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

    // Sort by score descending (best match first)
    results.sort((a, b) => b.score - a.score);

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
        score: 0.85, // Partial match — value only, not full line
        isFullLineMatch: false,
        entropy: rule.entropy,
      };
    }

    // Full line match — highest confidence
    const matchedValue = match[rule.secretGroup] ?? match[0] ?? candidateValue;

    return {
      ruleId: rule.id,
      ruleName: rule.description,
      matchedValue,
      score: 0.92, // Full line regex match = very high confidence
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
