import {
  SecretCandidate,
  EntropyLayerResult,
} from "../types/DetectionResult.js";
import {
  calculateShannonEntropy,
  analyzeCharset,
  adjustedEntropyScore,
} from "../utils/ShannonEntropy.js";

/**
 * Layer 2 — Entropy Engine
 *
 * Measures the randomness (Shannon entropy) of a candidate string.
 * High entropy indicates the string is more likely to be a real secret.
 *
 * Entropy alone is NOT sufficient (UUIDs have high entropy but aren't secrets).
 * Gate 3 eliminates known non-secret high-entropy formats.
 * This layer provides an entropy-based contribution to the confidence score.
 *
 * Default entropy threshold: 3.0 (from Gitleaks research)
 * Rule-specific thresholds: taken from DB1 rule definition
 */

// Default entropy threshold when no rule-specific threshold is available
const DEFAULT_ENTROPY_THRESHOLD = 3.0;

export class Layer2_EntropyEngine {
  /**
   * Evaluates the entropy of a candidate secret value.
   *
   * @param candidate - The secret candidate
   * @param ruleEntropyThreshold - Rule-specific entropy threshold (from DB1)
   */
  public evaluate(
    candidate: SecretCandidate,
    ruleEntropyThreshold?: number,
  ): EntropyLayerResult {
    const value = candidate.value;
    const threshold = ruleEntropyThreshold ?? DEFAULT_ENTROPY_THRESHOLD;

    // Calculate raw Shannon entropy
    const entropy = calculateShannonEntropy(value);

    // Analyze character composition
    const charsetAnalysis = analyzeCharset(value);

    // Normalized score (0.0-1.0) with charset diversity bonus
    const adjustedScore = adjustedEntropyScore(value);

    // Final score considers both normalized entropy and charset diversity
    const score = this.computeFinalScore(
      entropy,
      threshold,
      adjustedScore,
      charsetAnalysis.charsetSize,
    );

    return {
      entropy,
      ruleThreshold: threshold,
      meetsThreshold: entropy >= threshold,
      score,
      charsetAnalysis: {
        hasUppercase: charsetAnalysis.hasUppercase,
        hasLowercase: charsetAnalysis.hasLowercase,
        hasDigits: charsetAnalysis.hasDigits,
        hasSpecial: charsetAnalysis.hasSpecial,
        charsetSize: charsetAnalysis.charsetSize,
      },
    };
  }

  /**
   * Computes the final entropy score.
   *
   * Factors:
   * 1. Does entropy meet the rule threshold?
   * 2. How far above/below the threshold is it?
   * 3. How diverse is the character set?
   */
  private computeFinalScore(
    entropy: number,
    threshold: number,
    adjustedScore: number,
    charsetSize: number,
  ): number {
    if (entropy < 2.0) {
      // Extremely low entropy — definitely not a random secret
      return 0.0;
    }

    if (entropy < threshold) {
      // Below threshold — partial credit scaled by how close we are
      const ratio = entropy / threshold;
      return Math.min(0.3, adjustedScore * ratio);
    }

    // Above threshold — full score with charset diversity bonus
    let score = adjustedScore;

    // Charset size bonus: larger charset = more likely real secret
    if (charsetSize >= 94) {
      score = Math.min(1.0, score + 0.05);
    } else if (charsetSize >= 62) {
      score = Math.min(1.0, score + 0.03);
    }

    // Penalize if string is very long (> 200 chars) — less likely to be a secret
    return score;
  }

  /**
   * Calculates entropy for a collection of strings (for StringGroup analysis).
   * Returns the average entropy across all strings.
   */
  public averageEntropy(values: string[]): number {
    if (values.length === 0) {
      return 0;
    }
    const total = values.reduce(
      (sum, v) => sum + calculateShannonEntropy(v),
      0,
    );
    return total / values.length;
  }
}
