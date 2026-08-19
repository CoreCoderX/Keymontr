import { StringGroupDatabase } from "../../database/StringGroupDatabase.js";
import {
  SecretCandidate,
  ContextLayerResult,
  ContextSignal,
} from "../types/DetectionResult.js";
import { extractIdentifiers } from "../utils/Tokenizer.js";

/**
 * Layer 3 — Context Engine
 *
 * Analyzes identifier names surrounding the candidate to determine
 * if the code context suggests a secret is being stored.
 *
 * Uses DB2 (StringGroup identifier database) for O(1) group lookup.
 *
 * Context window: ±5 lines from the candidate.
 * Distance weighting: closer lines = higher weight.
 *
 * Example:
 *   const OPENAI_API_KEY = "sk-...";
 *                ↑
 *   "OPENAI_API_KEY" → DB2 group "OpenAI" → strong context signal
 */

// Distance weighting for context signals
const DISTANCE_WEIGHTS: Record<number, number> = {
  0: 1.0, // Same line
  1: 0.8, // ±1 line
  2: 0.6, // ±2 lines
  3: 0.4, // ±3 lines
  4: 0.2, // ±4 lines
  5: 0.1, // ±5 lines
};

// Groups that contribute the most to secret classification
const HIGH_SIGNAL_GROUPS = new Set([
  "Generic Secrets",
  "Common Aliases & Casings",
  "AWS",
  "Azure",
  "Google Cloud Platform",
  "OpenAI",
  "Anthropic",
  "Stripe",
  "GitHub",
  "GitLab",
  "Certificates",
  "Databases",
  "OAuth & Social",
]);

/**
 * Context groups that identify a SPECIFIC provider/technology. Broad
 * catch-all groups ("Generic Secrets", "Common Aliases & Casings") are
 * excluded — they only indicate "something secret-like", not a vendor.
 */
export function isSpecificContextGroup(group: string): boolean {
  return (
    HIGH_SIGNAL_GROUPS.has(group) &&
    group !== "Generic Secrets" &&
    group !== "Common Aliases & Casings"
  );
}

export class Layer3_ContextEngine {
  constructor(private readonly stringGroupDb: StringGroupDatabase) {}

  /**
   * Evaluates the identifier context around a candidate secret.
   */
  public evaluate(candidate: SecretCandidate): ContextLayerResult {
    const allLines = this.buildContextLines(candidate);
    const signals: ContextSignal[] = [];
    const matchedGroups = new Set<string>();
    const allIdentifiers: string[] = [];

    for (const { line, distance } of allLines) {
      const identifiers = extractIdentifiers(line);
      allIdentifiers.push(...identifiers);

      for (const identifier of identifiers) {
        const match = this.stringGroupDb.getGroupWithVariants(identifier);
        if (match !== undefined) {
          signals.push({
            identifier,
            group: match.group,
            lineNumber: candidate.lineNumber + distance,
            distance: Math.abs(distance),
            weight: DISTANCE_WEIGHTS[Math.abs(distance)] ?? 0.1,
          });
          matchedGroups.add(match.group);
        }
      }
    }

    const score = this.computeContextScore(signals);

    // Order matched groups by the nearest signal's distance — the group
    // closest to the candidate is the most relevant description of it.
    const nearestDistance = new Map<string, number>();
    for (const signal of signals) {
      const current = nearestDistance.get(signal.group);
      if (current === undefined || signal.distance < current) {
        nearestDistance.set(signal.group, signal.distance);
      }
    }
    const orderedGroups = Array.from(matchedGroups).sort(
      (a, b) =>
        (nearestDistance.get(a) ?? 99) - (nearestDistance.get(b) ?? 99),
    );

    return {
      nearbyIdentifiers: [...new Set(allIdentifiers)],
      matchedGroups: orderedGroups,
      contextSignals: signals,
      score,
    };
  }

  /**
   * Builds the context lines with their distance from the candidate line.
   *
   * The candidate stores up to ±5 surrounding lines, but near a file
   * boundary the array is truncated. Distance must be derived from how many
   * lines can actually precede the candidate, NOT from the array position —
   * otherwise a secret near the top/bottom of a file has its neighbors
   * treated as adjacent (distance collapses).
   */
  private buildContextLines(
    candidate: SecretCandidate,
  ): Array<{ line: string; distance: number }> {
    const result: Array<{ line: string; distance: number }> = [];

    // Candidate line itself (distance 0)
    result.push({ line: candidate.line, distance: 0 });

    // Surrounding lines — stored BEFORE-first, then AFTER.
    // Only `candidate.lineNumber` lines can precede the candidate (0-based),
    // capped at the 5-line window.
    const surrounding = candidate.surroundingLines;
    const beforeCount = Math.min(5, candidate.lineNumber);

    for (let i = 0; i < surrounding.length; i++) {
      const line = surrounding[i];
      if (line !== undefined) {
        const distance = i < beforeCount ? i - beforeCount : i - beforeCount + 1;
        result.push({ line, distance });
      }
    }

    return result;
  }

  /**
   * Computes the context score from collected signals.
   *
   * Score components:
   * - Number of unique matching groups
   * - Weight-adjusted signal strength
   * - Whether any high-signal groups matched
   */
  private computeContextScore(signals: ContextSignal[]): number {
    if (signals.length === 0) {
      return 0.0;
    }

    // Weighted score: sum of (weight × group_bonus)
    let weightedSum = 0;
    let totalWeight = 0;

    for (const signal of signals) {
      const groupBonus = HIGH_SIGNAL_GROUPS.has(signal.group) ? 1.0 : 0.7;
      weightedSum += signal.weight * groupBonus;
      totalWeight += signal.weight;
    }

    if (totalWeight === 0) {
      return 0.0;
    }

    const rawScore = weightedSum / totalWeight;

    // Bonus for multiple unique matching groups (stronger evidence)
    const uniqueGroups = new Set(signals.map((s) => s.group)).size;
    const groupBonus = Math.min(0.2, (uniqueGroups - 1) * 0.05);

    // Bonus for same-line signal (strongest evidence)
    const hasSameLineSignal = signals.some((s) => s.distance === 0);
    const sameLineBonus = hasSameLineSignal ? 0.1 : 0.0;

    return Math.min(1.0, rawScore + groupBonus + sameLineBonus);
  }
}
