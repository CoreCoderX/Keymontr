import { GitleaksDatabase } from "../../database/GitleaksDatabase.js";
import { CollisionResolver } from "../../database/CollisionResolver.js";
import { SecretCandidate, RegexLayerResult } from "../types/DetectionResult.js";
import { CompiledRule } from "../types/RuleDefinition.js";

/**
 * Layer 1 — Regex Engine
 *
 * Runs the compiled Gitleaks regex rules against the candidate.
 * Handles keyword collisions by running ALL matching rules (not first-wins).
 *
 * A known-provider regex match is the highest-confidence signal we have.
 * "AKIA..." is an AWS key. "ghp_..." is a GitHub PAT. No ambiguity.
 *
 * Base score for a full-line regex match: 0.92
 * Base score for a value-only regex match: 0.85
 * No regex match: 0.0
 */
export class Layer1_RegexEngine {
  constructor(
    private readonly gitleaksDb: GitleaksDatabase,
    private readonly collisionResolver: CollisionResolver,
  ) {}

  /**
   * Runs regex detection on a candidate secret.
   */
  public evaluate(candidate: SecretCandidate): RegexLayerResult {
    // Collect all rule IDs triggered by the DB1 keyword hits
    const triggeredRuleIds = this.collectTriggeredRuleIds(candidate);

    if (triggeredRuleIds.size === 0) {
      return this.noMatch();
    }

    // Load the actual compiled rule objects
    const triggeredRules: CompiledRule[] = [];
    for (const ruleId of triggeredRuleIds) {
      const rule = this.gitleaksDb.getRule(ruleId);
      if (rule !== undefined) {
        triggeredRules.push(rule);
      }
    }

    if (triggeredRules.length === 0) {
      return this.noMatch();
    }

    // Run all triggered rules via the collision resolver
    const resolutions = this.collisionResolver.resolveCollisions(
      candidate.value,
      candidate.line,
      triggeredRules,
    );

    if (resolutions.length === 0) {
      return this.noMatch();
    }

    const best = this.collisionResolver.getBestResolution(resolutions);
    if (best === null) {
      return this.noMatch();
    }

    // All resolutions for transparency
    const allMatchedRules = resolutions.map((r) => ({
      ruleId: r.ruleId,
      score: r.score,
    }));

    return {
      matched: true,
      ruleId: best.ruleId,
      ruleName: best.ruleName,
      matchedValue: best.matchedValue,
      matchStart: candidate.startChar,
      matchEnd: candidate.endChar,
      score: best.score,
      isKnownProvider: true,
      allMatchedRules,
    };
  }

  /**
   * Collects all rule IDs that should be evaluated based on keyword hits.
   * Also runs ALL rules if no keyword hits exist (for thoroughness on high-entropy strings).
   */
  private collectTriggeredRuleIds(candidate: SecretCandidate): Set<string> {
    const ruleIds = new Set<string>();

    // From DB1 keyword hits recorded in the candidate
    for (const keyword of candidate.db1KeywordHits) {
      const ids = this.gitleaksDb.getRuleIdsForKeyword(keyword);
      for (const id of ids) {
        ruleIds.add(id);
      }
    }

    // Also run against value directly to catch patterns missed by keyword filter
    // This handles cases where the value itself (not surrounding identifiers) contains
    // provider-specific patterns like "AKIA", "ghp_", "sk-"
    const valueLower = candidate.value.toLowerCase();
    for (const kw of this.gitleaksDb.getAllKeywords()) {
      if (valueLower.includes(kw)) {
        const ids = this.gitleaksDb.getRuleIdsForKeyword(kw);
        for (const id of ids) {
          ruleIds.add(id);
        }
      }
    }

    return ruleIds;
  }

  /**
   * Returns the entropy threshold configured for a specific rule.
   * Returns undefined if the rule is unknown or has no entropy threshold.
   */
  public getEntropyThresholdForRule(ruleId: string): number | undefined {
    const rule = this.gitleaksDb.getRule(ruleId);
    if (rule === undefined || rule.entropy <= 0) {
      return undefined;
    }
    return rule.entropy;
  }

  private noMatch(): RegexLayerResult {
    return {
      matched: false,
      score: 0.0,
      isKnownProvider: false,
      allMatchedRules: [],
    };
  }
}
