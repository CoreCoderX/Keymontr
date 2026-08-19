import { Gate4Result } from "./Gate4_Detection.js";
import {
  PlaceholderResult,
  FormatDisambiguationResult,
  AllowlistResult,
  ConfidenceBreakdown,
} from "../types/DetectionResult.js";
import { KeymontrConfig } from "../../config/ConfigurationManager.js";
import { isGenericRule } from "../../database/CollisionResolver.js";
import { isSpecificContextGroup } from "../layers/Layer3_ContextEngine.js";

/**
 * Gate 6 — Confidence Score Aggregator
 *
 * Combines all detection layer scores into a single confidence score.
 *
 * Formula:
 *   BASE_SCORE = weighted sum of 5 layer scores
 *   RISK_ADJUSTED = BASE_SCORE × fileRiskMultiplier
 *   ALLOWLIST_ADJUSTED = RISK_ADJUSTED × allowlistMultiplier
 *   PLACEHOLDER_ADJUSTED = ALLOWLIST_ADJUSTED × placeholderMultiplier
 *   FORMAT_ADJUSTED = PLACEHOLDER_ADJUSTED × formatMultiplier
 *   FINAL = hard-override check → emit
 *
 * Hard overrides:
 *   - Known provider regex match: floor at 0.90
 *   - Inline ignore comment: set to 0.00
 */

interface WeightConfig {
  regex: number;
  entropy: number;
  context: number;
  stringGroup: number;
  fileContext: number;
}

const DEFAULT_WEIGHTS: WeightConfig = {
  regex: 0.35,
  entropy: 0.2,
  context: 0.2,
  stringGroup: 0.15,
  fileContext: 0.1,
};

export class Gate6_ConfidenceAggregator {
  private weights: WeightConfig;

  constructor(config: KeymontrConfig) {
    // Normalize weights so they always sum to 1.0
    const raw = config.detection.weights;
    const total =
      raw.regex + raw.entropy + raw.context + raw.stringGroup + raw.fileContext;

    if (total === 0 || isNaN(total)) {
      this.weights = { ...DEFAULT_WEIGHTS };
    } else {
      this.weights = {
        regex: raw.regex / total,
        entropy: raw.entropy / total,
        context: raw.context / total,
        stringGroup: raw.stringGroup / total,
        fileContext: raw.fileContext / total,
      };
    }
  }

  /**
   * Aggregates all gate results into a final confidence score.
   */
  public aggregate(
    gate4: Gate4Result,
    placeholderResult: PlaceholderResult,
    formatResult: FormatDisambiguationResult,
    allowlistResult: AllowlistResult,
  ): ConfidenceBreakdown {
    // ── Step 1: Compute weighted base score ───────────────────────────────
    const components = {
      regex: gate4.layer1.score,
      entropy: gate4.layer2.score,
      context: gate4.layer3.score,
      stringGroup: gate4.layer4.score,
      fileContext: gate4.layer5.score,
    };

    let synergyBonus = 0;
    // Synergy (entropy × context corroboration) is reserved for findings with
    // NO regex match (rule=none). When a regex already matched, entropy and
    // context merely re-confirm it — stacking a bonus on top pushes generic
    // high-entropy values into CRITICAL territory without provider evidence.
    if (!gate4.layer1.matched && components.context >= 0.4 && components.entropy >= 0.6) {
      synergyBonus = 0.28;
    }

    const baseScore =
      components.regex * this.weights.regex +
      components.entropy * this.weights.entropy +
      components.context * this.weights.context +
      components.stringGroup * this.weights.stringGroup +
      components.fileContext * this.weights.fileContext +
      synergyBonus;

    // ── Step 2: Apply multipliers ─────────────────────────────────────────
    const fileRiskMultiplier = gate4.layer5.fileRiskMultiplier;
    const allowlistMultiplier = allowlistResult.multiplier;
    const placeholderMultiplier = placeholderResult.multiplier;
    const formatMultiplier = formatResult.multiplier;

    const riskAdjusted = baseScore * fileRiskMultiplier;
    const allowlistAdjusted = riskAdjusted * allowlistMultiplier;
    const placeholderAdjusted = allowlistAdjusted * placeholderMultiplier;
    let finalScore = placeholderAdjusted * formatMultiplier;

    // ── Step 3: Hard overrides ────────────────────────────────────────────

    // Allowlisted → always 0.00 (hard zero)
    if (allowlistResult.isAllowlisted) {
      finalScore = 0.0;
    }

    // Known provider regex match → floor at 0.90
    // Real secrets from known providers should always trigger regardless of
    // what other layers say. This prevents false negatives from low entropy
    // or missing context dampening an actual AWS key detection.
    if (gate4.layer1.isKnownProvider && !allowlistResult.isAllowlisted) {
      finalScore = Math.max(finalScore, 0.9);
    }

    // Generic rule match + same-line provider-context signal → floor at 0.90
    // e.g. "awsSecretAccessKey: wJalrXUtnFEMI/..." has no specific AWS rule,
    // but the identifier is unambiguous AWS context on the candidate's own
    // line — treat it like a provider match. Broad groups (Generic Secrets,
    // Common Aliases & Casings) do NOT trigger this floor.
    if (
      gate4.layer1.matched &&
      isGenericRule(gate4.layer1.ruleId ?? "") &&
      !allowlistResult.isAllowlisted &&
      gate4.layer3.contextSignals.some(
        (signal) => signal.distance === 0 && isSpecificContextGroup(signal.group),
      )
    ) {
      finalScore = Math.max(finalScore, 0.9);
    }

    // PEM private-key header (e.g. "-----BEGIN RSA PRIVATE KEY-----") is
    // unambiguous even when the full block is split across concatenated
    // string literals — floor at 0.90.
    if (
      /-----BEGIN[A-Z0-9 _-]*PRIVATE KEY-----/.test(gate4.candidate.value) &&
      !allowlistResult.isAllowlisted
    ) {
      finalScore = Math.max(finalScore, 0.9);
    }

    // Identifier-shaped values with low entropy are field/key NAMES, not
    // secrets (e.g. the "private_key" field in a JSON service-account file).
    // A regex may match the surrounding line, but "private_key" itself has
    // ~2.9 bits of entropy — far below any secret threshold.
    if (
      /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(gate4.candidate.value) &&
      gate4.layer2.entropy < 3.0
    ) {
      finalScore = 0.0;
    }

    // Clamp to [0, 1]
    finalScore = Math.max(0.0, Math.min(1.0, finalScore));

    // ── Step 4: Build human-readable explanation ──────────────────────────
    const explanation = this.buildExplanation(
      components,
      baseScore,
      fileRiskMultiplier,
      allowlistMultiplier,
      placeholderMultiplier,
      formatMultiplier,
      finalScore,
      gate4.layer1.isKnownProvider,
    );

    return {
      components,
      weights: { ...this.weights },
      baseScore,
      multipliers: {
        fileRisk: fileRiskMultiplier,
        allowlist: allowlistMultiplier,
        placeholder: placeholderMultiplier,
        formatDisambiguation: formatMultiplier,
      },
      finalScore,
      explanation,
    };
  }

  private buildExplanation(
    components: Record<string, number>,
    baseScore: number,
    fileRisk: number,
    allowlist: number,
    placeholder: number,
    format: number,
    final: number,
    isKnownProvider: boolean,
  ): string {
    const parts: string[] = [];

    parts.push(
      `Base score: ${baseScore.toFixed(3)} ` +
        `(regex=${components["regex"]?.toFixed(2) ?? "0"}, ` +
        `entropy=${components["entropy"]?.toFixed(2) ?? "0"}, ` +
        `context=${components["context"]?.toFixed(2) ?? "0"}, ` +
        `strings=${components["stringGroup"]?.toFixed(2) ?? "0"}, ` +
        `file=${components["fileContext"]?.toFixed(2) ?? "0"})`,
    );

    if (fileRisk !== 1.0) {
      parts.push(`File risk multiplier: ×${fileRisk.toFixed(2)}`);
    }
    if (allowlist < 1.0) {
      parts.push(`Allowlist reduction: ×${allowlist.toFixed(2)}`);
    }
    if (placeholder < 1.0) {
      parts.push(`Placeholder reduction: ×${placeholder.toFixed(2)}`);
    }
    if (format < 1.0) {
      parts.push(`Format disambiguation: ×${format.toFixed(2)}`);
    }
    if (isKnownProvider) {
      parts.push(`Known provider override: floor=0.90`);
    }

    parts.push(`Final confidence: ${(final * 100).toFixed(1)}%`);

    return parts.join(" | ");
  }
}
