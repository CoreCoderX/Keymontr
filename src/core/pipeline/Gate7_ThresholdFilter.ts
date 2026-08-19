import { ConfidenceBreakdown } from "../types/DetectionResult.js";
import { SeverityLevel, severityFromScore } from "../types/SeverityLevel.js";
import { KeymontrConfig } from "../../config/ConfigurationManager.js";

/**
 * Gate 7 — Minimum Threshold Filter
 *
 * Converts a confidence score to a severity level and determines
 * whether the finding should be surfaced to the developer.
 *
 * Findings below the minimum confidence threshold are silently discarded.
 * This is the final guard against low-confidence noise.
 */

export interface Gate7Result {
  shouldReport: boolean;
  severity: SeverityLevel | null;
  confidenceScore: number;
  reason: string;
}

export class Gate7_ThresholdFilter {
  private readonly minimumToWarn: number;

  constructor(config: KeymontrConfig) {
    this.minimumToWarn = config.detection.minimumConfidenceToWarn;
  }

  /**
   * Evaluates whether a finding meets the minimum threshold for reporting.
   *
   * @param confidence - The final confidence breakdown from Gate 6
   */
  public evaluate(confidence: ConfidenceBreakdown): Gate7Result {
    const score = confidence.finalScore;

    if (score < this.minimumToWarn) {
      return {
        shouldReport: false,
        severity: null,
        confidenceScore: score,
        reason: `Below minimum threshold (${score.toFixed(3)} < ${this.minimumToWarn})`,
      };
    }

    const severity = severityFromScore(score);

    if (severity === null) {
      return {
        shouldReport: false,
        severity: null,
        confidenceScore: score,
        reason: "Score does not map to any severity level",
      };
    }

    return {
      shouldReport: true,
      severity,
      confidenceScore: score,
      reason: `Confidence ${(score * 100).toFixed(1)}% → ${severity}`,
    };
  }
}
