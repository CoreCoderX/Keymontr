import * as path from "path";
import {
  SecretCandidate,
  FileContextLayerResult,
  FileRiskLevel,
  FILE_RISK_MULTIPLIERS,
} from "../types/DetectionResult.js";
import {
  LineType,
  classifyLine,
  isStringAssignment,
  isArrayContext,
} from "../utils/LineClassifier.js";

/**
 * Layer 5 — File Context Scorer
 *
 * Uses file-level and line-level context to adjust confidence scores.
 *
 * This layer does NOT detect secrets — it modulates the confidence
 * of other layers based on WHERE the candidate appears.
 *
 * Key insights:
 * - A hardcoded value inside config.ts is more suspicious than in README.md
 * - An assignment statement is more suspicious than an array element
 * - A comment is almost never a live secret (it's documentation)
 * - .env files are almost always holding real credentials
 */

export class Layer5_FileContextScorer {
  /**
   * Scores the file and line context of a candidate.
   *
   * @param candidate - The secret candidate
   * @param fileUri - Absolute path to the file
   * @param fileRiskLevel - Risk level determined by Gate 0
   * @param isLineInComment - Whether this line is in a comment block
   */
  public evaluate(
    candidate: SecretCandidate,
    fileRiskLevel: FileRiskLevel,
    isLineInComment: boolean,
  ): FileContextLayerResult {
    const line = candidate.line;
    const lineType = classifyLine(line);

    const isInComment = isLineInComment || lineType === LineType.COMMENT;
    const isInString = isStringAssignment(line);
    const isAssignment =
      lineType === LineType.ASSIGNMENT || lineType === LineType.OBJECT_PROPERTY;
    const isInArray =
      lineType === LineType.ARRAY_ELEMENT || isArrayContext(line);

    const fileRiskMultiplier = FILE_RISK_MULTIPLIERS[fileRiskLevel];

    const score = this.computeScore(
      lineType,
      isInComment,
      isInString,
      isAssignment,
      isInArray,
      fileRiskMultiplier,
    );

    return {
      fileRiskLevel,
      fileRiskMultiplier,
      isInComment,
      isInString,
      isAssignment,
      isInArray,
      lineType,
      score,
    };
  }

  /**
   * Computes the file context score.
   */
  private computeScore(
    lineType: LineType,
    isInComment: boolean,
    isInString: boolean,
    isAssignment: boolean,
    isInArray: boolean,
    fileRiskMultiplier: number,
  ): number {
    let score = 0.5; // Baseline: neutral context

    // ── Line type adjustments ──────────────────────────────────────────────
    if (isInComment) {
      // Comments are documentation — strong negative signal
      score -= 0.35;
    } else if (isAssignment) {
      // Assignment is the most common way to store a secret
      score += 0.25;
    } else if (lineType === LineType.IMPORT) {
      // Import statements almost never contain hardcoded secrets
      score -= 0.2;
    } else if (lineType === LineType.RETURN_STATEMENT) {
      // Returning a literal — could be a secret from a factory function
      score += 0.05;
    } else if (isInArray) {
      // Arrays of strings are less likely to hold secrets individually
      score -= 0.1;
    }

    // ── String assignment bonus ────────────────────────────────────────────
    if (isInString && !isInComment) {
      score += 0.1;
    }

    // ── File risk multiplier scaling ──────────────────────────────────────
    // The file risk multiplier adjusts the base score
    // HIGH risk file (1.4): score × 1.4 / 1.0 → amplified
    // REDUCED risk file (0.5): score × 0.5 / 1.0 → dampened
    score = score * fileRiskMultiplier;

    return Math.max(0.0, Math.min(1.0, score));
  }

  /**
   * Extracts a human-readable file name from a URI.
   */
  public getFileName(fileUri: string): string {
    return path.basename(fileUri);
  }
}
