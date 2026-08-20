import { SeverityLevel } from "./SeverityLevel.js";
import {
  SecretCandidate,
  ConfidenceBreakdown,
  FileRiskLevel,
} from "./DetectionResult.js";

/**
 * The remediation suggestion for a detected secret.
 */
export interface RemediationSuggestion {
  suggestedEnvKey: string;
  autoFixAvailable: boolean;
  fixSteps: string[];
  estimatedEffort: "instant" | "seconds" | "minutes";
}

/**
 * Suppression metadata for a finding.
 */
export interface SuppressionInfo {
  suppressionKey: string;
  inlineIgnoreComment: string;
  isPermanentlySuppressed: boolean;
  isSessionSuppressed: boolean;
}

/**
 * A fully resolved secret finding — the final output of the pipeline.
 */
export interface SecretFinding {
  /** Unique ID for this finding (UUID) */
  id: string;

  /** The raw candidate that was detected */
  candidate: SecretCandidate;

  /** Complete confidence breakdown */
  confidence: ConfidenceBreakdown;

  /** Final severity level */
  severity: SeverityLevel;

  /** Detection metadata */
  detection: {
    matchedRuleId?: string;
    matchedRuleName?: string;
    matchedGroup?: string;
    entropyValue: number;
    isKnownProvider: boolean;
  };

  /** Auto-fix suggestions */
  remediation: RemediationSuggestion;

  /** Suppression information */
  suppression: SuppressionInfo;

  /** File and timing metadata */
  meta: {
    detectedAt: Date;
    fileUri: string;
    fileName: string;
    fileRiskLevel: FileRiskLevel;
    languageId: string;
    triggerType: string;
  };
}

/**
 * The complete output of one pipeline run.
 */
export interface PipelineResult {
  fileUri: string;
  scannedAt: Date;
  findings: SecretFinding[];
  stats: {
    linesScanned: number;
    candidatesEvaluated: number;
    findingsCount: number;
    skippedByGate: Record<string, number>;
    processingTimeMs: number;
  };
  error?: string;
}

/**
 * Suppression record stored in developer memory.
 */
export interface SuppressionRecord {
  suppressionKey: string;
  fileUri: string;
  /** Zero-based line number of the suppressed finding. */
  lineNumber?: number;
  lineContent: string;
  ruleId?: string;
  /** Severity of the suppressed finding. Absent when unknown (e.g. session-only). */
  severity?: SeverityLevel;
  suppressedAt: Date;
  reason?: string;
  expiresAt?: Date;
}
