/**
 * Severity levels for secret findings.
 * Ordered from lowest to highest severity.
 */
export enum SeverityLevel {
  INFORMATIONAL = "informational",
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

/**
 * Numeric representation for comparisons.
 */
export const SEVERITY_NUMERIC: Record<SeverityLevel, number> = {
  [SeverityLevel.INFORMATIONAL]: 1,
  [SeverityLevel.LOW]: 2,
  [SeverityLevel.MEDIUM]: 3,
  [SeverityLevel.HIGH]: 4,
  [SeverityLevel.CRITICAL]: 5,
};

/**
 * Human-readable labels.
 */
export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  [SeverityLevel.INFORMATIONAL]: "Informational",
  [SeverityLevel.LOW]: "Low",
  [SeverityLevel.MEDIUM]: "Medium",
  [SeverityLevel.HIGH]: "High",
  [SeverityLevel.CRITICAL]: "Critical",
};

/**
 * VS Code theme color keys used for severity indicators.
 *
 * These resolve to real theme colors (adapting to light/dark themes)
 * and are applied via vscode.ThemeIcon + vscode.ThemeColor so the
 * sidebar and explorer show native indicator icons instead of emoji.
 */
export const SEVERITY_THEME_COLORS: Record<SeverityLevel, string> = {
  [SeverityLevel.INFORMATIONAL]: "charts.blue",
  [SeverityLevel.LOW]: "charts.green",
  [SeverityLevel.MEDIUM]: "charts.yellow",
  [SeverityLevel.HIGH]: "charts.orange",
  [SeverityLevel.CRITICAL]: "errorForeground",
};

/**
 * Confidence score thresholds that map to severity levels.
 */
export const SEVERITY_THRESHOLDS = {
  MINIMUM_TO_WARN: 0.4,
  INFORMATIONAL: { min: 0.4, max: 0.55 },
  LOW: { min: 0.55, max: 0.65 },
  MEDIUM: { min: 0.65, max: 0.75 },
  HIGH: { min: 0.75, max: 0.88 },
  CRITICAL: { min: 0.88, max: 1.0 },
} as const;

/**
 * Determines severity level from a confidence score.
 */
export function severityFromScore(score: number): SeverityLevel | null {
  if (score < SEVERITY_THRESHOLDS.MINIMUM_TO_WARN) {
    return null;
  }
  if (score >= SEVERITY_THRESHOLDS.CRITICAL.min) {
    return SeverityLevel.CRITICAL;
  }
  if (score >= SEVERITY_THRESHOLDS.HIGH.min) {
    return SeverityLevel.HIGH;
  }
  if (score >= SEVERITY_THRESHOLDS.MEDIUM.min) {
    return SeverityLevel.MEDIUM;
  }
  if (score >= SEVERITY_THRESHOLDS.LOW.min) {
    return SeverityLevel.LOW;
  }
  return SeverityLevel.INFORMATIONAL;
}

/**
 * Returns true if the severity level should block a git commit
 * based on the provided configuration.
 */
export function shouldBlockCommit(
  severity: SeverityLevel,
  blockOnCritical: boolean,
  blockOnHigh: boolean,
  blockOnMedium: boolean,
): boolean {
  switch (severity) {
    case SeverityLevel.CRITICAL:
      return blockOnCritical;
    case SeverityLevel.HIGH:
      return blockOnHigh;
    case SeverityLevel.MEDIUM:
      return blockOnMedium;
    case SeverityLevel.LOW:
    case SeverityLevel.INFORMATIONAL:
      return false;
    default:
      return false;
  }
}
