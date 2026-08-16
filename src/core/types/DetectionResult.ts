/**
 * Possible line types for code context classification.
 */
export enum LineType {
  ASSIGNMENT = "assignment",
  FUNCTION_ARGUMENT = "function_argument",
  OBJECT_PROPERTY = "object_property",
  ARRAY_ELEMENT = "array_element",
  COMMENT = "comment",
  IMPORT = "import",
  RETURN_STATEMENT = "return",
  EXPORT = "export",
  UNKNOWN = "unknown",
}

/**
 * File risk classification levels.
 */
export enum FileRiskLevel {
  EXCLUDED = -1,
  REDUCED = 0,
  NORMAL = 1,
  ELEVATED = 2,
  HIGH = 3,
}

export const FILE_RISK_MULTIPLIERS: Record<FileRiskLevel, number> = {
  [FileRiskLevel.EXCLUDED]: 0,
  [FileRiskLevel.REDUCED]: 0.5,
  [FileRiskLevel.NORMAL]: 1.0,
  [FileRiskLevel.ELEVATED]: 1.2,
  [FileRiskLevel.HIGH]: 1.4,
};

/**
 * A candidate secret string extracted from source code.
 */
export interface SecretCandidate {
  /** The raw string value (the candidate secret) */
  value: string;
  /** 0-based line number */
  lineNumber: number;
  /** 0-based start char index on the line */
  startChar: number;
  /** 0-based end char index on the line */
  endChar: number;
  /** Full line content */
  line: string;
  /** Up to 5 lines before and after */
  surroundingLines: string[];
  /** Which DB1 keywords triggered this candidate */
  db1KeywordHits: string[];
  /** Which DB2 identifiers triggered this candidate */
  db2IdentifierHits: string[];
}

/**
 * Result from Layer 1 — Regex Engine.
 */
export interface RegexLayerResult {
  matched: boolean;
  ruleId?: string;
  ruleName?: string;
  matchedValue?: string;
  matchStart?: number;
  matchEnd?: number;
  score: number;
  isKnownProvider: boolean;
  allMatchedRules: Array<{ ruleId: string; score: number }>;
}

/**
 * Character set analysis for entropy calculation.
 */
export interface CharsetAnalysis {
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasDigits: boolean;
  hasSpecial: boolean;
  charsetSize: number;
}

/**
 * Result from Layer 2 — Entropy Engine.
 */
export interface EntropyLayerResult {
  entropy: number;
  ruleThreshold: number;
  meetsThreshold: boolean;
  score: number;
  charsetAnalysis: CharsetAnalysis;
}

/**
 * A single context signal from nearby code.
 */
export interface ContextSignal {
  identifier: string;
  group: string;
  lineNumber: number;
  distance: number;
  weight: number;
}

/**
 * Result from Layer 3 — Context Engine.
 */
export interface ContextLayerResult {
  nearbyIdentifiers: string[];
  matchedGroups: string[];
  contextSignals: ContextSignal[];
  score: number;
}

/**
 * Result from Layer 4 — StringGroup Engine (Paper Implementation).
 */
export interface StringGroupLayerResult {
  surroundingStrings: string[];
  authenticationStrings: string[];
  providerStrings: string[];
  score: number;
}

/**
 * Result from Layer 5 — File Context Scorer.
 */
export interface FileContextLayerResult {
  fileRiskLevel: FileRiskLevel;
  fileRiskMultiplier: number;
  isInComment: boolean;
  isInString: boolean;
  isAssignment: boolean;
  isInArray: boolean;
  lineType: LineType;
  score: number;
}

/**
 * Aggregated scores from Gate 2 — Placeholder Elimination.
 */
export interface PlaceholderResult {
  isPlaceholder: boolean;
  confidence: number;
  matchedPatterns: string[];
  multiplier: number;
}

/**
 * Result from Gate 3 — Format Disambiguation.
 */
export interface FormatDisambiguationResult {
  isKnownNonSecret: boolean;
  matchedFormats: string[];
  confidenceReduction: number;
  multiplier: number;
}

/**
 * Result from Gate 5 — Allowlist Engine.
 */
export interface AllowlistResult {
  isAllowlisted: boolean;
  matchedAllowlist?: string;
  multiplier: number;
}

/**
 * Full breakdown of the confidence score.
 */
export interface ConfidenceBreakdown {
  components: {
    regex: number;
    entropy: number;
    context: number;
    stringGroup: number;
    fileContext: number;
  };
  weights: {
    regex: number;
    entropy: number;
    context: number;
    stringGroup: number;
    fileContext: number;
  };
  baseScore: number;
  multipliers: {
    fileRisk: number;
    allowlist: number;
    placeholder: number;
    formatDisambiguation: number;
  };
  finalScore: number;
  explanation: string;
}
