/**
 * Represents a single allowlist entry from DB1 (Gitleaks).
 */
export interface RuleAllowlist {
  description?: string;
  paths?: string[];
  regexes?: string[];
  regexTarget?: "match" | "line";
  stopwords?: string[];
  condition?: "AND" | "OR";
}

/**
 * Represents a single Gitleaks rule from DB1.
 */
export interface GitleaksRule {
  id: string;
  description: string;
  regex: string;
  entropy?: number;
  keywords: string[];
  path?: string;
  secretGroup?: number;
  allowlists?: RuleAllowlist[];
}

/**
 * Top-level structure of gitleaks-rules.json.
 */
export interface GitleaksRulesFile {
  title: string;
  minVersion: string;
  allowlist?: {
    description?: string;
    paths?: string[];
    regexes?: string[];
    stopwords?: string[];
  };
  rules: GitleaksRule[];
}

/**
 * Compiled rule — regex is pre-compiled for performance.
 */
export interface CompiledRule {
  id: string;
  description: string;
  regex: RegExp;
  rawRegex: string;
  entropy: number;
  keywords: string[];
  pathRegex?: RegExp;
  secretGroup: number;
  allowlists: CompiledAllowlist[];
}

/**
 * Compiled allowlist — regexes are pre-compiled.
 */
export interface CompiledAllowlist {
  description?: string;
  paths: RegExp[];
  regexes: RegExp[];
  regexTarget: "match" | "line";
  stopwords: string[];
  condition: "AND" | "OR";
}

/**
 * DB1 keyword index: keyword string → rule IDs (plural, for collision handling).
 */
export type DB1KeywordIndex = Map<string, string[]>;

/**
 * DB2 identifier index: identifier string → group name.
 */
export type DB2IdentifierIndex = Map<string, string>;

/**
 * Custom rule defined by the developer in .keymontr.json.
 */
export interface CustomRule {
  id: string;
  description: string;
  regex: string;
  entropy?: number;
  keywords?: string[];
  severity?: "informational" | "low" | "medium" | "high" | "critical";
}
