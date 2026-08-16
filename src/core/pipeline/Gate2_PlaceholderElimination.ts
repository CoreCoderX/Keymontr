import { SecretCandidate } from "../types/DetectionResult.js";
import { PlaceholderResult } from "../types/DetectionResult.js";

/**
 * Gate 2 — Placeholder Elimination Layer
 *
 * This gate is the #1 defense against false positives from developer-written
 * placeholder values. It detects strings that look like secrets but are
 * obviously not real credentials.
 *
 * A confirmed placeholder sets confidence multiplier to 0.05,
 * effectively suppressing all warnings for that candidate.
 *
 * Exception: If a DB1 regex matches exactly AND entropy is very high,
 * the placeholder reduction is overridden (a real key used as "placeholder").
 */

interface PlaceholderPattern {
  name: string;
  pattern: RegExp;
  multiplier: number; // How much to reduce confidence
}

const PLACEHOLDER_PATTERNS: PlaceholderPattern[] = [
  // ── Template-style placeholders ───────────────────────────────────────────
  {
    name: "angle-bracket-template",
    pattern: /^<[^>]{1,100}>$/,
    multiplier: 0.02,
  },
  {
    name: "square-bracket-template",
    pattern: /^\[[^\]]{1,100}\]$/,
    multiplier: 0.02,
  },
  {
    name: "curly-brace-template",
    pattern: /^\{[^}]{1,100}\}$/,
    multiplier: 0.02,
  },
  {
    name: "shell-variable",
    pattern: /^\$\{?[A-Z_][A-Z0-9_]*\}?$/,
    multiplier: 0.02,
  },

  // ── Explicit placeholder words ─────────────────────────────────────────────
  {
    name: "contains-example",
    pattern: /\b(example|sample|placeholder|dummy|fake|mock|stub|fixture)\b/i,
    multiplier: 0.05,
  },
  {
    name: "your-or-my-prefix",
    pattern:
      /\b(your|my|the|our|enter|insert|provide|put|add)[-_\s]?(api[-_]?key|token|secret|password|credential|key)\b/i,
    multiplier: 0.03,
  },
  {
    name: "changeme",
    pattern:
      /\b(change[-_]?me|replace[-_]?me|todo|fixme|update[-_]?me|fill[-_]?me|set[-_]?me)\b/i,
    multiplier: 0.02,
  },
  {
    name: "test-prefix",
    pattern:
      /^(test|demo|dev|staging|local|fake|mock|dummy)[-_][a-z0-9_-]{1,50}$/i,
    multiplier: 0.08,
  },

  // ── Repeated character patterns ────────────────────────────────────────────
  {
    name: "all-same-char",
    pattern: /^(.)\1{7,}$/, // 8+ of same character
    multiplier: 0.01,
  },
  {
    name: "sequential-repeat",
    pattern: /^(ab|abc|abcd|123|1234){3,}$/i,
    multiplier: 0.01,
  },
  {
    name: "x-padding",
    pattern: /^x{6,}$/i,
    multiplier: 0.01,
  },

  // ── Common test/null values ────────────────────────────────────────────────
  {
    name: "null-like",
    pattern: /^(null|none|undefined|empty|blank|n\/a|na|nil|void|false|true)$/i,
    multiplier: 0.01,
  },
  {
    name: "common-test-password",
    pattern:
      /^(password|passwd|pass|secret|admin|root|test|demo|user|qwerty|letmein|welcome|monkey|dragon|123456|password1)[\d!@#]*$/i,
    multiplier: 0.08,
  },

  // ── Documentation patterns ─────────────────────────────────────────────────
  {
    name: "your-x-here",
    pattern: /\b(your|the|a)\s+\w+\s+here\b/i,
    multiplier: 0.02,
  },
  {
    name: "insert-x-here",
    pattern: /\b(insert|enter|add|put|place)\s+(your\s+)?\w+\s+here\b/i,
    multiplier: 0.02,
  },

  // ── Placeholder formats by length ──────────────────────────────────────────
  {
    name: "short-placeholder",
    pattern: /^[a-z_]{2,6}$/i, // Too short and simple to be a real secret
    multiplier: 0.1,
  },
];

export class Gate2_PlaceholderElimination {
  /**
   * Evaluates a candidate for placeholder characteristics.
   *
   * @param candidate - The secret candidate from Gate 1
   * @returns PlaceholderResult with confidence multiplier
   */
  public evaluate(candidate: SecretCandidate): PlaceholderResult {
    const value = candidate.value;
    const matchedPatterns: string[] = [];
    let lowestMultiplier = 1.0;

    for (const { name, pattern, multiplier } of PLACEHOLDER_PATTERNS) {
      if (pattern.test(value)) {
        matchedPatterns.push(name);
        if (multiplier < lowestMultiplier) {
          lowestMultiplier = multiplier;
        }
      }
    }

    // Also check surrounding context for placeholder indicators
    const contextMultiplier = this.evaluateContext(candidate);
    if (contextMultiplier < lowestMultiplier) {
      lowestMultiplier = contextMultiplier;
      if (contextMultiplier < 0.2) {
        matchedPatterns.push("placeholder-context");
      }
    }

    const isPlaceholder = matchedPatterns.length > 0;

    return {
      isPlaceholder,
      confidence: isPlaceholder ? lowestMultiplier : 1.0,
      matchedPatterns,
      multiplier: isPlaceholder ? lowestMultiplier : 1.0,
    };
  }

  /**
   * Evaluates surrounding context for placeholder indicators.
   * Returns 1.0 if no placeholder context found, lower if found.
   */
  private evaluateContext(candidate: SecretCandidate): number {
    const lineAndSurrounding = [candidate.line, ...candidate.surroundingLines]
      .join(" ")
      .toLowerCase();

    const contextPlaceholderPhrases = [
      "example.com",
      "your-domain",
      "example-domain",
      "placeholder",
      "// TODO",
      "# TODO",
      "# replace",
      "// replace",
      "/* replace",
    ];

    for (const phrase of contextPlaceholderPhrases) {
      if (lineAndSurrounding.includes(phrase.toLowerCase())) {
        return 0.15;
      }
    }

    return 1.0;
  }
}
