import {
  SecretCandidate,
  FormatDisambiguationResult,
} from "../types/DetectionResult.js";

/**
 * Gate 3 — Format Disambiguation Layer
 *
 * Actively identifies high-entropy strings that are known NOT to be secrets.
 * This prevents false positives from:
 * - Git SHAs (public by design)
 * - UUIDs (identifiers, not credentials)
 * - Content hashes (integrity checks)
 * - CSS colors (design values)
 * - Bcrypt outputs (hash outputs, not inputs)
 *
 * Each matched format applies a confidence reduction multiplier.
 * Some formats are near-certain non-secrets (UUID → 0.05 multiplier).
 * Others are possible but unlikely (MD5 → 0.30 multiplier).
 */

interface NonSecretFormat {
  name: string;
  pattern: RegExp;
  multiplier: number;
  description: string;
}

const NON_SECRET_FORMATS: NonSecretFormat[] = [
  // ── UUID formats ─────────────────────────────────────────────────────────
  {
    name: "uuid-v4",
    pattern:
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    multiplier: 0.04,
    description: "UUID v4 — database/entity identifier, not a credential",
  },
  {
    name: "uuid-generic",
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    multiplier: 0.06,
    description: "Generic UUID format",
  },

  // ── Git / version control hashes ──────────────────────────────────────────
  {
    name: "git-sha-full",
    pattern: /^[0-9a-f]{40}$/i,
    multiplier: 0.05,
    description: "Full Git SHA-1 commit hash",
  },
  {
    name: "git-sha-short",
    pattern: /^[0-9a-f]{7,12}$/i,
    multiplier: 0.3,
    description: "Short Git SHA",
  },

  // ── Cryptographic HASH OUTPUTS (not keys/secrets) ─────────────────────────
  {
    name: "sha256-hash",
    pattern: /^[0-9a-f]{64}$/i,
    multiplier: 0.15,
    description: "SHA-256 hash output",
  },
  {
    name: "sha512-hash",
    pattern: /^[0-9a-f]{128}$/i,
    multiplier: 0.1,
    description: "SHA-512 hash output",
  },
  {
    name: "md5-hash",
    pattern: /^[0-9a-f]{32}$/i,
    multiplier: 0.25,
    description: "MD5 hash",
  },
  {
    name: "bcrypt-output",
    pattern: /^\$2[aby]\$\d{2}\$.{53}$/,
    multiplier: 0.04,
    description: "Bcrypt hash output — the hash, not the password",
  },
  {
    name: "argon2-output",
    pattern: /^\$argon2(i|d|id)\$v=\d+\$/,
    multiplier: 0.04,
    description: "Argon2 hash output",
  },

  // ── Subresource Integrity / npm hashes ────────────────────────────────────
  {
    name: "sri-hash",
    pattern: /^sha(256|384|512)-[A-Za-z0-9+/]+=*$/,
    multiplier: 0.03,
    description: "Subresource Integrity hash — public integrity check",
  },
  {
    name: "npm-integrity",
    pattern: /^sha\d+-[A-Za-z0-9+/]+=*$/,
    multiplier: 0.03,
    description: "npm package integrity hash",
  },

  // ── CSS / design values ───────────────────────────────────────────────────
  {
    name: "css-color-hex",
    pattern: /^#([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i,
    multiplier: 0.02,
    description: "CSS hex color value",
  },

  // ── Network / infrastructure ──────────────────────────────────────────────
  {
    name: "email-address",
    pattern: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/,
    multiplier: 0.1,
    description: "Email address — public identifier, not a credential",
  },
  {
    name: "ipv4-address",
    pattern: /^(\d{1,3}\.){3}\d{1,3}$/,
    multiplier: 0.05,
    description: "IPv4 address",
  },
  {
    name: "ipv6-address",
    pattern: /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i,
    multiplier: 0.05,
    description: "IPv6 address",
  },
  {
    name: "mac-address",
    pattern: /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i,
    multiplier: 0.04,
    description: "MAC address",
  },
  {
    name: "cidr-notation",
    pattern: /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
    multiplier: 0.04,
    description: "CIDR network notation",
  },

  // ── Version / build identifiers ───────────────────────────────────────────
  {
    name: "semver",
    pattern: /^v?\d+\.\d+\.\d+(-[a-z0-9.+]+)?$/i,
    multiplier: 0.03,
    description: "Semantic version string",
  },
  {
    name: "build-hash",
    pattern: /^\d+\.\d+\.\d+\+[a-z0-9]+$/i,
    multiplier: 0.04,
    description: "Build version with hash",
  },

  // ── Base64 short (too short to be a real secret) ──────────────────────────
  {
    name: "base64-very-short",
    pattern: /^[A-Za-z0-9+/]{4,16}={0,2}$/,
    multiplier: 0.25,
    description: "Very short Base64 string — unlikely credential",
  },

  // ── URL patterns ──────────────────────────────────────────────────────────
  {
    name: "full-url",
    pattern: /^https?:\/\/[^\s"']{10,}$/,
    multiplier: 0.15,
    description: "Full URL — credentials are not usually URLs",
  },

  // ── Template interpolation remnants ───────────────────────────────────────
  {
    name: "template-expression",
    pattern: /\$\{[^}]+\}|%\([^)]+\)s|\{\{[^}]+\}\}/,
    multiplier: 0.1,
    description: "Template expression — runtime variable, not hardcoded secret",
  },

  // ── Common encoding artifacts ─────────────────────────────────────────────
  {
    name: "percent-encoded",
    pattern: /^(%[0-9a-f]{2}){4,}$/i,
    multiplier: 0.1,
    description: "Percent-encoded string (URL encoding)",
  },
  {
    name: "hex-color-without-hash",
    // Only when in a CSS/design context — plain 6-char hex
    pattern: /^[0-9a-f]{6}$/i,
    multiplier: 0.35,
    description: "Possible CSS color without # prefix",
  },
];

export class Gate3_FormatDisambiguation {
  /**
   * Tests a candidate against all known non-secret formats.
   *
   * @param candidate - The secret candidate from Gate 2
   * @returns Format disambiguation result with combined multiplier
   */
  public evaluate(candidate: SecretCandidate): FormatDisambiguationResult {
    const value = candidate.value.trim();
    const matchedFormats: string[] = [];
    let lowestMultiplier = 1.0;

    for (const format of NON_SECRET_FORMATS) {
      if (format.pattern.test(value)) {
        matchedFormats.push(format.name);
        if (format.multiplier < lowestMultiplier) {
          lowestMultiplier = format.multiplier;
        }
      }
    }

    const isKnownNonSecret = matchedFormats.length > 0;
    const confidenceReduction = isKnownNonSecret ? 1.0 - lowestMultiplier : 0.0;

    return {
      isKnownNonSecret,
      matchedFormats,
      confidenceReduction,
      multiplier: isKnownNonSecret ? lowestMultiplier : 1.0,
    };
  }
}
