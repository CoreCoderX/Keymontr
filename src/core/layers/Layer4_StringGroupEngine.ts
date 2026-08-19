import {
  SecretCandidate,
  StringGroupLayerResult,
} from "../types/DetectionResult.js";
import { extractStringLiterals } from "../utils/Tokenizer.js";

/**
 * Layer 4 — StringGroup Engine
 *
 * Direct implementation of the base research paper's StringGroup concept:
 * "Checked-In Secret Detection: Strings Are All You Need"
 *
 * Instead of analyzing variable names (Layer 3), this layer analyzes
 * the surrounding STRING LITERALS to understand what the code is doing.
 *
 * Insight from paper: Code that deals with secrets tends to have nearby
 * string literals like "Authorization", "Bearer", "API-Key", "OAuth" etc.
 * These are more robust than variable names because:
 * 1. Developers cannot easily obfuscate them without breaking functionality
 * 2. They appear consistently regardless of programming language
 * 3. They survive code refactoring
 *
 * Example:
 *   fetch("https://api.openai.com/v1/chat", {
 *     headers: {
 *       "Authorization": "Bearer " + apiKey,   ← "Authorization", "Bearer" are signals
 *       "Content-Type": "application/json",
 *     }
 *   });
 */

// Authentication-indicator string literals (from paper's StringGroup)
const AUTH_INDICATOR_STRINGS = [
  "authorization",
  "bearer",
  "token",
  "api-key",
  "x-api-key",
  "x-auth-token",
  "x-access-token",
  "oauth",
  "oauth2",
  "jwt",
  "basic auth",
  "digest",
  "authentication",
  "credentials",
  "secret",
  "private",
  "access-token",
  "refresh-token",
  "id-token",
  "api_key",
  "auth_token",
  "client_secret",
  "client_id",
  "grant_type",
  "client_credentials",
];

// Known provider string literals
const PROVIDER_STRINGS = [
  "openai",
  "anthropic",
  "aws",
  "amazon",
  "google",
  "azure",
  "microsoft",
  "stripe",
  "paypal",
  "braintree",
  "github",
  "gitlab",
  "bitbucket",
  "slack",
  "discord",
  "telegram",
  "twilio",
  "sendgrid",
  "mailgun",
  "firebase",
  "supabase",
  "mongodb",
  "postgresql",
  "mysql",
  "redis",
  "cloudflare",
  "datadog",
  "sentry",
  "okta",
  "auth0",
  "cognito",
  "keycloak",
  "vault",
  "hashicorp",
  "vercel",
  "netlify",
  "heroku",
  "railway",
  "render",
  "fly.io",
  "digitalocean",
];

// HTTP-related strings that suggest API communication (common context for secrets)
const HTTP_INDICATOR_STRINGS = [
  "content-type",
  "application/json",
  "headers",
  "fetch",
  "axios",
  "request",
  "post",
  "get",
  "put",
  "delete",
  "patch",
  "http",
  "https",
  "endpoint",
  "baseurl",
  "base_url",
  "api_url",
];

export class Layer4_StringGroupEngine {
  /**
   * Analyzes surrounding string literals to determine if the context
   * suggests secret usage, as described in the base paper.
   *
   * @param candidate - The secret candidate
   */
  public evaluate(candidate: SecretCandidate): StringGroupLayerResult {
    // Collect all string literals from surrounding lines
    const allLines = [candidate.line, ...candidate.surroundingLines];
    const surroundingStrings: string[] = [];

    for (const line of allLines) {
      const literals = extractStringLiterals(line);
      for (const lit of literals) {
        // Exclude the candidate value itself — we don't want circular scoring
        if (lit !== candidate.value) {
          surroundingStrings.push(lit);
        }
      }
    }

    // Classify each surrounding string
    const authenticationStrings: string[] = [];
    const providerStrings: string[] = [];
    const httpStrings: string[] = [];

    for (const str of surroundingStrings) {
      const strLower = str.toLowerCase();

      if (AUTH_INDICATOR_STRINGS.some((auth) => strLower.includes(auth))) {
        authenticationStrings.push(str);
      }

      if (PROVIDER_STRINGS.some((provider) => strLower.includes(provider))) {
        providerStrings.push(str);
      }

      if (HTTP_INDICATOR_STRINGS.some((http) => strLower.includes(http))) {
        httpStrings.push(str);
      }
    }

    const score = this.computeStringGroupScore(
      authenticationStrings,
      providerStrings,
      httpStrings,
      surroundingStrings.length,
    );

    return {
      surroundingStrings,
      authenticationStrings,
      providerStrings,
      score,
    };
  }

  /**
   * Computes the StringGroup score based on found string categories.
   *
   * Scoring logic (from paper analysis):
   * - Authentication strings: highest signal (these specifically indicate secret use)
   * - Provider strings: strong signal (confirms which service the secret is for)
   * - HTTP strings: moderate signal (suggests API communication context)
   * - No relevant strings: low score (context doesn't confirm secret usage)
   */
  private computeStringGroupScore(
    authStrings: string[],
    providerStrings: string[],
    httpStrings: string[],
    totalSurroundingStrings: number,
  ): number {
    if (totalSurroundingStrings === 0) {
      return 0.0;
    }

    let score = 0.0;

    // Authentication strings: +0.40 per unique auth category found (capped)
    if (authStrings.length > 0) {
      const uniqueAuthCount = new Set(authStrings.map((s) => s.toLowerCase()))
        .size;
      score += Math.min(0.55, uniqueAuthCount * 0.2);
    }

    // Provider strings: +0.20 per unique provider (capped)
    if (providerStrings.length > 0) {
      const uniqueProviderCount = new Set(
        providerStrings.map((s) => s.toLowerCase()),
      ).size;
      score += Math.min(0.25, uniqueProviderCount * 0.2);
    }

    // HTTP strings: +0.10 (weaker signal — many non-secret API calls exist)
    if (httpStrings.length > 0) {
      score += 0.1;
    }

    // Bonus: if both auth AND provider strings found together, strong corroboration
    if (authStrings.length > 0 && providerStrings.length > 0) {
      score += 0.1;
    }

    return Math.min(1.0, score);
  }
}
