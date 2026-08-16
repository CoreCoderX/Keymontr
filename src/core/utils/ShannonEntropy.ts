/**
 * Calculates the Shannon entropy of a string.
 *
 * Shannon entropy formula:
 * H = -Σ p(x) × log2(p(x))
 * where p(x) is the probability (frequency) of character x.
 *
 * Higher entropy = more random = more likely to be a real secret.
 * Lower entropy = more predictable = likely a placeholder or word.
 */
export function calculateShannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }

  const frequencyMap = new Map<string, number>();

  for (const char of value) {
    frequencyMap.set(char, (frequencyMap.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  const length = value.length;

  for (const count of frequencyMap.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Normalizes entropy to a 0.0–1.0 score.
 *
 * Thresholds based on empirical analysis of real secrets:
 *  < 2.0  → Very low (e.g. "aaaaaaaaaa")
 *  2.0–3.0 → Low (e.g. "password123")
 *  3.0–3.5 → Moderate (UUID-like without dashes)
 *  3.5–4.0 → Good (real API keys start here)
 *  4.0–4.5 → High (most production API keys)
 *  > 4.5  → Very high (cryptographic keys)
 */
export function normalizeEntropyScore(entropy: number): number {
  if (entropy < 2.0) {
    return 0.0;
  }
  if (entropy < 3.0) {
    return 0.2;
  }
  if (entropy < 3.5) {
    return 0.4;
  }
  if (entropy < 4.0) {
    return 0.6;
  }
  if (entropy < 4.5) {
    return 0.8;
  }
  return 1.0;
}

/**
 * Analyzes the character set composition of a string.
 * A larger, more diverse charset indicates a more random, likely real secret.
 */
export interface CharsetAnalysis {
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasDigits: boolean;
  hasSpecial: boolean;
  charsetSize: number;
}

export function analyzeCharset(value: string): CharsetAnalysis {
  const hasUppercase = /[A-Z]/.test(value);
  const hasLowercase = /[a-z]/.test(value);
  const hasDigits = /[0-9]/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);

  let charsetSize = 0;
  if (hasUppercase) {
    charsetSize += 26;
  }
  if (hasLowercase) {
    charsetSize += 26;
  }
  if (hasDigits) {
    charsetSize += 10;
  }
  if (hasSpecial) {
    charsetSize += 32;
  }

  return { hasUppercase, hasLowercase, hasDigits, hasSpecial, charsetSize };
}

/**
 * Returns true if the string meets a minimum entropy threshold.
 * Used in Layer 2 as the primary gate for entropy-based detection.
 */
export function meetsEntropyThreshold(
  value: string,
  threshold: number,
): boolean {
  return calculateShannonEntropy(value) >= threshold;
}

/**
 * Returns the adjusted entropy score considering charset diversity.
 * Strings that use more character classes are more likely to be real secrets.
 */
export function adjustedEntropyScore(value: string): number {
  const entropy = calculateShannonEntropy(value);
  const normalized = normalizeEntropyScore(entropy);
  const charset = analyzeCharset(value);

  // Boost score for diverse charsets
  let charsetBonus = 0;
  const diversityCount = [
    charset.hasUppercase,
    charset.hasLowercase,
    charset.hasDigits,
    charset.hasSpecial,
  ].filter(Boolean).length;

  if (diversityCount >= 4) {
    charsetBonus = 0.1;
  } else if (diversityCount === 3) {
    charsetBonus = 0.05;
  }

  return Math.min(1.0, normalized + charsetBonus);
}
