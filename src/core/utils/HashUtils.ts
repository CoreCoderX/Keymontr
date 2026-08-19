import * as crypto from "crypto";

/**
 * Generates a SHA-256 hash of the given input string.
 * Used for creating suppression keys.
 */
export function sha256(input: string): string {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Generates a suppression key for a specific finding.
 * The key is deterministic — same file + line content → same key.
 * Does NOT include the secret value itself (only the hash is stored).
 */
export function generateSuppressionKey(
  fileUri: string,
  lineNumber: number,
  lineContent: string,
  ruleId?: string,
): string {
  const input = `${fileUri}:${lineNumber}:${lineContent.trim()}:${ruleId ?? "unknown"}`;
  return sha256(input);
}

/**
 * Generates a unique finding ID.
 * Format: ss-{timestamp}-{random}
 */
export function generateFindingId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `ss-${timestamp}-${random}`;
}

/**
 * Generates a hash of the secret value itself.
 * Used for comparing without exposing the actual value.
 * NEVER store or log the raw secret — only the hash.
 */
export function hashSecretValue(value: string): string {
  return sha256(value);
}

/**
 * Compares two strings in constant time to prevent timing attacks.
 * Used when comparing suppression keys.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}
