import { LineType } from "../types/DetectionResult.js";

/**
 * Classifies a line of source code to understand its context.
 * Used by Layer 5 (File Context Scorer) to adjust confidence.
 */

// Patterns for detecting comment lines across languages
const COMMENT_PATTERNS = [
  /^\s*\/\//, // JS/TS single line comment
  /^\s*\/\*/, // JS/TS block comment start
  /^\s*\*/, // JS/TS block comment middle
  /^\s*#/, // Python, Ruby, Shell, YAML comment
  /^\s*--/, // SQL, Haskell comment
  /^\s*<!--/, // HTML comment
  /^\s*"""/, // Python docstring (can contain examples)
  /^\s*'''/, // Python docstring variant
];

// Patterns for detecting import/require statements
const IMPORT_PATTERNS = [
  /^\s*import\s+/,
  /^\s*from\s+\S+\s+import/,
  /^\s*(const|let|var)\s+\S+\s*=\s*require\s*\(/,
  /^\s*use\s+\S+/, // Rust/PHP use
  /^\s*#include\s*/, // C/C++
];

// Patterns for assignment statements
const ASSIGNMENT_PATTERNS = [
  /^\s*(const|let|var)\s+\w+\s*[:=]/, // JS/TS
  /^\s*\w+\s*=\s*/, // Python assignment
  /^\s*\w+\s*:=\s*/, // Go short assignment
  /^\s*(private|public|protected|static|final|readonly)\s+/,
  /^\s*\w+\s*:\s*\w+\s*=/, // TypeScript typed assignment
];

// Patterns for object property definitions
const OBJECT_PROPERTY_PATTERNS = [
  /^\s*["']?\w+["']?\s*:\s*/, // JSON or object literal
  /^\s*\w+\s*=\s*[^=]/, // TOML or .env style
];

// Patterns for function arguments / call expressions
const FUNCTION_CALL_PATTERNS = [/\w+\s*\(/, /=>\s*\{/];

// Patterns for return statements
const RETURN_PATTERNS = [/^\s*return\s+/, /^\s*yield\s+/];

// Patterns for array elements
const ARRAY_PATTERNS = [/^\s*[[,]/, /\[\s*$/];

/**
 * Determines the syntactic type of a given line.
 */
export function classifyLine(line: string): LineType {
  const trimmed = line.trim();

  if (trimmed.length === 0) {
    return LineType.UNKNOWN;
  }

  // Comments take highest priority — we reduce confidence for comments
  for (const pattern of COMMENT_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.COMMENT;
    }
  }

  // Import / require
  for (const pattern of IMPORT_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.IMPORT;
    }
  }

  // Return statements
  for (const pattern of RETURN_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.RETURN_STATEMENT;
    }
  }

  // Assignment (most common for secrets)
  for (const pattern of ASSIGNMENT_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.ASSIGNMENT;
    }
  }

  // Object property
  for (const pattern of OBJECT_PROPERTY_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.OBJECT_PROPERTY;
    }
  }

  // Array elements
  for (const pattern of ARRAY_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.ARRAY_ELEMENT;
    }
  }

  // Function call
  for (const pattern of FUNCTION_CALL_PATTERNS) {
    if (pattern.test(line)) {
      return LineType.FUNCTION_ARGUMENT;
    }
  }

  return LineType.UNKNOWN;
}

/**
 * Determines if a line is inside a comment block.
 * Tracks multi-line comment state across lines.
 */
export function buildCommentMap(lines: string[]): boolean[] {
  const commentMap: boolean[] = new Array<boolean>(lines.length).fill(false);
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";

    if (inBlockComment) {
      commentMap[i] = true;
      if (line.includes("*/")) {
        inBlockComment = false;
      }
      continue;
    }

    // Single-line comment check
    const trimmed = line.trim();
    if (
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("--") ||
      trimmed.startsWith("<!--")
    ) {
      commentMap[i] = true;
      continue;
    }

    // Block comment start
    if (trimmed.includes("/*")) {
      if (!trimmed.includes("*/")) {
        inBlockComment = true;
      }
      commentMap[i] = true;
    }
  }

  return commentMap;
}

/**
 * Returns true if the value appears to be inside a string assignment
 * (vs. a bare value or comment).
 */
export function isStringAssignment(line: string): boolean {
  return /\s*[:=]\s*["'`]/.test(line);
}

/**
 * Returns true if the line appears to be inside an array literal.
 */
export function isArrayContext(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith("[") || trimmed.startsWith(",");
}
export { LineType };

