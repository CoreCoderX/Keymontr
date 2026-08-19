/**
 * Tokenizes a line of source code into meaningful parts.
 * Used by Gate 1 (pre-filter) and Layer 3 (context analysis).
 */

export interface Token {
  value: string;
  type: TokenType;
  start: number;
  end: number;
}

export enum TokenType {
  IDENTIFIER = "identifier",
  STRING_LITERAL = "string_literal",
  NUMBER = "number",
  OPERATOR = "operator",
  KEYWORD = "keyword",
  COMMENT = "comment",
  WHITESPACE = "whitespace",
  PUNCTUATION = "punctuation",
}

// Common programming language keywords to skip during identifier analysis
export const LANGUAGE_KEYWORDS = new Set([
  // JavaScript / TypeScript
  "const",
  "let",
  "var",
  "function",
  "class",
  "return",
  "import",
  "export",
  "from",
  "require",
  "default",
  "new",
  "this",
  "typeof",
  "instanceof",
  "if",
  "else",
  "for",
  "while",
  "do",
  "switch",
  "case",
  "break",
  "continue",
  "try",
  "catch",
  "finally",
  "throw",
  "async",
  "await",
  "void",
  "null",
  "undefined",
  "true",
  "false",
  "static",
  "public",
  "private",
  "protected",
  "readonly",
  "interface",
  "type",
  "enum",
  "extends",
  "implements",
  // Python
  "def",
  "lambda",
  "with",
  "as",
  "pass",
  "del",
  "not",
  "and",
  "or",
  "in",
  "is",
  "global",
  "nonlocal",
  "yield",
  "raise",
  "assert",
  "except",
  "elif",
  // Go, Rust, Java common
  "func",
  "package",
  "struct",
  "impl",
  "use",
  "mod",
  "pub",
  "fn",
  "mut",
  "let",
  "match",
  "enum",
  "trait",
  "where",
]);

/**
 * Extracts all string literal values from a line of source code.
 * Handles single quotes, double quotes, and backtick template literals.
 */
export function extractStringLiterals(line: string): string[] {
  const literals: string[] = [];

  // Double-quoted strings
  const doubleQuoteRegex = /"((?:[^"\\]|\\.)*)"/g;
  let match = doubleQuoteRegex.exec(line);
  while (match !== null) {
    if (match[1] !== undefined && match[1].length > 0) {
      literals.push(match[1]);
    }
    match = doubleQuoteRegex.exec(line);
  }

  // Single-quoted strings
  const singleQuoteRegex = /'((?:[^'\\]|\\.)*)'/g;
  match = singleQuoteRegex.exec(line);
  while (match !== null) {
    if (match[1] !== undefined && match[1].length > 0) {
      literals.push(match[1]);
    }
    match = singleQuoteRegex.exec(line);
  }

  // Template literals (backtick) — only if no ${} interpolation
  const backtickRegex = /`((?:[^`$\\]|\\.)*)`/g;
  match = backtickRegex.exec(line);
  while (match !== null) {
    if (
      match[1] !== undefined &&
      match[1].length > 0 &&
      !match[1].includes("${")
    ) {
      literals.push(match[1]);
    }
    match = backtickRegex.exec(line);
  }

  return literals;
}

/**
 * Extracts all identifier tokens from a line.
 * Filters out language keywords and very short tokens.
 */
export function extractIdentifiers(line: string): string[] {
  // Remove string literals first to avoid matching words inside them
  const withoutStrings = line
    .replace(/"(?:[^"\\]|\\.)*"/g, "")
    .replace(/'(?:[^'\\]|\\.)*'/g, "")
    .replace(/`(?:[^`\\]|\\.)*`/g, "");

  // Remove comments
  const withoutComments = withoutStrings
    .replace(/\/\/.*$/, "")
    .replace(/\/\*.*?\*\//g, "")
    .replace(/#.*$/, ""); // Python comments

  // Extract identifier tokens
  const identifierRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g;
  const identifiers: string[] = [];

  let idMatch = identifierRegex.exec(withoutComments);
  while (idMatch !== null) {
    const token = idMatch[1];
    if (
      token !== undefined &&
      token.length >= 2 &&
      !LANGUAGE_KEYWORDS.has(token.toLowerCase())
    ) {
      identifiers.push(token);
    }
    idMatch = identifierRegex.exec(withoutComments);
  }

  return identifiers;
}

/**
 * Extracts candidate secret values from a line.
 * Looks for string literals that meet minimum length and entropy requirements.
 * Returns objects with value and position.
 */
export interface StringLiteralWithPosition {
  value: string;
  start: number;
  end: number;
  quoteChar: string;
}

/**
 * Extracts an unquoted `KEY=value` assignment from a line, as commonly
 * found in .env files, TOML, and Dockerfiles (e.g. `API_KEY=sk-...`).
 *
 * Only returns a value when the line contains NO quoted string literal,
 * to avoid double-extracting quoted assignments. A trailing inline comment
 * (` # comment`) is stripped from the value.
 */
export function extractEnvStyleValue(line: string): StringLiteralWithPosition[] {
  const envAssignmentRegex = /^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(.+)$/;
  const match = envAssignmentRegex.exec(line);

  if (match === null) {
    return [];
  }

  const eqIndex = line.indexOf("=");
  const rest = line.slice(eqIndex + 1);
  const value = rest.replace(/\s+#.*$/, "").trim();

  if (value.length === 0) {
    return [];
  }

  const valueStartInRest = rest.indexOf(value);
  const start = eqIndex + 1 + valueStartInRest;

  return [
    {
      value,
      start,
      end: start + value.length,
      quoteChar: "",
    },
  ];
}

export function extractStringLiteralsWithPosition(
  line: string,
): StringLiteralWithPosition[] {
  const results: StringLiteralWithPosition[] = [];

  // Double quotes
  const doubleQuoteRegex = /"((?:[^"\\]|\\.)*)"/g;
  let match = doubleQuoteRegex.exec(line);
  while (match !== null) {
    if (match[1] !== undefined && match[1].length >= 8) {
      results.push({
        value: match[1],
        start: match.index + 1,
        end: match.index + match[0].length - 1,
        quoteChar: '"',
      });
    }
    match = doubleQuoteRegex.exec(line);
  }

  // Single quotes
  const singleQuoteRegex = /'((?:[^'\\]|\\.)*)'/g;
  match = singleQuoteRegex.exec(line);
  while (match !== null) {
    if (match[1] !== undefined && match[1].length >= 8) {
      results.push({
        value: match[1],
        start: match.index + 1,
        end: match.index + match[0].length - 1,
        quoteChar: "'",
      });
    }
    match = singleQuoteRegex.exec(line);
  }

  // Backticks (no interpolation)
  const backtickRegex = /`((?:[^`$\\]|\\.)*)`/g;
  match = backtickRegex.exec(line);
  while (match !== null) {
    if (
      match[1] !== undefined &&
      match[1].length >= 8 &&
      !match[1].includes("${")
    ) {
      results.push({
        value: match[1],
        start: match.index + 1,
        end: match.index + match[0].length - 1,
        quoteChar: "`",
      });
    }
    match = backtickRegex.exec(line);
  }

  return results;
}

/**
 * Normalizes an identifier to all common casing variants for index lookup.
 * e.g. "apiKey" → ["apiKey", "api_key", "API_KEY", "ApiKey", "apikey"]
 */
export function generateIdentifierVariants(identifier: string): string[] {
  const variants = new Set<string>();

  // Original
  variants.add(identifier);

  // Lowercase
  variants.add(identifier.toLowerCase());

  // Uppercase
  variants.add(identifier.toUpperCase());

  // snake_case from camelCase
  const snakeCase = identifier
    .replace(/([A-Z])/g, "_$1")
    .toLowerCase()
    .replace(/^_/, "");
  variants.add(snakeCase);
  variants.add(snakeCase.toUpperCase());

  // camelCase from snake_case
  if (identifier.includes("_")) {
    const camel = identifier
      .toLowerCase()
      .replace(/_([a-z])/g, (_, letter: string) => letter.toUpperCase());
    variants.add(camel);

    // PascalCase
    const pascal = camel.charAt(0).toUpperCase() + camel.slice(1);
    variants.add(pascal);
  }

  // kebab-case
  variants.add(snakeCase.replace(/_/g, "-"));

  return Array.from(variants);
}
