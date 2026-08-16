import { Layer4_StringGroupEngine } from "../../../../src/core/layers/Layer4_StringGroupEngine";
import { SecretCandidate } from "../../../../src/core/types/DetectionResult";

function makeCandidate(
  value: string,
  line: string,
  surrounding: string[] = [],
): SecretCandidate {
  return {
    value,
    lineNumber: 5,
    startChar: line.indexOf(value),
    endChar: line.indexOf(value) + value.length,
    line,
    surroundingLines: surrounding,
    db1KeywordHits: [],
    db2IdentifierHits: [],
  };
}

describe("Layer4_StringGroupEngine", () => {
  let engine: Layer4_StringGroupEngine;

  beforeEach(() => {
    engine = new Layer4_StringGroupEngine();
  });

  it("should score high when Authorization and Bearer strings are nearby", () => {
    const surrounding = [
      `  headers: {`,
      `    "Authorization": "Bearer " + token,`,
      `    "Content-Type": "application/json",`,
      `  }`,
    ];
    const candidate = makeCandidate(
      "sk-abc123xyz789",
      `const token = "sk-abc123xyz789";`,
      surrounding,
    );
    const result = engine.evaluate(candidate);
    expect(result.score).toBeGreaterThan(0.3);
    expect(result.authenticationStrings.length).toBeGreaterThan(0);
  });

  it("should detect provider strings near the candidate", () => {
    const surrounding = [
      `import OpenAI from "openai";`,
      `const client = new OpenAI({`,
    ];
    const candidate = makeCandidate(
      "sk-abc123xyz789secret",
      `  apiKey: "sk-abc123xyz789secret",`,
      surrounding,
    );
    const result = engine.evaluate(candidate);
    expect(result.providerStrings.length).toBeGreaterThan(0);
    expect(result.score).toBeGreaterThan(0.1);
  });

  it("should score low when no authentication context exists", () => {
    const candidate = makeCandidate(
      "randomstringvalue123",
      `const data = "randomstringvalue123";`,
      [`function processData() {`, `  return result;`, `}`],
    );
    const result = engine.evaluate(candidate);
    expect(result.authenticationStrings).toEqual([]);
    expect(result.score).toBeLessThan(0.3);
  });

  it("should not include the candidate value in surrounding strings analysis", () => {
    const value = "sk-abc123xyz789secretkey";
    const candidate = makeCandidate(value, `const key = "${value}";`, []);
    const result = engine.evaluate(candidate);
    // The candidate value itself should not appear in surroundingStrings
    expect(result.surroundingStrings).not.toContain(value);
  });

  it("should score highest when both auth and provider strings are present", () => {
    const surrounding = [
      `// OpenAI client configuration`,
      `const headers = { "Authorization": "Bearer sk-...", "Content-Type": "application/json" }`,
    ];
    const highContextCandidate = makeCandidate(
      "sk-realkey123456789",
      `const apiKey = "sk-realkey123456789";`,
      surrounding,
    );

    const lowContextCandidate = makeCandidate(
      "sk-realkey123456789",
      `const apiKey = "sk-realkey123456789";`,
      [],
    );

    const highResult = engine.evaluate(highContextCandidate);
    const lowResult = engine.evaluate(lowContextCandidate);

    expect(highResult.score).toBeGreaterThan(lowResult.score);
  });
});
