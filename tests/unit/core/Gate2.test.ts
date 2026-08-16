import { Gate2_PlaceholderElimination } from "../../../src/core/pipeline/Gate2_PlaceholderElimination";
import { SecretCandidate } from "../../../src/core/types/DetectionResult";

function makeCandidate(value: string, line?: string): SecretCandidate {
  return {
    value,
    lineNumber: 0,
    startChar: 0,
    endChar: value.length,
    line: line ?? `const key = "${value}";`,
    surroundingLines: [],
    db1KeywordHits: [],
    db2IdentifierHits: [],
  };
}

describe("Gate2_PlaceholderElimination", () => {
  let gate: Gate2_PlaceholderElimination;

  beforeEach(() => {
    gate = new Gate2_PlaceholderElimination();
  });

  describe("should detect placeholders", () => {
    const placeholders = [
      "<YOUR_API_KEY>",
      "[YOUR_TOKEN_HERE]",
      "{API_SECRET}",
      "$API_KEY",
      "${MY_SECRET}",
      "your-api-key-here",
      "changeme",
      "replace-me",
      "aaaaaaaaaaaaaaaa",
      "00000000000000000",
      "xxxxxxxxxxxx",
      "password",
      "test_token_value",
      "example-api-key",
      "dummy-secret-value",
      "null",
      "undefined",
      "none",
    ];

    for (const placeholder of placeholders) {
      it(`should identify placeholder: "${placeholder}"`, () => {
        const result = gate.evaluate(makeCandidate(placeholder));
        expect(result.isPlaceholder).toBe(true);
        expect(result.multiplier).toBeLessThan(0.5);
      });
    }
  });

  describe("should NOT flag real secrets as placeholders", () => {
    const realSecrets = [
      "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
      "AKIAIOSFODNN7ABCDEFGH12345",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYpRODUCTION",
      "xoxb-53-W33EJT-YKbKFkNRTpCbQrSJakO1GzA2",
    ];

    for (const secret of realSecrets) {
      it(`should not flag as placeholder: "${secret.substring(0, 20)}..."`, () => {
        const result = gate.evaluate(makeCandidate(secret));
        expect(result.isPlaceholder).toBe(false);
        expect(result.multiplier).toBe(1.0);
      });
    }
  });

  describe("multiplier values", () => {
    it("should have multiplier close to 0 for explicit template placeholders", () => {
      const result = gate.evaluate(makeCandidate("<YOUR_API_KEY>"));
      expect(result.multiplier).toBeLessThanOrEqual(0.05);
    });

    it("should have multiplier 1.0 for non-placeholders", () => {
      const result = gate.evaluate(
        makeCandidate("xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS"),
      );
      expect(result.multiplier).toBe(1.0);
    });
  });
});
