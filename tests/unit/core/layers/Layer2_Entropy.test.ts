import { Layer2_EntropyEngine } from "../../../../src/core/layers/Layer2_EntropyEngine";
import { SecretCandidate } from "../../../../src/core/types/DetectionResult";

function makeCandidate(value: string): SecretCandidate {
  return {
    value,
    lineNumber: 0,
    startChar: 10,
    endChar: 10 + value.length,
    line: `const key = "${value}";`,
    surroundingLines: [],
    db1KeywordHits: [],
    db2IdentifierHits: [],
  };
}

describe("Layer2_EntropyEngine", () => {
  let engine: Layer2_EntropyEngine;

  beforeEach(() => {
    engine = new Layer2_EntropyEngine();
  });

  describe("high-entropy strings (real secrets)", () => {
    const highEntropyValues = [
      "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd",
      "AKIAIOSFODNN7EXAMPLE1234567890ABCDEFGHIJKLMN",
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ];

    for (const value of highEntropyValues) {
      it(`should score high entropy for: ${value.substring(0, 20)}...`, () => {
        const result = engine.evaluate(makeCandidate(value));
        expect(result.entropy).toBeGreaterThan(3.0);
        expect(result.score).toBeGreaterThan(0.5);
      });
    }
  });

  describe("low-entropy strings (likely not secrets)", () => {
    const lowEntropyValues = [
      "aaaaaaaaaaaaaaaa",
      "passwordpassword",
      "12341234123412341",
      "helloworldhello",
      "aaabbbcccdddeee",
    ];

    for (const value of lowEntropyValues) {
      it(`should score low entropy for: "${value}"`, () => {
        const result = engine.evaluate(makeCandidate(value));
        expect(result.score).toBeLessThan(0.5);
      });
    }
  });

  describe("threshold evaluation", () => {
    it("should meet threshold when entropy >= threshold", () => {
      // High-entropy random string
      const value = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS";
      const result = engine.evaluate(makeCandidate(value), 3.0);
      expect(result.meetsThreshold).toBe(true);
    });

    it("should not meet threshold when entropy < threshold", () => {
      const value = "aaaaaaaaaaaaaaaa";
      const result = engine.evaluate(makeCandidate(value), 3.5);
      expect(result.meetsThreshold).toBe(false);
    });
  });

  describe("charset analysis", () => {
    it("should detect mixed charset", () => {
      const value = "Ab1!Cd2@Ef3#Gh4$Ij5%Kl6^Mn7&Op8*Qr9(";
      const result = engine.evaluate(makeCandidate(value));
      expect(result.charsetAnalysis.hasUppercase).toBe(true);
      expect(result.charsetAnalysis.hasLowercase).toBe(true);
      expect(result.charsetAnalysis.hasDigits).toBe(true);
      expect(result.charsetAnalysis.hasSpecial).toBe(true);
    });

    it("should detect hex-only charset", () => {
      const value = "deadbeef1234567890abcdef0123456789ab";
      const result = engine.evaluate(makeCandidate(value));
      expect(result.charsetAnalysis.hasUppercase).toBe(false);
      expect(result.charsetAnalysis.hasDigits).toBe(true);
    });
  });

  describe("averageEntropy", () => {
    it("should compute average entropy for multiple strings", () => {
      const values = ["password", "xK9mP2qR5vN8wL1j"];
      const avg = engine.averageEntropy(values);
      expect(avg).toBeGreaterThan(0);
      expect(avg).toBeLessThan(6);
    });

    it("should return 0 for empty array", () => {
      expect(engine.averageEntropy([])).toBe(0);
    });
  });
});
