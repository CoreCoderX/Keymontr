import { Gate6_ConfidenceAggregator } from "../../../src/core/pipeline/Gate6_ConfidenceAggregator";
import { DEFAULT_CONFIG } from "../../../src/config/DefaultConfig";
import { Gate4Result } from "../../../src/core/pipeline/Gate4_Detection";
import {
  PlaceholderResult,
  FormatDisambiguationResult,
  AllowlistResult,
  FileRiskLevel,
  LineType,
} from "../../../src/core/types/DetectionResult";

function makeGate4Result(overrides: Partial<Gate4Result> = {}): Gate4Result {
  return {
    layer1: {
      matched: false,
      score: 0,
      isKnownProvider: false,
      allMatchedRules: [],
    },
    layer2: {
      entropy: 3.0,
      ruleThreshold: 3.0,
      meetsThreshold: true,
      score: 0.6,
      charsetAnalysis: {
        hasUppercase: true,
        hasLowercase: true,
        hasDigits: true,
        hasSpecial: false,
        charsetSize: 62,
      },
    },
    layer3: {
      nearbyIdentifiers: [],
      matchedGroups: [],
      contextSignals: [],
      score: 0.5,
    },
    layer4: {
      surroundingStrings: [],
      authenticationStrings: [],
      providerStrings: [],
      score: 0.3,
    },
    layer5: {
      fileRiskLevel: FileRiskLevel.NORMAL,
      fileRiskMultiplier: 1.0,
      isInComment: false,
      isInString: true,
      isAssignment: true,
      isInArray: false,
      lineType: LineType.ASSIGNMENT,
      score: 0.7,
    },
    ruleEntropyThreshold: 3.0,
    ...overrides,
  };
}

const noReduction: PlaceholderResult = {
  isPlaceholder: false,
  confidence: 1.0,
  matchedPatterns: [],
  multiplier: 1.0,
};
const noFormat: FormatDisambiguationResult = {
  isKnownNonSecret: false,
  matchedFormats: [],
  confidenceReduction: 0,
  multiplier: 1.0,
};
const noAllowlist: AllowlistResult = { isAllowlisted: false, multiplier: 1.0 };

describe("Gate6_ConfidenceAggregator", () => {
  let aggregator: Gate6_ConfidenceAggregator;

  beforeEach(() => {
    aggregator = new Gate6_ConfidenceAggregator(DEFAULT_CONFIG);
  });

  it("should compute a non-zero score for a moderate detection", () => {
    const gate4 = makeGate4Result();
    const result = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(result.finalScore).toBeGreaterThan(0);
    expect(result.finalScore).toBeLessThanOrEqual(1.0);
  });

  it("should apply known provider override (floor at 0.90)", () => {
    const gate4 = makeGate4Result({
      layer1: {
        matched: true,
        ruleId: "aws-access-token",
        ruleName: "AWS Access Token",
        matchedValue: "AKIAIOSFODNN7EXAMPLE",
        score: 0.92,
        isKnownProvider: true,
        allMatchedRules: [],
      },
    });
    const result = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(result.finalScore).toBeGreaterThanOrEqual(0.9);
  });

  it("should set score to 0 when allowlisted", () => {
    const gate4 = makeGate4Result();
    const allowlisted: AllowlistResult = {
      isAllowlisted: true,
      matchedAllowlist: "test stopword",
      multiplier: 0.02,
    };
    const result = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      allowlisted,
    );
    expect(result.finalScore).toBe(0);
  });

  it("should apply placeholder reduction", () => {
    const gate4 = makeGate4Result();
    const placeholder: PlaceholderResult = {
      isPlaceholder: true,
      confidence: 0.05,
      matchedPatterns: ["contains-example"],
      multiplier: 0.05,
    };
    const withPlaceholder = aggregator.aggregate(
      gate4,
      placeholder,
      noFormat,
      noAllowlist,
    );
    const withoutPlaceholder = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(withPlaceholder.finalScore).toBeLessThan(
      withoutPlaceholder.finalScore,
    );
  });

  it("should apply format disambiguation reduction", () => {
    const gate4 = makeGate4Result();
    const format: FormatDisambiguationResult = {
      isKnownNonSecret: true,
      matchedFormats: ["uuid-v4"],
      confidenceReduction: 0.95,
      multiplier: 0.04,
    };
    const withFormat = aggregator.aggregate(
      gate4,
      noReduction,
      format,
      noAllowlist,
    );
    const withoutFormat = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(withFormat.finalScore).toBeLessThan(withoutFormat.finalScore);
  });

  it("should produce a breakdown explanation string", () => {
    const gate4 = makeGate4Result();
    const result = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(result.explanation).toBeTruthy();
    expect(result.explanation.length).toBeGreaterThan(10);
  });

  it("should include component breakdown", () => {
    const gate4 = makeGate4Result();
    const result = aggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    expect(result.components.regex).toBeDefined();
    expect(result.components.entropy).toBeDefined();
    expect(result.components.context).toBeDefined();
    expect(result.components.stringGroup).toBeDefined();
    expect(result.components.fileContext).toBeDefined();
  });

  it("should handle zero-weight configuration gracefully", () => {
    const zeroConfig = {
      ...DEFAULT_CONFIG,
      detection: {
        ...DEFAULT_CONFIG.detection,
        weights: {
          regex: 0,
          entropy: 0,
          context: 0,
          stringGroup: 0,
          fileContext: 0,
        },
      },
    };
    const zeroAggregator = new Gate6_ConfidenceAggregator(zeroConfig);
    const gate4 = makeGate4Result();
    const result = zeroAggregator.aggregate(
      gate4,
      noReduction,
      noFormat,
      noAllowlist,
    );
    // Should fall back to defaults, not crash
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
  });
});
