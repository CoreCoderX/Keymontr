import { SecretHistoryStore, HistoryRecord } from "../../../src/storage/SecretHistoryStore";
import { SecretFinding } from "../../../src/core/types/SecretFinding";
import { SeverityLevel } from "../../../src/core/types/SeverityLevel";
import { FileRiskLevel } from "../../../src/core/types/DetectionResult";

function makeFinding(overrides: Partial<SecretFinding> = {}): SecretFinding {
  const base: SecretFinding = {
    id: "ss-abc-123",
    candidate: {
      value: "sk-secret-value",
      line: 'const key = "sk-secret-value";',
      lineNumber: 10,
      startChar: 14,
      endChar: 30,
      surroundingLines: [],
      db1KeywordHits: ["key"],
      db2IdentifierHits: [],
    },
    confidence: {
      components: {
        regex: 0.5,
        entropy: 0.5,
        context: 0.5,
        stringGroup: 0.5,
        fileContext: 0.5,
      },
      weights: {
        regex: 0.2,
        entropy: 0.2,
        context: 0.2,
        stringGroup: 0.2,
        fileContext: 0.2,
      },
      baseScore: 0.9,
      multipliers: {
        fileRisk: 1.0,
        allowlist: 1.0,
        placeholder: 1.0,
        formatDisambiguation: 1.0,
      },
      finalScore: 0.9,
      explanation: "test finding",
    },
    severity: SeverityLevel.HIGH,
    detection: {
      matchedRuleId: "generic-api-key",
      matchedRuleName: "Generic API Key",
      entropyValue: 3.5,
      isKnownProvider: false,
    },
    remediation: {
      suggestedEnvKey: "API_KEY",
      autoFixAvailable: true,
      fixSteps: ["Move to .env"],
      estimatedEffort: "instant",
    },
    suppression: {
      suppressionKey: "abc123hash",
      inlineIgnoreComment: "// keymontr-ignore",
      isPermanentlySuppressed: false,
      isSessionSuppressed: false,
    },
    meta: {
      detectedAt: new Date("2026-01-01T00:00:00Z"),
      fileUri: "/workspace/config.ts",
      fileName: "config.ts",
      fileRiskLevel: FileRiskLevel.HIGH,
      languageId: "typescript",
      triggerType: "save",
    },
  };
  return { ...base, ...overrides };
}

describe("SecretHistoryStore", () => {
  const state = new Map<string, unknown>();
  const globalState = {
    get: jest.fn((key: string, def: unknown) => {
      const v = state.get(key);
      return v === undefined ? def : v;
    }),
    set: jest.fn(async (key: string, value: unknown) => {
      state.set(key, value);
    }),
  };

  beforeEach(() => {
    state.clear();
    jest.clearAllMocks();
  });

  it("records a new detection once, ignoring re-scans of the same secret", async () => {
    const store = new SecretHistoryStore(globalState as never);
    store.load();

    const finding = makeFinding();
    await store.recordDetection(finding);
    await store.recordDetection(finding);
    await store.recordDetection(finding);

    const stats = store.getStatistics();
    expect(stats.totalDetected).toBe(1);
    expect(store.getHistory()).toHaveLength(1);

    // A different secret (different suppressionKey) counts separately
    const other = makeFinding({
      id: "ss-def-456",
      candidate: {
        ...finding.candidate,
        value: "other-secret",
        line: 'const other = "other-secret";',
      },
      suppression: {
        ...finding.suppression,
        suppressionKey: "def456hash",
      },
    });
    await store.recordDetection(other);

    expect(store.getStatistics().totalDetected).toBe(2);
    expect(store.getHistory()).toHaveLength(2);
  });

  it("treats a secret that reappears after being fixed as a new occurrence", async () => {
    const store = new SecretHistoryStore(globalState as never);
    store.load();

    const finding = makeFinding();
    await store.recordDetection(finding);
    await store.markFixed(finding.id, finding.suppression.suppressionKey);

    let stats = store.getStatistics();
    expect(stats.totalDetected).toBe(1);
    expect(stats.totalFixed).toBe(1);

    // Same secret reappears (same suppressionKey, new random id)
    await store.recordDetection(makeFinding({ id: "ss-xyz-999" }));

    stats = store.getStatistics();
    expect(stats.totalDetected).toBe(1); // not inflated
    expect(stats.totalFixed).toBe(0); // the fixed record was replaced by the active one
    const records = store.getHistory();
    expect(records).toHaveLength(1);
    expect(records[0].isFixed).toBe(false);
  });

  it("rebuilds statistics from history on load, deduplicating by suppressionKey", () => {
    const store = new SecretHistoryStore(globalState as never);
    store.load();

    const a = makeFinding();
    awaitRecord(store, a);
    awaitRecord(store, a);
    awaitRecord(store, makeFinding({
      id: "ss-b-2",
      suppression: { ...a.suppression, suppressionKey: "bb2hash" },
    }));

    // Simulate a reload: rebuild stats from persisted history
    const reloaded = new SecretHistoryStore(globalState as never);
    reloaded.load();

    expect(reloaded.getStatistics().totalDetected).toBe(2);
    expect(reloaded.getStatistics().totalFixed).toBe(0);
  });

  it("migrates legacy history without suppressionKeys by wiping inflated data", async () => {
    state.set("keymontr.secretHistory", [
      {
        id: "ss-legacy-1",
        fileUri: "/workspace/config.ts",
        fileName: "config.ts",
        severity: "high",
        ruleId: "generic-api-key",
        detectedAt: "2026-01-01T00:00:00Z",
        isFixed: false,
      },
      {
        id: "ss-legacy-2",
        fileUri: "/workspace/config.ts",
        fileName: "config.ts",
        severity: "high",
        ruleId: "generic-api-key",
        detectedAt: "2026-01-02T00:00:00Z",
        isFixed: false,
      },
    ]);
    state.set("keymontr.statistics", {
      totalDetected: 75,
      totalFixed: 1,
      totalSuppressed: 0,
      commitsBlocked: 0,
      byType: { "generic-api-key": 75 },
      bySeverity: { high: 75 },
      byFile: { "config.ts": 75 },
      lastUpdated: "2026-01-02T00:00:00Z",
    });

    const store = new SecretHistoryStore(globalState as never);
    store.load();

    expect(store.getHistory()).toHaveLength(0);
    expect(store.getStatistics().totalDetected).toBe(0);
    expect(store.getStatistics().totalFixed).toBe(0);
  });
});

async function awaitRecord(
  store: SecretHistoryStore,
  finding: SecretFinding,
): Promise<void> {
  await store.recordDetection(finding);
}