import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { EnvFileMigrator } from "../../../src/remediation/EnvFileMigrator";
import { SecretFinding } from "../../../src/core/types/SecretFinding";
import { FileRiskLevel } from "../../../src/core/types/DetectionResult";

function makeFinding(suggestedEnvKey: string, value: string): SecretFinding {
  return {
    id: "test-finding",
    candidate: {
      value,
      lineNumber: 0,
      startChar: 0,
      endChar: value.length,
      line: `${suggestedEnvKey}=${value}`,
      surroundingLines: [],
      db1KeywordHits: [],
      db2IdentifierHits: [],
    },
    confidence: {
      components: {
        regex: 1,
        entropy: 1,
        context: 0.8,
        stringGroup: 0,
        fileContext: 0.5,
      },
      weights: {
        regex: 0.35,
        entropy: 0.2,
        context: 0.2,
        stringGroup: 0.15,
        fileContext: 0.1,
      },
      baseScore: 0.8,
      multipliers: {
        fileRisk: 1.4,
        allowlist: 1,
        placeholder: 1,
        formatDisambiguation: 1,
      },
      finalScore: 0.9,
      explanation: "test fixture",
    },
    severity: "critical" as SecretFinding["severity"],
    detection: {
      entropyValue: 4.2,
      isKnownProvider: true,
    },
    remediation: {
      suggestedEnvKey,
      autoFixAvailable: true,
      fixSteps: [],
      estimatedEffort: "instant",
    },
    suppression: {
      suppressionKey: "test",
      inlineIgnoreComment: "// secureshield-ignore",
      isPermanentlySuppressed: false,
      isSessionSuppressed: false,
    },
    meta: {
      detectedAt: new Date(),
      fileUri: "/workspace/config.ts",
      fileName: "config.ts",
      fileRiskLevel: FileRiskLevel.HIGH,
      languageId: "typescript",
      triggerType: "manual-scan",
    },
  };
}

describe("EnvFileMigrator", () => {
  let workspaceRoot: string;

  beforeEach(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), "keymontr-env-"));
  });

  afterEach(() => {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  });

  function readEnv(): string {
    return fs.readFileSync(path.join(workspaceRoot, ".env"), "utf-8");
  }

  it("creates .env and adds a new key when the file does not exist", () => {
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("API_KEY", "sk-1234"));

    expect(result.success).toBe(true);
    expect(result.envFileCreated).toBe(true);
    expect(result.envValueUpdated).toBeUndefined();
    expect(readEnv()).toContain("API_KEY=sk-1234");
  });

  it("appends a new key to an existing .env without touching other keys", () => {
    fs.writeFileSync(
      path.join(workspaceRoot, ".env"),
      "DB_HOST=localhost\n",
      "utf-8",
    );
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("API_KEY", "sk-1234"));

    expect(result.success).toBe(true);
    expect(result.envFileCreated).toBe(false);
    const content = readEnv();
    expect(content).toContain("DB_HOST=localhost");
    expect(content).toContain("API_KEY=sk-1234");
  });

  it("replaces the previous value when the key already exists", () => {
    fs.writeFileSync(
      path.join(workspaceRoot, ".env"),
      "# my key\nAPI_KEY=old-value\nDB_HOST=localhost\n",
      "utf-8",
    );
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("API_KEY", "new-value"));

    expect(result.success).toBe(true);
    expect(result.envValueUpdated).toBe(true);
    const content = readEnv();
    expect(content).toContain("API_KEY=new-value");
    expect(content).not.toContain("API_KEY=old-value");
    expect(content).toContain("DB_HOST=localhost");
    expect(content).toContain("# my key");
  });

  it("succeeds without rewriting when the value is identical", () => {
    fs.writeFileSync(
      path.join(workspaceRoot, ".env"),
      "API_KEY=same-value\n",
      "utf-8",
    );
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("API_KEY", "same-value"));

    expect(result.success).toBe(true);
    expect(result.envValueUpdated).toBe(false);
    expect(readEnv()).toBe("API_KEY=same-value\n");
  });

  it("updates existing keys in CRLF files without corrupting line endings", () => {
    fs.writeFileSync(
      path.join(workspaceRoot, ".env"),
      "API_KEY=old-value\r\nDB_HOST=localhost\r\n",
      "utf-8",
    );
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("API_KEY", "new-value"));

    expect(result.success).toBe(true);
    expect(result.envValueUpdated).toBe(true);
    const content = readEnv();
    expect(content).toContain("API_KEY=new-value\r\n");
    expect(content).toContain("DB_HOST=localhost\r\n");
  });

  it("rejects invalid environment variable names", () => {
    const migrator = new EnvFileMigrator(workspaceRoot);

    const result = migrator.migrate(makeFinding("1BAD KEY!", "value"));

    expect(result.success).toBe(false);
    expect(result.error).toContain("Invalid environment variable name");
  });
});
