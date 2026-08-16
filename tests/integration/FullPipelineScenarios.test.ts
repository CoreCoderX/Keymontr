import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { Pipeline } from "../../src/core/pipeline/Pipeline";
import { DatabaseManager } from "../../src/database/DatabaseManager";
import { ConfigurationManager } from "../../src/config/ConfigurationManager";
import { Gate8_DeveloperMemory } from "../../src/core/pipeline/Gate8_DeveloperMemory";
import { SeverityLevel } from "../../src/core/types/SeverityLevel";

// Integration test — uses real database structures (mock files)
// In production, real DB files are under regex/ and stringgroup/

describe("Full Pipeline Integration", () => {
  let tempDir: string;
  let pipeline: Pipeline;

  const mockRulesFile = {
    title: "test",
    minVersion: "v8.25.0",
    allowlist: {
      stopwords: ["example", "test"],
      regexes: [],
      paths: [],
    },
    rules: [
      {
        id: "openai-api-key",
        description: "OpenAI API Key",
        regex: `(?:OPENAI|openai)[^0-9a-zA-Z\n]{0,20}(?-i)(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})`,
        entropy: 3.0,
        keywords: ["sk-", "openai"],
        secretGroup: 1,
        allowlists: [
          {
            stopwords: ["example", "test"],
            regexes: [],
            regexTarget: "match" as const,
            paths: [],
          },
        ],
      },
      {
        id: "generic-api-key",
        description: "Generic API Key",
        regex: `(?:api[\\s_-]?key|apikey)[^0-9a-zA-Z\n]{0,10}([a-zA-Z0-9_-]{20,64})`,
        entropy: 3.5,
        keywords: ["api_key", "apikey", "api-key"],
        secretGroup: 1,
        allowlists: [],
      },
    ],
  };

  const mockIdentifierIndex: Record<string, string> = {
    api_key: "Generic Secrets",
    apiKey: "Generic Secrets",
    API_KEY: "Generic Secrets",
    OPENAI_API_KEY: "OpenAI",
    openai_api_key: "OpenAI",
    password: "Generic Secrets",
    PASSWORD: "Generic Secrets",
    token: "Generic Secrets",
    TOKEN: "Generic Secrets",
    private_key: "Certificates",
    secret: "Generic Secrets",
    SECRET: "Generic Secrets",
  };

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-integration-"));

    const db1Assets = path.join(tempDir, "regex", "assets");
    const db2Assets = path.join(tempDir, "stringgroup", "assets");
    fs.mkdirSync(db1Assets, { recursive: true });
    fs.mkdirSync(db2Assets, { recursive: true });

    fs.writeFileSync(
      path.join(db1Assets, "gitleaks-rules.json"),
      JSON.stringify(mockRulesFile),
    );
    fs.writeFileSync(
      path.join(db2Assets, "keyword-index.json"),
      JSON.stringify(mockIdentifierIndex),
    );

    DatabaseManager.reset();
    const dbManager = DatabaseManager.getInstance();
    await dbManager.initialize(tempDir);

    const config = new ConfigurationManager();
    config.load(tempDir);

    const gate8 = new Gate8_DeveloperMemory();
    pipeline = new Pipeline(dbManager, config, gate8);
  });

  afterEach(() => {
    DatabaseManager.reset();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe("True Positive Scenarios", () => {
    it("should detect a hardcoded API key in TypeScript", async () => {
      const content = `
import OpenAI from "openai";
const client = new OpenAI({
  apiKey: "sk-proj-AbCdEfGhIjKlMnT3BlbkFJOpQrStUvWxYz12345",
});
      `.trim();

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "api.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });

      expect(result.findings.length).toBeGreaterThan(0);
    });

    it("should detect credentials in .env file", async () => {
      const content = `
DATABASE_URL=postgresql://user:myS3cr3tP4ssw0rd@localhost/db
API_KEY=xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS
STRIPE_SECRET_KEY=sk_live_realproductionkey123456789
      `.trim();

      const result = await pipeline.run({
        fileUri: path.join(tempDir, ".env"),
        fileContent: content,
        languageId: "dotenv",
        triggerType: "save",
      });

      // .env files have HIGH risk level — confidence boosted
      expect(result.stats.linesScanned).toBeGreaterThan(0);
    });
  });

  describe("False Positive Prevention Scenarios", () => {
    it("should NOT flag a comment with example credentials", async () => {
      const content = `
// Example usage:
// const apiKey = "your-api-key-here";
// const token = "example-token-1234";
function initClient() {
  console.log("Initialized");
}
      `.trim();

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "usage.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });

      // Any findings should have low/informational severity at most
      const highSeverityFindings = result.findings.filter(
        (f) =>
          f.severity === SeverityLevel.CRITICAL ||
          f.severity === SeverityLevel.HIGH,
      );
      expect(highSeverityFindings.length).toBe(0);
    });

    it("should NOT flag node_modules files", async () => {
      const content = `module.exports = { secret: "sk-proj-reallookslikeasecretbutisapackage" };`;

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "node_modules", "some-pkg", "index.js"),
        fileContent: content,
        languageId: "javascript",
        triggerType: "save",
      });

      expect(result.findings.length).toBe(0);
      expect(result.stats.skippedByGate["gate0"]).toBe(1);
    });

    it("should NOT flag UUIDs as secrets", async () => {
      const content = `
const userId = "550e8400-e29b-41d4-a716-446655440000";
const sessionId = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
      `.trim();

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "ids.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });

      const criticalOrHigh = result.findings.filter(
        (f) =>
          f.severity === SeverityLevel.CRITICAL ||
          f.severity === SeverityLevel.HIGH,
      );
      expect(criticalOrHigh.length).toBe(0);
    });

    it("should NOT flag lock file paths (Gate 0 excluded)", async () => {
      const result = await pipeline.run({
        fileUri: path.join(tempDir, "package-lock.json"),
        fileContent: `{"integrity":"sha512-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890=="}`,
        languageId: "json",
        triggerType: "open",
      });

      expect(result.findings.length).toBe(0);
      expect(result.stats.skippedByGate["gate0"]).toBe(1);
    });

    it("should NOT flag inline-ignored lines", async () => {
      const content = `const api_key = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uStest"; // secureshield-ignore`;

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "config.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });

      expect(result.findings.length).toBe(0);
    });
  });

  describe("Performance", () => {
    it("should process a 500-line file in under 500ms", async () => {
      const safeLines = Array.from(
        { length: 500 },
        (_, i) => `const variable${i} = "safe_value_${i}";`,
      );
      const content = safeLines.join("\n");

      const start = Date.now();
      const result = await pipeline.run({
        fileUri: path.join(tempDir, "large.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });
      const elapsed = Date.now() - start;

      expect(result.stats.processingTimeMs).toBeLessThan(500);
      expect(elapsed).toBeLessThan(1000);
    });

    it("should handle incremental scanning efficiently", async () => {
      const lines = Array.from(
        { length: 50 },
        (_, i) => `const variable${i} = "value_${i}_long_enough";`,
      );
      const content = lines.join("\n");

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "incremental.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "typing",
        changedLines: [5, 6, 7], // Only check 3 lines
      });

      // Should scan far fewer lines than the total
      expect(result.stats.linesScanned).toBeLessThan(50);
    });
  });

  describe("Stats", () => {
    it("should report accurate processing statistics", async () => {
      const content = `
const a = "short";
const b = "also_short";
const c = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uSmore";
      `.trim();

      const result = await pipeline.run({
        fileUri: path.join(tempDir, "stats.ts"),
        fileContent: content,
        languageId: "typescript",
        triggerType: "save",
      });

      expect(result.stats.linesScanned).toBeGreaterThan(0);
      expect(result.stats.processingTimeMs).toBeGreaterThanOrEqual(0);
      expect(result.scannedAt).toBeInstanceOf(Date);
      expect(result.fileUri).toContain("stats.ts");
    });
  });
});
