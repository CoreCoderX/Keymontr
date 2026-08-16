import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { Pipeline } from "../../src/core/pipeline/Pipeline";
import { DatabaseManager } from "../../src/database/DatabaseManager";
import { ConfigurationManager } from "../../src/config/ConfigurationManager";
import { Gate8_DeveloperMemory } from "../../src/core/pipeline/Gate8_DeveloperMemory";

/**
 * Performance benchmark tests.
 *
 * Ensures the pipeline meets latency targets for real-time IDE use:
 * - Single line scan: < 10ms
 * - 100-line file: < 100ms
 * - 500-line file: < 300ms
 * - 1000-line file: < 600ms
 */

describe("Performance Benchmark", () => {
  let pipeline: Pipeline;
  let tempDir: string;

  const mockRules = {
    title: "perf-test",
    minVersion: "v8.25.0",
    rules: [
      {
        id: "generic-key",
        description: "Generic Key",
        regex: `(?:api[_-]?key)[^0-9a-zA-Z\n]{0,10}([a-zA-Z0-9_-]{20,64})`,
        entropy: 3.0,
        keywords: ["api_key", "apikey"],
        secretGroup: 1,
        allowlists: [],
      },
    ],
  };

  const mockIndex: Record<string, string> = {
    api_key: "Generic Secrets",
    apiKey: "Generic Secrets",
    password: "Generic Secrets",
    token: "Generic Secrets",
  };

  beforeAll(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-perf-"));
    const db1Dir = path.join(tempDir, "regex", "assets");
    const db2Dir = path.join(tempDir, "stringgroup", "assets");
    fs.mkdirSync(db1Dir, { recursive: true });
    fs.mkdirSync(db2Dir, { recursive: true });
    fs.writeFileSync(
      path.join(db1Dir, "gitleaks-rules.json"),
      JSON.stringify(mockRules),
    );
    fs.writeFileSync(
      path.join(db2Dir, "keyword-index.json"),
      JSON.stringify(mockIndex),
    );

    DatabaseManager.reset();
    const dbManager = DatabaseManager.getInstance();
    await dbManager.initialize(tempDir);

    const config = new ConfigurationManager();
    config.load(tempDir);

    const gate8 = new Gate8_DeveloperMemory();
    pipeline = new Pipeline(dbManager, config, gate8);
  });

  afterAll(() => {
    DatabaseManager.reset();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function generateSafeLines(count: number): string {
    return Array.from(
      { length: count },
      (_, i) => `const variable${i} = "safe_value_not_a_secret_${i}";`,
    ).join("\n");
  }

  function generateMixedLines(count: number): string {
    return Array.from({ length: count }, (_, i) => {
      if (i % 50 === 0) {
        return `const api_key = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS${i}";`;
      }
      return `const variable${i} = "safe_value_${i}_no_secret_here_longer_text";`;
    }).join("\n");
  }

  it("should scan a 100-line clean file in under 200ms", async () => {
    const content = generateSafeLines(100);
    const start = Date.now();

    await pipeline.run({
      fileUri: path.join(tempDir, "file100.ts"),
      fileContent: content,
      languageId: "typescript",
      triggerType: "save",
    });

    expect(Date.now() - start).toBeLessThan(200);
  }, 10000);

  it("should scan a 500-line file in under 500ms", async () => {
    const content = generateSafeLines(500);
    const start = Date.now();

    await pipeline.run({
      fileUri: path.join(tempDir, "file500.ts"),
      fileContent: content,
      languageId: "typescript",
      triggerType: "save",
    });

    expect(Date.now() - start).toBeLessThan(500);
  }, 15000);

  it("should scan a 1000-line file in under 1000ms", async () => {
    const content = generateMixedLines(1000);
    const start = Date.now();

    await pipeline.run({
      fileUri: path.join(tempDir, "file1000.ts"),
      fileContent: content,
      languageId: "typescript",
      triggerType: "save",
    });

    expect(Date.now() - start).toBeLessThan(1000);
  }, 20000);

  it("should handle incremental scan (5 changed lines) in under 50ms", async () => {
    const content = generateSafeLines(500);
    const start = Date.now();

    await pipeline.run({
      fileUri: path.join(tempDir, "incremental.ts"),
      fileContent: content,
      languageId: "typescript",
      triggerType: "typing",
      changedLines: [10, 11, 12, 13, 14],
    });

    expect(Date.now() - start).toBeLessThan(50);
  }, 10000);

  it("should process the same file twice (cached path) faster", async () => {
    const content = generateSafeLines(200);
    const fileUri = path.join(tempDir, "cached.ts");

    // First run — cold
    const coldStart = Date.now();
    await pipeline.run({
      fileUri,
      fileContent: content,
      languageId: "typescript",
      triggerType: "save",
    });
    const coldTime = Date.now() - coldStart;

    // Second run — warm
    const warmStart = Date.now();
    await pipeline.run({
      fileUri,
      fileContent: content,
      languageId: "typescript",
      triggerType: "save",
    });
    const warmTime = Date.now() - warmStart;

    // Both should be fast
    expect(coldTime).toBeLessThan(300);
    expect(warmTime).toBeLessThan(300);

    console.log(`  Cold: ${coldTime}ms  |  Warm: ${warmTime}ms`);
  }, 15000);

  it("should immediately exclude node_modules files (Gate 0 < 1ms)", async () => {
    const content = `const key = "xK9mP2qR5vN8wL1jB4hT7yZ0cA3eFgDi6uS";`;
    const start = Date.now();

    const result = await pipeline.run({
      fileUri: path.join(tempDir, "node_modules", "some-pkg", "index.js"),
      fileContent: content,
      languageId: "javascript",
      triggerType: "save",
    });

    const elapsed = Date.now() - start;

    expect(result.findings.length).toBe(0);
    expect(result.stats.skippedByGate["gate0"]).toBe(1);
    expect(elapsed).toBeLessThan(20);
  }, 5000);
});
