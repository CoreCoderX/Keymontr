import { Gate1_PreFilter } from "../../../src/core/pipeline/Gate1_PreFilter";
import { GitleaksDatabase } from "../../../src/database/GitleaksDatabase";
import { StringGroupDatabase } from "../../../src/database/StringGroupDatabase";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

describe("Gate1_PreFilter", () => {
  let gate: Gate1_PreFilter;
  let tempDir: string;

  const sampleRules = {
    title: "test",
    minVersion: "v8.25.0",
    rules: [
      {
        id: "openai-api-key",
        description: "OpenAI API Key",
        regex: "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
        entropy: 3.0,
        keywords: ["sk-", "openai"],
      },
      {
        id: "github-pat",
        description: "GitHub PAT",
        regex: "ghp_[0-9a-zA-Z]{36}",
        entropy: 3.0,
        keywords: ["ghp_"],
      },
    ],
  };

  const sampleIndex = {
    api_key: "Generic Secrets",
    apiKey: "Generic Secrets",
    API_KEY: "Generic Secrets",
    password: "Generic Secrets",
    OPENAI_API_KEY: "OpenAI",
    token: "Generic Secrets",
  };

  beforeEach(async () => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-gate1-"));

    const db1Dir = path.join(tempDir, "regex", "assets");
    const db2Dir = path.join(tempDir, "sg", "assets");
    fs.mkdirSync(db1Dir, { recursive: true });
    fs.mkdirSync(db2Dir, { recursive: true });

    fs.writeFileSync(
      path.join(db1Dir, "gitleaks-rules.json"),
      JSON.stringify(sampleRules),
    );
    fs.writeFileSync(
      path.join(db2Dir, "keyword-index.json"),
      JSON.stringify(sampleIndex),
    );

    const gitleaksDb = new GitleaksDatabase(db1Dir);
    const sgDb = new StringGroupDatabase(db2Dir);
    await gitleaksDb.load();
    await sgDb.load();

    gate = new Gate1_PreFilter(gitleaksDb, sgDb);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should pass a line with a known DB1 keyword and string literal", () => {
    const line = `const key = "sk-abcdefgh1234567890T3BlbkFJabcdefgh12345678";`;
    const result = gate.evaluateLine(line, 0, [], false);
    expect(result.passed).toBe(true);
    expect(result.candidates.length).toBeGreaterThan(0);
    expect(result.db1Hits.length).toBeGreaterThan(0);
  });

  it("should pass a line with a known DB2 identifier", () => {
    const line = `const api_key = "some-random-looking-valuexyz1234567890abcdef";`;
    const result = gate.evaluateLine(line, 0, [], false);
    expect(result.passed).toBe(true);
    expect(result.db2Hits).toContain("api_key");
  });

  it("should NOT pass a line with no keyword hits", () => {
    const line = `const userName = "JohnDoe";`;
    const result = gate.evaluateLine(line, 0, [], false);
    expect(result.passed).toBe(false);
  });

  it("should NOT pass an empty line", () => {
    const result = gate.evaluateLine("", 0, [], false);
    expect(result.passed).toBe(false);
  });

  it("should NOT pass a line with keyword but string too short", () => {
    const line = `const api_key = "abc";`;
    const result = gate.evaluateLine(line, 0, [], false);
    expect(result.passed).toBe(false);
  });

  it("should detect GitHub PAT prefix in string value", () => {
    const line = `const token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ";`;
    const result = gate.evaluateLine(line, 0, [], false);
    expect(result.passed).toBe(true);
    expect(result.db1Hits.some((h) => h.includes("ghp_"))).toBe(true);
  });

  it("should extract correct candidate start/end positions", () => {
    const secretValue = "sk-abcdefgh1234567890T3BlbkFJabcdefgh12345678";
    const line = `const key = "${secretValue}";`;
    const result = gate.evaluateLine(line, 5, [], false);
    expect(result.passed).toBe(true);
    const candidate = result.candidates[0];
    expect(candidate).toBeDefined();
    if (candidate !== undefined) {
      expect(candidate.lineNumber).toBe(5);
      expect(candidate.value).toBe(secretValue);
    }
  });
});
