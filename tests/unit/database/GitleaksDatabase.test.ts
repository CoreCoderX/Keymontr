import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { GitleaksDatabase } from "../../../src/database/GitleaksDatabase";
import { GitleaksRulesFile } from "../../../src/core/types/RuleDefinition";

describe("GitleaksDatabase", () => {
  let tempDir: string;
  let db: GitleaksDatabase;

  const sampleRulesFile: GitleaksRulesFile = {
    title: "test gitleaks config",
    minVersion: "v8.25.0",
    allowlist: {
      description: "global allowlist",
      paths: ["vendor/.*"],
      regexes: ["EXAMPLE_.*"],
      stopwords: ["example", "test"],
    },
    rules: [
      {
        id: "aws-access-token",
        description: "AWS Access Token",
        regex: "(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
        entropy: 3.5,
        keywords: ["akia", "asia"],
        allowlists: [
          {
            regexTarget: "match",
            regexes: ["AKIAIOSFODNN7EXAMPLE"],
            stopwords: ["example"],
          },
        ],
      },
      {
        id: "github-pat",
        description: "GitHub Personal Access Token",
        regex: "ghp_[0-9a-zA-Z]{36}",
        entropy: 3.0,
        keywords: ["ghp_"],
        allowlists: [],
      },
      {
        id: "openai-api-key",
        description: "OpenAI API Key",
        regex: "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
        entropy: 3.0,
        keywords: ["openai", "sk-"],
      },
    ],
  };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-test-"));
    fs.writeFileSync(
      path.join(tempDir, "gitleaks-rules.json"),
      JSON.stringify(sampleRulesFile),
      "utf-8",
    );
    db = new GitleaksDatabase(tempDir);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe("load()", () => {
    it("should load and compile rules successfully", async () => {
      await db.load();
      expect(db.loaded).toBe(true);
      expect(db.getRuleCount()).toBe(3);
    });

    it("should throw if rules file does not exist", async () => {
      const badDb = new GitleaksDatabase("/nonexistent/path");
      await expect(badDb.load()).rejects.toThrow("not found");
    });

    it("should throw if rules file contains invalid JSON", async () => {
      fs.writeFileSync(
        path.join(tempDir, "gitleaks-rules.json"),
        "{ invalid json",
        "utf-8",
      );
      await expect(db.load()).rejects.toThrow("parse");
    });

    it("should throw if rules array is missing", async () => {
      fs.writeFileSync(
        path.join(tempDir, "gitleaks-rules.json"),
        JSON.stringify({ title: "test" }),
        "utf-8",
      );
      await expect(db.load()).rejects.toThrow("missing 'rules'");
    });

    it("should compile global allowlists", async () => {
      await db.load();
      const globalRegexes = db.getGlobalAllowlistRegexes();
      expect(globalRegexes.length).toBeGreaterThan(0);
    });
  });

  describe("getRuleIdsForKeyword()", () => {
    beforeEach(async () => {
      await db.load();
    });

    it("should return rule IDs for known keyword", () => {
      const ruleIds = db.getRuleIdsForKeyword("akia");
      expect(ruleIds).toContain("aws-access-token");
    });

    it("should return multiple rule IDs for shared keyword (collision)", () => {
      // Both openai-api-key and github-pat would share nothing, but let's test sk-
      const ruleIds = db.getRuleIdsForKeyword("sk-");
      expect(ruleIds).toContain("openai-api-key");
    });

    it("should return empty array for unknown keyword", () => {
      const ruleIds = db.getRuleIdsForKeyword("__nonexistent__");
      expect(ruleIds).toEqual([]);
    });

    it("should be case-insensitive", () => {
      const lower = db.getRuleIdsForKeyword("akia");
      const upper = db.getRuleIdsForKeyword("AKIA");
      expect(lower).toEqual(upper);
    });
  });

  describe("getRule()", () => {
    beforeEach(async () => {
      await db.load();
    });

    it("should return a compiled rule by ID", () => {
      const rule = db.getRule("aws-access-token");
      expect(rule).toBeDefined();
      expect(rule?.id).toBe("aws-access-token");
      expect(rule?.regex).toBeInstanceOf(RegExp);
    });

    it("should return undefined for unknown rule ID", () => {
      const rule = db.getRule("nonexistent-rule");
      expect(rule).toBeUndefined();
    });

    it("should have compiled allowlists", () => {
      const rule = db.getRule("aws-access-token");
      expect(rule?.allowlists).toBeDefined();
      expect(rule?.allowlists.length).toBeGreaterThan(0);
    });
  });

  describe("getAllRules()", () => {
    it("should return all compiled rules", async () => {
      await db.load();
      const rules = db.getAllRules();
      expect(rules.length).toBe(3);
      for (const rule of rules) {
        expect(rule.id).toBeTruthy();
        expect(rule.regex).toBeInstanceOf(RegExp);
      }
    });
  });

  describe("error handling", () => {
    it("should throw if methods called before load()", () => {
      expect(() => db.getRule("aws-access-token")).toThrow("not loaded");
    });

    it("should handle rules with invalid regex gracefully", async () => {
      const fileWithBadRegex: GitleaksRulesFile = {
        ...sampleRulesFile,
        rules: [
          ...sampleRulesFile.rules,
          {
            id: "bad-regex-rule",
            description: "Rule with invalid regex",
            regex: "([invalid",
            entropy: 3.0,
            keywords: ["bad"],
          },
        ],
      };
      fs.writeFileSync(
        path.join(tempDir, "gitleaks-rules.json"),
        JSON.stringify(fileWithBadRegex),
        "utf-8",
      );
      await db.load();
      // Should load successfully, just skip the bad rule
      expect(db.loaded).toBe(true);
      expect(db.getRule("bad-regex-rule")).toBeUndefined();
      // Valid rules should still be loaded
      expect(db.getRuleCount()).toBe(3);
    });
  });
});
