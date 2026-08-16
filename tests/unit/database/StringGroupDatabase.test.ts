import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { StringGroupDatabase } from "../../../src/database/StringGroupDatabase";

describe("StringGroupDatabase", () => {
  let tempDir: string;
  let db: StringGroupDatabase;

  const sampleIndex: Record<string, string> = {
    API_KEY: "Generic Secrets",
    api_key: "Generic Secrets",
    apiKey: "Generic Secrets",
    OPENAI_API_KEY: "OpenAI",
    openai_api_key: "OpenAI",
    AWS_ACCESS_KEY_ID: "AWS",
    aws_access_key_id: "AWS",
    STRIPE_SECRET_KEY: "Stripe",
    password: "Generic Secrets",
    PASSWORD: "Generic Secrets",
    token: "Generic Secrets",
    TOKEN: "Generic Secrets",
    private_key: "Certificates",
    PRIVATE_KEY: "Certificates",
  };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ss-sg-test-"));
    fs.writeFileSync(
      path.join(tempDir, "keyword-index.json"),
      JSON.stringify(sampleIndex),
      "utf-8",
    );
    db = new StringGroupDatabase(tempDir);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe("load()", () => {
    it("should load the keyword index successfully", async () => {
      await db.load();
      expect(db.loaded).toBe(true);
      expect(db.getKeywordCount()).toBe(Object.keys(sampleIndex).length);
    });

    it("should throw if keyword index file does not exist", async () => {
      const badDb = new StringGroupDatabase("/nonexistent/path");
      await expect(badDb.load()).rejects.toThrow("not found");
    });

    it("should throw if keyword index contains invalid JSON", async () => {
      fs.writeFileSync(
        path.join(tempDir, "keyword-index.json"),
        "not valid json",
        "utf-8",
      );
      await expect(db.load()).rejects.toThrow("parse");
    });
  });

  describe("getGroup()", () => {
    beforeEach(async () => {
      await db.load();
    });

    it("should return the group for a known identifier", () => {
      expect(db.getGroup("API_KEY")).toBe("Generic Secrets");
      expect(db.getGroup("OPENAI_API_KEY")).toBe("OpenAI");
      expect(db.getGroup("AWS_ACCESS_KEY_ID")).toBe("AWS");
    });

    it("should return undefined for unknown identifier", () => {
      expect(db.getGroup("totally_unknown_var")).toBeUndefined();
    });
  });

  describe("getGroupWithVariants()", () => {
    beforeEach(async () => {
      await db.load();
    });

    it("should find exact match", () => {
      const result = db.getGroupWithVariants("API_KEY");
      expect(result?.group).toBe("Generic Secrets");
    });

    it("should find lowercase variant", () => {
      const result = db.getGroupWithVariants("api_key");
      expect(result?.group).toBe("Generic Secrets");
    });

    it("should find camelCase variant", () => {
      const result = db.getGroupWithVariants("apiKey");
      expect(result?.group).toBe("Generic Secrets");
    });

    it("should return undefined for completely unknown identifier", () => {
      const result = db.getGroupWithVariants("xyz_nonexistent_thing_abc");
      expect(result).toBeUndefined();
    });

    it("should return the matched variant", () => {
      const result = db.getGroupWithVariants("api_key");
      expect(result?.matchedVariant).toBe("api_key");
    });
  });

  describe("getGroupsForIdentifiers()", () => {
    beforeEach(async () => {
      await db.load();
    });

    it("should return all matching groups for multiple identifiers", () => {
      const results = db.getGroupsForIdentifiers([
        "apiKey",
        "AWS_ACCESS_KEY_ID",
        "unknownVar",
        "STRIPE_SECRET_KEY",
      ]);

      expect(results.length).toBe(3);
      const groups = results.map((r) => r.group);
      expect(groups).toContain("Generic Secrets");
      expect(groups).toContain("AWS");
      expect(groups).toContain("Stripe");
    });

    it("should return empty array for no matches", () => {
      const results = db.getGroupsForIdentifiers(["abc", "xyz", "foo"]);
      expect(results).toEqual([]);
    });
  });

  describe("getAllGroupNames()", () => {
    it("should return all unique group names", async () => {
      await db.load();
      const names = db.getAllGroupNames();
      expect(names).toContain("Generic Secrets");
      expect(names).toContain("OpenAI");
      expect(names).toContain("AWS");
      expect(names).toContain("Stripe");
      expect(names).toContain("Certificates");
    });
  });

  describe("error handling", () => {
    it("should throw if methods called before load()", () => {
      expect(() => db.getGroup("test")).toThrow("not loaded");
    });
  });
});
