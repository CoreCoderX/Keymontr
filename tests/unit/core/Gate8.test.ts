import { Gate8_DeveloperMemory } from "../../../src/core/pipeline/Gate8_DeveloperMemory";
import { SeverityLevel } from "../../../src/core/types/SeverityLevel";

describe("Gate8_DeveloperMemory", () => {
  let memory: Gate8_DeveloperMemory;

  beforeEach(() => {
    memory = new Gate8_DeveloperMemory();
  });

  describe("check()", () => {
    it("should return not-suppressed for a new finding", () => {
      const result = memory.check("/file.ts", 10, 'const key = "secret";');
      expect(result.isSuppressed).toBe(false);
      expect(result.suppressionType).toBe("none");
    });

    it("should return suppressionKey", () => {
      const result = memory.check("/file.ts", 10, 'const key = "secret";');
      expect(result.suppressionKey).toBeTruthy();
      expect(result.suppressionKey.length).toBe(64); // SHA256 hex
    });
  });

  describe("suppressPermanently()", () => {
    it("should suppress a finding permanently", () => {
      memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.HIGH,
        "aws-access-token",
        "Test reason",
      );

      const result = memory.check(
        "/file.ts",
        10,
        'const key = "secret";',
        "aws-access-token",
      );
      expect(result.isSuppressed).toBe(true);
      expect(result.suppressionType).toBe("permanent");
    });

    it("should store the suppression reason", () => {
      const record = memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.HIGH,
        undefined,
        "False positive — test fixture",
      );

      expect(record.reason).toBe("False positive — test fixture");
    });

    it("should persist across multiple check() calls", () => {
      memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.CRITICAL,
      );

      // Check multiple times — should always be suppressed
      for (let i = 0; i < 5; i++) {
        const result = memory.check("/file.ts", 10, 'const key = "secret";');
        expect(result.isSuppressed).toBe(true);
      }
    });

    it("should expire suppressions past their expiry date", () => {
      const pastDate = new Date(Date.now() - 1000); // 1 second ago
      memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.LOW,
        undefined,
        undefined,
        pastDate,
      );

      const result = memory.check("/file.ts", 10, 'const key = "secret";');
      expect(result.isSuppressed).toBe(false);
    });
  });

  describe("suppressForSession()", () => {
    it("should suppress a finding for the session", () => {
      memory.suppressForSession("/file.ts", 10, 'const key = "secret";');
      const result = memory.check("/file.ts", 10, 'const key = "secret";');
      expect(result.isSuppressed).toBe(true);
      expect(result.suppressionType).toBe("session");
    });
  });

  describe("unsuppress()", () => {
    it("should remove a permanent suppression", () => {
      memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.HIGH,
      );
      const { suppressionKey } = memory.check(
        "/file.ts",
        10,
        'const key = "secret";',
      );
      memory.unsuppress(suppressionKey);

      const afterUnsuppress = memory.check(
        "/file.ts",
        10,
        'const key = "secret";',
      );
      expect(afterUnsuppress.isSuppressed).toBe(false);
    });
  });

  describe("persistence", () => {
    it("should serialize and reload suppressions correctly", () => {
      memory.suppressPermanently(
        "/file.ts",
        10,
        'const key = "secret";',
        SeverityLevel.HIGH,
      );
      memory.suppressPermanently(
        "/other.ts",
        5,
        'const pwd = "pass";',
        SeverityLevel.MEDIUM,
      );

      const records = memory.toPersistenceRecords();
      expect(records.length).toBe(2);

      const newMemory = new Gate8_DeveloperMemory();
      newMemory.loadFromPersistence(records);

      expect(
        newMemory.check("/file.ts", 10, 'const key = "secret";').isSuppressed,
      ).toBe(true);
      expect(
        newMemory.check("/other.ts", 5, 'const pwd = "pass";').isSuppressed,
      ).toBe(true);
    });
  });

  describe("clearSession()", () => {
    it("should clear all session suppressions", () => {
      memory.suppressForSession("/file.ts", 10, 'const key = "secret";');
      memory.clearSession();
      const result = memory.check("/file.ts", 10, 'const key = "secret";');
      expect(result.isSuppressed).toBe(false);
    });
  });

  describe("counts", () => {
    it("should track permanent and session counts correctly", () => {
      memory.suppressPermanently("/a.ts", 1, "line1", SeverityLevel.HIGH);
      memory.suppressPermanently("/b.ts", 2, "line2", SeverityLevel.LOW);
      memory.suppressForSession("/c.ts", 3, "line3");

      expect(memory.permanentCount).toBe(2);
      expect(memory.sessionCount).toBe(1);
    });
  });
});
