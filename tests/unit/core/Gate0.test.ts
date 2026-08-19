import { Gate0_FileIntelligence } from "../../../src/core/pipeline/Gate0_FileIntelligence";
import { FileRiskLevel } from "../../../src/core/types/DetectionResult";
import { DEFAULT_EXCLUDED_PATHS } from "../../../src/config/DefaultConfig";

describe("Gate0_FileIntelligence", () => {
  let gate: Gate0_FileIntelligence;

  beforeEach(() => {
    gate = new Gate0_FileIntelligence(DEFAULT_EXCLUDED_PATHS);
  });

  describe("should EXCLUDE files", () => {
    const excludedPaths = [
      "/project/node_modules/lodash/index.js",
      "/project/dist/bundle.js",
      "/project/build/output.js",
      "/project/.next/server/app.js",
      "/project/coverage/lcov.info",
      "/project/package-lock.json",
      "/project/yarn.lock",
      "/project/pnpm-lock.yaml",
      "/project/Cargo.lock",
      "/project/poetry.lock",
      "/project/.git/config",
      "/project/vendor/lib.php",
      "/project/app.min.js",
      "/project/styles.min.css",
    ];

    for (const filePath of excludedPaths) {
      it(`should exclude: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.riskLevel).toBe(FileRiskLevel.EXCLUDED);
        expect(result.shouldScan).toBe(false);
      });
    }
  });

  describe("should assign HIGH risk to sensitive files", () => {
    const highRiskFiles = [
      "/project/.env",
      "/project/.env.local",
      "/project/.env.production",
      "/project/.env.staging",
      "/project/secrets.json",
      "/project/credentials.json",
    ];

    for (const filePath of highRiskFiles) {
      it(`should be HIGH risk: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.riskLevel).toBe(FileRiskLevel.HIGH);
        expect(result.shouldScan).toBe(true);
        expect(result.riskMultiplier).toBeGreaterThan(1.0);
      });
    }
  });

  describe("should assign REDUCED risk to documentation", () => {
    const reducedRiskFiles = [
      "/project/README.md",
      "/project/docs/API.md",
      "/project/CHANGELOG.md",
      "/project/notes.txt",
    ];

    for (const filePath of reducedRiskFiles) {
      it(`should be REDUCED risk: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.riskLevel).toBe(FileRiskLevel.REDUCED);
        expect(result.riskMultiplier).toBeLessThan(1.0);
      });
    }
  });

  describe("should assign REDUCED risk to test files", () => {
    const testFiles = [
      "/project/src/__tests__/api.test.ts",
      "/project/src/api.spec.ts",
      "/project/tests/fixtures/mock-data.js",
      "/project/test/helpers/setup.py",
    ];

    for (const filePath of testFiles) {
      it(`should be REDUCED risk: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.riskLevel).toBe(FileRiskLevel.REDUCED);
      });
    }
  });

  describe("should assign NORMAL risk to regular source files", () => {
    const normalFiles = [
      "/project/src/app.ts",
      "/project/src/index.js",
      "/project/src/config.py",
      "/project/lib/utils.go",
    ];

    for (const filePath of normalFiles) {
      it(`should be NORMAL risk: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.riskLevel).toBe(FileRiskLevel.NORMAL);
        expect(result.riskMultiplier).toBe(1.0);
      });
    }
  });

  describe("binary file exclusion", () => {
    const binaryFiles = [
      "/project/image.png",
      "/project/photo.jpg",
      "/project/video.mp4",
      "/project/archive.zip",
      "/project/font.woff2",
      "/project/document.pdf",
    ];

    for (const filePath of binaryFiles) {
      it(`should exclude binary file: ${filePath}`, () => {
        const result = gate.assess(filePath);
        expect(result.shouldScan).toBe(false);
      });
    }
  });

  describe("custom exclusion paths", () => {
    it("should respect custom exclusion patterns", () => {
      const gateWithCustom = new Gate0_FileIntelligence([
        ...DEFAULT_EXCLUDED_PATHS,
        "**/custom-ignore/**",
      ]);

      const result = gateWithCustom.assess("/project/custom-ignore/secret.ts");
      expect(result.shouldScan).toBe(false);
    });
  });
});
