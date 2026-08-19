import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  GitIgnoreMatcher,
  GitIgnoreService,
} from "../../../src/git/GitIgnoreMatcher";

describe("GitIgnoreMatcher", () => {
  describe("simple patterns", () => {
    it("ignores .env at any depth", () => {
      const matcher = new GitIgnoreMatcher(".env\n");
      expect(matcher.isIgnored(".env")).toBe(true);
      expect(matcher.isIgnored("src/config/.env")).toBe(true);
    });

    it("does not match .env against foo.env", () => {
      const matcher = new GitIgnoreMatcher(".env\n");
      expect(matcher.isIgnored("foo.env")).toBe(false);
      expect(matcher.isIgnored("src/foo.env")).toBe(false);
    });

    it("matches *.env patterns at any depth", () => {
      const matcher = new GitIgnoreMatcher("*.env\n");
      expect(matcher.isIgnored("foo.env")).toBe(true);
      expect(matcher.isIgnored("src/prod.env")).toBe(true);
      expect(matcher.isIgnored("src/main.ts")).toBe(false);
    });
  });

  describe("anchored patterns", () => {
    it("only matches /dist at the gitignore directory level", () => {
      const matcher = new GitIgnoreMatcher("/dist\n");
      expect(matcher.isIgnored("dist")).toBe(true);
      expect(matcher.isIgnored("src/dist")).toBe(false);
    });

    it("matches foo/bar relative to the gitignore directory", () => {
      const matcher = new GitIgnoreMatcher("build/output\n");
      expect(matcher.isIgnored("build/output")).toBe(true);
      expect(matcher.isIgnored("src/build/output")).toBe(false);
    });
  });

  describe("directory-only patterns", () => {
    it("ignores everything beneath node_modules", () => {
      const matcher = new GitIgnoreMatcher("node_modules/\n");
      expect(matcher.isIgnored("node_modules")).toBe(true);
      expect(matcher.isIgnored("node_modules/lodash/index.js")).toBe(true);
      expect(matcher.isIgnored("a/b/node_modules/x.js")).toBe(true);
      expect(matcher.isIgnored("src/app.ts")).toBe(false);
    });

    it("does not match a file named like a dir-only pattern", () => {
      const matcher = new GitIgnoreMatcher("build/\n");
      expect(matcher.isIgnored("build/output.js")).toBe(true);
      expect(matcher.isIgnored("build")).toBe(true);
    });
  });

  describe("double-star patterns", () => {
    it("**/dist/** matches dist at any depth", () => {
      const matcher = new GitIgnoreMatcher("**/dist/**\n");
      expect(matcher.isIgnored("dist/bundle.js")).toBe(true);
      expect(matcher.isIgnored("a/b/dist/bundle.js")).toBe(true);
    });

    it("a/**/b matches intermediate directories", () => {
      const matcher = new GitIgnoreMatcher("a/**/b\n");
      expect(matcher.isIgnored("a/b")).toBe(true);
      expect(matcher.isIgnored("a/x/y/b")).toBe(true);
      expect(matcher.isIgnored("a/x/c")).toBe(false);
    });
  });

  describe("negation", () => {
    it("un-ignores files matched by a negation", () => {
      const matcher = new GitIgnoreMatcher(".env\n!.env\n");
      expect(matcher.isIgnored(".env")).toBe(false);
    });

    it("last matching pattern wins", () => {
      const matcher = new GitIgnoreMatcher("*.env\n!prod.env\n");
      expect(matcher.isIgnored("prod.env")).toBe(false);
      expect(matcher.isIgnored("dev.env")).toBe(true);
    });

    it("negation only applies to the paths it matches", () => {
      const matcher = new GitIgnoreMatcher("*.env\n!src/keep.env\n");
      expect(matcher.isIgnored("src/keep.env")).toBe(false);
      expect(matcher.isIgnored("other/keep.env")).toBe(true);
    });
  });

  describe("comments and blank lines", () => {
    it("ignores comments and empty lines", () => {
      const matcher = new GitIgnoreMatcher(
        "# comment\n\n  \n.env\n# another comment\n",
      );
      expect(matcher.isIgnored(".env")).toBe(true);
    });
  });

  describe("no match", () => {
    it("evaluate returns null when no rule matches", () => {
      const matcher = new GitIgnoreMatcher(".env\n");
      expect(matcher.evaluate("src/app.ts")).toBeNull();
    });
  });
});

describe("GitIgnoreService", () => {
  let workspaceRoot: string;

  beforeEach(() => {
    workspaceRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "keymontr-gitignore-"),
    );
  });

  afterEach(() => {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
  });

  function writeFile(relativePath: string, content: string): string {
    const absolutePath = path.join(workspaceRoot, relativePath);
    fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
    fs.writeFileSync(absolutePath, content, "utf-8");
    return absolutePath;
  }

  it("ignores .env when the root .gitignore lists it", () => {
    writeFile(".gitignore", ".env\n");
    const service = new GitIgnoreService(workspaceRoot);

    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(true);
    expect(
      service.isFileIgnored(path.join(workspaceRoot, "src", ".env")),
    ).toBe(true);
    expect(
      service.isFileIgnored(path.join(workspaceRoot, "src", "app.ts")),
    ).toBe(false);
  });

  it("treats files as not ignored when there is no .gitignore", () => {
    const service = new GitIgnoreService(workspaceRoot);
    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(false);
  });

  it("flags .env when .gitignore exists but does not list it", () => {
    writeFile(".gitignore", "node_modules/\ndist/\n");
    const service = new GitIgnoreService(workspaceRoot);

    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(false);
  });

  it("deeper .gitignore files override shallower ones", () => {
    writeFile(".gitignore", ".env\n");
    writeFile("src/.gitignore", "!.env\n");
    const service = new GitIgnoreService(workspaceRoot);

    // Root .env stays ignored; src/.env is explicitly un-ignored.
    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(true);
    expect(
      service.isFileIgnored(path.join(workspaceRoot, "src", ".env")),
    ).toBe(false);
  });

  it("respects dir-only patterns from the root .gitignore", () => {
    writeFile(".gitignore", "secrets/\n");
    const service = new GitIgnoreService(workspaceRoot);

    expect(
      service.isFileIgnored(
        path.join(workspaceRoot, "secrets", "credentials.json"),
      ),
    ).toBe(true);
  });

  it("returns false for files outside the workspace", () => {
    writeFile(".gitignore", ".env\n");
    const service = new GitIgnoreService(workspaceRoot);

    const outside = path.join(os.tmpdir(), "unrelated", "file.env");
    expect(service.isFileIgnored(outside)).toBe(false);
  });

  it("picks up .gitignore changes after they are written", () => {
    const service = new GitIgnoreService(workspaceRoot);
    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(false);

    writeFile(".gitignore", ".env\n");
    expect(service.isFileIgnored(path.join(workspaceRoot, ".env"))).toBe(true);
  });
});
