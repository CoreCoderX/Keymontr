import * as fs from "fs";
import * as path from "path";

const GITIGNORE_FILE = ".gitignore";

interface GitIgnoreRule {
  negated: boolean;
  dirOnly: boolean;
  regex: RegExp;
}

/**
 * Escapes a single character for use inside a RegExp literal.
 */
function escapeRegExpChar(ch: string): string {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * GitIgnoreMatcher — Parses the contents of a .gitignore file and
 * evaluates whether a path (relative to the directory the .gitignore
 * lives in) is ignored.
 *
 * Implements the core gitignore rules:
 * - Blank lines and lines starting with `#` are ignored
 * - A trailing `/` restricts the pattern to directories
 * - A leading `/` or a `/` in the middle anchors the pattern to the
 *   .gitignore's directory; otherwise the pattern matches at any depth
 * - `!` negates a pattern; the last matching pattern wins
 * - `*`, `**` and `?` wildcards are supported
 */
export class GitIgnoreMatcher {
  private readonly rules: GitIgnoreRule[];

  constructor(content: string) {
    this.rules = this.parse(content);
  }

  /**
   * Evaluates a path relative to the .gitignore directory.
   *
   * @returns true if ignored, false if explicitly un-ignored by a
   *          negation, or null if no rule matched the path.
   */
  public evaluate(relativePath: string): boolean | null {
    const normalized = relativePath.replace(/\\/g, "/");
    const candidates = this.buildDirectoryCandidates(normalized);

    let result: boolean | null = null;

    for (const rule of this.rules) {
      // Directory-only patterns also match every ancestor directory of
      // the path (e.g. `node_modules/` ignores files beneath it).
      const targets = rule.dirOnly ? candidates : [normalized];

      for (const target of targets) {
        if (rule.regex.test(target)) {
          result = !rule.negated;
          break;
        }
      }
    }

    return result;
  }

  /**
   * Convenience wrapper: true only when the path is actually ignored.
   */
  public isIgnored(relativePath: string): boolean {
    return this.evaluate(relativePath) === true;
  }

  private parse(content: string): GitIgnoreRule[] {
    const rules: GitIgnoreRule[] = [];

    for (const rawLine of content.split(/\r?\n/)) {
      let line = rawLine.replace(/\s+$/, "");

      if (line.length === 0 || line.startsWith("#")) {
        continue;
      }

      let negated = false;
      if (line.startsWith("!")) {
        negated = true;
        line = line.slice(1);
      }
      if (line.length === 0) {
        continue;
      }

      let dirOnly = false;
      if (line.endsWith("/")) {
        dirOnly = true;
        line = line.slice(0, -1);
      }
      if (line.length === 0) {
        continue;
      }

      const anchored = line.startsWith("/") || line.includes("/");
      const pattern = line.startsWith("/") ? line.slice(1) : line;
      const regex = this.patternToRegex(pattern, anchored);

      if (regex !== null) {
        rules.push({ negated, dirOnly, regex });
      }
    }

    return rules;
  }

  private patternToRegex(pattern: string, anchored: boolean): RegExp | null {
    try {
      let out = "";

      for (let i = 0; i < pattern.length; i++) {
        const ch = pattern[i];

        if (ch === "*") {
          if (pattern[i + 1] === "*") {
            if (pattern[i + 2] === "/") {
              // `**/` — zero or more directories
              out += "(?:.*/)?";
              i += 2;
            } else {
              // bare `**` — anything (including nothing)
              out += ".*";
              i += 1;
            }
          } else {
            out += "[^/]*";
          }
        } else if (ch === "?") {
          out += "[^/]";
        } else if (ch === "\\") {
          const next = pattern[i + 1];
          if (next !== undefined) {
            out += escapeRegExpChar(next);
            i += 1;
          } else {
            out += "\\\\";
          }
        } else {
          out += escapeRegExpChar(ch);
        }
      }

      // Non-anchored patterns match at any depth below the .gitignore dir.
      const source = anchored ? `^${out}$` : `^(?:.*/)?${out}$`;
      return new RegExp(source);
    } catch {
      return null;
    }
  }

  /**
   * Returns the path itself plus every parent directory path
   * (e.g. "src/a/b.js" → ["src/a/b.js", "src/a", "src"]).
   */
  private buildDirectoryCandidates(relativePath: string): string[] {
    const candidates: string[] = [];
    let current = relativePath;

    while (true) {
      candidates.push(current);
      const idx = current.lastIndexOf("/");
      if (idx <= 0) {
        break;
      }
      current = current.slice(0, idx);
    }

    return candidates;
  }
}

/**
 * GitIgnoreService — Workspace-aware gitignore evaluation.
 *
 * Reads .gitignore files from the workspace root down to the file's own
 * directory, so nested .gitignore files work too. Deeper files take
 * precedence over shallower ones (later matching rules win), mirroring
 * git's behaviour.
 */
export class GitIgnoreService {
  private readonly matcherCache = new Map<
    string,
    { mtimeMs: number; matcher: GitIgnoreMatcher }
  >();

  constructor(private readonly workspaceRoot: string) {}

  /**
   * Returns true if the given absolute file path is ignored by git
   * according to the applicable .gitignore files.
   */
  public isFileIgnored(absolutePath: string): boolean {
    const relative = path.relative(this.workspaceRoot, absolutePath);

    // Not inside the workspace → nothing to evaluate.
    if (
      relative === "" ||
      relative.startsWith("..") ||
      path.isAbsolute(relative)
    ) {
      return false;
    }

    // Collect the directories that may hold a .gitignore, root first.
    const gitignoreDirs: string[] = [];
    let current = path.dirname(absolutePath);

    while (true) {
      gitignoreDirs.unshift(current);

      if (current === this.workspaceRoot) {
        break;
      }

      // Guard against prefix collisions (e.g. C:/proj vs C:/project).
      if (!current.startsWith(this.workspaceRoot + path.sep)) {
        break;
      }

      const parent = path.dirname(current);
      if (parent === current) {
        break;
      }
      current = parent;
    }

    let ignored = false;

    for (const dir of gitignoreDirs) {
      const matcher = this.getMatcher(dir);
      if (matcher === null) {
        continue;
      }

      const relativeToDir = path.relative(dir, absolutePath).replace(/\\/g, "/");
      const result = matcher.evaluate(relativeToDir);

      // A deeper .gitignore that matches overrides shallower ones.
      if (result !== null) {
        ignored = result;
      }
    }

    return ignored;
  }

  /**
   * Loads (and caches, keyed by mtime) the .gitignore of a directory.
   * Returns null when the directory has no .gitignore.
   */
  private getMatcher(dir: string): GitIgnoreMatcher | null {
    const gitignorePath = path.join(dir, GITIGNORE_FILE);

    let stat: fs.Stats;
    try {
      stat = fs.statSync(gitignorePath);
    } catch {
      return null;
    }

    const cached = this.matcherCache.get(dir);
    if (cached?.mtimeMs === stat.mtimeMs) {
      return cached.matcher;
    }

    try {
      const content = fs.readFileSync(gitignorePath, "utf-8");
      const matcher = new GitIgnoreMatcher(content);
      this.matcherCache.set(dir, { mtimeMs: stat.mtimeMs, matcher });
      return matcher;
    } catch {
      return null;
    }
  }
}
