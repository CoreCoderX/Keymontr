#!/usr/bin/env node
/**
 * Emits the runtime-optimized asset layout straight from the curated source
 * fragments in this directory (scripts/stringgroups/0*.json):
 *
 *   assets/
 *   ├── groups/<slug>.json   // one file per group ({ name, keywords })
 *   ├── stringgroups.json    // Group -> Keywords  (for maintenance)
 *   └── keyword-index.json   // Keyword -> Group   (for runtime, O(1) lookup)
 *
 * Casing variants are expanded (snake/camel/Pascal/kebab/dot/no-separator)
 * and exact duplicates are removed (case-sensitive, variants preserved) —
 * mirroring the curated build. Combinatorial mega-groups are not generated.
 *
 * Requires Node.js >= 18. No dependencies.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const ASSETS = path.resolve(ROOT, 'assets');
const GROUPS_DIR = path.join(ASSETS, 'groups');
const FRAGMENT_GLOB = /^(\d+)-.+\.json$/;

// ---------------------------------------------------------------------------
// Word splitting / casing utilities
// ---------------------------------------------------------------------------

function toWords(raw) {
  return raw
    .split(/[_\-. ]+/)
    .flatMap((part) => {
      const p = part.trim();
      if (!p) return [];
      // Split camelCase / PascalCase boundaries, but treat all-uppercase
      // tokens (e.g. "APIKEY", "AWS") as a single word.
      if (p === p.toUpperCase() || p === p.toLowerCase()) return [p.toLowerCase()];
      return p.split(/(?<=[a-z0-9])(?=[A-Z])/).map((w) => w.toLowerCase());
    })
    .filter((w) => w.length > 0);
}

function title(w) {
  return w.length > 0 ? w[0].toUpperCase() + w.slice(1) : w;
}

function variantsOf(raw) {
  const words = toWords(raw);
  if (words.length === 0) return [];
  if (words.length === 1) {
    const w = words[0];
    const set = new Set([w, w.toUpperCase(), title(w), w.toLowerCase()]);
    return [...set].filter((k) => k.length >= 2);
  }
  const set = new Set([raw]);
  const lower = words.map((w) => w.toLowerCase());
  set.add(lower.join('_'));
  set.add(lower.map((w) => w.toUpperCase()).join('_'));
  set.add(lower.map((w, i) => (i === 0 ? w : title(w))).join(''));
  set.add(lower.map((w) => title(w)).join(''));
  set.add(lower.join('-'));
  set.add(lower.map((w) => w.toUpperCase()).join('-'));
  set.add(lower.join('.'));
  set.add(lower.join(''));
  set.add(lower.map((w) => w.toUpperCase()).join(''));
  set.add(lower.map((w) => title(w)).join(''));
  return [...set].filter((k) => k.length >= 2 && /^[A-Za-z0-9._\-]+$/.test(k));
}

// ---------------------------------------------------------------------------
// Fragments (source of truth)
// ---------------------------------------------------------------------------

function loadFragments() {
  const files = fs
    .readdirSync(__dirname)
    .filter((f) => FRAGMENT_GLOB.test(f))
    .sort();
  const groups = [];
  const seenGroups = new Set();
  for (const file of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(__dirname, file), 'utf8'));
    if (!Array.isArray(raw)) throw new Error(`${file}: expected a JSON array`);
    for (const g of raw) {
      if (!g || typeof g.name !== 'string' || !Array.isArray(g.keywords)) {
        throw new Error(`${file}: malformed group (${JSON.stringify(g)?.slice(0, 80)})`);
      }
      const name = g.name.trim();
      if (seenGroups.has(name)) throw new Error(`Duplicate group name: ${name}`);
      seenGroups.add(name);
      groups.push({ name, keywords: g.keywords.map((k) => String(k).trim()).filter(Boolean) });
    }
  }
  return groups;
}

function slugify(name) {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return slug || 'group';
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

function main() {
  const groups = loadFragments();

  // Expand variants and dedupe globally; first occurrence (group order, then
  // keyword order) wins.
  const consumed = new Set();
  const expanded = [];
  for (const group of groups) {
    const keywords = [];
    for (const kw of group.keywords) {
      for (const v of variantsOf(kw)) {
        if (!consumed.has(v)) {
          consumed.add(v);
          keywords.push(v);
        }
      }
    }
    if (keywords.length > 0) expanded.push({ name: group.name, keywords });
  }

  fs.mkdirSync(GROUPS_DIR, { recursive: true });

  // 1. assets/stringgroups.json — object keyed by group name
  const byName = {};
  for (const g of expanded) byName[g.name] = g.keywords;
  fs.writeFileSync(path.join(ASSETS, 'stringgroups.json'), JSON.stringify(byName, null, 2) + '\n', 'utf8');

  // 2. assets/keyword-index.json — flat Keyword -> Group
  const index = {};
  for (const g of expanded) {
    for (const kw of g.keywords) {
      if (index[kw] !== undefined && index[kw] !== g.name) {
        throw new Error(`Keyword collision across groups: ${kw} in ${index[kw]} and ${g.name}`);
      }
      index[kw] = g.name;
    }
  }
  fs.writeFileSync(path.join(ASSETS, 'keyword-index.json'), JSON.stringify(index, null, 2) + '\n', 'utf8');

  // 3. assets/groups/<slug>.json — one file per group
  const seenSlugs = new Set();
  for (const g of expanded) {
    const slug = slugify(g.name);
    if (seenSlugs.has(slug)) throw new Error(`Duplicate group slug: ${slug} (${g.name})`);
    seenSlugs.add(slug);
    fs.writeFileSync(
      path.join(GROUPS_DIR, `${slug}.json`),
      JSON.stringify({ name: g.name, keywords: g.keywords }, null, 2) + '\n',
      'utf8'
    );
  }

  const total = expanded.reduce((n, g) => n + g.keywords.length, 0);
  console.log(`groups: ${expanded.length}`);
  console.log(`keywords: ${total}`);
  console.log(`index entries: ${Object.keys(index).length}`);
  console.log(`per-group files: ${expanded.length}`);
  console.log('written under:', ASSETS);
}

main();
