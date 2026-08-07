#!/usr/bin/env node
/**
 * Validates the emitted asset layout:
 *  - assets/stringgroups.json  keys are group names, values are keyword arrays
 *  - assets/keyword-index.json maps every keyword to its group (and nothing else)
 *  - assets/groups/*.json  files match stringgroups.json 1:1 by name/keywords
 * Prints a summary; exits non-zero on any failure.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ASSETS = path.resolve(__dirname, '..', '..', 'assets');

let failures = 0;
const fail = (msg) => {
  failures++;
  console.error('FAIL: ' + msg);
};

const byName = JSON.parse(fs.readFileSync(path.join(ASSETS, 'stringgroups.json'), 'utf8'));
const index = JSON.parse(fs.readFileSync(path.join(ASSETS, 'keyword-index.json'), 'utf8'));

if (typeof byName !== 'object' || Array.isArray(byName)) fail('stringgroups.json is not an object');
const names = Object.keys(byName);
if (names.length === 0) fail('stringgroups.json is empty');

// Every index key maps to an existing group and is actually in that group.
for (const [kw, group] of Object.entries(index)) {
  if (!byName[group]) fail(`index maps ${kw} to unknown group ${group}`);
  else if (!byName[group].includes(kw)) fail(`index maps ${kw} to ${group} which does not contain it`);
}

// Every group keyword is present in the index.
for (const g of names) {
  for (const kw of byName[g]) {
    if (index[kw] !== g) fail(`keyword ${kw} of group ${g} is missing/incorrect in index`);
  }
}

// Per-group files.
const files = fs.readdirSync(path.join(ASSETS, 'groups')).filter((f) => f.endsWith('.json'));
if (files.length !== names.length) fail(`expected ${names.length} per-group files, found ${files.length}`);
for (const f of files) {
  const g = JSON.parse(fs.readFileSync(path.join(ASSETS, 'groups', f), 'utf8'));
  if (!g || typeof g.name !== 'string' || !Array.isArray(g.keywords)) fail(`bad file ${f}`);
  if (!byName[g.name]) fail(`file ${f}: unknown group name ${g.name}`);
  else if (JSON.stringify(g.keywords) !== JSON.stringify(byName[g.name])) {
    fail(`file ${f}: keywords differ from stringgroups.json for ${g.name}`);
  }
}

const total = names.reduce((n, g) => n + byName[g].length, 0);
console.log('groups:', names.length);
console.log('keywords:', total);
console.log('index entries:', Object.keys(index).length);
console.log('per-group files:', files.length);
console.log('first 8 groups:', names.slice(0, 8).join(', '));
console.log(failures === 0 ? 'VALIDATION PASSED' : `VALIDATION FAILED (${failures} issue(s))`);
process.exit(failures === 0 ? 0 : 1);
