#!/usr/bin/env python3
"""
gitleaks-to-stringgroup.py — convert regex/scripts/gitleaks.toml into a
stringgroup-style JSON database (mirroring stringgroup/assets/ layout).

Output tree (written under regex/assets/, never touches stringgroup/):

    regex/assets/
    ├── gitleaks-rules.json     # COMPREHENSIVE DB — every field preserved
    │                           #   {title, minVersion, allowlist, rules:[...]}
    │                           #   each rule: id, description, regex, entropy,
    │                           #   keywords, path, secretGroup, allowlists
    │                           #   (allowlists keep regexes[]/regexTarget/
    │                           #    paths[]/stopwords[]/condition verbatim)
    ├── stringgroups.json       # Group -> Keywords   (keyed by rule id)
    ├── keyword-index.json      # Keyword -> Group    (flat O(1) lookup map)
    └── groups/<rule-id>.json   # one file per rule: { "name": <id>, "keywords": [...] }

Naming / policy
  * One gitleaks rule == one stringgroup "group", named by the rule's `id`
    (kept fully separate from the curated stringgroup/ database).
  * Keywords are the rule's raw gitleaks `keywords` verbatim (they are
    pre-filter substrings such as "sk-", "aws_access_key_id", "ghp_").
    No casing expansion is applied — these are not full identifier names.
  * A keyword used by several rules maps to the FIRST rule that declares it
    (first-occurrence-wins, matching the curated emit-assets.mjs behavior);
    collisions are reported, never silently dropped.
  * Rules without keywords (e.g. pkcs12-file) get keywords derived from the
    rule id so they still appear in the index/groups.

Requires Python >= 3.11 (tomllib). No third-party dependencies.

Usage:
    python regex/scripts/gitleaks-to-stringgroup.py [--out DIR] [--verify]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    sys.exit("tomllib requires Python >= 3.11 (stdlib). Aborting.")

ROOT = Path(__file__).resolve().parent.parent          # regex/
DEFAULT_TOML = ROOT / "scripts" / "gitleaks.toml"
DEFAULT_OUT = ROOT / "assets"

# Tokens too generic to be useful as derived keywords (fallback only).
GENERIC_TOKENS = {
    "a", "an", "the", "of", "for", "and", "or", "in", "on", "to",
    "api", "key", "token", "secret", "access", "auth", "user", "id",
    "file", "password", "passwd", "url", "uri", "endpoint", "service",
    "account", "config", "value", "name", "string", "credential", "cred",
}


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_toml(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def slugify(name: str) -> str:
    """Same slug rule as stringgroup/scripts/stringgroups/emit-assets.mjs."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "group"


def derive_keywords(rule_id: str) -> list[str]:
    """Fallback keywords for rules with no `keywords` entry (e.g. pkcs12-file)."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", rule_id) if t and t not in GENERIC_TOKENS]
    kws = set(tokens)
    if len(tokens) >= 2:
        kws.add("-".join(tokens))
        kws.add("".join(tokens))
    return sorted(k for k in kws if len(k) >= 2)


# ---------------------------------------------------------------------------
# Verification (structural cross-check)
# ---------------------------------------------------------------------------

def verify(cfg: dict, rules: list[dict]) -> None:
    print("--- cross-verification ---")
    print(f"title: {cfg.get('title')!r}  minVersion: {cfg.get('minVersion')!r}")

    allowlist = cfg.get("allowlist")
    if allowlist is not None:
        print(f"global allowlist: description={allowlist.get('description')!r} "
              f"paths={len(allowlist.get('paths', []))} "
              f"regexes={len(allowlist.get('regexes', []))} "
              f"stopwords={len(allowlist.get('stopwords', []))}")

    ids = [r["id"] for r in rules if "id" in r]
    dup_ids = [i for i, c in Counter(ids).items() if c > 1]
    if dup_ids:
        print(f"WARNING: duplicate rule ids: {dup_ids}")
    for r in rules:
        if "regex" not in r and "path" not in r:
            print(f"WARNING: rule {r['id']!r} has neither regex nor path")
    no_kw = [r["id"] for r in rules if not r.get("keywords")]
    if no_kw:
        print(f"rules without keywords (derived from id): {', '.join(no_kw)}")

    aw_count = sum(len(r.get("allowlists", [])) for r in rules)
    print(f"rules: {len(rules)}  (ids unique: {len(ids) == len(set(ids))})")
    print(f"rules with allowlists: {sum(1 for r in rules if r.get('allowlists'))}  "
          f"(allowlist objects: {aw_count})")
    print("--- end cross-verification ---\n")


# ---------------------------------------------------------------------------
# Build & emit
# ---------------------------------------------------------------------------

def build(cfg: dict) -> tuple[list[dict], dict, dict, dict[str, list[str]]]:
    """Return (rules, by_name, index, collisions) from the parsed config.

    A keyword claimed by several rules maps to the FIRST rule that declares it
    (first-occurrence-wins); collisions maps keyword -> all claiming rule ids.
    """
    rules = list(cfg.get("rules", []))
    by_name: dict[str, list[str]] = {}
    index: dict[str, str] = {}
    claimants: dict[str, list[str]] = {}

    for r in rules:
        rid = r["id"]
        kws = [str(k).strip() for k in r.get("keywords", []) if str(k).strip()]
        if not kws:
            kws = derive_keywords(rid)
        # dedupe within the rule, keep order
        seen, clean = set(), []
        for k in kws:
            if k not in seen:
                seen.add(k)
                clean.append(k)
        by_name[rid] = clean

        for k in clean:
            claimants.setdefault(k, []).append(rid)
            if k not in index:          # first claimant wins
                index[k] = rid

    collisions = {k: v for k, v in claimants.items() if len(v) > 1}
    return rules, by_name, index, collisions


def emit(out: Path, cfg: dict, rules: list[dict], by_name: dict[str, list[str]],
         index: dict[str, str], collisions: dict[str, list[str]]) -> None:
    groups_dir = out / "groups"
    groups_dir.mkdir(parents=True, exist_ok=True)

    # 1. comprehensive DB — full rule objects, every gitleaks field preserved
    db = {"title": cfg.get("title"), "minVersion": cfg.get("minVersion")}
    if "allowlist" in cfg:
        db["allowlist"] = cfg["allowlist"]
    db["rules"] = rules
    (out / "gitleaks-rules.json").write_text(
        json.dumps(db, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 2. Group -> Keywords
    (out / "stringgroups.json").write_text(
        json.dumps(by_name, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 3. Keyword -> Group (first-occurrence wins)
    (out / "keyword-index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # 4. one file per rule
    for rid, kws in by_name.items():
        slug = slugify(rid)
        (groups_dir / f"{slug}.json").write_text(
            json.dumps({"name": rid, "keywords": kws}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")

    # summary
    print("--- generated ---")
    print(f"rules (groups):        {len(by_name)}")
    print(f"keywords total:        {sum(len(v) for v in by_name.values())}")
    print(f"keywords unique:       {len(index)}")
    remapped = sum(len(v) - 1 for v in collisions.values())
    print(f"collision keywords:    {len(collisions)} ({remapped} occurrences remapped to first rule)")
    print(f"per-group files:       {len(list(groups_dir.glob('*.json')))}")
    print(f"written under:         {out}")


def self_check(by_name: dict[str, list[str]], index: dict[str, str],
               collisions: dict[str, list[str]]) -> None:
    failures = 0

    def fail(msg: str) -> None:
        nonlocal failures
        failures += 1
        print(f"FAIL: {msg}")

    for kw, rid in index.items():
        if rid not in by_name:
            fail(f"index maps {kw!r} to unknown group {rid}")
        elif kw not in by_name[rid]:
            fail(f"index maps {kw!r} to {rid} which does not contain it")

    for rid, kws in by_name.items():
        for kw in kws:
            if index.get(kw) != rid:
                if kw not in collisions:
                    fail(f"keyword {kw!r} of {rid} missing from index (not a collision)")

    for kw, rids in collisions.items():
        if index[kw] not in rids:
            fail(f"collision {kw!r} maps to {index[kw]!r}, not among {rids}")

    print("--- self-check ---")
    print("VALIDATION PASSED" if failures == 0 else f"VALIDATION FAILED ({failures} issue(s))")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--toml", type=Path, default=DEFAULT_TOML, help="path to gitleaks.toml")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory (default: regex/assets)")
    ap.add_argument("--verify", action="store_true", help="only run the structural cross-check")
    args = ap.parse_args()

    if not args.toml.exists():
        sys.exit(f"toml not found: {args.toml}")
    cfg = parse_toml(args.toml)
    rules = cfg.get("rules", [])
    print(f"parsed: {args.toml}")

    verify(cfg, rules)
    if args.verify:
        return 0

    rules, by_name, index, collisions = build(cfg)
    emit(args.out, cfg, rules, by_name, index, collisions)
    self_check(by_name, index, collisions)
    return 0


if __name__ == "__main__":
    sys.exit(main())
