#!/usr/bin/env python3
"""
verify-gitleaks.py — small cross-check of regex/scripts/gitleaks.toml

Parses the TOML with tomllib (stdlib, Python >= 3.11) and reports:
  * rule count + distinct fields used
  * how many rules are missing id / regex / keywords
  * allowlist structure (top-level + per-rule), including nested-rule fields
    (regexes[], regexTarget, paths[], stopwords[], condition)
  * keyword stats (total / unique / collisions across rules)

Run:  python regex/scripts/verify-gitleaks.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    sys.exit("tomllib requires Python >= 3.11 (stdlib). Aborting.")

ROOT = Path(__file__).resolve().parent.parent
TOML = ROOT / "scripts" / "gitleaks.toml"

RULE_FIELDS = {"id", "description", "regex", "keywords", "entropy",
               "path", "secretGroup", "allowlists"}
ALLOWLIST_FIELDS = {"description", "paths", "regexes", "regexTarget",
                    "stopwords", "condition"}


def main() -> None:
    with TOML.open("rb") as fh:
        cfg = tomllib.load(fh)

    rules = cfg.get("rules", [])
    print(f"parsed: {TOML.relative_to(ROOT)}")
    print(f"title: {cfg.get('title')!r}  minVersion: {cfg.get('minVersion')!r}")

    # --- global allowlist -------------------------------------------------
    top_allowlist = cfg.get("allowlist")
    if top_allowlist is not None:
        print("\n[global allowlist]")
        for k, v in sorted(top_allowlist.items()):
            print(f"  {k}: {len(v) if isinstance(v, list) else v}")

    # --- rules -------------------------------------------------------------
    print(f"\nrules: {len(rules)}")
    field_counts: Counter[str] = Counter()
    missing: dict[str, int] = Counter()
    for r in rules:
        field_counts.update(r.keys())
        for f in ("id", "regex", "keywords"):
            if f not in r:
                missing[f] += 1
        if "keywords" in r and len(r["keywords"]) == 0:
            missing["empty_keywords"] += 1

    print("rule fields used:")
    for f in sorted(RULE_FIELDS | set(field_counts)):
        print(f"  {f}: {field_counts.get(f, 0)}")
    print("rules missing/odd:")
    for f, n in sorted(missing.items()):
        print(f"  no {f}: {n}")

    # --- per-rule allowlists (incl. nested-rule shape) ----------------------
    rule_allowlists = sum(1 for r in rules if "allowlists" in r)
    print(f"\nrules with [[rules.allowlists]]: {rule_allowlists}")
    aw_field_counts: Counter[str] = Counter()
    aw_count = 0
    nested_shapes: Counter[tuple] = Counter()
    for r in rules:
        for aw in r.get("allowlists", []):
            aw_count += 1
            aw_field_counts.update(aw.keys())
            has = tuple(f in aw for f in
                        ("regexes", "regexTarget", "paths", "stopwords", "condition"))
            nested_shapes[has] += 1
    print(f"total allowlist objects (all rules): {aw_count}")
    print("allowlist fields used:")
    for f in sorted(ALLOWLIST_FIELDS | set(aw_field_counts)):
        print(f"  {f}: {aw_field_counts.get(f, 0)}")
    print("allowlist shapes (regexes, regexTarget, paths, stopwords, condition):")
    for shape, n in nested_shapes.most_common():
        print(f"  {shape}: {n}")

    # --- keywords ------------------------------------------------------------
    kws: list[str] = []
    per_rule = Counter()
    for r in rules:
        ks = r.get("keywords", [])
        per_rule[len(ks)] += 1
        kws.extend(ks)
    print(f"\nkeywords total: {len(kws)}  unique: {len(set(kws))}")

    dup = [k for k, c in Counter(kws).items() if c > 1]
    print(f"keywords used by >1 rule (collisions): {len(dup)}")
    for k, c in Counter(kws).most_common(15):
        print(f"  {k!r}: {c}")
    print("rules by keyword count:", dict(sorted(per_rule.items())))

    # --- spot check ids unique ------------------------------------------------
    ids = [r["id"] for r in rules if "id" in r]
    dup_ids = [i for i, c in Counter(ids).items() if c > 1]
    print(f"\nids: {len(ids)}  unique: {len(set(ids))}  duplicates: {dup_ids or 'none'}")

    print("\nOK — structure looks parseable." if not dup_ids else "\nWARNING: duplicate ids found.")


if __name__ == "__main__":
    main()
