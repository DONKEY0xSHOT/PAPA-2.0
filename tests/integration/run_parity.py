#!/usr/bin/env python3

# Parity gate comparing PAPA's --json output to capa.exe's for one sample and
# rule corpus. The capability rule-name sets must match exactly: the corpus is
# at zero false positives and zero false negatives, so any divergence fails.
#
# Exit codes:
#   0  PAPA and capa matched the same capability rules
#   1  parity violated (a false positive or false negative)
#   2  usage error, or one of the tools failed to run

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Set, Tuple


def run_tool(exe: Path, sample: Path, rules: Path) -> dict:
    """Invoke an analyzer with --json and return the parsed document."""

    cmd = [str(exe), "--json", "--rules", str(rules), str(sample)]
    proc = subprocess.run(cmd, capture_output=True, timeout=900)

    # capa exits non-zero on some valid reports (a static-limitation rule fired,
    # for instance), so we still parse stdout, which is the document we compare.
    if proc.returncode != 0:
        sys.stderr.write(f"[warn] {exe.name} exit={proc.returncode}\n")
        sys.stderr.write(proc.stderr.decode(errors="replace")[:500] + "\n")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[error] could not parse {exe.name} JSON: {e}\n")
        sys.stderr.write(proc.stdout.decode(errors="replace")[:500] + "\n")
        sys.exit(2)


def rule_name_set(doc: dict) -> Set[str]:
    """Return the matched capability rule names, excluding library rules."""

    # Library rules (meta.lib) are building blocks capa emits in --json but
    # never reports as capabilities, so they stay out of the comparison.
    rules = doc.get("rules", {})
    if not isinstance(rules, dict):
        return set()
    return set(
        name
        for name, r in rules.items()
        if not (isinstance(r, dict) and r.get("meta", {}).get("lib", False))
    )


def compare(papa_doc: dict, capa_doc: dict) -> Tuple[Set[str], Set[str], Set[str]]:
    """Return the (shared, papa_only, capa_only) rule-name sets."""

    p = rule_name_set(papa_doc)
    c = rule_name_set(capa_doc)
    return p & c, p - c, c - p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--papa", required=True, type=Path, help="papa.exe path")
    ap.add_argument("--capa", required=True, type=Path, help="capa.exe path")
    ap.add_argument("--rules", required=True, type=Path, help="rule corpus dir")
    ap.add_argument("--sample", required=True, type=Path, help="binary to analyze")
    args = ap.parse_args()

    for p in (args.papa, args.capa, args.rules, args.sample):
        if not p.exists():
            sys.stderr.write(f"[error] missing path: {p}\n")
            return 2

    papa_doc = run_tool(args.papa, args.sample, args.rules)
    capa_doc = run_tool(args.capa, args.sample, args.rules)

    shared, papa_only, capa_only = compare(papa_doc, capa_doc)

    print(f"sample: {args.sample.name}")
    print(f"  papa:   {len(rule_name_set(papa_doc))} rules")
    print(f"  capa:   {len(rule_name_set(capa_doc))} rules")
    print(f"  shared: {len(shared)}")
    print(f"  papa-only (FP): {len(papa_only)}")
    print(f"  capa-only (FN): {len(capa_only)}")

    if papa_only:
        print("\nFalse positives:")
        for n in sorted(papa_only):
            print(f"  + {n}")

    if capa_only:
        print("\nFalse negatives:")
        for n in sorted(capa_only):
            print(f"  - {n}")

    # Recall and precision over every rule either tool matched.
    if shared or papa_only or capa_only:
        recall = len(shared) / max(1, len(shared) + len(capa_only))
        precision = len(shared) / max(1, len(shared) + len(papa_only))
        print(f"\nrecall:    {recall:.1%}")
        print(f"precision: {precision:.1%}")

    return 1 if (papa_only or capa_only) else 0


if __name__ == "__main__":
    sys.exit(main())
