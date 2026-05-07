#!/usr/bin/env python3

#
# Parity harness comparing PAPA's JSON output to CAPA's JSON output for the
# same sample and rule corpus. The harness is intentionally written in Python 
# because the heavy lifting is JSON normalization plus set algebra, both of
# which are trivial in the standard library
#
# Exit codes:
#   0  - all rule names papa matched are also matched by capa, and no rule
#        name capa matched is missing from papa beyond an explicit allow-list
#   1  - parity violated (false positives or false negatives outside the list)
#   2  - usage error or one of the tools failed to run

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Set, Tuple


def run_tool(exe: Path, sample: Path, rules: Path) -> dict:
    """Invoke an analyzer with --json and return the parsed dict.

    Both papa.exe and capa.exe accept the same --rules and --json flags."""
    cmd = [str(exe), "--json", "--rules", str(rules), str(sample)]
    proc = subprocess.run(cmd, capture_output=True, timeout=900)
    if proc.returncode != 0:
        # capa.exe sometimes returns non-zero even with valid output (e.g. on
        # samples where a static-only-limitation rule fires). We still try to
        # parse stdout because the JSON document is what we care about
        sys.stderr.write(f"[warn] {exe.name} exit={proc.returncode}\n")
        sys.stderr.write(proc.stderr.decode(errors='replace')[:500] + "\n")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[error] could not parse {exe.name} JSON: {e}\n")
        sys.stderr.write(proc.stdout.decode(errors='replace')[:500] + "\n")
        sys.exit(2)


def rule_name_set(doc: dict) -> Set[str]:
    """Extract the set of matched rule names.

    Both papa and capa store rules under doc['rules'] with rule names as keys."""
    rules = doc.get("rules", {})
    if not isinstance(rules, dict):
        return set()
    return set(rules.keys())


def compare(papa_doc: dict, capa_doc: dict) -> Tuple[Set[str], Set[str], Set[str]]:
    """Return (shared, papa_only, capa_only)."""
    p = rule_name_set(papa_doc)
    c = rule_name_set(capa_doc)
    return p & c, p - c, c - p


# Rule names papa is currently expected to miss against capa-rules-9.4.0
# Each entry is documented with its root cause; the entry should be removed
# the moment papa learns to handle the construct
KNOWN_MISSES = {
    # Rules CAPA matches that PAPA misses, all traced to CFG-fidelity gaps
    # vivisect's heuristics around function boundaries are richer than PAPA's
    # recursive-descent plus .pdata seeding. Closing these requires either
    # FLIRT-style signatures or a richer prologue/epilogue analyzer
    "check for time delay via GetTickCount":             "CFG fidelity",
    "terminate process":                                  "CFG fidelity",
    "compress data via ZLIB inflate or deflate":          "CFG fidelity",
    "compute adler32 checksum":                           "CFG fidelity",
    "enumerate process modules":                          "CFG fidelity",
    "resolve function by parsing PE exports":             "CFG fidelity",
    "create process memory minidump":                     "CFG fidelity",
    "execute shellcode via indirect call":                "CFG fidelity",
    "get file version info":                              "CFG fidelity",
    "patch process command line":                         "CFG fidelity",
    "send HTTP request":                                  "CFG fidelity",
}

# Rules PAPA matches that CAPA does not, traced to PAPA's lack of FLIRT-style
# library function detection. CAPA marks CRT-internal functions as library
# functions and suppresses matches there. PAPA without FLIRT must include them
# Each name has been validated by inspecting the matching function in PAPA's
# output and confirming it sits inside CRT bootstrap code
KNOWN_FALSE_POSITIVES = {
    "encode data using ADD XOR SUB operations": "CRT helper without FLIRT",
    "enumerate PE sections":                    "CRT helper without FLIRT",
    "set thread local storage value":           "CRT TLS init without FLIRT",
    "authenticate HMAC":                        "CRT helper without FLIRT",
    "get process heap force flags":             "CRT helper without FLIRT",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--papa",   required=True, type=Path, help="papa.exe path")
    ap.add_argument("--capa",   required=True, type=Path, help="capa.exe path")
    ap.add_argument("--rules",  required=True, type=Path, help="rule corpus dir")
    ap.add_argument("--sample", required=True, type=Path, help="binary to analyze")
    ap.add_argument("--strict", action="store_true",
                    help="fail on any FN even if it is in the known-misses list")
    args = ap.parse_args()

    for p in (args.papa, args.capa, args.rules, args.sample):
        if not p.exists():
            sys.stderr.write(f"[error] missing path: {p}\n")
            return 2

    papa_doc = run_tool(args.papa, args.sample, args.rules)
    capa_doc = run_tool(args.capa, args.sample, args.rules)

    shared, papa_only, capa_only = compare(papa_doc, capa_doc)

    # Header
    print(f"sample: {args.sample.name}")
    print(f"  papa:   {len(rule_name_set(papa_doc))} rules")
    print(f"  capa:   {len(rule_name_set(capa_doc))} rules")
    print(f"  shared: {len(shared)}")
    print(f"  papa-only (FP): {len(papa_only)}")
    print(f"  capa-only (FN): {len(capa_only)}")

    fail = False
    if papa_only:
        unexplained_fp = sorted(n for n in papa_only if n not in KNOWN_FALSE_POSITIVES)
        explained_fp   = sorted(n for n in papa_only if n in KNOWN_FALSE_POSITIVES)
        if explained_fp and not args.strict:
            print("\nFalse positives (known limitations, ignored):")
            for n in explained_fp:
                print(f"  + {n}  [{KNOWN_FALSE_POSITIVES[n]}]")
        if unexplained_fp:
            print("\nFalse positives (UNEXPECTED):")
            for n in unexplained_fp:
                print(f"  + {n}")
            fail = True
        if explained_fp and args.strict:
            print("\nFalse positives (allow-listed but --strict):")
            for n in explained_fp:
                print(f"  + {n}")
            fail = True

    if capa_only:
        unexplained = sorted(n for n in capa_only if n not in KNOWN_MISSES)
        explained   = sorted(n for n in capa_only if n in KNOWN_MISSES)
        if explained and not args.strict:
            print(f"\nFalse negatives (known limitations, ignored):")
            for n in explained:
                print(f"  - {n}  [{KNOWN_MISSES[n]}]")
        if unexplained:
            print("\nFalse negatives (UNEXPECTED):")
            for n in unexplained:
                print(f"  - {n}")
            fail = True
        if explained and args.strict:
            print("\nFalse negatives (allow-listed but --strict):")
            for n in explained:
                print(f"  - {n}")
            fail = True

    # Recall and precision over the full set of rules either tool found
    if shared or papa_only or capa_only:
        recall    = len(shared) / max(1, len(shared) + len(capa_only))
        precision = len(shared) / max(1, len(shared) + len(papa_only))
        print(f"\nrecall:    {recall:.1%}")
        print(f"precision: {precision:.1%}")

    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
