#!/usr/bin/env python3

#
# Parity diagnostics for the FLIRT/CFG parity push. Two responsibilities:
#
#   capa-cache  Capture capa's --json output once per sample into a durable
#               cache directory, so the (slow) capa runs never need repeating.
#   report      Run papa on a sample, diff the rule-name set against the cached
#               capa reference, and classify every false positive / false
#               negative by cross-referencing capa's and papa's recovered
#               function and library-function sets. This classification is what
#               turns a bare rule name into a root-cause lead:
#                 FN -> is the function FLIRT-suppressed by papa, analyzed by
#                       papa but not matched, or never recovered by papa
#                 FP -> does capa mark that function library, analyze it without
#                       matching, or never recover it
#
# This is a development diagnostic, distinct from run_parity.py which is the
# pass/fail CI gate with the documented allow-list.

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

# Logical key -> fixture filename. The key is used for cache filenames so a
# space in "CFF Explorer.exe" never reaches the shell or a path join surprise.
SAMPLES: Dict[str, str] = {
    "chrome": "chrome.exe",
    "cff_explorer": "CFF Explorer.exe",
    "capa": "capa.exe",
    "everything": "Everything.exe",
    "msedge": "msedge.exe",
    "notepad": "notepad.exe",
    "calc": "calc.exe",
}


class AnalysisFailed(Exception):
    """A tool run timed out or produced unparseable output.

    The command loops catch this and move on to the next sample, so one slow
    or broken binary never aborts the whole batch."""


def resolve_samples(keys: List[str]) -> Dict[str, str]:
    """Map each requested key to a fixture filename, preserving order.

    A key may be passed as ``key=filename`` to register a sample outside the
    built-in set, so the corpus can grow without editing this file."""
    out: Dict[str, str] = {}
    for token in keys:
        key, sep, filename = token.partition("=")
        if sep:
            out[key] = filename
        elif key in SAMPLES:
            out[key] = SAMPLES[key]
        else:
            sys.stderr.write(f"[skip] unknown key: {key}\n")
    return out


def addr_value(obj: object) -> Optional[int]:
    """Pull the integer VA out of any capa/papa address shape.

    Handles {"value": V}, {"address": {"value": V}}, and nested combinations."""
    if isinstance(obj, dict):
        if isinstance(obj.get("value"), int):
            return obj["value"]
        if "address" in obj:
            return addr_value(obj["address"])
    return None


def match_va(entry: object) -> Optional[int]:
    """Top-level VA of a single rule match.

    capa stores [address, node] pairs; papa stores a bare address object."""
    if isinstance(entry, list) and entry:
        return addr_value(entry[0])
    return addr_value(entry)


def rule_names(doc: dict) -> Set[str]:
    rules = doc.get("rules", {})
    return set(rules.keys()) if isinstance(rules, dict) else set()


def match_vas(doc: dict, rule: str) -> List[int]:
    rules = doc.get("rules", {})
    matches = rules.get(rule, {}).get("matches", []) if isinstance(rules, dict) else []
    vas = [match_va(m) for m in matches] if isinstance(matches, list) else []
    return sorted({v for v in vas if v is not None})


def library_vas(doc: dict) -> Set[int]:
    lf = doc.get("meta", {}).get("analysis", {}).get("library_functions", [])
    out: Set[int] = set()
    if isinstance(lf, list):
        for e in lf:
            v = addr_value(e)
            if v is not None:
                out.add(v)
    return out


def analyzed_vas(doc: dict) -> Set[int]:
    """VAs of functions the tool analyzed (non-library), from feature counts.

    capa nests under analysis.feature_counts.functions; papa flattens to
    analysis.feature_counts_functions."""
    an = doc.get("meta", {}).get("analysis", {})
    fns = an.get("feature_counts_functions")
    if fns is None:
        fns = an.get("feature_counts", {}).get("functions", [])
    out: Set[int] = set()
    if isinstance(fns, list):
        for e in fns:
            v = addr_value(e)
            if v is not None:
                out.add(v)
    return out


def classify_fn(capa_vas: List[int], papa_lib: Set[int], papa_funcs: Set[int]) -> Dict[str, List[str]]:
    """Bucket each capa match VA by why papa missed it."""
    buckets: Dict[str, List[str]] = {"flirt_suppressed": [], "analyzed_no_match": [], "not_recovered": []}
    for va in capa_vas:
        if va in papa_lib:
            buckets["flirt_suppressed"].append(hex(va))
        elif va in papa_funcs:
            buckets["analyzed_no_match"].append(hex(va))
        else:
            buckets["not_recovered"].append(hex(va))
    return {k: v for k, v in buckets.items() if v}


def classify_fp(papa_vas: List[int], capa_lib: Set[int], capa_funcs: Set[int]) -> Dict[str, List[str]]:
    """Bucket each papa match VA by why capa did not match it."""
    buckets: Dict[str, List[str]] = {"capa_library": [], "analyzed_no_match": [], "not_recovered": []}
    for va in papa_vas:
        if va in capa_lib:
            buckets["capa_library"].append(hex(va))
        elif va in capa_funcs:
            buckets["analyzed_no_match"].append(hex(va))
        else:
            buckets["not_recovered"].append(hex(va))
    return {k: v for k, v in buckets.items() if v}


def run_json(exe: Path, sample: Path, rules: Path, timeout: int) -> dict:
    cmd = [str(exe), "--json", "--rules", str(rules), str(sample)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.stderr.write(f"[timeout] {exe.name} exceeded {timeout}s on {sample.name}\n")
        raise AnalysisFailed from None
    if proc.returncode != 0:
        sys.stderr.write(f"[warn] {exe.name} exit={proc.returncode} on {sample.name}\n")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[error] {exe.name} JSON parse failed on {sample.name}: {e}\n")
        sys.stderr.write(proc.stdout.decode(errors="replace")[:600] + "\n")
        raise AnalysisFailed from e


def cmd_capa_cache(args: argparse.Namespace) -> int:
    args.cache.mkdir(parents=True, exist_ok=True)
    rc = 0
    for key, fn in resolve_samples(args.keys).items():
        out = args.cache / f"capa_{key}.json"
        if out.exists() and not args.force:
            try:
                doc = json.loads(out.read_bytes())
                if rule_names(doc):
                    print(f"[cached] {key}: {len(rule_names(doc))} rules already in {out.name}")
                    continue
            except json.JSONDecodeError:
                pass  # fall through and recapture a corrupt cache file
        sample = args.fixtures / fn
        if not sample.exists():
            sys.stderr.write(f"[error] missing sample: {sample}\n")
            rc = 2
            continue
        t0 = time.time()
        try:
            doc = run_json(args.capa, sample, args.rules, args.timeout)
        except AnalysisFailed:
            rc = 2
            continue
        out.write_bytes(json.dumps(doc).encode())
        print(f"[ok] {key}: {len(rule_names(doc))} rules, {time.time() - t0:.0f}s -> {out.name}")
    return rc


def report_one(key: str, papa_doc: dict, capa_doc: dict) -> dict:
    p, c = rule_names(papa_doc), rule_names(capa_doc)
    fps, fns = sorted(p - c), sorted(c - p)
    papa_lib, papa_funcs = library_vas(papa_doc), analyzed_vas(papa_doc)
    capa_lib, capa_funcs = library_vas(capa_doc), analyzed_vas(capa_doc)
    inv = {
        "key": key,
        "papa_rules": len(p),
        "capa_rules": len(c),
        "shared": len(p & c),
        "recall": round(100.0 * len(p & c) / len(c), 1) if c else 100.0,
        "precision": round(100.0 * len(p & c) / len(p), 1) if p else 100.0,
        "false_positives": {n: classify_fp(match_vas(papa_doc, n), capa_lib, capa_funcs) for n in fps},
        "false_negatives": {n: classify_fn(match_vas(capa_doc, n), papa_lib, papa_funcs) for n in fns},
    }
    return inv


def print_report(inv: dict) -> None:
    print(f"=== {inv['key']} ===")
    print(f"  papa={inv['papa_rules']} capa={inv['capa_rules']} shared={inv['shared']} "
          f"recall={inv['recall']}% precision={inv['precision']}%")
    print(f"  false positives (papa-only): {len(inv['false_positives'])}")
    for n, buckets in inv["false_positives"].items():
        print(f"    - {n}: {buckets}")
    print(f"  false negatives (capa-only): {len(inv['false_negatives'])}")
    for n, buckets in inv["false_negatives"].items():
        print(f"    - {n}: {buckets}")


def cmd_report(args: argparse.Namespace) -> int:
    args.cache.mkdir(parents=True, exist_ok=True)
    rc = 0
    for key, fn in resolve_samples(args.keys).items():
        capa_path = args.cache / f"capa_{key}.json"
        if not capa_path.exists():
            sys.stderr.write(f"[error] no cached capa reference for {key} ({capa_path}); run capa-cache first\n")
            rc = 2
            continue
        sample = args.fixtures / fn
        if not sample.exists():
            sys.stderr.write(f"[error] missing sample: {sample}\n")
            rc = 2
            continue
        capa_doc = json.loads(capa_path.read_bytes())
        t0 = time.time()
        try:
            papa_doc = run_json(args.papa, sample, args.rules, args.timeout)
        except AnalysisFailed:
            rc = 2
            continue
        (args.cache / f"papa_{key}.json").write_bytes(json.dumps(papa_doc).encode())
        inv = report_one(key, papa_doc, capa_doc)
        inv["papa_seconds"] = round(time.time() - t0, 1)
        (args.cache / f"inventory_{key}.json").write_text(json.dumps(inv, indent=2))
        print_report(inv)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="PAPA parity diagnostics")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capa-cache", help="capture capa --json references")
    c.add_argument("--capa", required=True, type=Path)
    c.add_argument("--rules", required=True, type=Path)
    c.add_argument("--fixtures", required=True, type=Path)
    c.add_argument("--cache", required=True, type=Path)
    c.add_argument("--keys", nargs="+", default=list(SAMPLES))
    c.add_argument("--timeout", type=int, default=3600)
    c.add_argument("--force", action="store_true")
    c.set_defaults(func=cmd_capa_cache)

    r = sub.add_parser("report", help="run papa and classify FP/FN vs cached capa")
    r.add_argument("--papa", required=True, type=Path)
    r.add_argument("--rules", required=True, type=Path)
    r.add_argument("--fixtures", required=True, type=Path)
    r.add_argument("--cache", required=True, type=Path)
    r.add_argument("--keys", nargs="+", default=list(SAMPLES))
    r.add_argument("--timeout", type=int, default=1800)
    r.set_defaults(func=cmd_report)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
