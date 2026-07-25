#!/usr/bin/env python3
"""Check the source tree against the project's coding standards.
"""
from __future__ import annotations

import io
import re
import sys
from pathlib import Path

SOURCE_DIRS = ("src", "include", "tools", "tests")
SOURCE_SUFFIXES = (".cpp", ".h")

# Abbreviations that legitimately end a sentence with a period
ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "..")

# Paths that would leak a developer's checkout or identity into the tree
PII_PATTERNS = (
    re.compile(r"[A-Za-z]:[\\/]Users[\\/]", re.IGNORECASE),
    re.compile(r"/home/[a-z0-9_.-]+/", re.IGNORECASE),
    re.compile(r"[A-Za-z]:[\\/]Documents and Settings[\\/]", re.IGNORECASE),
)


def source_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for directory in SOURCE_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for suffix in SOURCE_SUFFIXES:
            out.extend(base.rglob(f"*{suffix}"))
    # third_party is vendored and keeps its upstream style
    return sorted(p for p in out if "third_party" not in p.parts)


def check_file(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = io.open(path, encoding="utf-8").read()
    except UnicodeDecodeError:
        return [f"{path.relative_to(root)}: not valid UTF-8"]

    lines = text.splitlines()
    for index, line in enumerate(lines):
        where = f"{path.relative_to(root)}:{index + 1}"
        stripped = line.strip()

        # Non-ASCII anywhere in a source file. This catches emojis, em and en
        # dashes, and stray box-drawing glyphs, all of which are out, and it
        # keeps the tree readable under any locale
        for char in line:
            if ord(char) > 127:
                problems.append(
                    f"{where}: non-ASCII character U+{ord(char):04X} in source"
                )
                break

        for pattern in PII_PATTERNS:
            if pattern.search(line):
                problems.append(f"{where}: absolute or personal path in source")
                break

        if not stripped.startswith("//"):
            continue

        if ";" in stripped:
            problems.append(f"{where}: semicolon in a comment, split it into two lines")

        # A comment must not end with a period. Only the last line of a comment
        # run is the end of that comment
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if following.startswith("//"):
            continue
        if stripped.endswith(".") and not any(
            stripped.endswith(abbr) for abbr in ABBREVIATIONS
        ):
            problems.append(f"{where}: comment ends with a period")

    return problems


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    files = source_files(root)
    if not files:
        print(f"no source files found under {root}", file=sys.stderr)
        return 2

    problems: list[str] = []
    for path in files:
        problems.extend(check_file(path, root))

    if problems:
        for problem in problems:
            print(problem)
        print(f"\n{len(problems)} coding-standard violation(s) in {len(files)} files")
        return 1

    print(f"coding standards OK ({len(files)} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
