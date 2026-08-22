#!/usr/bin/env python3
"""Check the source tree against the project's coding standards.

Run it from the project root with no arguments. Exits non-zero and prints every
violation with its file and line, so CI failures point straight at the fix.

The rules enforced here are the ones a compiler cannot catch. Everything else
(warnings as errors, the language subset) is enforced by the build itself.
"""
from __future__ import annotations

import io
import re
import sys
from pathlib import Path

SOURCE_DIRS = ("src", "include", "tools", "tests")
SOURCE_SUFFIXES = (".cpp", ".h")

# Build and CI files, checked for comment length the same way the sources are
BUILD_PATTERNS = ("*.yml", "*.yaml", "*.cmake", "CMakeLists.txt", "*.py",
                  ".clang-tidy", ".clang-format")

# Abbreviations that legitimately end a sentence with a period
ABBREVIATIONS = ("e.g.", "i.e.", "etc.", "vs.", "cf.", "..")

# Longest run of consecutive comment lines allowed anywhere in the tree
MAX_COMMENT_LINES = 2

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


def build_files(root: Path) -> list[Path]:
    """The build and CI files, which carry hash comments rather than slashes."""
    out: list[Path] = []
    for pattern in BUILD_PATTERNS:
        out.extend(root.rglob(pattern))
    return sorted(
        p for p in out
        if "third_party" not in p.parts
        and ".git" not in p.parts
        and not any(part.startswith("build") for part in p.parts)
    )


def comment_run_problems(path: Path, root: Path, lines: list[str],
                         marker: str) -> list[str]:
    """Flag any run of consecutive comment lines longer than the limit."""
    problems: list[str] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].lstrip()
        if stripped.startswith(marker) and not stripped.startswith("#!"):
            end = index
            while end < len(lines) and lines[end].lstrip().startswith(marker):
                end += 1
            if end - index > MAX_COMMENT_LINES:
                problems.append(
                    f"{path.relative_to(root)}:{index + 1}: comment run is "
                    f"{end - index} lines, the limit is {MAX_COMMENT_LINES}"
                )
            index = end
        else:
            index += 1
    return problems


def check_file(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = io.open(path, encoding="utf-8").read()
    except UnicodeDecodeError:
        return [f"{path.relative_to(root)}: not valid UTF-8"]

    lines = text.splitlines()

    # A comment run is at most two lines. Anything longer is rationale or
    # history, which belongs in the docs rather than beside the code
    problems.extend(comment_run_problems(path, root, lines, "//"))

    for index, line in enumerate(lines):
        where = f"{path.relative_to(root)}:{index + 1}"
        stripped = line.strip()

        # Non-ASCII anywhere in a source file, which catches emojis, dashes and stray
        # glyphs, and keeps the tree readable under any locale
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

        # A backslash ending a // comment splices the next line into it, so whatever
        # follows silently disappears. MSVC does not warn, so it is checked here
        if stripped.endswith("\\"):
            problems.append(
                f"{where}: comment ends with a backslash, which swallows the next line"
            )

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

    # The build and CI files get the comment-length rule too, since a wall of
    # commentary is as hard to read in a workflow as it is beside the code
    build = build_files(root)
    for path in build:
        try:
            lines = io.open(path, encoding="utf-8").read().splitlines()
        except UnicodeDecodeError:
            problems.append(f"{path.relative_to(root)}: not valid UTF-8")
            continue
        problems.extend(comment_run_problems(path, root, lines, "#"))

    checked = len(files) + len(build)
    if problems:
        for problem in problems:
            print(problem)
        print(f"\n{len(problems)} coding-standard violation(s) in {checked} files")
        return 1

    print(f"coding standards OK ({checked} files checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
