#!/usr/bin/env python3
"""Check the source tree against the project's coding standards.

Run it from the project root with no arguments. Exits non-zero and prints every
violation with its file and line, so CI failures point straight at the fix.

The rules enforced here are the ones a compiler cannot catch. Everything else
(warnings as errors, the language subset) is enforced by the build itself.
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys
from pathlib import Path

SOURCE_DIRS = ("src", "include", "tools", "tests")
SOURCE_SUFFIXES = (".cpp", ".h")

# Build and CI files, whose comments are checked the same way the sources are
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

# A run of rule characters, which only a section divider needs
DIVIDER_PATTERN = re.compile(r"[-=*#~_]{3,}")

# Pointers to planning notes or to any Markdown file, which a comment should not lean on
# The M-number labels match in upper case only, so an operand such as r/m8 passes
REFERENCE_PATTERN = re.compile(
    r"(?i:\b(?:phase|milestone|task)s?\b|\bplan section|\bdesign doc|\b[\w.-]+\.md\b"
    r"|\bsection \d+(?:\.\d+)*)"
    r"|\bM\d\b"
)

# A sentence break straight after an article or preposition, left by joining two lines
JOIN_PATTERN = re.compile(r"\b(?:the|a|an|of|to|nor|without|by|for)\. [A-Z]")


def tracked_files(root: Path) -> set[Path] | None:
    """The paths git tracks under root, or None when git is unavailable or lists none."""
    try:
        listing = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return {root / name for name in os.fsdecode(listing).split("\0") if name} or None


def only_tracked(paths: list[Path], tracked: set[Path] | None) -> list[Path]:
    """Drop the paths git does not track, or keep them all outside a checkout."""
    if tracked is None:
        return paths
    return [p for p in paths if p in tracked]


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


def comment_text_problems(where: str, text: str) -> list[str]:
    """Flag a divider, a pointer outside the tree, or a sentence broken mid-phrase."""
    problems: list[str] = []
    if DIVIDER_PATTERN.search(text):
        problems.append(f"{where}: section divider in a comment, use one short comment")
    reference = REFERENCE_PATTERN.search(text)
    if reference:
        problems.append(
            f"{where}: comment points at '{reference.group(0)}' instead of stating "
            f"the point itself"
        )
    join = JOIN_PATTERN.search(text)
    if join:
        problems.append(
            f"{where}: '{join.group(0)}' in a comment looks like two lines joined "
            f"mid-sentence"
        )
    return problems


def hash_comment_problems(path: Path, root: Path, lines: list[str]) -> list[str]:
    """Apply the comment text rules to every hash comment line of a build file."""
    problems: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") and not stripped.startswith("#!"):
            where = f"{path.relative_to(root)}:{index + 1}"
            problems.extend(comment_text_problems(where, stripped[1:]))
    return problems


def check_file(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = io.open(path, encoding="utf-8").read()
    except UnicodeDecodeError:
        return [f"{path.relative_to(root)}: not valid UTF-8"]

    lines = text.splitlines()

    # A comment run is at most two lines. Anything longer is rationale or
    # history, which belongs somewhere other than beside the code
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

        marker = "///" if stripped.startswith("///") else "//"
        problems.extend(comment_text_problems(where, stripped[len(marker):]))

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
    # Untracked files never reach the tree, so they are not checked
    tracked = tracked_files(root)
    files = only_tracked(source_files(root), tracked)
    if not files:
        print(f"no source files found under {root}", file=sys.stderr)
        return 2

    problems: list[str] = []
    for path in files:
        problems.extend(check_file(path, root))

    # The build and CI files get the comment length and text rules too, since a wall
    # of commentary is as hard to read in a workflow as it is beside the code
    build = only_tracked(build_files(root), tracked)
    for path in build:
        try:
            lines = io.open(path, encoding="utf-8").read().splitlines()
        except UnicodeDecodeError:
            problems.append(f"{path.relative_to(root)}: not valid UTF-8")
            continue
        problems.extend(comment_run_problems(path, root, lines, "#"))
        problems.extend(hash_comment_problems(path, root, lines))

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
