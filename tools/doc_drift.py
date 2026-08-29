#!/usr/bin/env python3
"""
Documentation Drift Sentinel.

Checks what a repository SAYS about itself against what the repository
actually CONTAINS. It exists because the most durable documentation bugs
are not typos, they are claims that were true once and were never
revisited: a file tree that lists a file since renamed, a link to a
document since moved, a GitHub repository description still advertising a
plan length the application no longer has.

Three checks, in decreasing order of certainty:

  A. Tree claims.   Fenced code blocks in the README that draw a file
                    tree are parsed, and every filename in them must
                    exist on disk. Fully deterministic. Errors.

  B. Link claims.   Relative Markdown links and image sources must
                    resolve to a file on disk. Fully deterministic.
                    Errors.

  C. Number claims. Noun-anchored numbers in the GitHub repository
                    description ("21-day plan", "14 question
                    deconstructions") are compared against the same noun
                    in the README. Heuristic. Warnings, never errors.

Check C is deliberately weaker than A and B, and says so in its output.
A README legitimately contains historical numbers: a migration note
reading "42-day to 21-day" mentions both, and no parser can be certain
which one the project currently claims. So C reports the disagreement and
the evidence, and leaves the judgment to a person. Promoting C to an
error would train its reader to ignore it, which is worse than not
running it.

External network access is not required. The repository description is
passed in with --description; the workflow supplies it.

Standard library only. No pip install, no package.json, no lockfile.

Exit codes:
    0  no errors (warnings and notices may still be printed)
    1  at least one error
    2  could not run at all, for example no README was found
"""

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

# Nouns worth comparing between a description and a README. Each maps to
# the canonical singular used in output. Deliberately a closed list: an
# open-ended "any number near any word" rule produces noise, and noise is
# how a check gets ignored.
NOUNS = {
    "day": "day", "days": "day",
    "question": "question", "questions": "question",
    "card": "card", "cards": "card",
    "section": "section", "sections": "section",
    "domain": "domain", "domains": "domain",
    "objective": "objective", "objectives": "objective",
    "acl": "ACL", "acls": "ACL",
    "record": "record", "records": "record",
    "pair": "pair", "pairs": "pair",
    "role": "role", "roles": "role",
    "table": "table", "tables": "table",
}

NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12,
}

# "21-day", "21 day", "14 question", "seven ACLs", "Eleven sections"
CLAIM_RE = re.compile(
    r"\b(\d{1,4}|" + "|".join(NUMBER_WORDS) + r")[\s\-]+([A-Za-z]+)\b",
    re.IGNORECASE,
)

# Markdown links and images with a relative target.
LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")

# A line inside a fenced block that looks like a tree entry.
TREE_LINE_RE = re.compile(r"^[\s|`]*(?:[├└│]+[─-]*\s*)+(.+?)\s*$")

FENCE_RE = re.compile(r"^\s*```")


def annotate(level, path, message):
    """Emit a GitHub Actions annotation, and a readable line elsewhere."""
    print(f"::{level} file={path}::{message}")


def read(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None if exc else None


def fenced_blocks(text):
    """Yield the body of each fenced code block."""
    lines = text.splitlines()
    inside = False
    buf = []
    for line in lines:
        if FENCE_RE.match(line):
            if inside:
                yield "\n".join(buf)
                buf = []
            inside = not inside
            continue
        if inside:
            buf.append(line)
    # An unterminated fence is not a drift problem; drop it silently.


def tree_entries(block):
    """Filenames drawn in a file-tree code block.

    Only lines using box-drawing characters count. A block of shell
    commands has none, so it is skipped without special-casing.
    """
    names = []
    for line in block.splitlines():
        if not any(ch in line for ch in "├└│"):
            continue
        m = TREE_LINE_RE.match(line)
        if not m:
            continue
        entry = m.group(1).strip()
        # Strip trailing prose used as an inline comment in these trees,
        # e.g. "index.html           the entire application".
        entry = re.split(r"\s{2,}", entry)[0].strip()
        entry = entry.rstrip("/")
        if not entry or entry.startswith("#"):
            continue
        # Ignore ellipsis and annotation rows.
        if set(entry) <= set(". "):
            continue
        names.append(entry)
    return names


def check_tree(readme_path, text, root):
    """A. Every file drawn in a README tree must exist."""
    errors = 0
    checked = 0
    claimed = []
    for block in fenced_blocks(text):
        claimed.extend(tree_entries(block))

    for name in claimed:
        checked += 1
        # A tree shows basenames, not paths. Accept a match anywhere in
        # the repository: the claim is "this file exists", not "this file
        # is at this exact depth", which the drawing cannot express
        # unambiguously.
        if (root / name).exists():
            continue
        if any(root.rglob(name)):
            continue
        annotate(
            "error", readme_path,
            f"The file tree in this README lists '{name}', which does not exist "
            f"anywhere in the repository. Either the file was renamed or removed "
            f"and the tree was not updated, or the tree is aspirational."
        )
        errors += 1
    return checked, errors


def check_links(label, readme_abs, text):
    """B. Every relative Markdown link must resolve.

    `label` is the repository-relative path used in annotations;
    `readme_abs` is the absolute path whose parent directory relative
    links are resolved against. Keeping these separate matters: resolving
    against the process working directory instead of the README's own
    directory silently reports every valid link as broken.
    """
    errors = 0
    checked = 0
    for target in LINK_RE.findall(text):
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue  # absolute URL, mailto, etc.
        if target.startswith("#"):
            continue  # in-page anchor
        clean = target.split("#", 1)[0].split("?", 1)[0]
        if not clean:
            continue
        checked += 1
        candidate = (readme_abs.parent / clean)
        if candidate.exists():
            continue
        annotate(
            "error", label,
            f"Relative link '{target}' does not resolve to a file in this "
            f"repository. A broken link in a README is a claim the repository "
            f"cannot honour."
        )
        errors += 1
    return checked, errors


def claims(text):
    """noun -> Counter of values asserted for it."""
    found = {}
    for raw_value, raw_noun in CLAIM_RE.findall(text):
        noun = NOUNS.get(raw_noun.lower())
        if noun is None:
            continue
        key = raw_value.lower()
        value = NUMBER_WORDS.get(key)
        if value is None:
            try:
                value = int(raw_value)
            except ValueError:
                continue
        found.setdefault(noun, Counter())[value] += 1
    return found


def check_numbers(readme_path, text, description):
    """C. Description numbers should agree with the README. Warnings only."""
    if not description:
        annotate(
            "notice", readme_path,
            "No repository description was supplied, so the description-versus-README "
            "number comparison was skipped. An empty description is not itself a "
            "defect, but it is a missed opportunity on a public repository."
        )
        return 0, 0

    desc_claims = claims(description)
    readme_claims = claims(text)
    warnings = 0
    compared = 0

    for noun, counter in sorted(desc_claims.items()):
        if noun not in readme_claims:
            continue  # nothing to compare against; silence beats a guess
        compared += 1
        readme_values = readme_claims[noun]
        # The dominant README value: most frequently asserted, ties broken
        # toward the larger number so the check errs on the side of
        # speaking up rather than staying quiet.
        dominant = sorted(readme_values.items(), key=lambda kv: (-kv[1], -kv[0]))[0][0]
        for value in counter:
            if value == dominant:
                continue
            if value in readme_values:
                annotate(
                    "warning", readme_path,
                    f"The repository description says {value} {noun}(s), but the README's "
                    f"dominant figure is {dominant} {noun}(s) "
                    f"(README mentions: {dict(sorted(readme_values.items()))}). "
                    f"{value} does appear in the README, so this may be a historical "
                    f"reference rather than drift. Confirm which figure is current."
                )
            else:
                annotate(
                    "warning", readme_path,
                    f"The repository description says {value} {noun}(s). The README never "
                    f"states that figure; it says {dominant} {noun}(s) "
                    f"(README mentions: {dict(sorted(readme_values.items()))}). "
                    f"This is the stronger drift signal of the two."
                )
            warnings += 1

    return compared, warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check a repository's claims against its contents.")
    parser.add_argument("--root", default=".", help="Repository root (default: current directory)")
    parser.add_argument("--description", default="", help="The GitHub repository description")
    parser.add_argument("--readme", action="append", default=[],
                        help="README path, relative to root. Repeatable. "
                             "Defaults to every README.md found, excluding common vendor directories.")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()

    if args.readme:
        readmes = [root / r for r in args.readme]
        missing = [p for p in readmes if not p.is_file()]
        if missing:
            for p in missing:
                annotate("error", p, "Explicitly requested README not found.")
            return 2
    else:
        skip = {".git", "node_modules", "vendor", "dist", "build", ".venv"}
        readmes = sorted(
            p for p in root.rglob("README.md")
            if not skip & set(p.relative_to(root).parts)
        )

    if not readmes:
        print("::error::No README.md found. Nothing could be checked, which is "
              "treated as a failure rather than a pass.")
        return 2

    total_errors = 0
    total_warnings = 0

    for readme in readmes:
        rel = readme.relative_to(root)
        text = read(readme)
        if text is None:
            annotate("error", rel, "README could not be read.")
            total_errors += 1
            continue

        tree_checked, tree_errors = check_tree(rel, text, root)
        link_checked, link_errors = check_links(rel, readme, text)
        # The description belongs to the repository, so compare it only
        # against the top-level README. A README in docs/ is not what the
        # description is summarising.
        is_top = readme.parent == root
        num_checked, num_warnings = check_numbers(rel, text, args.description) if is_top else (0, 0)

        total_errors += tree_errors + link_errors
        total_warnings += num_warnings

        print(f"{rel}: {tree_checked} tree entr(ies), {link_checked} relative link(s), "
              f"{num_checked} description figure(s) compared")

    print(f"\nChecked {len(readmes)} README(s): {total_errors} error, {total_warnings} warning.")

    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
