"""Offline mirror check of source additions, without printing matched values."""

import argparse
import pathlib
import re
import subprocess
import sys


BASE = "11baf828457848a5b6ec13657c2222456676c861"
LITERAL = re.compile(
    r"https?://[A-Za-z0-9][A-Za-z0-9.-]*"
    r"|(?<![\w-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|dev|systems|tech)\b"
    r"|(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])"
)


def added_lines(diff):
    """Yield the path, destination line number and text of each added line."""
    path = None
    number = None
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path = None
            number = None
        elif line.startswith("@@ "):
            number = int(re.search(r"\+(\d+)", line).group(1))
        elif number is not None:
            if line.startswith("+"):
                yield path, number, line[1:]
                number += 1
            elif line.startswith(" "):
                number += 1
        elif line.startswith("+++ b/"):
            path = line.removeprefix("+++ b/")


def source_additions(root, base):
    diff = subprocess.check_output(
        [
            "git", "-c", "core.quotePath=false", "diff", "--no-ext-diff",
            "--no-textconv", "--no-renames", "--unified=0", base, "--", "src/",
        ],
        cwd=root,
        text=True,
    )
    yield from added_lines(diff)
    # Include files not staged yet, so the check also guards a draft worktree.
    untracked = subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard", "-z", "--", "src/"],
        cwd=root,
        text=True,
    )
    for name in filter(None, untracked.split("\0")):
        for number, line in enumerate((root / name).read_text().splitlines(), 1):
            yield name, number, line


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-with", default=BASE, help="pinned base commit")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", args.compare_with):
        parser.error("--compare-with requires a hexadecimal commit ID")
    root = pathlib.Path(__file__).resolve().parents[1]
    additions = list(source_additions(root, args.compare_with))
    hits = [(path, number) for path, number, line in additions if LITERAL.search(line)]
    for path, number in hits:
        print(f"hostname or account literal added: {path}:{number}")
    print(f"added source lines scanned: {len(additions)}")
    print(f"added hostname or account lines: {len(hits)}")
    print("source addition scan: " + ("FAIL" if hits else "PASS"))
    return bool(hits)


if __name__ == "__main__":
    sys.exit(main())
