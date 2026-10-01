"""Print the CHANGELOG.md section for one version, as the GitHub release body.

    python .github/scripts/release_notes.py 0.9.0            # section text on stdout
    python .github/scripts/release_notes.py 0.9.0 --check    # exit 1 if the section is missing/empty

CHANGELOG.md follows Keep a Changelog: each release is a `## [X.Y.Z] - YYYY-MM-DD` heading and
the section runs until the next `## ` heading. Link-reference lines (`[X.Y.Z]: https://...`)
at the bottom of the file are not part of any section. The release workflow fails when the
tag's section is missing, so a release cannot go out with an empty body again.
"""
from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FOOTER = """
---
**Downloads:** `SubnetSleuth-{v}-setup.exe` (desktop app, per-user install), `SubnetSleuth-{v}-portable.zip`
(the same app as a folder), `subnetsleuth-{v}-win-x64.exe` and `subnetsleuth-{v}-linux-x64` (command line,
no Python needed; the Linux binary needs glibc 2.35 or newer). Verify a file against
`SHA256SUMS.txt`. The full list of changes is in
[CHANGELOG.md](https://github.com/kerbe42/subnetsleuth/blob/v{v}/CHANGELOG.md).
"""


def section(text: str, version: str) -> str:
    version = version.lstrip("v")
    heading = re.compile(r"^## \[" + re.escape(version) + r"\](?:\s*-\s*(\S+))?\s*$", re.M)
    m = heading.search(text)
    if not m:
        return ""
    rest = text[m.end():]
    nxt = re.search(r"^## ", rest, re.M)
    body = rest[: nxt.start()] if nxt else rest
    # drop trailing link references if this is the last section
    body = re.sub(r"^\[[^\]]+\]:\s+\S+\s*$", "", body, flags=re.M)
    return body.strip()


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    version = argv[0].lstrip("v")
    check = "--check" in argv
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        text = f.read()
    body = section(text, version)
    if not body:
        print(f"CHANGELOG.md has no '## [{version}]' section (or it is empty); add one before tagging", file=sys.stderr)
        return 1
    if check:
        print(f"CHANGELOG.md: section for {version} found ({len(body.splitlines())} lines)")
        return 0
    sys.stdout.write(body + "\n" + FOOTER.format(v=version))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
