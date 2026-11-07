"""Validate the project skill registry (skills/*/SKILL.md).

Rules enforced: one folder per skill, SKILL.md with YAML frontmatter containing
`name` (equal to the folder) and a short `description`, plus the required headings.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

REQUIRED_HEADINGS = ("## Overview", "## Usage", "## Verification")
MAX_DESCRIPTION = 160


@dataclass
class Problem:
    skill: str
    message: str


def parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    fields = {}
    for line in text[3:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def validate(root: Path) -> List[Problem]:
    problems: List[Problem] = []
    if not root.is_dir():
        return [Problem("-", "skills directory missing: %s" % root)]
    for folder in sorted(p for p in root.iterdir()
                        if p.is_dir() and not p.name.startswith("_")):
        skill_md = folder / "SKILL.md"
        if not skill_md.is_file():
            problems.append(Problem(folder.name, "missing SKILL.md"))
            continue
        text = skill_md.read_text(encoding="utf-8")
        fields = parse_frontmatter(text)
        if not fields:
            problems.append(Problem(folder.name, "missing YAML frontmatter"))
            continue
        if fields.get("name") != folder.name:
            problems.append(Problem(folder.name, "frontmatter name != folder name"))
        description = fields.get("description", "")
        if not description:
            problems.append(Problem(folder.name, "missing description"))
        elif len(description) > MAX_DESCRIPTION:
            problems.append(Problem(folder.name, "description longer than %d" % MAX_DESCRIPTION))
        for heading in REQUIRED_HEADINGS:
            if heading not in text:
                problems.append(Problem(folder.name, "missing heading %s" % heading))
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    import sys
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent
    problems = validate(root)
    for problem in problems:
        print("%s: %s" % (problem.skill, problem.message))
    print("skills ok" if not problems else "%d problem(s)" % len(problems))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))