#!/usr/bin/env python3
"""Validate centos skill metadata and local reference links."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = ROOT.parent.parent
LINK_RE = re.compile(r"`((?:\.\./|references/|templates/|scripts/)[^`]+)`")


def fail(message):
    print("ERROR: %s" % message)
    return 1


def has_frontmatter(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return (
        len(lines) >= 4
        and lines[0] == "---"
        and any(line.startswith("name: ") for line in lines[1:4])
        and any(line.startswith("description: ") for line in lines[1:5])
        and "---" in lines[1:8]
    )


def resolve_link(base_file, link):
    local_target = (base_file.parent / link).resolve()
    if local_target.exists():
        return local_target
    project_target = (PROJECT_ROOT / link).resolve()
    if project_target.exists():
        return project_target
    return local_target


def main():
    errors = 0
    skill_dirs = sorted(path for path in ROOT.iterdir() if path.is_dir())
    if not skill_dirs:
        return fail("no skill directories found under %s" % ROOT)

    for skill_dir in skill_dirs:
        skill_file = skill_dir / "SKILL.md"
        agent_file = skill_dir / "agents" / "openai.yaml"
        if not skill_file.exists():
            errors += fail("missing SKILL.md: %s" % skill_dir)
            continue
        if skill_file.stat().st_size == 0:
            errors += fail("empty SKILL.md: %s" % skill_file)
        if not has_frontmatter(skill_file):
            errors += fail("invalid frontmatter: %s" % skill_file)
        if not agent_file.exists():
            errors += fail("missing agents/openai.yaml: %s" % skill_dir)

    for path in sorted(ROOT.rglob("*")):
        if path.is_file() and path.stat().st_size == 0:
            errors += fail("empty file: %s" % path)
        if path.suffix not in (".md", ".yaml", ".yml"):
            continue
        text = path.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = resolve_link(path, match.group(1))
            if not target.exists():
                errors += fail("broken link in %s: %s" % (path, match.group(1)))

    if errors:
        print("Skill validation failed with %s error(s)." % errors)
        return 1
    print("Skill validation passed for %s skill(s)." % len(skill_dirs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
