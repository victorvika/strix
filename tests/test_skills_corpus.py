"""Corpus health checks for the packaged skill library.

Skills are prompt material, so a badly formed file does not raise - it silently
degrades an agent's context. These tests make the invariants explicit:

* every skill has YAML frontmatter with a ``name`` and a ``description``
* the ``name`` matches the file it lives in (so ``load_skill`` resolves it)
* no two selectable skills share a bare name (bare lookups would be ambiguous)
* the body starts with a single H1 and is not empty
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from strix.skills import get_all_skill_names, load_skills
from strix.utils.resource_paths import get_strix_resource_path


if TYPE_CHECKING:
    from pathlib import Path


SKILLS_ROOT = get_strix_resource_path("skills")
FRONTMATTER = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
MAX_DESCRIPTION_CHARS = 600
# Internal categories are loaded by the agent graph, never offered to users, so
# they are exempt from the "unique bare name" rule.
INTERNAL_CATEGORIES = frozenset({"scan_modes", "coordination", "analysis"})

NEW_SKILLS = ("bug_bounty_programs", "mobile_api_testing", "authorization_matrix")


def _skill_files() -> list[Path]:
    return sorted(
        path
        for path in SKILLS_ROOT.rglob("*.md")
        if path.name != "README.md" and not path.name.startswith("__")
    )


def _frontmatter(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    match = FRONTMATTER.match(text)
    assert match is not None, f"{path} has no YAML frontmatter"
    parsed = yaml.safe_load(match.group("body"))
    assert isinstance(parsed, dict), f"{path} frontmatter is not a mapping"
    return parsed, text[match.end() :].strip()


def _ids(paths: list[Path]) -> list[str]:
    return [path.relative_to(SKILLS_ROOT).as_posix() for path in paths]


@pytest.mark.parametrize("path", _skill_files(), ids=_ids(_skill_files()))
def test_skill_frontmatter_is_complete(path: Path) -> None:
    metadata, body = _frontmatter(path)

    name = metadata.get("name")
    assert isinstance(name, str) and name.strip(), f"{path} has no usable name"
    description = " ".join(str(metadata.get("description", "")).split())
    assert description, f"{path} has no description"
    assert len(description) <= MAX_DESCRIPTION_CHARS, (
        f"{path} description is {len(description)} chars; keep it under "
        f"{MAX_DESCRIPTION_CHARS} so it stays readable in a prompt"
    )
    assert body, f"{path} has an empty body"
    assert body.startswith("# "), f"{path} body must start with an H1 heading"


@pytest.mark.parametrize("path", _skill_files(), ids=_ids(_skill_files()))
def test_skill_name_matches_filename(path: Path) -> None:
    metadata, _ = _frontmatter(path)
    name = str(metadata["name"])
    assert name in {path.stem, path.stem.replace("_", "-")}, (
        f"{path} declares name '{name}'; expected '{path.stem}' or "
        f"'{path.stem.replace('_', '-')}' so lookups by filename keep working"
    )


def test_selectable_skill_names_are_unique() -> None:
    selectable = [
        path.stem for path in _skill_files() if path.parent.name not in INTERNAL_CATEGORIES
    ]
    duplicates = sorted({name for name in selectable if selectable.count(name) > 1})
    assert not duplicates, f"ambiguous bare skill names: {duplicates}"
    assert get_all_skill_names() == set(selectable)


@pytest.mark.parametrize("skill_name", NEW_SKILLS)
def test_bounty_workflow_skills_load(skill_name: str) -> None:
    loaded = load_skills([skill_name])
    assert skill_name in loaded, f"{skill_name} did not resolve to a skill file"
    body = loaded[skill_name]
    assert body.lstrip().startswith("# ")
    assert "##" in body, "a skill should be structured with sections"


def test_bug_bounty_skill_covers_authorization_and_validation() -> None:
    body = load_skills(["bug_bounty_programs"])["bug_bounty_programs"].lower()
    for required in ("authorization", "scope", "duplicate", "impact", "triage"):
        assert required in body, f"bug bounty skill should discuss {required}"


def test_mobile_skill_is_honest_about_sandbox_tooling() -> None:
    body = load_skills(["mobile_api_testing"])["mobile_api_testing"].lower()
    flat = body.replace("*", "")
    for tool in ("adb", "frida", "jadx"):
        assert tool in flat, f"mobile skill should name {tool} to scope expectations"
    assert "does not ship" in flat, "mobile skill must state the sandbox lacks device tooling"


def test_authorization_matrix_skill_has_matrix_and_validation() -> None:
    body = load_skills(["authorization_matrix"])["authorization_matrix"].lower()
    for required in ("actor", "object", "verb", "baseline", "false positive"):
        assert required in body, f"authorization matrix skill should discuss {required}"
