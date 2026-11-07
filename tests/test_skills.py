"""Skills registry rules (skills/README.md) are enforced by validate_skills.py."""
import pathlib
import sys
import unittest

SKILLS = pathlib.Path("skills")
sys.path.insert(0, str(SKILLS))

from validate_skills import validate  # noqa: E402


class SkillRegistryTests(unittest.TestCase):
    def test_registry_is_valid(self):
        problems = validate(SKILLS)
        self.assertEqual(problems, [], [f"{p.skill}: {p.message}" for p in problems])

    def test_template_exists(self):
        self.assertTrue((SKILLS / "_TEMPLATE_SKILL.md").is_file())

    def test_index_lists_every_skill(self):
        index = (SKILLS / "README.md").read_text(encoding="utf-8")
        folders = sorted(p.name for p in SKILLS.iterdir()
                         if p.is_dir() and not p.name.startswith("_"))
        for folder in folders:
            self.assertIn("`%s`" % folder, index)


if __name__ == "__main__":
    unittest.main()