"""Unit tests for skill-inventory metadata merging in extract.py.

Covers the bare-name vs namespaced-invocation join bug: plugin skills are
parsed with name=<bare> and source="plugin:<marketplace>/<plugin>", but are
invoked at runtime as "<plugin>:<skill>". The merge must resolve the namespaced
invocation key back to the parsed metadata so descriptions and install pointers
survive into skillInventory.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402


class BuildSkillMetaTest(unittest.TestCase):
    def test_bare_name_lookup_preserved(self):
        skills = [{"name": "ux-mockup", "source": "user", "description": "Create mockups"}]
        meta = extract.build_skill_meta(skills)
        self.assertEqual(meta["ux-mockup"]["description"], "Create mockups")

    def test_plugin_skill_resolvable_by_namespaced_key(self):
        skills = [
            {
                "name": "ce-brainstorm",
                "source": "plugin:every-marketplace/compound-engineering",
                "description": "Explore requirements and approaches",
            }
        ]
        meta = extract.build_skill_meta(skills)
        # Runtime invocation key is "<plugin>:<skill>", not the bare name.
        self.assertIn("compound-engineering:ce-brainstorm", meta)
        entry = meta["compound-engineering:ce-brainstorm"]
        self.assertEqual(entry["description"], "Explore requirements and approaches")
        # The install pointer (full plugin source) is preserved on the entry.
        self.assertEqual(entry["source"], "plugin:every-marketplace/compound-engineering")

    def test_plugin_skill_resolvable_by_dir_name_when_frontmatter_name_differs(self):
        # compound-engineering's ce-brainstorm: dir "ce-brainstorm", name "ce:brainstorm",
        # invoked as "compound-engineering:ce-brainstorm".
        skills = [
            {
                "name": "ce:brainstorm",
                "_invocation_name": "ce-brainstorm",
                "source": "plugin:every-marketplace/compound-engineering",
                "description": "Explore requirements",
            }
        ]
        meta = extract.build_skill_meta(skills)
        self.assertIn("compound-engineering:ce-brainstorm", meta)
        self.assertEqual(meta["compound-engineering:ce-brainstorm"]["description"], "Explore requirements")

    def test_distinct_plugins_same_skill_name_do_not_collide(self):
        skills = [
            {"name": "review", "source": "plugin:m1/alpha", "description": "alpha review"},
            {"name": "review", "source": "plugin:m2/beta", "description": "beta review"},
        ]
        meta = extract.build_skill_meta(skills)
        self.assertEqual(meta["alpha:review"]["description"], "alpha review")
        self.assertEqual(meta["beta:review"]["description"], "beta review")

    def test_user_skill_not_given_namespaced_key(self):
        skills = [{"name": "screenshot", "source": "user", "description": "shots"}]
        meta = extract.build_skill_meta(skills)
        self.assertEqual(list(meta.keys()), ["screenshot"])


if __name__ == "__main__":
    unittest.main()
