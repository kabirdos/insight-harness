"""Tests for the body-derived fallback description in extract.py.

Skills with a blank frontmatter `description` should fall back to the first
prose line of their (scrubbed) body, rather than shipping an empty description.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402


class DeriveDescriptionTest(unittest.TestCase):
    def test_plain_prose_after_title(self):
        md = "# Document Review\n\nReview requirements or plan documents via personas."
        self.assertEqual(
            extract.derive_description_from_body(md),
            "Review requirements or plan documents via personas.",
        )

    def test_blockquote_tagline(self):
        md = "# ux-mockup\n\n> Generate self-contained HTML mockups with feedback."
        self.assertEqual(
            extract.derive_description_from_body(md),
            "Generate self-contained HTML mockups with feedback.",
        )

    def test_skips_overview_heading(self):
        md = "# Writing Plans\n\n## Overview\n\nWrite comprehensive implementation plans."
        self.assertEqual(
            extract.derive_description_from_body(md),
            "Write comprehensive implementation plans.",
        )

    def test_skips_code_fence(self):
        md = "# T\n\n```\ncode block line\n```\n\nActual prose here."
        self.assertEqual(extract.derive_description_from_body(md), "Actual prose here.")

    def test_strips_bullet_and_emphasis(self):
        md = "# T\n\n- **Does** a `thing` well."
        self.assertEqual(extract.derive_description_from_body(md), "Does a thing well.")

    def test_empty_and_title_only(self):
        self.assertEqual(extract.derive_description_from_body(""), "")
        self.assertEqual(extract.derive_description_from_body("# Only A Title\n"), "")

    def test_truncates_to_120_chars(self):
        md = "# T\n\n" + ("x" * 200)
        self.assertEqual(len(extract.derive_description_from_body(md)), 120)


class FallbackWiringTest(unittest.TestCase):
    def test_blank_frontmatter_description_filled_from_body(self):
        with TemporaryDirectory() as d:
            skills_dir = Path(d) / "skills"
            sk = skills_dir / "myskill"
            sk.mkdir(parents=True)
            (sk / "SKILL.md").write_text(
                "---\nname: myskill\n---\n\nDoes a specific useful thing for testing.\n",
                encoding="utf-8",
            )
            empty = Path(d) / "empty"
            empty.mkdir()
            with patch.object(extract, "SKILLS_DIR", skills_dir), \
                 patch.object(extract, "PLUGINS_DIR", empty), \
                 patch.object(extract, "COMMANDS_DIR", empty):
                inv = extract.extract_skill_inventory(include_showcase=True)
            entry = next(s for s in inv if s["name"] == "myskill")
            self.assertEqual(entry["description"], "Does a specific useful thing for testing.")

    def test_existing_frontmatter_description_not_overwritten(self):
        with TemporaryDirectory() as d:
            skills_dir = Path(d) / "skills"
            sk = skills_dir / "myskill"
            sk.mkdir(parents=True)
            (sk / "SKILL.md").write_text(
                "---\nname: myskill\ndescription: Authored description.\n---\n\nBody prose line.\n",
                encoding="utf-8",
            )
            empty = Path(d) / "empty"
            empty.mkdir()
            with patch.object(extract, "SKILLS_DIR", skills_dir), \
                 patch.object(extract, "PLUGINS_DIR", empty), \
                 patch.object(extract, "COMMANDS_DIR", empty):
                inv = extract.extract_skill_inventory(include_showcase=True)
            entry = next(s for s in inv if s["name"] == "myskill")
            self.assertEqual(entry["description"], "Authored description.")


if __name__ == "__main__":
    unittest.main()
