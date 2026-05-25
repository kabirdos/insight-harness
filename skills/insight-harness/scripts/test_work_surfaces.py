"""Tests for the Work Surfaces signal in extract.py.

Two parts:
  1. Per-session Claude Code entrypoint breakdown (each session's dominant
     entrypoint, aggregated across sessions).
  2. Coarse other-agent-tool presence detection — directory existence and
     last-modified mtime ONLY, never reading directory contents.

Both are hermetic: the tool-presence test points detection at a temp HOME, and
the entrypoint test exercises the pure aggregation helpers directly.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402


class DominantEntrypointTest(unittest.TestCase):
    def test_single_value(self):
        self.assertEqual(extract.dominant_entrypoint({"cli": 400}), "cli")

    def test_picks_mode_not_minority(self):
        # A session that is overwhelmingly cli with a stray sdk-cli line is a
        # cli session, not an sdk-cli session.
        self.assertEqual(
            extract.dominant_entrypoint({"cli": 380, "sdk-cli": 1}), "cli"
        )

    def test_empty_returns_none(self):
        self.assertIsNone(extract.dominant_entrypoint({}))

    def test_tie_is_deterministic(self):
        # Ties resolve alphabetically so output is stable across runs.
        self.assertEqual(
            extract.dominant_entrypoint({"cli": 5, "sdk-cli": 5}), "cli"
        )


class AgentToolPresenceTest(unittest.TestCase):
    def test_detects_present_dirs_with_last_active(self):
        with TemporaryDirectory() as d:
            home = Path(d)
            # Codex CLI present
            (home / ".codex").mkdir()
            # Cursor present
            (home / ".cursor").mkdir()
            # Claude desktop present (Application Support/Claude/claude-code)
            (home / "Library" / "Application Support" / "Claude" / "claude-code").mkdir(
                parents=True
            )
            # Codex desktop NOT present (Application Support/Codex)

            result = extract.detect_agent_tools(home=home)

        by_tool = {t["tool"]: t for t in result}
        # Every known tool is reported (present or not) so the list is stable.
        self.assertIn("Codex CLI", by_tool)
        self.assertIn("Codex desktop", by_tool)
        self.assertIn("Cursor", by_tool)
        self.assertIn("Claude desktop", by_tool)

        self.assertTrue(by_tool["Codex CLI"]["present"])
        self.assertTrue(by_tool["Cursor"]["present"])
        self.assertTrue(by_tool["Claude desktop"]["present"])
        self.assertFalse(by_tool["Codex desktop"]["present"])

        # Present tools carry an ISO lastActive; absent tools carry null.
        for entry in result:
            if entry["present"]:
                self.assertIsInstance(entry["lastActive"], str)
                # Parses as a valid ISO timestamp.
                datetime.fromisoformat(entry["lastActive"])
            else:
                self.assertIsNone(entry["lastActive"])

    def test_absent_when_no_dirs(self):
        with TemporaryDirectory() as d:
            result = extract.detect_agent_tools(home=Path(d))
        self.assertTrue(result)  # known tools still enumerated
        self.assertTrue(all(t["present"] is False for t in result))
        self.assertTrue(all(t["lastActive"] is None for t in result))

    def test_does_not_read_directory_contents(self):
        # Privacy posture: presence is existence/mtime only. We assert the
        # helper never opens files inside the detected dirs by planting a file
        # whose read would raise, then confirming detection still succeeds.
        with TemporaryDirectory() as d:
            home = Path(d)
            codex = home / ".codex"
            codex.mkdir()
            (codex / "secret.json").write_text('{"token":"sk-secret"}', encoding="utf-8")

            opened = []
            real_open = open

            def tracking_open(file, *args, **kwargs):
                opened.append(str(file))
                return real_open(file, *args, **kwargs)

            import builtins

            builtins.open = tracking_open
            try:
                result = extract.detect_agent_tools(home=home)
            finally:
                builtins.open = real_open

        codex_entry = next(t for t in result if t["tool"] == "Codex CLI")
        self.assertTrue(codex_entry["present"])
        # No file inside the .codex dir was opened.
        self.assertFalse(
            any(str(home / ".codex" / "secret.json") == p for p in opened)
        )


class WorkSurfacesHtmlTest(unittest.TestCase):
    """The generated HTML must carry workSurfaces in the JSON island and render
    a Work Surfaces section."""

    def _minimal_data(self):
        return {
            "session_meta_summary": {},
            "jsonl_metadata": {
                "session_entrypoints": {"cli": 27, "sdk-cli": 2},
                "agent_tools": [
                    {"tool": "Codex CLI", "present": True, "lastActive": "2026-05-20T10:00:00+00:00"},
                    {"tool": "Cursor", "present": False, "lastActive": None},
                ],
            },
            "settings": {},
            "skill_inventory": [],
            "installed_plugins": [],
            "permissions_profile": {},
            "harness_files": {},
            "custom_agents": [],
        }

    def test_json_island_contains_work_surfaces(self):
        html = extract.generate_html(self._minimal_data())
        self.assertIn('"workSurfaces"', html)
        self.assertIn("sdk-cli", html)
        self.assertIn("Codex CLI", html)

    def test_html_renders_work_surfaces_section(self):
        html = extract.generate_html(self._minimal_data())
        self.assertIn("Work Surfaces", html)


if __name__ == "__main__":
    unittest.main()
