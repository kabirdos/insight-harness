"""Tests for the Codex extractor scaffold (Phase 1, Unit 1).

Covers the Unit-1 output contract and the no-data edge case, plus scaffold
integrity: the module-global Codex roots derive from ``CODEX_DIR`` (so tests can
``patch.object`` a single root) and the reused-helper imports resolved.

Hermetic pattern mirrors ``test_skill_description_fallback.py``:
``sys.path.insert`` + import, then ``patch.object`` on the dir globals against a
``TemporaryDirectory``. No real ``~/.codex`` is ever touched.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import codex_extract  # noqa: E402

FIXTURES = HERE / "tests" / "fixtures"


def _patch_codex_dir(root: Path):
    """Return a context-manager bundle that re-roots every Codex global under
    ``root``. Mirrors how ``CODEX_DIR``-derived constants are defined so a single
    temp dir patch repoints the whole tree (see Unit 1 "Patterns to follow").
    """
    return (
        patch.object(codex_extract, "CODEX_DIR", root),
        patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"),
        patch.object(codex_extract, "CODEX_SKILLS_DIR", root / "skills"),
        patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"),
        patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"),
        patch.object(codex_extract, "CODEX_VERSION_PATH", root / "version.json"),
        patch.object(codex_extract, "CODEX_USAGE_DATA_DIR", root / "usage-data"),
    )


class ScaffoldIntegrityTest(unittest.TestCase):
    def test_codex_roots_derive_from_codex_dir(self):
        cd = codex_extract.CODEX_DIR
        self.assertEqual(cd.name, ".codex")
        self.assertEqual(codex_extract.CODEX_SESSIONS_DIR, cd / "sessions")
        self.assertEqual(codex_extract.CODEX_SKILLS_DIR, cd / "skills")
        self.assertEqual(codex_extract.CODEX_RULES_DIR, cd / "rules")
        self.assertEqual(codex_extract.CODEX_CONFIG_PATH, cd / "config.toml")
        self.assertEqual(codex_extract.CODEX_VERSION_PATH, cd / "version.json")
        self.assertEqual(codex_extract.CODEX_USAGE_DATA_DIR, cd / "usage-data")

    def test_reused_helpers_imported(self):
        # The pure helpers the later units rely on must resolve on the module.
        for name in (
            "SanitizeError", "detect_pii", "scrub",
            "parse_skill_frontmatter", "build_skill_meta",
            "derive_description_from_body", "_read_raw_readme",
            "_finalize_showcase", "_read_hero_image", "_truncate_to_bytes",
            "extract_safe_command_name", "detect_agent_tools",
        ):
            self.assertTrue(
                hasattr(codex_extract, name),
                f"expected reused helper {name!r} importable on codex_extract",
            )


class FixtureValidityTest(unittest.TestCase):
    """The fixtures are consumed by Units 2/4 — keep them parseable + on-shape."""

    def test_fixtures_exist(self):
        for fname in (
            "rollout-payload-format.jsonl",
            "rollout-legacy-format.jsonl",
            "rollout-null-info.jsonl",
            "rollout-secret-bearing.jsonl",
        ):
            self.assertTrue((FIXTURES / fname).is_file(), f"missing fixture {fname}")

    def test_payload_format_is_envelope_shaped(self):
        lines = self._load("rollout-payload-format.jsonl")
        self.assertTrue(all("payload" in o for o in lines))
        # Cumulative token series the Unit-2 happy path asserts on (max != sum).
        totals = [
            o["payload"]["info"]["total_token_usage"]["total_tokens"]
            for o in lines
            if o["payload"].get("type") == "token_count" and o["payload"].get("info")
        ]
        self.assertEqual(totals, [28887, 67874, 107911])

    def test_legacy_format_has_no_payload_envelope(self):
        lines = self._load("rollout-legacy-format.jsonl")
        self.assertTrue(all("payload" not in o for o in lines))
        self.assertTrue(any(o.get("type") == "session_meta" for o in lines))

    def test_null_info_record_present(self):
        lines = self._load("rollout-null-info.jsonl")
        token_recs = [o["payload"] for o in lines if o["payload"].get("type") == "token_count"]
        self.assertTrue(any(r.get("info") is None for r in token_recs))
        self.assertTrue(any(r.get("info") is not None for r in token_recs))

    def test_secret_bearing_command_is_a_list_with_token(self):
        lines = self._load("rollout-secret-bearing.jsonl")
        fcalls = [o["payload"] for o in lines if o["payload"].get("type") == "function_call"]
        self.assertTrue(fcalls)
        args = json.loads(fcalls[0]["arguments"])
        self.assertIsInstance(args["command"], list)
        self.assertEqual(args["command"][:2], ["bash", "-lc"])
        # The token lives inside the inner command string — later units must
        # strip the wrapper and never emit it.
        self.assertIn("Bearer sk-FAKE123", args["command"][2])

    @staticmethod
    def _load(fname):
        text = (FIXTURES / fname).read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]


class OutputContractTest(unittest.TestCase):
    def test_happy_path_writes_html_and_prints_path(self):
        """CLI against a temp CODEX_DIR writes HTML under usage-data/ and prints
        its absolute path as the FINAL stdout line."""
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])

            captured = []
            with patch("builtins.print") as mock_print:
                # Only stdout (no file= kwarg) is part of the contract.
                def _record(*a, **kw):
                    if "file" not in kw or kw["file"] is sys.stdout:
                        captured.append(" ".join(str(x) for x in a))
                mock_print.side_effect = _record
                rc = codex_extract.main([])

            self.assertEqual(rc, 0)
            self.assertTrue(captured, "expected a final stdout line (the report path)")
            final_line = captured[-1]
            report_path = Path(final_line)
            self.assertTrue(report_path.is_absolute(), f"not absolute: {final_line}")
            self.assertTrue(report_path.is_file(), f"file not written: {final_line}")
            self.assertEqual(report_path.parent, (root / "usage-data").resolve())
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("<html", html.lower())
            self.assertIn("Codex Harness Profile", html)

    def test_no_include_skills_flag_parses(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--no-include-skills"])
            self.assertEqual(rc, 0)
            html = next((root / "usage-data").glob("*.html")).read_text()
            self.assertIn("include_skills=False", html)

    def test_absent_codex_dir_clean_exit(self):
        """Absent ~/.codex → clean 'no Codex data' exit, no crash, no file."""
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"  # deliberately NOT created
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])

            stderr_lines = []
            with patch("builtins.print") as mock_print:
                def _record(*a, **kw):
                    if kw.get("file") is sys.stderr:
                        stderr_lines.append(" ".join(str(x) for x in a))
                mock_print.side_effect = _record
                rc = codex_extract.main([])

            self.assertEqual(rc, 0)
            self.assertFalse((root / "usage-data").exists(), "no output dir on no-data exit")
            self.assertTrue(
                any("No Codex data" in ln for ln in stderr_lines),
                f"expected a no-data message, got: {stderr_lines}",
            )


if __name__ == "__main__":
    unittest.main()
