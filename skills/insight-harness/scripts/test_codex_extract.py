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


def _stage_sessions(root: Path, fixtures: dict[str, str]) -> Path:
    """Copy named fixtures into a temp Codex sessions/ tree (mirroring the real
    ``sessions/YYYY/MM/DD/rollout-*.jsonl`` nesting) and return the sessions dir.

    ``fixtures`` maps a fixture filename to the dated subpath it lands under, so
    the recursive glob in ``parse_rollouts`` is exercised exactly as it would be
    against real data.
    """
    sessions = root / "sessions"
    for fixture_name, dated_subpath in fixtures.items():
        dest = sessions / dated_subpath
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text((FIXTURES / fixture_name).read_text(encoding="utf-8"), encoding="utf-8")
    return sessions


class RolloutTokenAccountingTest(unittest.TestCase):
    """R3 — token totals are CUMULATIVE within a session: take the per-session
    max (last) and SUM the maxes across sessions. Never sum per-record."""

    def test_cumulative_series_takes_max_not_sum(self):
        # The payload fixture carries 28887, 67874, 107911 (cumulative). The
        # session total must be the MAX (107911), never the per-record sum
        # (204672) which would inflate ~the number of token_count records.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()

        self.assertEqual(result["total_tokens"], 107911)
        self.assertNotEqual(result["total_tokens"], 204672)  # the per-record sum

    def test_sum_of_per_session_maxes_across_sessions(self):
        # Two payload sessions: max 107911 + max 6200 = 114111. The cross-session
        # rule is sum-of-maxes, not max-of-maxes and not a global per-record sum.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
                "rollout-null-info.jsonl": "2026/05/21/rollout-b.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()

        # null-info session's only non-null cumulative total is 6200.
        self.assertEqual(result["total_tokens"], 107911 + 6200)

    def test_null_info_record_skipped_no_crash(self):
        # A token_count record with payload.info == null must be skipped without
        # a NoneType crash; the session's real total (6200) still lands.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-null-info.jsonl": "2026/05/21/rollout-b.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        self.assertEqual(result["total_tokens"], 6200)


class RolloutDualFormatTest(unittest.TestCase):
    """R9 — every rollout file counts as a session/timespan regardless of
    format; token + tool detail comes only from the payload-envelope format."""

    def test_legacy_file_counted_as_session_with_no_token_detail(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-legacy-format.jsonl": "2026/03/01/rollout-legacy.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        # Counted toward sessions...
        self.assertEqual(result["session_count"], 1)
        # ...but the legacy format carries no token_count records.
        self.assertEqual(result["total_tokens"], 0)

    def test_session_count_and_timespan_span_both_formats(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
                "rollout-legacy-format.jsonl": "2026/03/01/rollout-legacy.jsonl",
                "rollout-null-info.jsonl": "2026/05/21/rollout-b.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        self.assertEqual(result["session_count"], 3)
        # Timespan spans the earliest legacy record ts (session_meta @ 09:00:00)
        # to the latest record ts of any session (null-info's second token_count
        # @ 2026-05-21T10:00:30) — timestamps come from every record envelope.
        self.assertEqual(result["first_session"], "2026-03-01T09:00:00")
        self.assertEqual(result["last_session"], "2026-05-21T10:00:30")

    def test_empty_sessions_dir_is_clean(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            (root / "sessions").mkdir(parents=True)
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        self.assertEqual(result["session_count"], 0)
        self.assertEqual(result["total_tokens"], 0)
        self.assertEqual(result["command_names"], {})

    def test_absent_sessions_dir_is_clean(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"  # sessions/ deliberately absent
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        self.assertEqual(result["session_count"], 0)
        self.assertEqual(result["total_tokens"], 0)


class RolloutCommandExtractionTest(unittest.TestCase):
    """R6 — emit ONLY the first token of the inner command; the shell-runner
    wrapper (bash -lc) is stripped, and the full command string never leaks."""

    def test_emits_only_first_token_after_unwrap(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()
        cmds = result["command_names"]
        # `git status` -> git ; `npm test` -> npm test (node test-runner allowlist).
        self.assertEqual(cmds.get("git"), 1)
        self.assertEqual(cmds.get("npm test"), 1)
        # The wrapper binaries must never be emitted as command names.
        self.assertNotIn("bash", cmds)
        self.assertNotIn("-lc", cmds)
        # No full command string ever survives as a key.
        for key in cmds:
            self.assertNotIn(" -lc ", f" {key} ")
            self.assertLess(len(key.split()), 3, f"command name too long: {key!r}")

    def test_secret_bearing_command_emits_only_curl_no_secret_leak(self):
        # The fixture's inner command is
        #   curl -H 'Authorization: Bearer sk-FAKE123' https://api.example.com/...
        # Only `curl` may be emitted; the secret and the Bearer scheme must
        # never appear ANYWHERE in the parsed output.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-secret-bearing.jsonl": "2026/05/22/rollout-secret.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()

        self.assertEqual(result["command_names"].get("curl"), 1)
        # Serialize the WHOLE parsed result and assert the secret never leaks.
        blob = json.dumps(result)
        self.assertNotIn("sk-FAKE123", blob)
        self.assertNotIn("Bearer", blob)
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("api.example.com", blob)


class RolloutPrivacyGuardTest(unittest.TestCase):
    """Open-tracking privacy guard — mirrors test_work_surfaces.py. After a full
    parse, NO content-carrier value (message bodies, reasoning, agent_message,
    task_complete, command outputs, apply_patch, session_meta prose, etc.) may
    be materialized into the parsed output."""

    # Substrings that only exist inside content carriers in the fixtures.
    FORBIDDEN_CONTENT = (
        "please refactor the parser module",          # user_message.message
        "add a changelog entry",                       # legacy user_message
        "Done — added the changelog entry.",           # legacy message.content
        "On branch main",                              # function_call_output.output
        "nothing to commit",                           # function_call_output.output
        '"object":"list"',                             # secret fixture output
        "git@github.com",                              # session_meta git url
        "deadbeefcafe",                                # session_meta commit hash
        "exampleuser/demo-project",                    # session_meta repo/cwd path
        "sk-FAKE123",                                   # the secret
        "Bearer",                                       # the auth scheme
        "Authorization",                                # the header name
    )

    def test_no_content_carrier_leaks_into_output(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
                "rollout-legacy-format.jsonl": "2026/03/01/rollout-legacy.jsonl",
                "rollout-null-info.jsonl": "2026/05/21/rollout-b.jsonl",
                "rollout-secret-bearing.jsonl": "2026/05/22/rollout-secret.jsonl",
            })
            with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                result = codex_extract.parse_rollouts()

        blob = json.dumps(result)
        for forbidden in self.FORBIDDEN_CONTENT:
            self.assertNotIn(
                forbidden, blob,
                f"content carrier leaked into parsed output: {forbidden!r}",
            )

    def test_parse_does_not_materialize_content_via_open_tracking(self):
        # Plant a tracking open() that records every line yielded from a rollout
        # file, then assert no content-carrier value was ever returned in the
        # final structure. (The files ARE read; the guarantee is that carriers
        # are not propagated into output.)
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-payload-format.jsonl": "2026/05/20/rollout-a.jsonl",
                "rollout-secret-bearing.jsonl": "2026/05/22/rollout-secret.jsonl",
            })

            import builtins
            real_open = builtins.open
            read_files = []

            def tracking_open(file, *args, **kwargs):
                if str(file).endswith(".jsonl"):
                    read_files.append(str(file))
                return real_open(file, *args, **kwargs)

            builtins.open = tracking_open
            try:
                with patch.object(codex_extract, "CODEX_SESSIONS_DIR", root / "sessions"):
                    result = codex_extract.parse_rollouts()
            finally:
                builtins.open = real_open

        # Sanity: both rollout files were actually opened/read.
        self.assertEqual(len(read_files), 2)
        # And yet nothing from the content carriers reached the output.
        blob = json.dumps(result)
        for forbidden in ("sk-FAKE123", "please refactor", '"object":"list"'):
            self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main()
