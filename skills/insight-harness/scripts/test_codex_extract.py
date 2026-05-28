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
        # Unit 5+: the flag still toggles showcase enrichment; we assert the
        # CLI parses it and writes the report without crashing. The visible
        # behavior under --no-include-skills is exercised in the skill
        # inventory tests; here we just confirm the wiring holds end-to-end.
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
            # Profile shell rendered + the always-on local-only limit present.
            self.assertIn("Codex Harness Profile", html)
            self.assertIn("Local Codex CLI usage only", html)

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


def _write_skill(skills_dir: Path, name: str, frontmatter: str, body: str = "") -> Path:
    """Create ``skills/<name>/SKILL.md`` under ``skills_dir`` and return its path.

    ``frontmatter`` is the YAML between the ``---`` fences (no fences); ``body``
    is the markdown after the closing fence.
    """
    sk = skills_dir / name
    sk.mkdir(parents=True, exist_ok=True)
    md = sk / "SKILL.md"
    md.write_text(f"---\n{frontmatter}\n---\n\n{body}\n", encoding="utf-8")
    return md


class CodexSkillInventoryTest(unittest.TestCase):
    """Unit 3 — Codex skills are INVENTORY ONLY: name, description,
    installPointer. NO ``calls`` / usage-count field (D4 — Codex loads skills
    into context; there is no reliable invocation signal)."""

    def test_happy_path_three_skills_listed_with_descriptions_no_counts(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            skills_dir = root / "skills"
            _write_skill(skills_dir, "alpha", "name: alpha\ndescription: Does alpha things.")
            _write_skill(skills_dir, "beta", "name: beta\ndescription: Does beta things.")
            _write_skill(skills_dir, "gamma", "name: gamma\ndescription: Does gamma things.")
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", skills_dir):
                inv = codex_extract.extract_skill_inventory_codex()

        names = sorted(e["name"] for e in inv)
        self.assertEqual(names, ["alpha", "beta", "gamma"])
        by_name = {e["name"]: e for e in inv}
        self.assertEqual(by_name["alpha"]["description"], "Does alpha things.")
        self.assertEqual(by_name["beta"]["installPointer"], "beta")
        # CRITICAL (D4): no entry may carry a calls/usage-count field.
        for e in inv:
            for forbidden in ("calls", "count", "invocations", "usage", "usageCount"):
                self.assertNotIn(
                    forbidden, e,
                    f"inventory entry must not carry a {forbidden!r} field: {e!r}",
                )

    def test_blank_frontmatter_description_is_body_derived(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            skills_dir = root / "skills"
            # No description in frontmatter → first prose line of the body.
            _write_skill(
                skills_dir, "myskill", "name: myskill",
                body="# My Skill\n\nDoes a specific useful thing for testing.",
            )
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", skills_dir):
                inv = codex_extract.extract_skill_inventory_codex()

        entry = next(e for e in inv if e["name"] == "myskill")
        self.assertEqual(entry["description"], "Does a specific useful thing for testing.")

    def test_repo_private_skill_excluded_entirely(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            skills_dir = root / "skills"
            _write_skill(skills_dir, "public-one", "name: public-one\ndescription: Visible.")
            _write_skill(skills_dir, "secret-one", "name: secret-one\ndescription: Hidden.\nrepo: private")
            _write_skill(skills_dir, "none-one", "name: none-one\ndescription: Also hidden.\nrepo: none")
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", skills_dir):
                inv = codex_extract.extract_skill_inventory_codex()

        names = [e["name"] for e in inv]
        self.assertIn("public-one", names)
        # repo: private / none → excluded entirely (not listed at all).
        self.assertNotIn("secret-one", names)
        self.assertNotIn("none-one", names)
        # And the private skill's metadata never leaks anywhere in the output.
        blob = json.dumps(inv)
        self.assertNotIn("secret-one", blob)
        self.assertNotIn("Hidden.", blob)

    def test_no_include_skills_still_inventory_only(self):
        # Even without the showcase pass the entries are inventory-only (no
        # calls) and private skills stay excluded.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            skills_dir = root / "skills"
            _write_skill(skills_dir, "alpha", "name: alpha\ndescription: A.")
            _write_skill(skills_dir, "secret", "name: secret\ndescription: S.\nrepo: private")
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", skills_dir):
                inv = codex_extract.extract_skill_inventory_codex(include_showcase=False)
        names = [e["name"] for e in inv]
        self.assertEqual(names, ["alpha"])
        self.assertNotIn("calls", inv[0])

    def test_absent_skills_dir_is_clean(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"  # skills/ deliberately absent
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", root / "skills"):
                inv = codex_extract.extract_skill_inventory_codex()
        self.assertEqual(inv, [])


class CodexThirdPartyReadmeScrubTest(unittest.TestCase):
    """SEC-10 (made concrete) — a third-party-owned README whose
    ``github.com/<upstream-owner>/...`` URL differs from the local git identity:
    (1) the local user's identity is NOT injected in place of the upstream owner
    (no mis-attribution rewrite), and (2) the emitted excerpt contains neither
    the local OS-username nor any ``sk-``/``Bearer `` token."""

    def test_third_party_readme_no_misattribution_no_secret_leak(self):
        upstream_owner = "anthropics"  # an org that is NOT the local user
        local_user = "craig-local-fake-1234"
        readme = (
            "# Toolkit\n\n"
            "Clone from https://github.com/anthropics/skilltools and run it.\n\n"
            f"Local path: /Users/{local_user}/work/toolkit\n\n"
            "Set the header `Authorization: Bearer sk-FAKE-THIRD-PARTY-999`.\n"
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            skills_dir = root / "skills"
            sk = skills_dir / "third-party-tool"
            sk.mkdir(parents=True)
            (sk / "SKILL.md").write_text(
                "---\nname: third-party-tool\ndescription: Wraps an upstream toolkit.\n---\n\nSee README.\n",
                encoding="utf-8",
            )
            (sk / "README.md").write_text(readme, encoding="utf-8")

            # Force a deterministic local identity so the assertion is hermetic:
            # USER drives _local_username(); empty git config so only the
            # owner-scan + username path rules apply.
            with patch.object(codex_extract, "CODEX_SKILLS_DIR", skills_dir), \
                 patch.dict("os.environ", {"USER": local_user}, clear=False), \
                 patch("pii_scrub._git_config", return_value=""):
                inv = codex_extract.extract_skill_inventory_codex()

        entry = next(e for e in inv if e["name"] == "third-party-tool")
        excerpt = entry.get("readmeMarkdown") or ""
        self.assertTrue(excerpt, "expected a scrubbed README excerpt to be emitted")

        # (1) No mis-attribution: the upstream owner is replaced with the generic
        # placeholder, and the LOCAL identity is NOT substituted in its place.
        self.assertIn("github.com/<your-username>/skilltools", excerpt)
        self.assertNotIn(f"github.com/{local_user}/", excerpt)
        # The upstream owner is scrubbed to a placeholder, not left verbatim and
        # not rewritten to the local user.
        self.assertNotIn(f"github.com/{upstream_owner}/", excerpt)

        # (2) Neither the local OS-username nor any sk-/Bearer token survives.
        self.assertNotIn(local_user, excerpt)
        self.assertNotIn("sk-FAKE-THIRD-PARTY-999", excerpt)
        self.assertNotIn("Bearer sk-", excerpt)
        # The local home path is collapsed to ~ (username scrubbed out).
        self.assertNotIn(f"/Users/{local_user}", excerpt)


class CodexPluginsFromConfigTest(unittest.TestCase):
    """Unit 3 / R10 — plugins are sourced from config.toml ``[plugins.*]``
    (name + enabled), NOT a directory walk. Real config keys are quoted and
    marketplace-qualified: ``[plugins."github@openai-curated"]``."""

    def test_plugins_read_from_config_with_enabled_flags(self):
        config = (
            'model = "gpt-5.5"\n'
            'approvals_reviewer = "user"\n\n'
            '[plugins."github@openai-curated"]\n'
            'enabled = true\n\n'
            '[plugins."slack@openai-curated"]\n'
            'enabled = false\n\n'
            '[plugins."granola@openai-curated"]\n'
            'enabled = true\n\n'
            # A non-plugin section must not bleed into the plugin list.
            '[projects."/Users/somebody/secret-project"]\n'
            'trust_level = "trusted"\n'
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            (root / "config.toml").write_text(config, encoding="utf-8")
            with patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                plugins = codex_extract.extract_plugins_from_config()

        by_name = {p["name"]: p for p in plugins}
        self.assertEqual(
            sorted(by_name),
            ["github@openai-curated", "granola@openai-curated", "slack@openai-curated"],
        )
        self.assertTrue(by_name["github@openai-curated"]["enabled"])
        self.assertFalse(by_name["slack@openai-curated"]["enabled"])
        self.assertTrue(by_name["granola@openai-curated"]["enabled"])
        # Each entry is {name, enabled} only — no other config detail bleeds in.
        for p in plugins:
            self.assertEqual(set(p), {"name", "enabled"})
        # The project-path section key must never appear in the plugin output.
        blob = json.dumps(plugins)
        self.assertNotIn("secret-project", blob)
        self.assertNotIn("/Users/somebody", blob)

    def test_plugin_missing_enabled_defaults_false(self):
        config = '[plugins."mystery@somewhere"]\n# no enabled key\n'
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            (root / "config.toml").write_text(config, encoding="utf-8")
            with patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                plugins = codex_extract.extract_plugins_from_config()
        self.assertEqual(plugins, [{"name": "mystery@somewhere", "enabled": False}])

    def test_no_config_or_no_plugins_table_is_empty(self):
        # Absent config.toml.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            with patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                self.assertEqual(codex_extract.extract_plugins_from_config(), [])
        # Present config.toml with no [plugins] table.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            (root / "config.toml").write_text('model = "gpt-5.5"\n', encoding="utf-8")
            with patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                self.assertEqual(codex_extract.extract_plugins_from_config(), [])

    def test_malformed_toml_does_not_crash(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)
            (root / "config.toml").write_text("this is = not [valid toml\n", encoding="utf-8")
            with patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                self.assertEqual(codex_extract.extract_plugins_from_config(), [])


def _write_config(root: Path, body: str) -> Path:
    """Write ``config.toml`` under a temp Codex ``root`` and return its path."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / "config.toml"
    path.write_text(body, encoding="utf-8")
    return path


def _write_rules(root: Path, files: dict[str, str]) -> Path:
    """Create ``rules/<name>.rules`` files under a temp Codex ``root`` and return
    the rules dir. ``files`` maps a filename (e.g. ``default.rules``) to its
    contents."""
    rules_dir = root / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for fname, contents in files.items():
        (rules_dir / fname).write_text(contents, encoding="utf-8")
    return rules_dir


class CodexRulesLeakTest(unittest.TestCase):
    """LOAD-BEARING SECURITY ASSERTION (R4/R8). The real ``*.rules`` DSL embeds
    absolute credential-file paths and Bearer tokens in LATER ``pattern`` elements
    (verified against the real ~/.codex/rules/default.rules). The parser must emit
    ``pattern[0]`` (the binary) ONLY and discard every later element + the
    ``decision``. Nothing path-like (``/``, ``~``, ``/Users/``) and no token may
    ever reach the safety output."""

    def test_rule_with_credential_path_and_bearer_token_emits_binary_only(self):
        rules = (
            # A rule whose later pattern elements are an absolute creds-file path.
            'prefix_rule(pattern=["git", "add", '
            '"/Users/someone/Library/Application Support/com.vercel.cli/auth.json"], '
            'decision="allow")\n'
            # A rule whose later element embeds a live-looking Bearer token.
            'prefix_rule(pattern=["curl", "-H", '
            '"Authorization: Bearer sk-FAKE-LEAK-9999"], decision="allow")\n'
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _write_rules(root, {"default.rules": rules})
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()

        allowlist = safety["rulesAllowlist"]
        # The binaries (pattern[0]) ARE surfaced.
        self.assertIn("git", allowlist)
        self.assertIn("curl", allowlist)

        # NOTHING else from the rule may survive. Scan the FULL serialized safety
        # output — the island scans the serialized string (R11), so this is the
        # exact surface that would ship.
        blob = json.dumps(safety)
        # The credentials path and every path-like fragment of it.
        self.assertNotIn("auth.json", blob)
        self.assertNotIn("com.vercel.cli", blob)
        self.assertNotIn("/Users/someone", blob)
        self.assertNotIn("Application Support", blob)
        # The token, the auth scheme, and the header carrier.
        self.assertNotIn("sk-FAKE-LEAK-9999", blob)
        self.assertNotIn("Bearer", blob)
        self.assertNotIn("Authorization", blob)
        # The DSL's own non-binary noise must not leak either.
        self.assertNotIn("decision", blob)
        self.assertNotIn("allow", blob)

        # And the structural guarantee: no allowlist binary contains a path-like
        # character (defense beyond the substring checks above).
        for binary in allowlist:
            self.assertNotIn("~", binary, f"path-like char in binary: {binary!r}")
            self.assertNotIn("/Users/", binary, f"home path in binary: {binary!r}")
            # A bare binary may itself be an absolute path (e.g. /bin/zsh), but it
            # must never carry an argument that contains a slash + a filename that
            # looks like a leaked path. We assert no later-element survived by
            # checking the binary is a single token (no embedded spaces).
            self.assertNotIn(" ", binary, f"binary carries an argument: {binary!r}")


class CodexSafetyHappyPathTest(unittest.TestCase):
    """R4 happy path — the real config keys surface as ENUM VALUES only;
    per-project ``trust_level`` values appear but the ``[projects."<path>"]``
    section keys (home-dir/project-name leaks) NEVER do; rules emit binaries
    only."""

    def test_enums_surfaced_and_project_paths_never_emitted(self):
        config = (
            'model = "gpt-5.5"\n'
            'approvals_reviewer = "user"\n\n'
            '[projects."/Users/x/proj"]\n'
            'trust_level = "trusted"\n\n'
            '[projects."/Users/x/another-secret-proj"]\n'
            'trust_level = "untrusted"\n\n'
            '[apps.connector_76869538009648d5b282a4bb21c3d157.tools.github_create_pull_request]\n'
            'approval_mode = "approve"\n'
        )
        rules = (
            'prefix_rule(pattern=["python3", "-m", "pipeline.workflow"], decision="allow")\n'
            'prefix_rule(pattern=["git", "add"], decision="allow")\n'
            'prefix_rule(pattern=["git", "commit", "-m"], decision="allow")\n'
            'prefix_rule(pattern=["agent-browser"], decision="allow")\n'
            'prefix_rule(pattern=["/bin/zsh", "-lc", "ls -la"], decision="allow")\n'
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _write_config(root, config)
            _write_rules(root, {"default.rules": rules})
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()

        # Top-level reviewer enum surfaced verbatim.
        self.assertEqual(safety["approvalsReviewer"], "user")
        # Per-app approval_mode enum value(s) surfaced — VALUE only, never the key.
        self.assertIn("approve", safety["approvalModes"])
        # Per-project trust_level VALUES surfaced (deduped enum set).
        self.assertEqual(sorted(safety["trustLevels"]), ["trusted", "untrusted"])

        # Rules emit pattern[0] only, deduped (git add + git commit -> one "git").
        allowlist = safety["rulesAllowlist"]
        self.assertEqual(
            sorted(allowlist),
            ["/bin/zsh", "agent-browser", "git", "python3"],
        )

        # CRITICAL: the [projects."<path>"] section keys never appear anywhere.
        blob = json.dumps(safety)
        self.assertNotIn("/Users/x/proj", blob)
        self.assertNotIn("another-secret-proj", blob)
        self.assertNotIn("/Users/x", blob)
        # CRITICAL: the [apps.connector_*] UUID section key never appears — only
        # the approval_mode value beneath it was read.
        self.assertNotIn("connector_", blob)
        self.assertNotIn("76869538009648d5b282a4bb21c3d157", blob)
        # And no later rule element / path / arg leaked.
        self.assertNotIn("pipeline.workflow", blob)
        self.assertNotIn("-lc", blob)
        self.assertNotIn("ls -la", blob)

    def test_trust_levels_are_deduped_enum_set_not_per_project_list(self):
        # Many projects, all "trusted" → a single enum value, NOT one per project
        # (a per-project list would leak the project count / shape).
        config = (
            'approvals_reviewer = "user"\n'
            + "".join(
                f'[projects."/Users/x/p{i}"]\ntrust_level = "trusted"\n'
                for i in range(8)
            )
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _write_config(root, config)
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()
        self.assertEqual(safety["trustLevels"], ["trusted"])
        blob = json.dumps(safety)
        for i in range(8):
            self.assertNotIn(f"/Users/x/p{i}", blob)


class CodexSafetyEdgeCaseTest(unittest.TestCase):
    """R4 edge case — no ``rules/`` dir and an empty/minimal ``config.toml`` →
    'none configured' / empty structures, no crash; no connector UUID, no
    project-path keys."""

    def test_no_rules_dir_and_minimal_config_is_clean(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            # Minimal config: no safety keys at all. rules/ deliberately absent.
            _write_config(root, 'model = "gpt-5.5"\n')
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()

        self.assertEqual(safety["rulesAllowlist"], [])
        self.assertIsNone(safety["approvalsReviewer"])
        self.assertEqual(safety["approvalModes"], [])
        self.assertEqual(safety["trustLevels"], [])

    def test_absent_config_and_absent_rules_is_clean(self):
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            root.mkdir(parents=True)  # neither config.toml nor rules/ created
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()
        self.assertEqual(
            safety,
            {
                "rulesAllowlist": [],
                "approvalsReviewer": None,
                "approvalModes": [],
                "trustLevels": [],
            },
        )

    def test_connector_uuid_section_key_never_emitted_even_with_apps_table(self):
        # An [apps.connector_<uuid>] section present → read approval_mode VALUE
        # only; the UUID section key must never appear.
        config = (
            '[apps.connector_deadbeefcafe1234.tools.gmail_send]\n'
            'approval_mode = "ask"\n'
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _write_config(root, config)
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()
        self.assertEqual(safety["approvalModes"], ["ask"])
        blob = json.dumps(safety)
        self.assertNotIn("connector_", blob)
        self.assertNotIn("deadbeefcafe1234", blob)
        self.assertNotIn("gmail_send", blob)
        self.assertNotIn("gmail", blob)

    def test_malformed_rule_lines_are_skipped_not_crashed(self):
        # Comment lines, blank lines, and non-prefix_rule lines must be ignored
        # without raising.
        rules = (
            "# this is a comment\n"
            "\n"
            "deny_rule(pattern=[\"rm\"], decision=\"deny\")\n"  # not prefix_rule
            "garbage that is not a rule at all\n"
            'prefix_rule(pattern=["git", "status"], decision="allow")\n'
            "prefix_rule(pattern=[])\n"  # empty pattern → nothing to emit
        )
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _write_rules(root, {"default.rules": rules})
            with patch.object(codex_extract, "CODEX_RULES_DIR", root / "rules"), \
                 patch.object(codex_extract, "CODEX_CONFIG_PATH", root / "config.toml"):
                safety = codex_extract.extract_safety_posture()
        # Only the well-formed prefix_rule's binary survives.
        self.assertEqual(safety["rulesAllowlist"], ["git"])
        # The deny rule's binary must NOT be surfaced (we only parse prefix_rule).
        self.assertNotIn("rm", safety["rulesAllowlist"])


def _extract_island(html: str) -> dict:
    """Pull the JSON island out of the rendered HTML.

    Mirrors how a consumer would read the page: locate the
    ``<script type="application/json" id="harness-data">…</script>`` block and
    parse it. Tests use this so they assert against the SAME bytes that ship,
    not against the structured ``island`` dict returned from ``build_island``.
    """
    import re as _re
    m = _re.search(
        r'<script type="application/json" id="harness-data">(.*?)</script>',
        html,
        flags=_re.DOTALL,
    )
    assert m, "island script tag not found in HTML"
    serialized = m.group(1)
    # The renderer escapes any inner </script>; reverse it before json.loads.
    serialized = serialized.replace(r"<\/script>", "</script>")
    return json.loads(serialized)


def _full_profile_codex_root(d: Path, *, sessions: int = 6) -> Path:
    """Build a rich, ABOVE-FLOOR temp Codex root for the Unit-5 happy path.

    ``sessions`` rollouts of the payload-format fixture are dropped under
    distinct dated subpaths so ``parse_rollouts`` clears the activity floor;
    a skills tree, a plugin-bearing config.toml, and a safety rule are also
    wired in. Returns the codex root path.
    """
    root = d / ".codex"
    root.mkdir(parents=True)
    # Stage the same fixture under N distinct dated subpaths so the recursive
    # rollout glob sees N sessions. ``_stage_sessions``' filename-keyed dict
    # would collapse identical filenames, so write directly.
    fixture_text = (FIXTURES / "rollout-payload-format.jsonl").read_text(encoding="utf-8")
    for i in range(sessions):
        dest = root / "sessions" / "2026" / "05" / f"{20 + i:02d}" / f"rollout-{i}.jsonl"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(fixture_text, encoding="utf-8")
    # Three skills (one private — must be excluded).
    skills_dir = root / "skills"
    _write_skill(skills_dir, "alpha", "name: alpha\ndescription: Does alpha things.")
    _write_skill(skills_dir, "beta", "name: beta\ndescription: Does beta things.")
    _write_skill(skills_dir, "secret", "name: secret\ndescription: Hidden.\nrepo: private")
    # Plugins + safety from config.toml.
    (root / "config.toml").write_text(
        'model = "gpt-5.5"\n'
        'approvals_reviewer = "user"\n\n'
        '[plugins."github@openai-curated"]\nenabled = true\n\n'
        '[plugins."slack@openai-curated"]\nenabled = false\n\n'
        '[projects."/Users/x/proj"]\ntrust_level = "trusted"\n\n'
        '[apps.connector_deadbeefcafe1234.tools.gmail_send]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    (root / "rules").mkdir(parents=True, exist_ok=True)
    (root / "rules" / "default.rules").write_text(
        'prefix_rule(pattern=["git", "status"], decision="allow")\n'
        'prefix_rule(pattern=["npm", "test"], decision="allow")\n',
        encoding="utf-8",
    )
    return root


class CodexProfileHappyPathTest(unittest.TestCase):
    """Unit 5 happy path — rich fixture → island parses, ``tool == "codex"``,
    token total present, ``skillInventory`` entries have no ``calls`` field,
    and the envelope carries NO ``schema_version`` / ``generated_at`` keys
    (R1 — those are Phase 2's contract)."""

    def test_island_envelope_is_tool_only_and_skills_are_inventory(self):
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, profile = codex_extract.generate_profile()

        # Envelope discipline (R1).
        self.assertEqual(island["tool"], "codex")
        self.assertNotIn("schema_version", island)
        self.assertNotIn("generated_at", island)

        # Stats present + above the activity floor.
        self.assertGreater(island["stats"]["totalTokens"], 0)
        self.assertEqual(island["stats"]["sessionCount"], 6)

        # localOnly is always True (R12 — local-CLI scope, period).
        self.assertTrue(island["localOnly"])

        # Skills inventory-only: no ``calls`` / usage count anywhere.
        self.assertTrue(island["skillInventory"])
        for entry in island["skillInventory"]:
            for forbidden in ("calls", "count", "invocations", "usage", "usageCount"):
                self.assertNotIn(
                    forbidden, entry,
                    f"island skill entry leaked usage field {forbidden!r}: {entry!r}",
                )
        # Private skill excluded from the inventory entirely.
        names = [s["name"] for s in island["skillInventory"]]
        self.assertNotIn("secret", names)

        # HTML structural sanity — the headline section labels all render.
        # Safety renders as "Safety &amp; Automation" so just check the prefix.
        for label in ("Tokens", "Tool Usage", "CLI Commands", "Skills",
                       "Plugins", "Safety", "Workflow Phases", "Work Surfaces"):
            self.assertIn(label, html, f"section label {label!r} missing")
        # Verify Safety section is the FULL "Safety & Automation" heading,
        # not just an incidental occurrence of the word "Safety".
        self.assertIn("Safety &amp; Automation", html)

        # Above-floor path: the thin-tool caveat is NOT rendered.
        self.assertNotIn("Limited local Codex signal", html)
        # But the always-on local-only limit IS.
        self.assertIn("Local Codex CLI usage only", html)


class CodexThinToolCaveatTest(unittest.TestCase):
    """R12 — below the activity floor we render the slim shell with the
    'local CLI data only — this person may use Codex more elsewhere' caveat,
    not the full profile presentation."""

    def test_below_threshold_renders_caveat_not_full_profile(self):
        # ONE session, ~107k tokens — sessions below floor (5), tokens below
        # floor (50k). We use the null-info fixture which tops out at 6200
        # tokens to stay below BOTH floors.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-null-info.jsonl": "2026/05/21/rollout-thin.jsonl",
            })
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, profile = codex_extract.generate_profile()

        # Below floor by both criteria.
        self.assertEqual(island["stats"]["sessionCount"], 1)
        self.assertLess(
            island["stats"]["totalTokens"],
            codex_extract.ACTIVITY_FLOOR_TOKENS,
        )
        # The slim-shell caveat is present.
        self.assertIn("Limited local Codex signal", html)
        self.assertIn(
            "Local CLI data only — this person may use Codex more elsewhere",
            html,
        )
        # And the always-on local-only limit is still there too.
        self.assertIn("Local Codex CLI usage only", html)
        # Island stays full-shape regardless (Phase 2 consumers shouldn't have
        # to handle two shapes; the slim shell is a presentation choice).
        self.assertEqual(set(island.keys()), codex_extract.ALLOWED_ISLAND_KEYS)

    def test_above_threshold_renders_full_profile_with_local_only(self):
        # The happy-path fixture clears 6 sessions → above the session floor.
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        # Above-floor: no slim-shell caveat...
        self.assertNotIn("Limited local Codex signal", html)
        # ...but the local-only limit is ALWAYS present (R12).
        self.assertIn("Local Codex CLI usage only", html)
        # Stats reflect the rich slice.
        self.assertGreaterEqual(
            island["stats"]["sessionCount"], codex_extract.ACTIVITY_FLOOR_SESSIONS
        )


class CodexMcpBucketingTest(unittest.TestCase):
    """R8 — MCP/connector tool names must be normalized at counting time so
    the verbatim ``mcp__<server>__<tool>`` form never appears in the island or
    the rendered HTML. The single ``mcp:*`` bucket is what ships."""

    def test_planted_mcp_tool_name_is_bucketed_not_verbatim(self):
        # Stage a fresh rollout where one function_call carries an
        # mcp__gmail__send name. The bucketing happens inside parse_rollouts;
        # the verbatim name must NOT appear anywhere in the final output.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            sessions = root / "sessions" / "2026" / "05" / "30"
            sessions.mkdir(parents=True)
            (sessions / "rollout-mcp.jsonl").write_text(
                '{"timestamp":"2026-05-30T10:00:00Z","type":"session_meta",'
                '"payload":{"type":"session_meta","id":"sid"}}\n'
                '{"timestamp":"2026-05-30T10:00:05Z","type":"function_call",'
                '"payload":{"type":"function_call","name":"mcp__gmail__send",'
                '"arguments":"{}","call_id":"c1"}}\n'
                '{"timestamp":"2026-05-30T10:00:06Z","type":"function_call",'
                '"payload":{"type":"function_call","name":"mcp__slack__post_message",'
                '"arguments":"{}","call_id":"c2"}}\n'
                '{"timestamp":"2026-05-30T10:00:07Z","type":"function_call",'
                '"payload":{"type":"function_call","name":"apply_patch",'
                '"arguments":"{}","call_id":"c3"}}\n',
                encoding="utf-8",
            )
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        # The bucket is the only MCP signal that surfaces.
        self.assertEqual(island["toolUsage"].get("mcp:*"), 2)
        self.assertEqual(island["toolUsage"].get("apply_patch"), 1)
        # No verbatim mcp__server__tool form anywhere — neither in HTML nor
        # the serialized island.
        for blob in (html, json.dumps(island)):
            self.assertNotIn("mcp__gmail__send", blob)
            self.assertNotIn("mcp__slack__post_message", blob)
            self.assertNotIn("gmail", blob)
            self.assertNotIn("slack", blob)


class CodexIdentityScrubTest(unittest.TestCase):
    """R8 — repository_url / cwd / commit_hash / branch must never appear in
    the HTML OR the serialized island, even though the source fixtures carry
    them. The positive read-allowlist in parse_rollouts is the primary control;
    this test verifies the chain end-to-end."""

    def test_planted_repository_url_and_cwd_absent_from_both_html_and_island(self):
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        # The payload fixture's session_meta carries these — they must not leak.
        forbidden_strings = [
            "git@github.com",                    # repository_url
            "exampleuser/demo-project",          # repo + cwd path fragment
            "deadbeefcafe0000",                  # commit_hash prefix
            "/Users/exampleuser",                # cwd home leak
        ]
        serialized_island = json.dumps(island)
        for forbidden in forbidden_strings:
            self.assertNotIn(
                forbidden, html,
                f"identity leak in HTML: {forbidden!r}",
            )
            self.assertNotIn(
                forbidden, serialized_island,
                f"identity leak in serialized island: {forbidden!r}",
            )

    def test_connector_uuid_section_key_absent_from_emitted_profile(self):
        # The fixture config has [apps.connector_deadbeefcafe1234.tools...].
        # Safety extraction reads only the approval_mode VALUE; the UUID
        # section key must never reach the page or the island.
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        for blob in (html, json.dumps(island)):
            self.assertNotIn("connector_", blob)
            self.assertNotIn("deadbeefcafe1234", blob)
            self.assertNotIn("gmail_send", blob)
            self.assertNotIn("/Users/x/proj", blob)


class CodexIslandSubsetRenderedTest(unittest.TestCase):
    """R11 — the set of island data keys must equal the set of rendered field
    categories. No island-only field may exist (it would silently ship a leak
    that the HTML doesn't visibly disclose)."""

    def test_island_keys_match_rendered_section_categories(self):
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        # The committed island schema is the constant set.
        self.assertEqual(
            set(island.keys()),
            codex_extract.ALLOWED_ISLAND_KEYS,
            "island deviated from ALLOWED_ISLAND_KEYS — update the contract"
            " (and the renderer + the section map) deliberately.",
        )
        # Every island data key (envelope markers excluded) has a rendered
        # section. Section labels containing "&" are HTML-escaped in the page
        # so check against the escaped form.
        envelope_markers = {"tool", "localOnly"}
        for key in island.keys() - envelope_markers:
            section_label = codex_extract._ISLAND_KEY_TO_RENDERED_SECTION[key]
            escaped = section_label.replace("&", "&amp;")
            self.assertTrue(
                section_label in html or escaped in html,
                f"island key {key!r} → rendered section {section_label!r} "
                "missing from HTML",
            )

    def test_envelope_excludes_phase2_owned_keys(self):
        # R1 — schema_version / generated_at are Phase 2's contract; Phase 1
        # must NOT pre-commit them on the island envelope.
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            _, island, _ = codex_extract.generate_profile()
        self.assertNotIn("schema_version", island)
        self.assertNotIn("generated_at", island)
        self.assertNotIn("schemaVersion", island)
        self.assertNotIn("generatedAt", island)

    def test_island_in_html_parses_back_to_same_envelope(self):
        # The bytes that SHIP must round-trip to the same envelope discipline.
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()
        parsed = _extract_island(html)
        self.assertEqual(parsed["tool"], "codex")
        self.assertEqual(set(parsed.keys()), codex_extract.ALLOWED_ISLAND_KEYS)
        self.assertEqual(parsed["stats"], island["stats"])


class CodexNoHardcodedAuthorClaimsTest(unittest.TestCase):
    """F6 — with a THIN-data fixture the rendered prose must NOT claim safety
    features the fixture data doesn't show. Phase-0 finding F6: the Claude
    ``generate_writeup`` template was author-frozen and lied on others'
    reports. We don't repeat that — every claim is derived from data."""

    def test_thin_data_does_not_claim_destructive_command_guarding(self):
        # Zero rules + zero approval modes + zero plugins → the rendered HTML
        # MUST say "none configured" / "no signal", never claim the user has
        # safety hardening they don't have.
        with TemporaryDirectory() as d:
            root = Path(d) / ".codex"
            _stage_sessions(root, {
                "rollout-null-info.jsonl": "2026/05/21/rollout-thin.jsonl",
            })
            # Minimal config — no approvals_reviewer, no apps, no projects.
            (root / "config.toml").write_text(
                'model = "gpt-5.5"\n', encoding="utf-8",
            )
            # No rules dir.
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            html, island, _ = codex_extract.generate_profile()

        # The prose must NOT manufacture safety claims.
        forbidden_phrases = [
            "destructive command guarding",
            "blocks dangerous commands",
            "enforces approval on",
            "automatically guards",
            # Generic "this user has X" claims that the Claude writeup made.
            "This user has configured",
            "This author enforces",
        ]
        for phrase in forbidden_phrases:
            self.assertNotIn(
                phrase, html,
                f"prose hardcoded an author-specific safety claim: {phrase!r}",
            )

        # And the honest empty-state markers ARE present.
        self.assertIn("none configured", html)
        # Thin slice: the slim shell + caveat.
        self.assertIn("Limited local Codex signal", html)
        # Plugins absent → empty-state message.
        self.assertIn("No plugins declared", html)


class CodexMainWritesIslandTest(unittest.TestCase):
    """End-to-end via main() — the report file ON DISK carries the island
    embedded in a parseable form. The output contract (final stdout line is
    the report path) still holds."""

    def test_main_writes_html_with_embedded_island(self):
        with TemporaryDirectory() as d:
            root = _full_profile_codex_root(Path(d), sessions=6)
            patches = _patch_codex_dir(root)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])

            captured = []
            with patch("builtins.print") as mock_print:
                def _record(*a, **kw):
                    if "file" not in kw or kw["file"] is sys.stdout:
                        captured.append(" ".join(str(x) for x in a))
                mock_print.side_effect = _record
                rc = codex_extract.main([])

            self.assertEqual(rc, 0)
            self.assertTrue(captured)
            report_path = Path(captured[-1])
            html = report_path.read_text(encoding="utf-8")

        # The island parses back from the file on disk.
        parsed = _extract_island(html)
        self.assertEqual(parsed["tool"], "codex")
        self.assertIn("totalTokens", parsed["stats"])
        # The page declares the local-only limit.
        self.assertIn("Local Codex CLI usage only", html)


if __name__ == "__main__":
    unittest.main()
