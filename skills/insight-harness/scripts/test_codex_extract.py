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


if __name__ == "__main__":
    unittest.main()
