"""Unit tests for learn.py — the insight-harness "learn from another harness" mode.

Covers target parsing (URL / bare pair / dev-override), the agent-envelope vs
legacy-fallback normalization, the Accept-header negotiation, and main()'s exit
codes. Mirrors test_publish.py's mocked-opener pattern; no network is touched.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import learn  # noqa: E402

# A well-formed publish token: ih_<12 hex><64 hex> (same shape extract validates).
VALID_TOKEN = "ih_" + ("a" * 12) + ("b" * 64)


def _fake_response(body: bytes):
    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return body

    return _Resp()


class ParseTargetTests(unittest.TestCase):
    BASE = "https://insightharness.com"

    def test_human_report_url(self):
        api, user, slug = learn.parse_target(
            "https://insightharness.com/insights/savraj/20260422-5ayf16", self.BASE
        )
        self.assertEqual(user, "savraj")
        self.assertEqual(slug, "20260422-5ayf16")
        self.assertEqual(
            api, "https://insightharness.com/api/insights/savraj/20260422-5ayf16"
        )

    def test_edit_url_trailing_segment_ignored(self):
        api, user, slug = learn.parse_target(
            "https://insightharness.com/insights/alice/abc123/edit", self.BASE
        )
        self.assertEqual((user, slug), ("alice", "abc123"))
        self.assertEqual(api, "https://insightharness.com/api/insights/alice/abc123")

    def test_api_url_is_accepted(self):
        api, user, slug = learn.parse_target(
            "https://insightharness.com/api/insights/bob/xyz", self.BASE
        )
        self.assertEqual((user, slug), ("bob", "xyz"))
        self.assertEqual(api, "https://insightharness.com/api/insights/bob/xyz")

    def test_bare_user_slug_uses_base_url(self):
        api, user, slug = learn.parse_target("carol/deadbeef", "http://localhost:3000")
        self.assertEqual((user, slug), ("carol", "deadbeef"))
        self.assertEqual(api, "http://localhost:3000/api/insights/carol/deadbeef")

    def test_angle_brackets_and_trailing_slash_tolerated(self):
        api, user, slug = learn.parse_target(
            "<https://insightharness.com/insights/dan/s1/>", self.BASE
        )
        self.assertEqual((user, slug), ("dan", "s1"))

    def test_url_without_insights_segment_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_target("https://insightharness.com/about", self.BASE)

    def test_offdomain_host_rejected(self):
        # SECURITY: a crafted off-domain host must not be fetched — its JSON
        # (incl. consumer_guidance) would otherwise be fed to the host agent.
        with self.assertRaises(ValueError):
            learn.parse_target(
                "https://evil.example.com/insights/u/s", self.BASE
            )

    def test_dev_host_allowed_when_it_matches_base_url(self):
        api, user, slug = learn.parse_target(
            "http://localhost:3000/insights/u/s", "http://localhost:3000"
        )
        self.assertEqual((user, slug), ("u", "s"))
        self.assertEqual(api, "http://localhost:3000/api/insights/u/s")

    def test_canonical_host_allowed_even_under_dev_override(self):
        # The canonical site is always trusted, even when a dev override is set.
        api, _, _ = learn.parse_target(
            "https://insightharness.com/insights/u/s", "http://localhost:3000"
        )
        self.assertEqual(api, "https://insightharness.com/api/insights/u/s")

    def test_plaintext_http_canonical_rejected(self):
        # http://insightharness.com matches the host but not the https origin —
        # a MITM could tamper with the agent-consumed payload, so reject it.
        with self.assertRaises(ValueError):
            learn.parse_target("http://insightharness.com/insights/u/s", self.BASE)

    def test_bare_single_token_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_target("justausername", self.BASE)


class ParseGroupTargetTests(unittest.TestCase):
    BASE = "https://insightharness.com"

    def test_human_group_url(self):
        api = learn.parse_group_target(
            "https://insightharness.com/g/hyperzen", self.BASE
        )
        self.assertEqual(api, "https://insightharness.com/api/groups/hyperzen")

    def test_group_url_trailing_slash_tolerated(self):
        api = learn.parse_group_target(
            "https://insightharness.com/g/hyperzen/", self.BASE
        )
        self.assertEqual(api, "https://insightharness.com/api/groups/hyperzen")

    def test_bare_group_slug(self):
        api = learn.parse_group_target("g/hyperzen", self.BASE)
        self.assertEqual(api, "https://insightharness.com/api/groups/hyperzen")

    def test_api_groups_url(self):
        api = learn.parse_group_target(
            "https://insightharness.com/api/groups/hyperzen", self.BASE
        )
        self.assertEqual(api, "https://insightharness.com/api/groups/hyperzen")

    def test_bare_group_uses_base_url_override(self):
        api = learn.parse_group_target("g/devs", "http://localhost:3000")
        self.assertEqual(api, "http://localhost:3000/api/groups/devs")

    def test_join_invite_url_rejected(self):
        # /g/join/<token> is an invite link, not a profile — reject clearly.
        with self.assertRaises(ValueError) as ctx:
            learn.parse_group_target(
                "https://insightharness.com/g/join/deadbeef", self.BASE
            )
        self.assertIn("invite", str(ctx.exception).lower())

    def test_bare_join_invite_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_group_target("g/join/deadbeef", self.BASE)

    def test_offdomain_group_origin_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_group_target("https://evil.example.com/g/hyperzen", self.BASE)

    def test_plaintext_http_canonical_group_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_group_target("http://insightharness.com/g/hyperzen", self.BASE)

    def test_bad_slug_too_short_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_group_target("g/ab", self.BASE)

    def test_bad_slug_uppercase_rejected(self):
        with self.assertRaises(ValueError):
            learn.parse_group_target("https://insightharness.com/g/HyperZen", self.BASE)

    def test_non_group_url_returns_none(self):
        # A report URL is not group-shaped — falls through to parse_target.
        self.assertIsNone(
            learn.parse_group_target(
                "https://insightharness.com/insights/u/s", self.BASE
            )
        )

    def test_bare_user_slug_returns_none(self):
        self.assertIsNone(learn.parse_group_target("alice/abc123", self.BASE))


class LoadBearerTokenTests(unittest.TestCase):
    def _patch_paths(self, claude_path: Path, codex_path: Path):
        return (
            patch.object(learn, "PUBLISH_CONFIG_PATH", claude_path),
            patch.object(learn, "CODEX_CONFIG_PATH", codex_path),
        )

    def _write(self, path: Path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))

    def test_reads_claude_config(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"
            codex = Path(d) / "codex" / "config.json"
            self._write(claude, {"token": VALID_TOKEN})
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertEqual(learn.load_bearer_token(), VALID_TOKEN)

    def test_falls_back_to_codex_when_claude_missing(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"  # not created
            codex = Path(d) / "codex" / "config.json"
            self._write(codex, {"token": VALID_TOKEN})
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertEqual(learn.load_bearer_token(), VALID_TOKEN)

    def test_claude_wins_over_codex(self):
        import tempfile

        other = "ih_" + ("c" * 12) + ("d" * 64)
        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"
            codex = Path(d) / "codex" / "config.json"
            self._write(claude, {"token": VALID_TOKEN})
            self._write(codex, {"token": other})
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertEqual(learn.load_bearer_token(), VALID_TOKEN)

    def test_invalid_claude_token_falls_through_to_codex(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"
            codex = Path(d) / "codex" / "config.json"
            self._write(claude, {"token": "not-a-token"})
            self._write(codex, {"token": VALID_TOKEN})
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertEqual(learn.load_bearer_token(), VALID_TOKEN)

    def test_no_config_returns_none(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"
            codex = Path(d) / "codex" / "config.json"
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertIsNone(learn.load_bearer_token())

    def test_malformed_json_ignored(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            claude = Path(d) / "claude" / "config.json"
            codex = Path(d) / "codex" / "config.json"
            claude.parent.mkdir(parents=True, exist_ok=True)
            claude.write_text("{ not json")
            self._write(codex, {"token": VALID_TOKEN})
            p1, p2 = self._patch_paths(claude, codex)
            with p1, p2:
                self.assertEqual(learn.load_bearer_token(), VALID_TOKEN)


class NormalizePayloadTests(unittest.TestCase):
    def test_agent_envelope_passthrough(self):
        body = {"schema_version": "1.0.0", "profile": {"skillInventory": []}}
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "agent")
        self.assertIs(envelope, body)

    def test_legacy_human_shape_falls_back_and_strips_images(self):
        body = {
            "data": {
                "harnessData": {
                    "skillInventory": [
                        {"name": "x", "hero_base64": "AAAA", "hero_mime_type": "image/png"}
                    ]
                }
            }
        }
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "fallback")
        self.assertIsNone(envelope["schema_version"])
        self.assertIsNone(envelope["profile"]["skillInventory"][0]["hero_base64"])
        self.assertIn("_note", envelope)

    def test_unrecognized_shape_raises(self):
        with self.assertRaises(ValueError):
            learn.normalize_payload({"unexpected": True})

    def test_group_envelope_passthrough_and_hero_strip(self):
        body = {
            "schema_version": "1.0.0",
            "kind": "group",
            "group": {"slug": "hyperzen", "name": "HyperZen", "member_count": 1},
            "members": [
                {
                    "username": "alice",
                    "display_name": "Alice",
                    "report_slug": "abc",
                    "report_url": "https://insightharness.com/insights/alice/abc",
                    "profile": {
                        "skillInventory": [
                            {"name": "x", "hero_base64": "AAAA", "heroBase64": "BBBB"}
                        ]
                    },
                }
            ],
        }
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "group")
        self.assertEqual(envelope["kind"], "group")
        self.assertEqual(envelope["group"]["slug"], "hyperzen")
        entry = envelope["members"][0]["profile"]["skillInventory"][0]
        self.assertIsNone(entry["hero_base64"])
        self.assertIsNone(entry["heroBase64"])

    def test_group_envelope_with_tools_profile_strips_hero(self):
        body = {
            "kind": "group",
            "group": {"slug": "devs", "name": "Devs", "member_count": 1},
            "members": [
                {
                    "username": "bob",
                    "profile": {
                        "primaryTool": "codex",
                        "tools": {
                            "codex": {
                                "skillInventory": [
                                    {"name": "c", "heroBase64": "img"}
                                ]
                            }
                        },
                    },
                }
            ],
        }
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "group")
        entry = envelope["members"][0]["profile"]["tools"]["codex"]["skillInventory"][0]
        self.assertIsNone(entry["heroBase64"])

    def test_kind_absent_is_single_report_backcompat(self):
        # No kind key + schema_version → single-report agent mode, not group.
        body = {"schema_version": "1.0.0", "profile": {"skillInventory": []}}
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "agent")
        self.assertIs(envelope, body)

    def test_group_with_no_members_list_passthrough(self):
        body = {"kind": "group", "group": {"slug": "x", "name": "X", "member_count": 0}}
        envelope, mode = learn.normalize_payload(body)
        self.assertEqual(mode, "group")
        self.assertEqual(envelope["group"]["slug"], "x")


class StripHeroTests(unittest.TestCase):
    def test_strips_bare_inventory(self):
        out = learn._strip_hero(
            {"skillInventory": [{"name": "a", "hero_base64": "b", "hero_mime_type": "image/png"}]}
        )
        self.assertIsNone(out["skillInventory"][0]["hero_base64"])

    def test_strips_inside_tools_envelope(self):
        out = learn._strip_hero(
            {
                "primaryTool": "claude-code",
                "tools": {
                    "claude-code": {
                        "skillInventory": [{"name": "a", "hero_base64": "b"}]
                    }
                },
            }
        )
        self.assertIsNone(out["tools"]["claude-code"]["skillInventory"][0]["hero_base64"])

    def test_strips_codex_camelcase_hero(self):
        # codex_extract.py emits camelCase heroBase64 / heroMimeType.
        out = learn._strip_hero(
            {
                "tools": {
                    "codex": {
                        "skillInventory": [
                            {"name": "c", "heroBase64": "img", "heroMimeType": "image/png"}
                        ]
                    }
                }
            }
        )
        entry = out["tools"]["codex"]["skillInventory"][0]
        self.assertIsNone(entry["heroBase64"])
        self.assertIsNone(entry["heroMimeType"])


class FetchTests(unittest.TestCase):
    def test_fetch_sends_agent_accept_header(self):
        captured = {}

        def opener(request, timeout=None):
            captured["accept"] = request.get_header("Accept")
            captured["url"] = request.full_url
            return _fake_response(json.dumps({"schema_version": "1.0.0"}).encode())

        result = learn.fetch("https://x/api/insights/u/s", opener=opener)
        self.assertEqual(captured["accept"], learn.AGENT_MEDIA_TYPE)
        self.assertEqual(result, {"schema_version": "1.0.0"})

    def test_fetch_attaches_bearer_when_token_present(self):
        captured = {}

        def opener(request, timeout=None):
            # urllib title-cases header keys; get_header matches that.
            captured["auth"] = request.get_header("Authorization")
            return _fake_response(json.dumps({"kind": "group"}).encode())

        learn.fetch("https://x/api/groups/hyperzen", opener=opener, token=VALID_TOKEN)
        self.assertEqual(captured["auth"], f"Bearer {VALID_TOKEN}")

    def test_fetch_no_auth_header_without_token(self):
        captured = {}

        def opener(request, timeout=None):
            captured["auth"] = request.get_header("Authorization")
            return _fake_response(json.dumps({"schema_version": "1.0.0"}).encode())

        learn.fetch("https://x/api/insights/u/s", opener=opener)
        self.assertIsNone(captured["auth"])


class MainTests(unittest.TestCase):
    def _run(self, target, *, fetch_return=None, fetch_raises=None, token=None):
        out, err = io.StringIO(), io.StringIO()
        captured = {}

        # main() passes token=... into fetch; accept and record it.
        def fake_fetch(api_url, opener=None, token=None):
            captured["api_url"] = api_url
            captured["token"] = token
            if fetch_raises is not None:
                raise fetch_raises
            return fetch_return

        # Keep the test hermetic — never read the real on-disk config.
        with patch.object(learn, "fetch", side_effect=fake_fetch), patch.object(
            learn, "load_bearer_token", return_value=token
        ), patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
            rc = learn.main([target])
        self._captured = captured
        return rc, out.getvalue(), err.getvalue()

    def test_agent_payload_prints_envelope_and_exits_0(self):
        rc, out, _ = self._run(
            "savraj/20260422-5ayf16",
            fetch_return={"schema_version": "1.0.0", "profile": {"skillInventory": []}},
        )
        self.assertEqual(rc, 0)
        printed = json.loads(out)
        self.assertEqual(printed["schema_version"], "1.0.0")

    def test_fallback_warns_but_succeeds(self):
        rc, out, err = self._run(
            "u/s",
            fetch_return={"data": {"harnessData": {"skillInventory": []}}},
        )
        self.assertEqual(rc, 0)
        self.assertIn("WARNING", err)
        self.assertIsNone(json.loads(out)["schema_version"])

    def test_404_returns_1(self):
        err404 = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        rc, _, err = self._run("u/missing", fetch_raises=err404)
        self.assertEqual(rc, 1)
        self.assertIn("404", err)

    def test_bad_target_returns_2(self):
        rc, _, err = self._run("not-a-valid-target")
        self.assertEqual(rc, 2)
        self.assertIn("ERROR", err)

    def test_join_invite_target_returns_2(self):
        rc, _, err = self._run("https://insightharness.com/g/join/deadbeef")
        self.assertEqual(rc, 2)
        self.assertIn("invite", err.lower())

    def test_group_payload_prints_and_routes_to_group_api(self):
        rc, out, _ = self._run(
            "https://insightharness.com/g/hyperzen",
            fetch_return={
                "kind": "group",
                "group": {"slug": "hyperzen", "name": "HyperZen", "member_count": 0},
                "members": [],
            },
        )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["kind"], "group")
        self.assertEqual(
            self._captured["api_url"],
            "https://insightharness.com/api/groups/hyperzen",
        )

    def test_token_is_threaded_into_fetch(self):
        self._run(
            "g/hyperzen",
            fetch_return={"kind": "group", "group": {"slug": "hyperzen", "name": "H", "member_count": 0}},
            token=VALID_TOKEN,
        )
        self.assertEqual(self._captured["token"], VALID_TOKEN)

    def test_group_401_explains_membership(self):
        err401 = urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)
        rc, _, err = self._run("g/hyperzen", fetch_raises=err401)
        self.assertEqual(rc, 1)
        self.assertIn("membership", err.lower())

    def test_group_403_explains_membership(self):
        err403 = urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
        rc, _, err = self._run("g/hyperzen", fetch_raises=err403)
        self.assertEqual(rc, 1)
        self.assertIn("membership", err.lower())

    def test_group_404_says_no_such_group(self):
        err404 = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        rc, _, err = self._run("g/missing", fetch_raises=err404)
        self.assertEqual(rc, 1)
        self.assertIn("no such group", err.lower())


if __name__ == "__main__":
    unittest.main()
