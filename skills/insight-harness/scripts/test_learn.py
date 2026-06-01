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


class MainTests(unittest.TestCase):
    def _run(self, target, *, fetch_return=None, fetch_raises=None):
        out, err = io.StringIO(), io.StringIO()

        def fake_fetch(api_url, opener=None):
            if fetch_raises is not None:
                raise fetch_raises
            return fetch_return

        with patch.object(learn, "fetch", side_effect=fake_fetch), patch.object(
            sys, "stdout", out
        ), patch.object(sys, "stderr", err):
            rc = learn.main([target])
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


if __name__ == "__main__":
    unittest.main()
