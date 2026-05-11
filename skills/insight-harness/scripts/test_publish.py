"""Unit tests for the --publish / --token / --confirm flow in extract.py.

Covers the scenarios in Unit 11 of the tokenized direct-post plan:
- token validation
- config file persistence + 0600 mode
- 200 / 401 / 429 / 5xx / network-error response handling
- non-TTY --confirm short-circuit
- defensive re-chmod when config perms drift
"""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402


VALID_TOKEN = "ih_" + ("a" * 12) + ("b" * 64)


def _fake_response(status, body=b"", headers=None):
    """Build a urllib-like response object usable as a fake `opener`."""
    headers = headers or {}

    class _Resp:
        def __init__(self):
            self.status = status
            self._body = body
            self.headers = headers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return self._body

    return _Resp()


class TokenValidationTests(unittest.TestCase):
    def test_valid_token_passes(self):
        self.assertTrue(extract.is_valid_token(VALID_TOKEN))

    def test_wrong_prefix_rejected(self):
        self.assertFalse(extract.is_valid_token("ip_" + ("a" * 76)))

    def test_short_token_rejected(self):
        self.assertFalse(extract.is_valid_token("ih_abc"))

    def test_uppercase_rejected(self):
        self.assertFalse(extract.is_valid_token("ih_" + ("A" * 12) + ("b" * 64)))

    def test_non_hex_rejected(self):
        self.assertFalse(extract.is_valid_token("ih_" + ("g" * 12) + ("b" * 64)))

    def test_extra_chars_rejected(self):
        self.assertFalse(extract.is_valid_token(VALID_TOKEN + "x"))

    def test_none_rejected(self):
        self.assertFalse(extract.is_valid_token(None))


class ConfigPersistenceTests(unittest.TestCase):
    def test_save_token_writes_0600_file(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            extract.save_token_to_config(VALID_TOKEN, config_path=path)
            data = json.loads(path.read_text())
            self.assertEqual(data, {"token": VALID_TOKEN})
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_save_token_rejects_malformed(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            with self.assertRaises(ValueError):
                extract.save_token_to_config("not-a-token", config_path=path)
            self.assertFalse(path.exists())

    def test_load_token_returns_none_when_missing(self):
        with TemporaryDirectory() as d:
            self.assertIsNone(
                extract.load_token_from_config(config_path=Path(d) / "config.json")
            )

    def test_load_token_round_trips(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            extract.save_token_to_config(VALID_TOKEN, config_path=path)
            self.assertEqual(
                extract.load_token_from_config(config_path=path),
                VALID_TOKEN,
            )

    def test_load_token_re_chmods_when_perms_drift(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            extract.save_token_to_config(VALID_TOKEN, config_path=path)
            os.chmod(path, 0o644)
            extract.load_token_from_config(config_path=path)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_load_token_rejects_malformed_token_in_file(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            path.write_text(json.dumps({"token": "garbage"}))
            self.assertIsNone(extract.load_token_from_config(config_path=path))

    def test_load_token_rejects_unparseable_json(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            path.write_text("not-json{")
            self.assertIsNone(extract.load_token_from_config(config_path=path))


class PostReportTests(unittest.TestCase):
    def test_success_returns_status_body_headers(self):
        body = json.dumps({"editUrl": "https://example/edit", "slug": "s"}).encode()
        opener = lambda req, timeout=None: _fake_response(  # noqa: E731
            200, body=body, headers={"X-Test": "1"}
        )
        status, raw, headers = extract.post_report(
            b"<html></html>", VALID_TOKEN, upload_id="u-1", base_url="http://x", opener=opener
        )
        self.assertEqual(status, 200)
        self.assertEqual(raw, body)
        self.assertEqual(headers.get("X-Test"), "1")

    def test_http_error_captured_as_response_tuple(self):
        def opener(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized",
                {"Content-Type": "application/json"},
                io.BytesIO(b'{"error":"bad token"}'),
            )

        status, body, headers = extract.post_report(
            b"<html></html>", VALID_TOKEN, opener=opener
        )
        self.assertEqual(status, 401)
        self.assertEqual(body, b'{"error":"bad token"}')

    def test_request_carries_bearer_and_upload_id(self):
        captured = {}

        def opener(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            captured["body"] = req.data
            return _fake_response(200, body=b'{"editUrl":"u"}')

        extract.post_report(
            b"<html>hi</html>",
            VALID_TOKEN,
            upload_id="upload-123",
            base_url="http://localhost:3000",
            opener=opener,
        )
        self.assertEqual(captured["url"], "http://localhost:3000/api/upload")
        self.assertEqual(
            captured["headers"]["authorization"], "Bearer " + VALID_TOKEN
        )
        self.assertEqual(captured["headers"]["x-upload-id"], "upload-123")
        self.assertEqual(
            captured["headers"]["content-type"], "application/octet-stream"
        )
        self.assertEqual(captured["body"], b"<html>hi</html>")


class PublishReportTests(unittest.TestCase):
    def test_200_prints_result_line_and_exits_0(self):
        body = json.dumps({"editUrl": "https://insightful.com/edit/abc"}).encode()
        opener = lambda req, timeout=None: _fake_response(200, body=body)  # noqa: E731
        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_out = io.StringIO()
            with patch("extract.copy_to_clipboard", return_value=True), \
                 patch.object(sys, "stdout", buf_out):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    report_path=report, opener=opener,
                )
            self.assertEqual(rc, 0)
            self.assertEqual(
                buf_out.getvalue().strip().splitlines()[-1],
                "RESULT: https://insightful.com/edit/abc",
            )

    def test_401_saves_html_and_exits_2(self):
        opener = lambda req, timeout=None: _fake_response(401, body=b'{"error":"bad"}')  # noqa: E731
        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_err = io.StringIO()
            with patch.object(sys, "stderr", buf_err):
                rc = extract.publish_report(
                    b"<html>payload</html>", VALID_TOKEN,
                    report_path=report, opener=opener,
                )
            self.assertEqual(rc, 2)
            self.assertTrue(report.exists())
            self.assertIn("expired or revoked", buf_err.getvalue())

    def test_429_surfaces_retry_after(self):
        opener = lambda req, timeout=None: _fake_response(  # noqa: E731
            429,
            body=b'{"error":"rate limited"}',
            headers={"Retry-After": "3600"},
        )
        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_err = io.StringIO()
            with patch.object(sys, "stderr", buf_err):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    report_path=report, opener=opener,
                )
            self.assertEqual(rc, 2)
            self.assertIn("3600", buf_err.getvalue())
            self.assertIn("rate limited", buf_err.getvalue())

    def test_5xx_saves_locally_and_exits_2(self):
        opener = lambda req, timeout=None: _fake_response(503, body=b'{"error":"down"}')  # noqa: E731
        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_err = io.StringIO()
            with patch.object(sys, "stderr", buf_err):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    report_path=report, opener=opener,
                )
            self.assertEqual(rc, 2)
            self.assertTrue(report.exists())
            self.assertIn("Upload failed", buf_err.getvalue())

    def test_network_error_saves_locally_and_exits_2(self):
        def opener(req, timeout=None):
            raise urllib.error.URLError("Connection refused")

        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_err = io.StringIO()
            with patch.object(sys, "stderr", buf_err):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    report_path=report, opener=opener,
                )
            self.assertEqual(rc, 2)
            self.assertTrue(report.exists())
            self.assertIn("Network error", buf_err.getvalue())

    def test_confirm_non_tty_skips_post(self):
        called = {"hit": False}

        def opener(req, timeout=None):
            called["hit"] = True
            return _fake_response(200, body=b'{"editUrl":"x"}')

        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_err = io.StringIO()
            with patch("sys.stdin.isatty", return_value=False), \
                 patch.object(sys, "stderr", buf_err):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    confirm=True, report_path=report, opener=opener,
                )
            self.assertEqual(rc, 0)
            self.assertFalse(called["hit"])
            self.assertTrue(report.exists())

    def test_confirm_yes_proceeds(self):
        opener = lambda req, timeout=None: _fake_response(  # noqa: E731
            200,
            body=json.dumps({"editUrl": "https://insightful.com/edit/z"}).encode(),
        )
        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            buf_out = io.StringIO()
            with patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value="y"), \
                 patch("extract.copy_to_clipboard", return_value=False), \
                 patch.object(sys, "stdout", buf_out):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    confirm=True, report_path=report, opener=opener,
                )
            self.assertEqual(rc, 0)
            self.assertIn("RESULT:", buf_out.getvalue())

    def test_confirm_no_skips(self):
        called = {"hit": False}

        def opener(req, timeout=None):
            called["hit"] = True
            return _fake_response(200, body=b'{"editUrl":"x"}')

        with TemporaryDirectory() as d:
            report = Path(d) / "report.html"
            with patch("sys.stdin.isatty", return_value=True), \
                 patch("builtins.input", return_value="n"), \
                 patch.object(sys, "stderr", io.StringIO()):
                rc = extract.publish_report(
                    b"<html></html>", VALID_TOKEN,
                    confirm=True, report_path=report, opener=opener,
                )
            self.assertEqual(rc, 0)
            self.assertFalse(called["hit"])


class MainWiringTests(unittest.TestCase):
    """Light-touch tests that main() routes the publish flags correctly.

    These don't run the full extraction pipeline — they short-circuit by
    asserting early-exit behavior (e.g. --token alone, --publish without
    config) so they stay fast and don't depend on a real ~/.claude tree.
    """

    def test_token_alone_writes_config_and_exits_0(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "config.json"
            with patch("extract.PUBLISH_CONFIG_PATH", cfg):
                with patch.object(sys, "stderr", io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        extract.main(["--token", VALID_TOKEN])
            self.assertEqual(ctx.exception.code, 0)
            data = json.loads(cfg.read_text())
            self.assertEqual(data, {"token": VALID_TOKEN})

    def test_token_alone_with_malformed_exits_2(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "config.json"
            with patch("extract.PUBLISH_CONFIG_PATH", cfg):
                with patch.object(sys, "stderr", io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        extract.main(["--token", "garbage"])
            self.assertEqual(ctx.exception.code, 2)
            self.assertFalse(cfg.exists())

    def test_publish_without_token_or_config_exits_2(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "config.json"  # does not exist
            with patch("extract.PUBLISH_CONFIG_PATH", cfg):
                buf_err = io.StringIO()
                with patch.object(sys, "stderr", buf_err):
                    with self.assertRaises(SystemExit) as ctx:
                        extract.main(["--publish"])
            self.assertEqual(ctx.exception.code, 2)
            self.assertIn("No token configured", buf_err.getvalue())

    def test_publish_passes_confirm_through(self):
        """Wiring test: --publish --confirm must reach publish_report(confirm=True).

        Regression coverage for the P1 finding where main() dropped the
        --confirm flag. We mock out the entire extraction pipeline and
        assert on the args that reach publish_report.
        """
        captured = {}

        def fake_publish(html_bytes, token, confirm=False, **kw):
            captured["confirm"] = confirm
            captured["token"] = token
            return 0

        with TemporaryDirectory() as d:
            cfg = Path(d) / "config.json"
            # Seed the config so --publish doesn't bail early.
            extract.save_token_to_config(VALID_TOKEN, config_path=cfg)

            # Stub every heavy extractor to a no-op return + dated_path
            # write. We patch the writer step by intercepting publish_report
            # after the HTML is generated.
            patches = [
                patch("extract.PUBLISH_CONFIG_PATH", cfg),
                patch("extract.publish_report", side_effect=fake_publish),
                patch("extract.extract_settings", return_value={"hooks": []}),
                patch("extract.extract_installed_plugins", return_value=[]),
                patch("extract.extract_skill_inventory", return_value=[]),
                patch("extract.extract_hook_scripts", return_value={}),
                patch("extract.extract_custom_agents", return_value=[]),
                patch("extract.extract_harness_files", return_value={}),
                patch("extract.extract_session_meta", return_value=[]),
                patch("extract.aggregate_session_meta", return_value={}),
                patch("extract.extract_jsonl_metadata", return_value={}),
                patch("extract.extract_permissions_profile", return_value={}),
                patch("extract.extract_insights_report", return_value=None),
                patch("extract.extract_safety_posture", return_value={}),
                patch("extract.extract_experimental_features", return_value={}),
                patch("extract.extract_stats_cache", return_value={}),
                patch("extract.extract_instruction_maturity", return_value={}),
                patch("extract.extract_memory_architecture", return_value={}),
                patch("extract.extract_agent_details", return_value=[]),
                patch("extract.extract_team_configs", return_value={}),
                patch("extract.extract_marketplace_diversity", return_value={}),
                patch("extract.extract_statusline", return_value={}),
                patch("extract.extract_ide_integration", return_value={}),
                patch("extract.extract_hybrid_tools", return_value={}),
                patch("extract.extract_blocklist_issues", return_value={}),
                patch("extract.extract_permission_accumulation", return_value={}),
                patch("extract.compute_throughput_total_tokens", return_value=0),
                patch("extract.generate_html", return_value="<html></html>"),
                patch("extract.CLAUDE_DIR", Path(d)),
                patch("extract.check_for_updates"),
                patch.object(sys, "stderr", io.StringIO()),
            ]
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])

            with self.assertRaises(SystemExit) as ctx:
                extract.main(["--publish", "--confirm"])

            self.assertEqual(ctx.exception.code, 0)
            self.assertTrue(captured.get("confirm"))
            self.assertEqual(captured.get("token"), VALID_TOKEN)


class ConfigPermsTests(unittest.TestCase):
    """The token must never be on disk with world/group-readable perms."""

    def test_save_creates_file_with_0600_perms_even_with_loose_umask(self):
        old_umask = os.umask(0o022)
        try:
            with TemporaryDirectory() as d:
                path = Path(d) / "config.json"
                extract.save_token_to_config(VALID_TOKEN, config_path=path)
                mode = stat.S_IMODE(path.stat().st_mode)
                self.assertEqual(mode, 0o600, oct(mode))
        finally:
            os.umask(old_umask)

    def test_save_tightens_existing_loose_file(self):
        """If a pre-existing config.json is 0644, save_token must clamp to 0600."""
        with TemporaryDirectory() as d:
            path = Path(d) / "config.json"
            path.write_text("{}")
            os.chmod(path, 0o644)
            extract.save_token_to_config(VALID_TOKEN, config_path=path)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600, oct(mode))


class BaseUrlTests(unittest.TestCase):
    def test_env_var_overrides_default(self):
        with patch.dict(os.environ, {extract.PUBLISH_BASE_URL_ENV: "http://localhost:3000"}):
            self.assertEqual(extract.publish_base_url(), "http://localhost:3000")

    def test_default_is_production(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(extract.PUBLISH_BASE_URL_ENV, None)
            self.assertEqual(
                extract.publish_base_url(),
                extract.PUBLISH_DEFAULT_BASE_URL,
            )


if __name__ == "__main__":
    unittest.main()
