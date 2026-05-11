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
