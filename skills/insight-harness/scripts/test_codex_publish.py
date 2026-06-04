"""Unit tests for the --publish / --token / --confirm flow in codex_extract.py.

The Codex extractor reuses extract.py's publish helpers verbatim against a
strictly Codex-local token config (CODEX_PUBLISH_CONFIG_PATH) — see
docs/plans/2026-06-02-001-feat-codex-direct-publish-plan.md (target repo
insight-harness). These tests cover the client wiring, not the helper
internals (which test_publish.py already exercises):

- token-only persistence to the Codex config (0600) and the KTD-3 ordering
  guarantee (works even when ~/.codex is absent)
- KTD-2 self-containment: --publish never reads the Claude token path
- the publish dispatch threads --confirm and the Codex report_path through
- a real RESULT: (200) / LOCAL: (401) / non-TTY-confirm round-trip via a
  faked urlopen, proving the final-stdout-line contract (KTD-5)

codex_extract.main() RETURNS an exit code (the __main__ guard calls
sys.exit(main())), so these assert on the return value rather than catching
SystemExit the way the extract.py tests do.
"""

from __future__ import annotations

import io
import json
import stat
import sys
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import codex_extract  # noqa: E402
import extract  # noqa: E402


VALID_TOKEN = "ih_" + ("a" * 12) + ("b" * 64)


def _fake_response(status, body=b"", headers=None):
    """Build a urllib-like response object usable as a fake `urlopen`."""
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


class TokenOnlyTests(unittest.TestCase):
    """`--token` without `--publish`: persist to the Codex config and exit."""

    def test_token_alone_writes_codex_config_and_exits_0(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "insight-harness" / "config.json"
            with patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg), \
                 patch.object(sys, "stderr", io.StringIO()):
                rc = codex_extract.main(["--token", VALID_TOKEN])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(cfg.read_text()), {"token": VALID_TOKEN})
            self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), 0o600)

    def test_token_alone_works_when_codex_dir_absent(self):
        """KTD-3: token persistence runs BEFORE the no-~/.codex early return,
        so `--token` alone still saves on a fresh Codex machine."""
        with TemporaryDirectory() as d:
            missing_codex = Path(d) / "does-not-exist"
            cfg = Path(d) / "insight-harness" / "config.json"
            with patch.object(codex_extract, "CODEX_DIR", missing_codex), \
                 patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg), \
                 patch.object(sys, "stderr", io.StringIO()):
                rc = codex_extract.main(["--token", VALID_TOKEN])
            self.assertEqual(rc, 0)
            self.assertTrue(cfg.exists())
            self.assertEqual(json.loads(cfg.read_text()), {"token": VALID_TOKEN})

    def test_token_alone_malformed_exits_2_and_writes_nothing(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "insight-harness" / "config.json"
            with patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg), \
                 patch.object(sys, "stderr", io.StringIO()):
                rc = codex_extract.main(["--token", "garbage"])
            self.assertEqual(rc, 2)
            self.assertFalse(cfg.exists())


class SelfContainedTokenTests(unittest.TestCase):
    """KTD-2: --publish resolves only the Codex token path, never Claude's."""

    def test_publish_without_codex_token_exits_2_and_only_reads_codex_path(self):
        with TemporaryDirectory() as d:
            cfg = Path(d) / "insight-harness" / "config.json"  # does not exist
            seen_paths = []
            real_load = codex_extract.load_token_from_config

            def spy_load(config_path=None):
                seen_paths.append(config_path)
                return real_load(config_path=config_path)

            buf_err = io.StringIO()
            with patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg), \
                 patch.object(codex_extract, "load_token_from_config", spy_load), \
                 patch.object(sys, "stderr", buf_err):
                rc = codex_extract.main(["--publish"])
            self.assertEqual(rc, 2)
            self.assertIn("No token configured", buf_err.getvalue())
            # Resolved exactly once, against the Codex config path only.
            self.assertEqual(seen_paths, [cfg])

    def test_publish_never_falls_back_to_a_valid_claude_token(self):
        """Behavioral guard (stronger than the spy above): even with a VALID
        token sitting at the Claude default config path, Codex --publish with no
        Codex token must still exit 2. A regression that read the Claude path —
        by any route, not just load_token_from_config(config_path=...) — would
        find this token, proceed past the exit-2, and fail this test."""
        with TemporaryDirectory() as d:
            codex_cfg = Path(d) / "codex" / "insight-harness" / "config.json"  # absent
            claude_cfg = Path(d) / "claude" / "insight-harness" / "config.json"
            # Plant a valid token at the Claude default location.
            codex_extract.save_token_to_config(VALID_TOKEN, config_path=claude_cfg)
            buf_err = io.StringIO()
            with patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", codex_cfg), \
                 patch.object(extract, "PUBLISH_CONFIG_PATH", claude_cfg), \
                 patch.object(sys, "stderr", buf_err):
                rc = codex_extract.main(["--publish"])
            self.assertEqual(rc, 2)
            self.assertIn("No token configured", buf_err.getvalue())


class PublishDispatchWiringTests(unittest.TestCase):
    """main() threads --confirm and the Codex report_path into publish_report
    and propagates its exit code, without re-running the publish internals."""

    def _publish_patches(self, d, fake_publish):
        codex_dir = Path(d) / "codex"
        codex_dir.mkdir()
        usage = codex_dir / "usage-data"
        report = usage / "report.html"
        cfg = codex_dir / "insight-harness" / "config.json"
        codex_extract.save_token_to_config(VALID_TOKEN, config_path=cfg)
        return [
            patch.object(codex_extract, "CODEX_DIR", codex_dir),
            patch.object(codex_extract, "CODEX_USAGE_DATA_DIR", usage),
            patch.object(codex_extract, "CODEX_PUBLISH_REPORT_PATH", report),
            patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg),
            patch.object(
                codex_extract, "generate_profile",
                return_value=("<html></html>", {}, {}),
            ),
            patch.object(codex_extract, "publish_report", side_effect=fake_publish),
            patch.object(sys, "stderr", io.StringIO()),
        ], report

    def test_publish_threads_confirm_token_and_report_path(self):
        captured = {}

        def fake_publish(html_bytes, token, confirm=False, report_path=None, **kw):
            captured.update(
                html=html_bytes, token=token, confirm=confirm,
                report_path=report_path,
            )
            return 0

        with TemporaryDirectory() as d:
            patches, report = self._publish_patches(d, fake_publish)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--publish", "--confirm"])

        self.assertEqual(rc, 0)
        self.assertTrue(captured["confirm"])
        self.assertEqual(captured["token"], VALID_TOKEN)
        self.assertEqual(captured["report_path"], report)
        self.assertEqual(captured["html"], b"<html></html>")

    def test_publish_propagates_nonzero_rc(self):
        with TemporaryDirectory() as d:
            patches, _ = self._publish_patches(d, lambda *a, **k: 2)
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--publish"])
        self.assertEqual(rc, 2)


class PublishRoundTripTests(unittest.TestCase):
    """Real publish_report through main(), faking only the network, to prove
    the RESULT:/LOCAL: final-stdout-line contract end to end."""

    def _real_publish_patches(self, d):
        codex_dir = Path(d) / "codex"
        codex_dir.mkdir()
        usage = codex_dir / "usage-data"
        report = usage / "report.html"
        cfg = codex_dir / "insight-harness" / "config.json"
        codex_extract.save_token_to_config(VALID_TOKEN, config_path=cfg)
        return [
            patch.object(codex_extract, "CODEX_DIR", codex_dir),
            patch.object(codex_extract, "CODEX_USAGE_DATA_DIR", usage),
            patch.object(codex_extract, "CODEX_PUBLISH_REPORT_PATH", report),
            patch.object(codex_extract, "CODEX_PUBLISH_CONFIG_PATH", cfg),
            patch.object(
                codex_extract, "generate_profile",
                return_value=("<html></html>", {}, {}),
            ),
            # publish_report internals live in extract; silence the clipboard.
            patch.object(extract, "copy_to_clipboard", MagicMock(return_value=True)),
        ], report

    def test_publish_200_emits_RESULT_and_returns_0(self):
        edit_url = "https://insightharness.com/insights/u/s/edit"
        body = json.dumps({"editUrl": edit_url}).encode()
        out = io.StringIO()
        with TemporaryDirectory() as d:
            patches, _ = self._real_publish_patches(d)
            patches += [
                patch("extract.urllib.request.urlopen",
                      return_value=_fake_response(200, body)),
                patch.object(sys, "stdout", out),
                patch.object(sys, "stderr", io.StringIO()),
            ]
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--publish"])
        self.assertEqual(rc, 0)
        last_line = out.getvalue().strip().splitlines()[-1]
        self.assertEqual(last_line, "RESULT: " + edit_url)

    def test_publish_401_emits_LOCAL_under_codex_report_path_and_returns_2(self):
        def raise_401(*a, **k):
            raise urllib.error.HTTPError(
                "https://insightharness.com/api/upload", 401, "Unauthorized",
                {}, io.BytesIO(b'{"error":"bad token"}'),
            )

        out = io.StringIO()
        with TemporaryDirectory() as d:
            patches, report = self._real_publish_patches(d)
            patches += [
                patch("extract.urllib.request.urlopen", side_effect=raise_401),
                patch.object(sys, "stdout", out),
                patch.object(sys, "stderr", io.StringIO()),
            ]
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--publish"])
            # Assert inside the with-block — `report` lives under the temp dir,
            # which is removed once the block exits.
            saved_exists = report.exists()  # stable copy saved on failure
        self.assertEqual(rc, 2)
        last_line = out.getvalue().strip().splitlines()[-1]
        self.assertEqual(last_line, "LOCAL: " + str(report))
        self.assertTrue(saved_exists)

    def test_publish_confirm_non_tty_skips_post_and_returns_0(self):
        """KTD-5: non-TTY --confirm saves locally, prints LOCAL:, exits 0,
        and never hits the network."""
        urlopen = MagicMock()
        out = io.StringIO()
        with TemporaryDirectory() as d:
            patches, report = self._real_publish_patches(d)
            patches += [
                patch("extract.urllib.request.urlopen", urlopen),
                patch("sys.stdin.isatty", return_value=False),
                patch.object(sys, "stdout", out),
                patch.object(sys, "stderr", io.StringIO()),
            ]
            for p in patches:
                p.start()
            self.addCleanup(lambda ps=patches: [p.stop() for p in ps])
            rc = codex_extract.main(["--publish", "--confirm"])
        self.assertEqual(rc, 0)
        urlopen.assert_not_called()
        last_line = out.getvalue().strip().splitlines()[-1]
        self.assertEqual(last_line, "LOCAL: " + str(report))


if __name__ == "__main__":
    unittest.main()
