"""Tests for hook-command scrubbing (Phase 0 F5 / brainstorm R13).

Hook commands are now exposed (scrubbed) in the agent payload so a consumer can
copy a hook config. The load-bearing safety property: a known secret-token shape
must never ship — the WHOLE command is redacted if one is present. Identity and
path PII are scrubbed by the standard rules.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402

# A deterministic rule so scrubbing is testable without depending on the
# machine's actual git config / username.
USER_PATH_RULE = [(re.compile(r"/Users/[^/\s]+"), "/Users/<user>")]


class ScrubHookCommandTests(unittest.TestCase):
    def test_empty_command(self):
        self.assertEqual(extract.scrub_hook_command("", USER_PATH_RULE), "")

    def test_safe_command_passes_through(self):
        cmd = "jq -r '.tool_input.command'"
        self.assertEqual(extract.scrub_hook_command(cmd, USER_PATH_RULE), cmd)

    def test_path_collapses_to_placeholder(self):
        # Paths become <path> wholesale — the basename lives in the `script`
        # field, so nothing path-shaped (incl. the basename) ships here.
        out = extract.scrub_hook_command(
            "python3 /Users/alice/.claude/hooks/guard.py", USER_PATH_RULE
        )
        self.assertEqual(out, "python3 <path>")
        self.assertNotIn("alice", out)

    def test_project_or_client_name_in_path_is_dropped(self):
        # Regression guard: NO path segment (intermediate or basename) leaks;
        # flags are preserved.
        out = extract.scrub_hook_command(
            "python3 /Users/alice/Coding/secret-client/hooks/guard.py --strict",
            USER_PATH_RULE,
        )
        self.assertEqual(out, "python3 <path> --strict")
        self.assertNotIn("secret-client", out)
        self.assertNotIn("Coding", out)
        self.assertNotIn("alice", out)

    def test_directory_valued_path_name_is_dropped(self):
        # The hard case: a directory path's basename IS the private name.
        out = extract.scrub_hook_command(
            "cd /Users/alice/Coding/acme-client && lint", USER_PATH_RULE
        )
        self.assertNotIn("acme-client", out)
        self.assertEqual(out, "cd <path> && lint")

    def test_shell_wrapper_command_preserves_actions(self):
        # bash -lc "..." wraps a whole snippet; only the path inside collapses,
        # the actions (&& npm test) must survive so the hook stays copyable.
        out = extract.scrub_hook_command(
            'bash -lc "cd /Users/me/app && npm test"', USER_PATH_RULE
        )
        self.assertNotIn("me/app", out)
        self.assertIn("npm test", out)
        self.assertIn("cd <path>", out)
        self.assertNotEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_backslash_escaped_space_path_does_not_leak(self):
        # An escaped-space path (cd ~/Coding/acme\ client) must stay one token so
        # the "client" segment can't leak out the side.
        out = extract.scrub_hook_command(
            "cd /Users/alice/Coding/acme\\ client && lint", USER_PATH_RULE
        )
        self.assertNotIn("client", out)
        self.assertEqual(out, "cd <path> && lint")

    def test_ih_publish_token_redacts(self):
        token = "ih_" + ("a" * 12) + ("b" * 64)
        out = extract.scrub_hook_command(
            f"python3 extract.py --token={token}", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_bearer_token_redacts_whole_command(self):
        out = extract.scrub_hook_command(
            "curl -H 'Authorization: Bearer abcDEF123456789' https://x", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_openai_style_key_redacts(self):
        out = extract.scrub_hook_command("echo sk-abcd1234efgh5678", USER_PATH_RULE)
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_underscore_bearing_sk_token_redacts(self):
        # Anthropic-style sk- tokens contain underscores (e.g. sk-ant-api03_...);
        # the char class must include `_` like the codex_extract gate does.
        out = extract.scrub_hook_command(
            "echo sk-ant-api03_AbCd1234EfGh5678", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_github_token_variants_redact(self):
        for tok in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
            out = extract.scrub_hook_command(
                f"git remote set-url o https://{tok}AbCd12345678@github.com/x",
                USER_PATH_RULE,
            )
            self.assertEqual(out, extract.HOOK_COMMAND_REDACTED, tok)

    def test_aws_key_redacts(self):
        out = extract.scrub_hook_command(
            "export AWS_KEY=AKIAIOSFODNN7EXAMPLE", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_lowercase_bearer_redacts(self):
        # HTTP auth schemes are case-insensitive; "bearer" must still trip.
        out = extract.scrub_hook_command(
            "curl -H 'authorization: bearer abcDEF123456789' https://x", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_fine_grained_github_pat_redacts(self):
        out = extract.scrub_hook_command(
            "git push https://github_pat_ABC123def456@github.com/x", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_slack_token_redacts(self):
        out = extract.scrub_hook_command(
            "echo xoxb-12345678-abcdEFGH", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_slack_webhook_url_redacts(self):
        out = extract.scrub_hook_command(
            "curl -X POST https://hooks.slack.com/services/T00/B00/abcDEF123 -d x",
            USER_PATH_RULE,
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_discord_webhook_url_redacts(self):
        out = extract.scrub_hook_command(
            "curl https://discord.com/api/webhooks/123/abcDEF_token -d x", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_credentials_in_url_redacts(self):
        out = extract.scrub_hook_command(
            "curl https://user:s3cr3tpass@example.com/notify", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_non_http_credential_url_redacts(self):
        # Credentials in any-scheme URL (postgres://, redis://, ...) must redact.
        out = extract.scrub_hook_command(
            "psql postgres://user:s3cr3tpass@db.internal", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_quoted_path_with_spaces_does_not_leak_segment(self):
        # A quoted path whose private segment contains a space must not leak by
        # being split across tokens (shlex keeps it whole).
        out = extract.scrub_hook_command(
            'python3 "/Users/alice/Coding/acme client/hooks/guard.py"',
            USER_PATH_RULE,
        )
        self.assertNotIn("acme", out)
        self.assertNotIn("client", out)
        self.assertIn("<path>", out)
        self.assertNotEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_gitlab_pat_redacts(self):
        out = extract.scrub_hook_command(
            # Deliberately not 20 chars so GitHub push-protection doesn't flag a
            # fake fixture, but still matches our glpat-{8,} gate.
            "curl -H 'PRIVATE-TOKEN: glpat-EXAMPLE-NOT-REAL' x", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_generic_high_entropy_token_redacts(self):
        # The entropy backstop catches unknown token families (no prefix needed):
        # a 32-char opaque run is treated as a credential.
        out = extract.scrub_hook_command(
            "deploy --key Xq7Saur42bG9mZ1pVw3KtY6Lc0Nf8Hd", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)

    def test_long_segmented_path_not_entropy_redacted(self):
        # Paths/identifiers break into short low-entropy runs, so a long script
        # path collapses to <path> (not redacted to the secret marker).
        out = extract.scrub_hook_command(
            "python3 /opt/hooks/validate_file_write_and_format_runner.py",
            USER_PATH_RULE,
        )
        self.assertEqual(out, "python3 <path>")

    def test_ordinary_path_command_not_redacted(self):
        # A normal script hook stays useful: path -> <path> (not the secret
        # marker), binary + flags preserved.
        out = extract.scrub_hook_command(
            "python3 /opt/tools/.claude/hooks/format_and_lint_runner.py --fix",
            USER_PATH_RULE,
        )
        self.assertEqual(out, "python3 <path> --fix")

    def test_benign_sk_substring_not_redacted(self):
        # "ta-sk-", "ma-sk-" etc.: an incidental sk- inside a word must NOT trip
        # the credential gate (it only fires at a token boundary). No paths here,
        # so the commands pass through unchanged.
        for cmd in (
            "task-formatter --check",
            "mask-secrets-runner --once",
            "disk-usage-report.sh",
        ):
            self.assertEqual(
                extract.scrub_hook_command(cmd, USER_PATH_RULE), cmd, cmd
            )

    def test_ssh_git_remote_owner_is_dropped(self):
        # SSH remotes (git@host:owner/repo) collapse to <path>, owner included.
        out = extract.scrub_hook_command(
            "git clone git@github.com:private-org/repo.git", USER_PATH_RULE
        )
        self.assertNotIn("private-org", out)
        self.assertEqual(out, "git clone <path>")

    def test_relative_path_project_name_dropped(self):
        # Bare relative paths leak their first segment too — collapse them.
        out = extract.scrub_hook_command(
            "bash myproject/hooks/run.sh", USER_PATH_RULE
        )
        self.assertNotIn("myproject", out)
        self.assertEqual(out, "bash <path>")

    def test_urls_are_dropped_wholesale(self):
        # URLs become <url> — host, path, query, and fragment all dropped, so
        # internal hosts and query-string tokens can't leak.
        for cmd, banned in (
            ("curl https://internal.corp/v1/notify", "internal.corp"),
            ("curl https://internal.corp", "internal.corp"),
            ("curl https://api.example.com/notify?token=s3cr3tvalue", "s3cr3tvalue"),
        ):
            out = extract.scrub_hook_command(cmd, USER_PATH_RULE)
            self.assertNotIn(banned, out, cmd)
            self.assertIn("<url>", out, cmd)
            self.assertNotEqual(out, extract.HOOK_COMMAND_REDACTED, cmd)

    def test_flag_value_path_abstracted_prefix_kept(self):
        out = extract.scrub_hook_command(
            "hook --config=/etc/app/secret.conf", USER_PATH_RULE
        )
        self.assertEqual(out, "hook --config=<path>")

    def test_secret_redacted_even_if_path_also_present(self):
        # Over-redaction: a secret anywhere wins, regardless of scrubbable PII.
        out = extract.scrub_hook_command(
            "python3 /Users/bob/h.py --key sk-deadbeef12345678", USER_PATH_RULE
        )
        self.assertEqual(out, extract.HOOK_COMMAND_REDACTED)
        self.assertNotIn("bob", out)


class ExtractSettingsEmitsCommandTests(unittest.TestCase):
    def test_settings_hooks_carry_scrubbed_command(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "dcg"}],
                    },
                    {
                        "matcher": "Write",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "curl -H 'Authorization: Bearer abcDEF123456789' x",
                            }
                        ],
                    },
                ]
            }
        }
        with TemporaryDirectory() as d:
            root = Path(d)
            (root / "settings.json").write_text(json.dumps(settings))
            with patch.object(extract, "CLAUDE_DIR", root):
                result = extract.extract_settings()

        hooks = {h["matcher"]: h for h in result["hooks"]}
        # Safe command is exposed verbatim.
        self.assertEqual(hooks["Bash"]["command"], "dcg")
        self.assertEqual(hooks["Bash"]["script"], "dcg")
        # Command carrying a Bearer token is redacted, not partially scrubbed.
        self.assertEqual(
            hooks["Write"]["command"], extract.HOOK_COMMAND_REDACTED
        )

    def test_owner_scan_is_seeded_with_hook_commands(self):
        # A github.com/<owner> URL in a hook command must reach detect_pii's
        # owner scan so the existing owner-URL rewrite applies to it.
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "git clone https://github.com/someowner/repo",
                            }
                        ],
                    }
                ]
            }
        }
        captured = {}
        real_detect = extract.detect_pii

        def spy_detect(content_for_owner_scan=""):
            captured["content"] = content_for_owner_scan
            return real_detect(content_for_owner_scan=content_for_owner_scan)

        with TemporaryDirectory() as d:
            root = Path(d)
            (root / "settings.json").write_text(json.dumps(settings))
            with patch.object(extract, "CLAUDE_DIR", root), patch.object(
                extract, "detect_pii", side_effect=spy_detect
            ):
                extract.extract_settings()

        self.assertIn("github.com/someowner/repo", captured["content"])


if __name__ == "__main__":
    unittest.main()
