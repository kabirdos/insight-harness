"""Unit tests for writeup-narrative credibility helpers in extract.py.

Locks Phase 0 findings F6 and F7: the human-readable writeup must never assert
things the user's data does not support.

- F6: the hook narrative once hardcoded the insight-harness author's own five
  script descriptions (and a static "these four hooks cover the most important
  safety/quality bases" claim) onto every report regardless of reality. The
  narrative now describes hooks only by *when they fire* and *what they match* —
  facts read straight from the config.
- F7: a report once read "averaging about 0 minutes each" for a user whose
  duration data was empty. Zero/missing stats are now omitted, not asserted.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract  # noqa: E402


def _he(s):
    """Mirror of the HTML-escaping helper used inside generate_writeup."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class ActivitySentenceTest(unittest.TestCase):
    def test_no_sessions_returns_empty(self):
        self.assertEqual(extract._activity_sentence(0, 0, 0), "")

    def test_zero_duration_and_ratio_omits_both_clauses(self):
        out = extract._activity_sentence(5, 0, 0)
        self.assertEqual(out, "Over the last 30 days, they've run 5 sessions.")
        # The F7 regression: never assert a zero duration.
        self.assertNotIn("minutes", out)
        self.assertNotIn("0 minutes", out)
        self.assertNotIn("message", out)

    def test_sub_minute_average_is_not_rounded_to_zero(self):
        out = extract._activity_sentence(5, 0.4, 0)
        self.assertNotIn("0 minutes", out)
        self.assertNotIn("minutes", out)

    def test_full_sentence_when_all_stats_present(self):
        out = extract._activity_sentence(12, 42, 0.15)
        self.assertIn("12 sessions", out)
        self.assertIn("42 minutes", out)
        # round(1 / 0.15) == 7
        self.assertIn("every 7 Claude messages", out)
        self.assertTrue(out.endswith("."))

    def test_duration_present_but_ratio_absent(self):
        out = extract._activity_sentence(3, 25, 0)
        self.assertIn("25 minutes", out)
        self.assertNotIn("message", out)


class DescribeHooksTest(unittest.TestCase):
    def test_describes_by_event_and_matcher(self):
        rows = extract._describe_hooks(
            [{"event": "PreToolUse", "matcher": "Bash", "script": "my_guard.sh"}],
            _he,
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("my_guard.sh", rows[0])
        self.assertIn("fires before a tool runs", rows[0])
        self.assertIn("<code>Bash</code>", rows[0])

    def test_coincidental_author_filename_gets_no_fabricated_description(self):
        # The exact F6 landmine: a user whose hook is named like one of the
        # author's scripts must NOT inherit the author's hardcoded description.
        rows = extract._describe_hooks(
            [
                {"event": "PostToolUse", "matcher": "Write|Edit", "script": "format_and_lint.py"},
                {"event": "PreToolUse", "matcher": "Bash", "script": "dcg"},
            ],
            _he,
        )
        joined = "".join(rows)
        self.assertNotIn("Prettier", joined)
        self.assertNotIn("ESLint", joined)
        self.assertNotIn("destructive shell commands", joined)
        self.assertNotIn("sensitive files", joined)

    def test_all_matcher_and_empty_matcher_add_no_scope(self):
        rows = extract._describe_hooks(
            [
                {"event": "Stop", "matcher": "(all)", "script": "save.py"},
                {"event": "Stop", "matcher": "", "script": "other.py"},
            ],
            _he,
        )
        for row in rows:
            self.assertNotIn("<code>", row)
            self.assertIn("fires when a turn finishes", row)

    def test_skips_inline_and_unknown_scripts(self):
        rows = extract._describe_hooks(
            [
                {"event": "PreToolUse", "matcher": "Bash", "script": "inline-bash"},
                {"event": "PreToolUse", "matcher": "Bash", "script": "unknown"},
                {"event": "PreToolUse", "matcher": "Bash", "script": ""},
                {"event": "PreToolUse", "matcher": "Bash", "script": "real.sh"},
            ],
            _he,
        )
        self.assertEqual(len(rows), 1)
        self.assertIn("real.sh", rows[0])

    def test_dedupes_identical_event_matcher_script(self):
        rows = extract._describe_hooks(
            [
                {"event": "PreToolUse", "matcher": "Bash", "script": "g.sh"},
                {"event": "PreToolUse", "matcher": "Bash", "script": "g.sh"},
            ],
            _he,
        )
        self.assertEqual(len(rows), 1)

    def test_same_script_on_different_events_is_kept(self):
        rows = extract._describe_hooks(
            [
                {"event": "PreToolUse", "matcher": "Bash", "script": "g.sh"},
                {"event": "Stop", "matcher": "(all)", "script": "g.sh"},
            ],
            _he,
        )
        self.assertEqual(len(rows), 2)

    def test_unknown_event_with_matcher_still_describes_scope(self):
        rows = extract._describe_hooks(
            [{"event": "SomeFutureEvent", "matcher": "Bash", "script": "x.sh"}],
            _he,
        )
        self.assertIn("<code>Bash</code>", rows[0])
        self.assertIn("x.sh", rows[0])

    def test_matcher_is_html_escaped(self):
        rows = extract._describe_hooks(
            [{"event": "PreToolUse", "matcher": "<svg>", "script": "x.sh"}],
            _he,
        )
        self.assertIn("&lt;svg&gt;", rows[0])
        self.assertNotIn("<svg>", rows[0])


if __name__ == "__main__":
    unittest.main()
