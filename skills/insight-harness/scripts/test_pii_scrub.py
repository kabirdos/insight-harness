#!/usr/bin/env python3
"""
Self-test for pii_scrub. Runs a fixture table against scrub() and exits
non-zero on any mismatch or invariant failure.

Uses a synthetic ruleset rather than reading the user's real git config so
the test is hermetic and reproducible. Run from any directory:

    python3 test_pii_scrub.py
"""

from __future__ import annotations

import re
import sys

from pii_scrub import SanitizeError, _fence_count, _newline_count, detect_pii, scrub


def _fake_rules() -> list[tuple[re.Pattern[str], str]]:
    """Synthetic ruleset that mirrors detect_pii() but uses fixed identifiers.

    Order must match detect_pii() so the same precedence is exercised.
    """
    pairs = [
        ("/Users/alice/", "~/"),
        ("/Users/alice", "~"),
        ("/home/alice/", "~/"),
        ("/home/alice", "~"),
        ("raw.githubusercontent.com/alice/", "raw.githubusercontent.com/<your-username>/"),
        ("githubusercontent.com/alice/", "githubusercontent.com/<your-username>/"),
        ("github.com/alice/", "github.com/<your-username>/"),
        ("@alice", "@<your-username>"),
        ("alice@example.com", "<your-email>"),
        ("Alice Wonderland", "<your-name>"),
    ]
    return [(re.compile(re.escape(n)), r) for n, r in pairs]


CASES: list[tuple[str, str, str]] = [
    # (description, input, expected)
    (
        "github URL replaced",
        "Clone from https://github.com/alice/repo.git",
        "Clone from https://github.com/<your-username>/repo.git",
    ),
    (
        "raw.githubusercontent URL replaced (longest-prefix wins)",
        "Asset at https://raw.githubusercontent.com/alice/repo/main/x.png",
        "Asset at https://raw.githubusercontent.com/<your-username>/repo/main/x.png",
    ),
    (
        "macOS path replaced with trailing slash",
        "See /Users/alice/Coding/foo for setup",
        "See ~/Coding/foo for setup",
    ),
    (
        "linux path replaced",
        "Drop into /home/alice and run make",
        "Drop into ~ and run make",
    ),
    (
        "git name replaced",
        "Author: Alice Wonderland",
        "Author: <your-name>",
    ),
    (
        "git email replaced",
        "Reach out at alice@example.com please",
        "Reach out at <your-email> please",
    ),
    (
        "@-mention replaced",
        "Ping @alice for review",
        "Ping @<your-username> for review",
    ),
    (
        "non-PII passes through",
        "Generic prose with no identifiers should not change.",
        "Generic prose with no identifiers should not change.",
    ),
    (
        "unrelated github user not replaced",
        "Compare with https://github.com/torvalds/linux",
        "Compare with https://github.com/torvalds/linux",
    ),
    (
        "fenced code block content also scrubbed (text replacement is greedy)",
        "```\ncd /Users/alice\n```\n",
        "```\ncd ~\n```\n",
    ),
    (
        "multi-line input preserves newlines",
        "Line 1 about /Users/alice\nLine 2 about @alice\nLine 3 normal\n",
        "Line 1 about ~\nLine 2 about @<your-username>\nLine 3 normal\n",
    ),
    (
        "empty string passes through",
        "",
        "",
    ),
]


def run_cases(rules: list[tuple[re.Pattern[str], str]]) -> int:
    failures = 0
    for desc, src, expected in CASES:
        try:
            out = scrub(src, rules=rules, context=desc)
        except SanitizeError as e:
            print(f"FAIL ({desc}): SanitizeError: {e}", file=sys.stderr)
            failures += 1
            continue
        if out != expected:
            print(f"FAIL ({desc})", file=sys.stderr)
            print(f"  input:    {src!r}", file=sys.stderr)
            print(f"  expected: {expected!r}", file=sys.stderr)
            print(f"  got:      {out!r}", file=sys.stderr)
            failures += 1
        else:
            # Sanity: invariants held (scrub() would have raised otherwise)
            assert _newline_count(src) == _newline_count(out)
            assert _fence_count(src) == _fence_count(out)
    return failures


def test_invariant_failure_raises():
    """A pathological rule that eats a newline must raise SanitizeError."""
    bad_rules = [(re.compile(r"\n"), "")]
    try:
        scrub("a\nb\n", rules=bad_rules, context="invariant-test")
    except SanitizeError:
        return 0
    print("FAIL: invariant test did not raise SanitizeError", file=sys.stderr)
    return 1


def test_detect_pii_with_no_git_config():
    """detect_pii() must not crash if git is missing or unconfigured."""
    rules = detect_pii()
    # No assertion on contents — just that it returns a list without raising
    assert isinstance(rules, list)
    return 0


def main():
    rules = _fake_rules()
    fixture_failures = run_cases(rules)
    invariant_failures = test_invariant_failure_raises()
    detect_failures = test_detect_pii_with_no_git_config()

    total = fixture_failures + invariant_failures + detect_failures
    if total == 0:
        print(f"OK ({len(CASES)} fixture cases + 2 meta-tests)")
        return 0
    print(f"FAILED: {total} failure(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
