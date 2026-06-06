"""Tests for the no-render-silent-zero rule in the standalone HTML.

Background: on machines without the legacy ``~/.claude/usage-data/session-meta/``
dir (which current Claude Code no longer writes), duration / avg-session /
commits / lines-added have no source. The old grid rendered them as a confident
"0h" / "0 commits", which reads as a *false claim* and undercuts the product's
"verified, honest data" promise (issue #29). ``_build_stat_cells`` and
``_build_git_meta_line`` now omit any metric whose source is genuinely empty.

For commits/lines the helpers distinguish *sourceless* (``None`` — the
session-meta dir is absent, so omit) from a *sourced zero* (an int ``0`` — the
source exists and genuinely measured zero, so render honestly). These tests pin
both that contract and the sourceless/sourced distinction.
"""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "extract", os.path.join(os.path.dirname(__file__), "extract.py")
)
extract = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(extract)
_build_stat_cells = extract._build_stat_cells
_build_git_meta_line = extract._build_git_meta_line


def _fmt(n):
    # Mirror the production fmt() closely enough for assertions: integers pass
    # through as str, which is all these tests need.
    return str(n)


def _cells(**overrides):
    base = dict(
        sessions=106,
        tokens=6_600_000,
        lifetime_tokens=0,
        duration_hours=0,
        avg_minutes=0,
        skills_used=12,
        hooks=4,
        commit_count=None,  # sourceless by default (no session-meta dir)
        pr_count=169,
        fmt=_fmt,
    )
    base.update(overrides)
    return "\n".join(_build_stat_cells(**base))


# ---------------------------------------------------------------------------
# Stat grid — omit sourceless metrics
# ---------------------------------------------------------------------------


def test_zero_metrics_are_omitted_not_rendered_as_zero():
    html = _cells()  # all sourceless metrics empty (commits = None)
    # The four sourceless metrics must NOT appear at all.
    assert "Duration" not in html
    assert "Avg Session" not in html
    assert "Commits" not in html
    assert "Lifetime Tokens" not in html
    # And critically, no confident "0h" / "0m" false claim leaks through.
    assert "0h" not in html
    assert "0m" not in html


def test_sourced_zero_commits_renders_but_sourceless_is_omitted():
    # A sourced zero (session-meta present, genuinely 0 commits) is honest data
    # and renders; a sourceless None is dropped. Same value class ("0"), opposite
    # treatment — the distinction Codex flagged.
    sourced = _cells(commit_count=0)
    assert "Commits" in sourced
    assert '>0<' in sourced  # the literal sourced-zero value
    sourceless = _cells(commit_count=None)
    assert "Commits" not in sourceless


def test_always_present_metrics_render_even_when_other_sources_empty():
    html = _cells()
    # Sessions, Tokens, Skills, Hooks, PRs always have a live source.
    assert "Sessions" in html
    assert "Tokens" in html
    assert "Skills Used" in html
    assert "Hooks" in html
    assert "PRs" in html


def test_real_duration_and_commits_do_render():
    html = _cells(
        lifetime_tokens=11_300_000,
        duration_hours=654.0,
        avg_minutes=37.0,
        commit_count=482,
    )
    assert "654.0h" in html and "Duration" in html
    assert "37m" in html and "Avg Session" in html
    assert "482" in html and "Commits" in html
    assert "Lifetime Tokens" in html


def test_sub_minute_average_is_dropped():
    # An avg under a minute rounds to "0m" — a false "instant session" signal.
    html = _cells(avg_minutes=0.4)
    assert "Avg Session" not in html
    assert "0m" not in html


def test_zero_pr_count_still_renders_because_source_is_live():
    # 0 PRs is an *honest* zero (the JSONL pr-link source exists and found none),
    # unlike a sourceless commits/duration zero, so the PRs cell stays.
    html = _cells(pr_count=0)
    assert "PRs" in html


def test_cell_count_grows_only_with_real_metrics():
    bare = _build_stat_cells(
        sessions=10, tokens=1, lifetime_tokens=0, duration_hours=0,
        avg_minutes=0, skills_used=1, hooks=1, commit_count=None, pr_count=0,
        fmt=_fmt,
    )
    full = _build_stat_cells(
        sessions=10, tokens=1, lifetime_tokens=5, duration_hours=9,
        avg_minutes=30, skills_used=1, hooks=1, commit_count=3, pr_count=0,
        fmt=_fmt,
    )
    # bare = Sessions, Tokens, Skills, Hooks, PRs = 5 (commits sourceless)
    assert len(bare) == 5
    # full adds Lifetime Tokens, Duration, Avg Session, Commits = 9
    assert len(full) == 9


# ---------------------------------------------------------------------------
# Git Patterns meta line
# ---------------------------------------------------------------------------


def test_git_meta_line_omits_sourceless_commits_and_lines():
    # None == sourceless (no session-meta): commits/lines dropped entirely.
    line = _build_git_meta_line(
        pr_count=169, commit_count=None, lines_added=None, fmt=_fmt
    )
    assert line == '<strong style="color:var(--ink)">169</strong> PRs'
    assert "commits" not in line
    assert "lines added" not in line


def test_git_meta_line_renders_sourced_zero_commits_and_lines():
    # A sourced 0 (session-meta present, genuinely zero) is honest data, so it
    # renders rather than being silently dropped.
    line = _build_git_meta_line(
        pr_count=169, commit_count=0, lines_added=0, fmt=_fmt
    )
    assert "0</strong> commits" in line
    assert "0</strong> lines added" in line


def test_git_meta_line_includes_real_commits_and_lines():
    line = _build_git_meta_line(
        pr_count=169, commit_count=482, lines_added=69_951, fmt=_fmt
    )
    assert "169" in line and "PRs" in line
    assert "482" in line and "commits" in line
    assert "69951" in line and "lines added" in line


def test_git_meta_line_pr_count_renders_even_at_zero():
    line = _build_git_meta_line(
        pr_count=0, commit_count=None, lines_added=None, fmt=_fmt
    )
    assert line == '<strong style="color:var(--ink)">0</strong> PRs'


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all no-silent-zero tests passed")
