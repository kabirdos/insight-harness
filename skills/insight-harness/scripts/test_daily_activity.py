"""Tests for the real daily-activity series builder (_build_daily_activity).

The activity heatmap historically rendered a *synthetic* daily distribution
seeded from aggregate totals. This helper joins the real per-day session counts
(stats-cache ``dailyActivity``) with summed per-day tokens (``dailyModelTokens``)
so the report can show actual days. These tests pin its contract.
"""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "extract", os.path.join(os.path.dirname(__file__), "extract.py")
)
extract = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(extract)
_build = extract._build_daily_activity


def test_joins_sessions_and_tokens_by_date():
    daily = [
        {"date": "2026-06-01", "sessionCount": 3, "messageCount": 10},
        {"date": "2026-06-02", "sessionCount": 1, "messageCount": 4},
    ]
    dmt = [
        {"date": "2026-06-01", "tokensByModel": {"opus": 100, "sonnet": 50}},
        {"date": "2026-06-02", "tokensByModel": {"opus": 7}},
    ]
    assert _build(daily, dmt) == [
        {"date": "2026-06-01", "sessions": 3, "tokens": 150},
        {"date": "2026-06-02", "sessions": 1, "tokens": 7},
    ]


def test_missing_token_day_defaults_zero():
    assert _build([{"date": "2026-06-01", "sessionCount": 2}], []) == [
        {"date": "2026-06-01", "sessions": 2, "tokens": 0}
    ]


def test_skips_entries_without_date():
    out = _build(
        [{"sessionCount": 5}, {"date": "2026-06-03", "sessionCount": 1}], []
    )
    assert out == [{"date": "2026-06-03", "sessions": 1, "tokens": 0}]


def test_keeps_most_recent_n():
    # 39 consecutive ISO dates (lexical == chronological); sessionCount == ordinal
    daily = [
        {
            "date": f"2026-06-{i:02d}" if i <= 30 else f"2026-07-{i - 30:02d}",
            "sessionCount": i,
        }
        for i in range(1, 40)
    ]
    out = _build(daily, [], keep=28)
    assert len(out) == 28
    assert out[0]["date"] == "2026-06-12" and out[0]["sessions"] == 12  # 39-28+1
    assert out[-1]["date"] == "2026-07-09" and out[-1]["sessions"] == 39


def test_unsorted_input_is_sorted_before_trimming():
    # "most recent keep days" must hold regardless of input row order
    daily = [
        {"date": "2026-06-03", "sessionCount": 3},
        {"date": "2026-06-01", "sessionCount": 1},
        {"date": "2026-06-02", "sessionCount": 2},
    ]
    out = _build(daily, [], keep=2)
    assert [e["date"] for e in out] == ["2026-06-02", "2026-06-03"]


def test_non_numeric_token_values_ignored():
    out = _build(
        [{"date": "d", "sessionCount": 1}],
        [{"date": "d", "tokensByModel": {"a": 5, "b": "oops"}}],
    )
    assert out[0]["tokens"] == 5


def test_empty_and_none_inputs():
    assert _build([], []) == []
    assert _build(None, None) == []


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all daily-activity tests passed")
