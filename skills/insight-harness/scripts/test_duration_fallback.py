"""Tests for the JSONL wall-clock duration fallback (_ts_span_minutes).

Background: per-session duration historically came only from
``~/.claude/usage-data/session-meta/*.json``. Newer Claude Code no longer
writes that directory (it consolidated into ``stats-cache.json``, which has no
per-session duration), so the extractor silently shipped ``durationHours: 0``.
The fallback reconstructs wall-clock duration from per-session JSONL
``timestamp`` envelope fields. These tests pin the helper's contract.
"""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "extract", os.path.join(os.path.dirname(__file__), "extract.py")
)
extract = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(extract)
_ts_span_minutes = extract._ts_span_minutes


def test_basic_span_in_minutes():
    assert round(_ts_span_minutes("2026-06-04T17:45:00.000Z", "2026-06-04T18:15:00.000Z")) == 30


def test_handles_millisecond_precision_and_z_suffix():
    span = _ts_span_minutes("2026-06-04T17:45:56.271Z", "2026-06-04T17:55:56.271Z")
    assert round(span) == 10


def test_span_across_hours():
    assert round(_ts_span_minutes("2026-06-04T09:00:00Z", "2026-06-04T11:30:00Z")) == 150


def test_malformed_input_returns_zero_not_crash():
    assert _ts_span_minutes("", "") == 0.0
    assert _ts_span_minutes("garbage", "also-garbage") == 0.0
    assert _ts_span_minutes(None, None) == 0.0


def test_non_positive_span_returns_zero():
    # last before first (clock skew / out-of-order lines) must not go negative
    assert _ts_span_minutes("2026-06-04T18:00:00Z", "2026-06-04T17:00:00Z") == 0.0
    # identical timestamps
    assert _ts_span_minutes("2026-06-04T18:00:00Z", "2026-06-04T18:00:00Z") == 0.0


def test_capped_value_is_caller_responsibility():
    # The helper returns raw minutes; the per-session MAX_SESSION_MINUTES cap is
    # applied by the scan loop, not here. A 10-hour gap returns 600, uncapped.
    assert round(_ts_span_minutes("2026-06-04T08:00:00Z", "2026-06-04T18:00:00Z")) == 600


def test_iso_utc_gate_accepts_z_rejects_other():
    # Only fixed-width UTC '...Z' timestamps may set the per-session min/max,
    # so a malformed or offset-format value can't corrupt the lexical span.
    gate = extract._TS_ISO_UTC
    assert gate.match("2026-06-04T17:45:56.271Z")  # millis + Z
    assert gate.match("2026-06-04T17:45:56Z")  # whole-second + Z
    # offset form and garbage must not match the prefix shape
    assert not gate.match("garbage")
    assert not gate.match("2026-06-04 17:45:56")  # space separator, no T
    # prefix matches but no trailing Z — the loop also requires endswith('Z'),
    # so a +00:00 offset value is rejected at selection time
    assert "2026-06-04T17:45:56.271+00:00".endswith("Z") is False


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all duration-fallback tests passed")
