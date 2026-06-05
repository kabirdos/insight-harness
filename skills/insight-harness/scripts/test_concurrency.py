"""Tests for the session-concurrency signal (_compute_concurrency / _parse_iso).

Concurrency ("runs N sessions in parallel") is computed by a sweep line over
per-session ``(start, end)`` wall-clock intervals derived from JSONL
timestamps. These tests pin the sweep's contract, including the back-to-back
tie-break (a session that ends exactly as the next begins must not count as
overlapping).
"""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "extract", os.path.join(os.path.dirname(__file__), "extract.py")
)
extract = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(extract)
_compute = extract._compute_concurrency


def iso(h, m=0):
    return f"2026-06-04T{h:02d}:{m:02d}:00Z"


def test_sequential_sessions_never_overlap():
    out = _compute([(iso(10), iso(11)), (iso(11), iso(12)), (iso(12), iso(13))])
    assert out["maxConcurrent"] == 1
    assert out["sessionsCounted"] == 3


def test_full_overlap_peaks_at_session_count():
    # three sessions all open together; starts staggered
    out = _compute([(iso(10), iso(13)), (iso(10, 30), iso(13)), (iso(11), iso(13))])
    assert out["maxConcurrent"] == 3
    assert out["medianConcurrent"] == 2  # at-start levels [1,2,3] -> median 2
    assert out["sessionsCounted"] == 3


def test_partial_overlap():
    out = _compute([(iso(10), iso(11)), (iso(10, 30), iso(12)), (iso(13), iso(14))])
    assert out["maxConcurrent"] == 2  # first two overlap; third is alone
    assert out["sessionsCounted"] == 3


def test_back_to_back_not_counted_as_overlap():
    # one ends exactly as the next begins -> ends sort before starts -> peak 1
    out = _compute([(iso(10), iso(11)), (iso(11), iso(12))])
    assert out["maxConcurrent"] == 1


def test_empty_input():
    assert _compute([]) == {
        "maxConcurrent": 0,
        "medianConcurrent": 0,
        "sessionsCounted": 0,
    }


def test_invalid_intervals_are_skipped():
    out = _compute([("bad", "worse"), (iso(12), iso(10)), (iso(9), iso(9))])
    assert out["sessionsCounted"] == 0
    assert out["maxConcurrent"] == 0


def test_parse_iso_contract():
    assert extract._parse_iso("2026-06-04T10:00:00Z") is not None
    assert extract._parse_iso("2026-06-04T10:00:00.123Z") is not None
    assert extract._parse_iso("garbage") is None
    assert extract._parse_iso(None) is None
    # naive (no offset/Z) rejected so the sweep never mixes naive + aware
    assert extract._parse_iso("2026-06-04T10:00:00") is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all concurrency tests passed")
