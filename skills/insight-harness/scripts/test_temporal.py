"""Tests for the temporal "when I work" signal (_compute_temporal).

Derives a when-you-work characterization from the stats-cache hour-of-day
activity map: a peak hour, a normalized hourCounts map, and a dominant-quarter
label with an optional late-night overlay.
"""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "extract", os.path.join(os.path.dirname(__file__), "extract.py")
)
extract = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(extract)
_t = extract._compute_temporal


def test_afternoon_peak_no_overlay():
    out = _t({"13": 50, "14": 60, "15": 40})
    assert out["label"] == "Afternoon peak"
    assert out["peakHour"] == 14
    assert out["hourCounts"] == {"13": 50, "14": 60, "15": 40}


def test_night_owl():
    # night-dominant (100% late) stays just "Night owl" — the overlay would be
    # redundant, so it is intentionally suppressed for night dominance.
    out = _t({"0": 30, "2": 40, "3": 20})
    assert out["label"] == "Night owl"
    assert out["peakHour"] == 2


def test_non_dict_input_returns_empty():
    # malformed stats-cache shapes must not crash report generation
    assert _t([]) == {}
    assert _t("x") == {}
    assert _t([1, 2]) == {}
    assert _t(42) == {}


def test_early_riser_and_evening():
    assert _t({"6": 10, "7": 20, "8": 15})["label"] == "Early riser"
    assert _t({"19": 10, "20": 30, "21": 15})["label"] == "Evening shift"


def test_midnight_oil_overlay_when_late_share_high():
    # afternoon dominant (100) but late window 22-5 is 35/135 = 26% >= 20%
    out = _t({"14": 50, "15": 50, "23": 20, "0": 15})
    assert out["label"] == "Afternoon peak · burns the midnight oil"


def test_no_overlay_when_late_share_low():
    out = _t({"14": 90, "23": 5, "0": 5})  # late 10/100 = 10% < 20%
    assert out["label"] == "Afternoon peak"


def test_empty_or_all_invalid_returns_empty():
    assert _t({}) == {}
    assert _t(None) == {}
    # bad key, out-of-range hour, zero, negative -> nothing usable
    assert _t({"x": 5, "99": 3, "5": 0, "6": -2}) == {}


def test_invalid_entries_skipped_valid_kept():
    out = _t({"x": 99, "15": 10, "badval": "nope", "20": 5})
    assert out["peakHour"] == 15
    assert "15" in out["hourCounts"] and "20" in out["hourCounts"]
    assert "x" not in out["hourCounts"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all temporal tests passed")
