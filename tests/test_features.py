"""Feature formulas against hand-computed values (pure, no database)."""

from __future__ import annotations

import pytest

from phishsense import config
from phishsense.services.features import (
    FEATURE_NAMES,
    OutcomeRecord,
    compute_features,
    vector_exposure,
    weakest_vector,
)

URL, URG, IMP, ATT, LEG = (*config.VECTORS, config.CATEGORY_LEGITIMATE)
CLICKED, REPORTED, SAFE, IGNORED = (
    config.DECISION_CLICKED, config.DECISION_REPORTED,
    config.DECISION_MARKED_SAFE, config.DECISION_IGNORED,
)
LINK, ATTACH = config.CLICK_VIA_LINK, config.CLICK_VIA_ATTACHMENT


def R(category, decision, via=None, lat=None, hover=0):
    if decision == CLICKED and via is None:
        via = ATTACH if category == ATT else LINK
    return OutcomeRecord(category, decision, via, lat, hover)


# One session, every feature computed by hand in the comments.
SESSION = [
    R(URL, CLICKED, LINK, lat=2000, hover=0),        # error, fast click, blind link click
    R(URL, REPORTED, lat=8000, hover=1500),
    R(URG, SAFE, lat=5000),                          # error
    R(IMP, IGNORED),                                 # miss, not an error
    R(ATT, CLICKED, ATTACH, lat=4000),               # error, not fast (4 s >= 3 s)
    R(LEG, CLICKED, LINK, lat=6000, hover=1200),     # inspected link click
    R(LEG, REPORTED, lat=10000),                     # false positive
    R(LEG, IGNORED),
]


def test_single_session_hand_computed():
    f = compute_features([SESSION])
    # |P| = 5, |L| = 3
    assert f.click_rate == pytest.approx(2 / 5)            # url + attachment compromised
    assert f.report_accuracy == pytest.approx(1 / 5)
    assert f.ignore_rate == pytest.approx(1 / 5)
    assert f.false_positive_rate == pytest.approx(1 / 3)
    assert f.hover_to_click_ratio == pytest.approx(1 / 2)  # link clicks: url(0 ms), leg(1200 ms)
    assert f.fast_click_rate == pytest.approx(1 / 3)       # clicks: url fast; att, leg not
    assert f.mean_decision_latency_s == pytest.approx((2 + 8 + 5 + 4 + 6 + 10) / 6)
    assert f.vser_url_spoofing == pytest.approx(1 / 2)
    assert f.vser_urgency == pytest.approx(1.0)
    assert f.vser_impersonation == pytest.approx(0.0)      # ignored is a miss, not an error
    assert f.vser_attachment == pytest.approx(1.0)
    assert f.repeat_error_measure == 0.0                   # no earlier session
    assert f.window_sessions == 1


def test_as_list_follows_feature_names():
    f = compute_features([SESSION])
    assert len(f.as_list()) == len(FEATURE_NAMES) == 12
    assert f.as_list()[FEATURE_NAMES.index("click_rate")] == f.click_rate
    assert f.vser(URL) == f.vser_url_spoofing


def test_window_uses_only_last_sessions():
    old_bad = [R(URL, CLICKED, lat=500)]
    good = [R(URL, REPORTED, lat=9000)]
    history = [old_bad] + [good] * config.FEATURE_WINDOW_SESSIONS
    f = compute_features(history)
    assert f.window_sessions == config.FEATURE_WINDOW_SESSIONS
    assert f.click_rate == 0.0 and f.report_accuracy == 1.0
    assert f.repeat_error_measure == 0.0


def test_repeat_error_measure_counts_vectors_failed_in_earlier_sessions():
    s0 = [R(URL, CLICKED, lat=1000)]
    s1 = [R(URL, CLICKED, lat=1000), R(URG, SAFE, lat=3000)]
    # window errors: s0 url (new), s1 url (repeat), s1 urgency (new) -> 1/3
    assert compute_features([s0, s1]).repeat_error_measure == pytest.approx(1 / 3)


def test_same_session_errors_are_not_repeats():
    s0 = [R(URL, CLICKED, lat=1000), R(URL, CLICKED, lat=1000)]
    assert compute_features([s0]).repeat_error_measure == 0.0


def test_repeat_error_remembers_errors_before_the_window():
    s_err = [R(URL, CLICKED, lat=1000)]
    s_ok = [R(URL, REPORTED, lat=5000)]
    history = [s_err, s_ok, s_ok, s_ok, s_err]  # window = last 3
    # only window error is the last one, and url was failed in session 0
    assert compute_features(history).repeat_error_measure == 1.0


def test_empty_denominators_have_defined_values():
    f = compute_features([[R(LEG, IGNORED)]])
    assert f.click_rate == f.report_accuracy == f.ignore_rate == 0.0
    assert f.false_positive_rate == 0.0
    assert f.hover_to_click_ratio == 1.0        # nothing clicked blindly
    assert f.fast_click_rate == 0.0
    assert f.mean_decision_latency_s == config.MAX_DECISION_LATENCY_S
    assert all(f.vser(v) == 0.0 for v in config.VECTORS)


def test_latency_is_clipped():
    f = compute_features([[R(URL, REPORTED, lat=10_000_000)]])
    assert f.mean_decision_latency_s == config.MAX_DECISION_LATENCY_S


def test_inspection_threshold_is_inclusive():
    at = config.INSPECT_HOVER_S * 1000
    f = compute_features([[R(URL, CLICKED, lat=5000, hover=int(at))]])
    assert f.hover_to_click_ratio == 1.0
    f = compute_features([[R(URL, CLICKED, lat=5000, hover=int(at) - 1)]])
    assert f.hover_to_click_ratio == 0.0


def test_inspected_quick_click_is_not_fast():
    # quick, but the user hovered long enough: careful, not impulsive
    f = compute_features([[R(URL, CLICKED, lat=2500, hover=1500)]])
    assert f.fast_click_rate == 0.0


def test_all_features_bounded():
    f = compute_features([SESSION, SESSION, SESSION])
    for name in FEATURE_NAMES:
        value = getattr(f, name)
        upper = config.MAX_DECISION_LATENCY_S if name == "mean_decision_latency_s" else 1.0
        assert 0.0 <= value <= upper


def test_no_history_is_an_error():
    with pytest.raises(ValueError):
        compute_features([])


# ------------------------------------------------------------ weakness
def test_vector_exposure():
    exp = vector_exposure([SESSION])
    assert (exp[URL].seen, exp[URL].errors) == (2, 1)
    assert (exp[IMP].seen, exp[IMP].errors) == (1, 0)


def test_weakest_vector_needs_minimum_exposure():
    # urgency and attachment have 100% error but only 1 email each; url has 2.
    assert weakest_vector([SESSION]) == URL


def test_weakest_vector_highest_rate_then_errors_then_order():
    s = [R(URG, CLICKED, lat=1)] * 2 + [R(URL, CLICKED, lat=1), R(URL, REPORTED, lat=1)]
    assert weakest_vector([s]) == URG                      # 1.0 beats 0.5
    s = [R(URG, CLICKED, lat=1)] * 2 + [R(URL, CLICKED, lat=1)] * 3
    assert weakest_vector([s]) == URL                      # same rate, more errors
    s = [R(URG, CLICKED, lat=1)] * 2 + [R(IMP, CLICKED, lat=1)] * 2
    assert weakest_vector([s]) == URG                      # full tie -> config order


def test_no_errors_means_no_weakness():
    s = [R(v, REPORTED, lat=1) for v in config.VECTORS for _ in range(2)]
    assert weakest_vector([s]) is None
