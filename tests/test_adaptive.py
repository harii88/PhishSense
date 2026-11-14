from __future__ import annotations

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.models import (
    Email,
    EmailOutcome,
    MLPrediction,
    ModelVersion,
    TrainingModule,
)
from phishsense.data.seed import seed_content
from phishsense.services import adaptive, features, simulation
from phishsense.services.adaptive import Recommendation, next_level, recommend
from phishsense.services.features import OutcomeRecord, compute_features
from phishsense.services.simulation import ReviewItem
from tests.helpers import make_trainee

URL, URG, IMP, ATT = config.VECTORS
CLICKED, REPORTED = config.DECISION_CLICKED, config.DECISION_REPORTED
LEVEL_1 = {v: 1 for v in config.VECTORS}


def R(category, decision):
    via = config.CLICK_VIA_LINK if decision == CLICKED else None
    return OutcomeRecord(category, decision, via, latency_ms=1000)


def rec_for(history, profile, risk=config.RISK_LOW, p=0.1, levels=LEVEL_1, passed=frozenset()):
    return recommend(
        profile=profile, fail_probability=p, risk_level=risk,
        vector=compute_features(history), history=history,
        levels=levels, passed_modules=set(passed),
    )


def keys(recs):
    return [(r.topic, r.level, r.mandatory) for r in recs]


# ---------------------------------------------------------------- levels
@pytest.mark.parametrize(
    "level, accuracy, expected",
    [(1, 0.8, 2), (1, 1.0, 2), (3, 1.0, 3), (2, 0.79, 2), (2, 0.5, 2),
     (2, 0.41, 2), (2, 0.4, 1), (1, 0.0, 1)],
)
def test_next_level(level, accuracy, expected):
    assert next_level(level, accuracy) == expected


def test_vector_accuracy_counts_only_phishing():
    def item(category, correct):
        email = Email(category=category, is_phishing=category != config.CATEGORY_LEGITIMATE)
        return ReviewItem(0, email, EmailOutcome(decision=REPORTED, correct=correct))

    items = [item(URL, True), item(URL, False), item(URG, None),  # ignored phishing: not correct
             item(config.CATEGORY_LEGITIMATE, True)]
    assert adaptive.vector_accuracy(items) == {URL: (1, 2), URG: (0, 1)}


# ------------------------------------------------------- recommendations
IMPULSIVE_HISTORY = [[R(v, CLICKED) for v in config.VECTORS for _ in range(2)]]


def test_impulsive_high_risk():
    recs = rec_for(IMPULSIVE_HISTORY, config.PROFILE_IMPULSIVE, config.RISK_HIGH, 0.9)
    assert keys(recs) == [(URL, 1, True), (config.TOPIC_PAUSE_INSPECT, 1, False)]
    assert "You fell for 2 of 2 URL-spoofing emails in your last session." in recs[0].reason
    assert "90%" in recs[0].reason and "Required" in recs[0].reason
    assert "100% of your clicks" in recs[1].reason


def test_passive_low_risk_gets_reporting_only():
    history = [[OutcomeRecord(v, config.DECISION_IGNORED) for v in config.VECTORS]]
    recs = rec_for(history, config.PROFILE_PASSIVE)
    assert keys(recs) == [(config.TOPIC_REPORTING, 1, False)]
    assert "100% of phishing emails" in recs[0].reason


def test_weak_module_uses_current_level():
    recs = rec_for(IMPULSIVE_HISTORY, config.PROFILE_IMPULSIVE, levels={**LEVEL_1, URL: 3})
    assert recs[0].topic == URL and recs[0].level == 3


def test_repeater_gets_remedial_module_for_repeated_vector():
    history = [[R(ATT, CLICKED), R(URL, REPORTED)], [R(ATT, CLICKED), R(ATT, REPORTED)]]
    recs = rec_for(history, config.PROFILE_REPEATER, levels={**LEVEL_1, ATT: 2})
    # weakest vector: attachment at level 2; remedial: attachment back at level 1
    assert keys(recs) == [(ATT, 2, False), (ATT, 1, False)]
    assert "more than one session" in recs[1].reason


def test_repeater_duplicates_are_merged():
    history = [[R(ATT, CLICKED)] * 2, [R(ATT, CLICKED)] * 2]
    recs = rec_for(history, config.PROFILE_REPEATER)
    assert keys(recs) == [(ATT, 1, False)]   # weak module and remedial are the same module


def test_repeater_without_repeats_falls_back_to_weakest():
    history = [[R(URG, CLICKED), R(URG, CLICKED)]]
    recs = rec_for(history, config.PROFILE_REPEATER, levels={**LEVEL_1, URG: 2})
    assert keys(recs) == [(URG, 2, False), (URG, 1, False)]


def test_vigilant_gets_next_unpassed_advanced_module():
    history = [[R(v, REPORTED) for v in config.VECTORS for _ in range(2)]]
    assert keys(rec_for(history, config.PROFILE_VIGILANT)) == [(IMP, 3, False)]
    assert keys(rec_for(history, config.PROFILE_VIGILANT, passed={(IMP, 3)})) == [(URL, 3, False)]
    all_passed = {(v, 3) for v in config.VECTORS}
    assert rec_for(history, config.PROFILE_VIGILANT, passed=all_passed) == []


def test_high_risk_with_nothing_to_recommend_is_safe():
    history = [[R(v, REPORTED) for v in config.VECTORS]]
    all_passed = {(v, 3) for v in config.VECTORS}
    assert rec_for(history, config.PROFILE_VIGILANT, config.RISK_HIGH, 0.7, passed=all_passed) == []


# ---------------------------------------------------------- persistence
@pytest.fixture
def setup(db):
    seed_content(db)
    user = make_trainee(db, "alice")
    sim = simulation.start_session(db, user)
    summary = simulation.finish_session(db, sim)
    versions = [ModelVersion(kind=k, version=1, n_synthetic=0, n_real=0, path="x", is_active=True)
                for k in config.MODEL_KINDS]
    db.add_all(versions)
    db.flush()
    prediction = MLPrediction(
        user_id=user.id, features_id=summary.features.id, cluster_id=0,
        profile=config.PROFILE_IMPULSIVE, fail_probability=0.9, risk_level=config.RISK_HIGH,
        kmeans_version_id=versions[0].id, rf_version_id=versions[1].id,
    )
    db.add(prediction)
    db.flush()
    return db, user, prediction


def _patch_recs(monkeypatch, recs):
    monkeypatch.setattr(adaptive, "recommend", lambda **_: recs)


def test_assign_creates_assignments_with_reasons(setup, monkeypatch):
    db, user, prediction = setup
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "why", True),
                              Recommendation(config.TOPIC_PAUSE_INSPECT, 1, "because")])
    created = adaptive.assign_training(db, user, prediction, [], LEVEL_1)
    assert [(a.module.topic, a.mandatory, a.reason) for a in created] == [
        (URL, True, "why"), (config.TOPIC_PAUSE_INSPECT, False, "because")]
    assert all(a.prediction_id == prediction.id for a in created)
    assert adaptive.open_assignments(db, user)[0].mandatory   # mandatory listed first


def test_no_duplicate_open_assignment_but_mandatory_upgrade(setup, monkeypatch):
    db, user, prediction = setup
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "first")])
    adaptive.assign_training(db, user, prediction, [], LEVEL_1)
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "first")])
    assert adaptive.assign_training(db, user, prediction, [], LEVEL_1) == []
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "now required", True)])
    touched = adaptive.assign_training(db, user, prediction, [], LEVEL_1)
    assert len(touched) == 1 and touched[0].mandatory and touched[0].reason == "now required"
    assert len(adaptive.open_assignments(db, user)) == 1


def test_completed_module_can_be_assigned_again(setup, monkeypatch):
    db, user, prediction = setup
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "r")])
    (first,) = adaptive.assign_training(db, user, prediction, [], LEVEL_1)
    first.completed_at = first.assigned_at
    assert adaptive.passed_modules(db, user) == {(URL, 1)}
    (second,) = adaptive.assign_training(db, user, prediction, [], LEVEL_1)
    assert second.id != first.id


def test_unknown_module_is_an_error(setup, monkeypatch):
    db, user, prediction = setup
    db.execute(TrainingModule.__table__.delete().where(TrainingModule.topic == URL))
    _patch_recs(monkeypatch, [Recommendation(URL, 1, "r")])
    with pytest.raises(LookupError):
        adaptive.assign_training(db, user, prediction, [], LEVEL_1)


def test_update_levels_from_session(db):
    seed_content(db)
    user = make_trainee(db, "alice")
    sim = simulation.start_session(db, user)
    summary = simulation.finish_session(db, sim)          # everything ignored: 0% accuracy
    for row in user.vector_levels:
        row.level = 2
    changes = adaptive.update_levels(db, user, summary)
    assert {(c.vector, c.old, c.new, c.correct, c.total) for c in changes} == {
        (v, 2, 1, 0, 2) for v in config.VECTORS}
    assert adaptive.current_levels(db, user) == LEVEL_1


def test_repeated_vectors():
    s1 = [R(URL, CLICKED), R(ATT, CLICKED)]
    s2 = [R(ATT, CLICKED), R(ATT, CLICKED)]
    s3 = [R(ATT, CLICKED), R(URL, CLICKED)]
    assert features.repeated_vectors([s1]) == []
    assert features.repeated_vectors([s1, s2, s3]) == [ATT, URL]   # 3 sessions vs 2
