from __future__ import annotations

import random
from collections import Counter

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data import content
from phishsense.data.models import (
    BehaviourFeatures,
    EmailOutcome,
    TrainingAssignment,
    TrainingModule,
    UserVectorLevel,
)
from phishsense.data.seed import ensure_admin, seed_content
from phishsense.services import features, simulation
from phishsense.services.simulation import SimulationError
from tests.helpers import Clock, make_trainee, play_impulsive, play_passive, play_vigilant


@pytest.fixture
def seeded(db):
    seed_content(db)
    return db


def codes(sim):
    return [d.email.code for d in sim.deliveries]


def categories(sim):
    return Counter(d.email.category for d in sim.deliveries)


# --------------------------------------------------------------- baseline
def test_baseline_is_identical_for_everyone(seeded):
    a = simulation.start_session(seeded, make_trainee(seeded, "alice"))
    b = simulation.start_session(seeded, make_trainee(seeded, "bob"))
    assert a.kind == b.kind == config.SESSION_KIND_BASELINE
    assert codes(a) == codes(b) == list(content.BASELINE_EMAIL_CODES)


def test_baseline_covers_every_vector_enough_to_find_a_weakness(seeded):
    sim = simulation.start_session(seeded, make_trainee(seeded, "alice"))
    counts = categories(sim)
    for vector in config.VECTORS:
        assert counts[vector] >= config.MIN_EMAILS_FOR_WEAKNESS
    assert counts[config.CATEGORY_LEGITIMATE] >= 3


def test_start_returns_open_session(seeded):
    user = make_trainee(seeded, "alice")
    first = simulation.start_session(seeded, user)
    assert simulation.start_session(seeded, user) is first


def test_levels_initialised(seeded):
    user = make_trainee(seeded, "alice")
    simulation.start_session(seeded, user)
    assert simulation.ensure_vector_levels(seeded, user) == {v: 1 for v in config.VECTORS}


def test_admin_cannot_start(seeded):
    admin = ensure_admin(seeded, username="root", password="admin-pass1")
    with pytest.raises(SimulationError, match="trainee"):
        simulation.start_session(seeded, admin)


def test_mandatory_training_blocks_next_session(seeded):
    user = make_trainee(seeded, "alice")
    module = seeded.scalar(select(TrainingModule).limit(1))
    seeded.add(TrainingAssignment(user_id=user.id, module_id=module.id, reason="r", mandatory=True))
    seeded.flush()
    with pytest.raises(SimulationError, match="required training"):
        simulation.start_session(seeded, user)


def test_missing_content_reported(db):
    with pytest.raises(SimulationError, match="seed"):
        simulation.start_session(db, make_trainee(db, "alice"))


# ----------------------------------------------------------------- finish
def test_finish_creates_outcomes_and_features(seeded):
    clock = Clock()
    user = make_trainee(seeded, "alice")
    sim = simulation.start_session(seeded, user)
    play_impulsive(seeded, sim, clock)
    summary = simulation.finish_session(seeded, sim, now=clock(1000))

    assert sim.is_complete and summary.failed
    assert len(summary.items) == len(content.BASELINE_EMAIL_CODES)
    assert seeded.query(EmailOutcome).filter_by(session_id=sim.id).count() == 12
    assert summary.phishing_total == 8 and summary.phishing_compromised == 8

    stored = seeded.scalar(select(BehaviourFeatures).where(BehaviourFeatures.session_id == sim.id))
    assert stored is summary.features
    expected = features.compute_features(summary.history)
    assert features.to_vector(stored) == expected

    with pytest.raises(SimulationError, match="already finished"):
        simulation.finish_session(seeded, sim)


def test_finishing_untouched_session_is_all_ignored(seeded):
    user = make_trainee(seeded, "alice")
    sim = simulation.start_session(seeded, user)
    summary = simulation.finish_session(seeded, sim)
    assert not summary.failed
    assert {i.outcome.decision for i in summary.items} == {config.DECISION_IGNORED}
    assert not any(i.outcome.opened for i in summary.items)
    assert summary.features.ignore_rate == 1.0


def test_three_behaviours_give_distinct_feature_profiles(seeded):
    clock = Clock()
    profiles = {}
    for name, play in [("imp", play_impulsive), ("vig", play_vigilant), ("pas", play_passive)]:
        user = make_trainee(seeded, name)
        sim = simulation.start_session(seeded, user)
        play(seeded, sim, clock)
        profiles[name] = simulation.finish_session(seeded, sim, now=clock(1000)).features

    imp, vig, pas = profiles["imp"], profiles["vig"], profiles["pas"]
    assert (imp.click_rate, imp.fast_click_rate, imp.hover_to_click_ratio) == (1.0, 1.0, 0.0)
    assert imp.mean_decision_latency_s < config.FAST_DECISION_S
    assert (vig.click_rate, vig.report_accuracy, vig.false_positive_rate) == (0.0, 1.0, 0.0)
    assert vig.mean_decision_latency_s > imp.mean_decision_latency_s
    assert (pas.click_rate, pas.report_accuracy, pas.ignore_rate) == (0.0, 0.0, 1.0)
    assert all(getattr(imp, f"vser_{v}") == 1.0 for v in config.VECTORS)


# --------------------------------------------------------------- adaptive
def finish_baseline(db, user, play, clock):
    sim = simulation.start_session(db, user)
    play(db, sim, clock)
    simulation.finish_session(db, sim, now=clock(1000))
    return sim


def test_adaptive_session_composition(seeded):
    clock = Clock()
    user = make_trainee(seeded, "alice")
    baseline = finish_baseline(seeded, user, play_impulsive, clock)

    sim = simulation.start_session(seeded, user, rng=random.Random(1))
    assert sim.kind == config.SESSION_KIND_ADAPTIVE
    counts = categories(sim)
    assert sum(counts[v] for v in config.VECTORS) == config.SESSION_PHISHING_COUNT
    assert counts[config.CATEGORY_LEGITIMATE] == config.SESSION_LEGITIMATE_COUNT
    assert len(set(codes(sim))) == len(codes(sim))           # no duplicates
    assert set(codes(sim)).isdisjoint(codes(baseline))        # unseen emails first

    # Impulsive user fails every vector equally -> tie broken by config order.
    weak = features.weakest_vector(features.load_history(seeded, user))
    assert weak == config.VECTORS[0]
    assert counts[weak] == config.SESSION_WEAK_VECTOR_SLOTS
    assert all(counts[v] >= 1 for v in config.VECTORS)


def test_vigilant_user_has_no_weak_vector(seeded):
    clock = Clock()
    user = make_trainee(seeded, "vera")
    finish_baseline(seeded, user, play_vigilant, clock)
    assert features.weakest_vector(features.load_history(seeded, user)) is None
    sim = simulation.start_session(seeded, user, rng=random.Random(3))
    counts = categories(sim)
    assert all(counts[v] >= 1 for v in config.VECTORS)
    assert max(counts[v] for v in config.VECTORS) == 2       # 5 slots over 4 vectors


def test_adaptive_session_respects_vector_levels(seeded):
    clock = Clock()
    user = make_trainee(seeded, "alice")
    finish_baseline(seeded, user, play_impulsive, clock)
    for row in seeded.scalars(select(UserVectorLevel).where(UserVectorLevel.user_id == user.id)):
        row.level = 3
    seeded.flush()
    sim = simulation.start_session(seeded, user, rng=random.Random(7))
    phishing = [d.email for d in sim.deliveries if d.email.is_phishing]
    # 2 level-3 emails exist per vector; the weak vector's 2 slots use both.
    assert all(e.difficulty == 3 for e in phishing)


def test_catalogue_exhaustion_falls_back_gracefully(seeded):
    clock = Clock()
    user = make_trainee(seeded, "alice")
    finish_baseline(seeded, user, play_impulsive, clock)
    for i in range(6):  # far more sessions than unseen emails
        sim = simulation.start_session(seeded, user, rng=random.Random(i))
        assert len(set(codes(sim))) == 8
        play_impulsive(seeded, sim, clock)
        simulation.finish_session(seeded, sim, now=clock(1000))


def test_features_window_and_history_order(seeded):
    clock = Clock()
    user = make_trainee(seeded, "alice")
    finish_baseline(seeded, user, play_impulsive, clock)
    for _ in range(3):
        sim = simulation.start_session(seeded, user, rng=random.Random(0))
        play_vigilant(seeded, sim, clock)
        summary = simulation.finish_session(seeded, sim, now=clock(1000))
    # After 3 vigilant sessions the impulsive baseline left the window...
    assert summary.features.window_sessions == config.FEATURE_WINDOW_SESSIONS
    assert summary.features.click_rate == 0.0
    assert len(features.load_history(seeded, user)) == 4
    assert features.latest_features(seeded, user) is summary.features


# -------------------------------------------------------------- planning
def test_plan_phishing_slots():
    rng = random.Random(0)
    weak = config.VECTOR_ATTACHMENT
    slots = simulation.plan_phishing_slots(weak, rng)
    assert len(slots) == config.SESSION_PHISHING_COUNT
    assert Counter(slots)[weak] == config.SESSION_WEAK_VECTOR_SLOTS
    assert set(slots) == set(config.VECTORS)

    slots = simulation.plan_phishing_slots(None, rng)
    assert set(slots) == set(config.VECTORS) and len(slots) == config.SESSION_PHISHING_COUNT

    with pytest.raises(ValueError):
        simulation.plan_phishing_slots("smishing", rng)
