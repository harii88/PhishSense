"""The project's demonstration scenario, end to end through the service layer.

1. Register two users.                2. Both enter the simulated inbox.
3. A clicks suspicious links; B inspects and reports.
4. Behaviour is recorded.             5. K-Means identifies the patterns.
6. Random Forest predicts risk.       7. Different risk levels are assigned.
8. A gets URL training (required); B gets advanced impersonation training.
9. Both complete another simulation.  10. Scores and levels update.
"""

from __future__ import annotations

import random

import pytest

from phishsense import config
from phishsense.data.seed import seed_content
from phishsense.services import pipeline, quiz, simulation
from tests.helpers import Clock, make_trainee, play_impulsive, play_vigilant


def mean_phishing_difficulty(sim) -> float:
    levels = [d.email.difficulty for d in sim.deliveries if d.email.is_phishing]
    return sum(levels) / len(levels)


def test_demonstration_scenario(db, ml_env):
    seed_content(db)
    clock = Clock()

    # 1-2: two users, both start with the identical baseline inbox
    alice = make_trainee(db, "alice", department="Finance")      # User A
    bob = make_trainee(db, "bob", department="Engineering")     # User B
    sim_a, sim_b = simulation.start_session(db, alice), simulation.start_session(db, bob)
    assert [d.email_id for d in sim_a.deliveries] == [d.email_id for d in sim_b.deliveries]

    # 3-4: different behaviour, recorded as events
    play_impulsive(db, sim_a, clock)
    play_vigilant(db, sim_b, clock)
    assert len(sim_a.events) > 0 and len(sim_b.events) > len(sim_a.events)

    # 5-7: the closed loop runs on completion
    a1 = pipeline.complete_session(db, sim_a, now=clock(1000))
    b1 = pipeline.complete_session(db, sim_b, now=clock(1000))
    assert a1.summary.failed and not b1.summary.failed
    assert a1.prediction.profile == config.PROFILE_IMPULSIVE
    assert b1.prediction.profile == config.PROFILE_VIGILANT
    assert a1.prediction.risk_level == config.RISK_HIGH
    assert b1.prediction.risk_level == config.RISK_LOW
    assert a1.prediction.fail_probability > b1.prediction.fail_probability

    # 8: different, explained training
    a_training = {(t.module.topic, t.module.level, t.mandatory) for t in a1.assignments}
    b_training = {(t.module.topic, t.module.level, t.mandatory) for t in b1.assignments}
    assert a_training == {(config.VECTOR_URL_SPOOFING, 1, True),
                          (config.TOPIC_PAUSE_INSPECT, 1, False)}
    assert b_training == {(config.VECTOR_IMPERSONATION, 3, False)}
    assert all(t.reason for t in a1.assignments + b1.assignments)

    # Difficulty: A stays at the floor, B moves up everywhere.
    assert {c.new for c in a1.level_changes} == {1}
    assert {c.new for c in b1.level_changes} == {2}

    # A's required training blocks the next simulation until its quiz is passed.
    with pytest.raises(simulation.SimulationError, match="required training"):
        simulation.start_session(db, alice)
    required = next(t for t in a1.assignments if t.mandatory)
    attempt = quiz.start_quiz(db, alice, required, rng=random.Random(0))
    for q in attempt.questions:
        assert quiz.answer(db, alice, attempt, q, q.correct_index).correct
    assert quiz.finish_quiz(db, alice, attempt).passed

    # 9: the next inboxes differ: B's is harder, A's targets URL spoofing
    sim_a2 = simulation.start_session(db, alice, rng=random.Random(1))
    sim_b2 = simulation.start_session(db, bob, rng=random.Random(1))
    assert sim_a2.kind == sim_b2.kind == config.SESSION_KIND_ADAPTIVE
    assert mean_phishing_difficulty(sim_b2) > mean_phishing_difficulty(sim_a2)
    a2_vectors = [d.email.category for d in sim_a2.deliveries]
    assert a2_vectors.count(config.VECTOR_URL_SPOOFING) == config.SESSION_WEAK_VECTOR_SLOTS

    # A has learned; both now inspect and report.
    play_vigilant(db, sim_a2, clock)
    play_vigilant(db, sim_b2, clock)
    a2 = pipeline.complete_session(db, sim_a2, now=clock(1000))
    b2 = pipeline.complete_session(db, sim_b2, now=clock(1000))

    # 10: updated scores and levels
    assert not a2.summary.failed
    assert a2.prediction.fail_probability < a1.prediction.fail_probability
    assert a2.summary.features.click_rate < a1.summary.features.click_rate
    assert a2.summary.features.window_sessions == 2
    assert {c.new for c in a2.level_changes} == {2}          # A climbs off the floor
    assert all(c.new == min(c.old + 1, 3) for c in b2.level_changes)
    assert b2.prediction.risk_level == config.RISK_LOW
