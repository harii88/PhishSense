from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.models import BehaviourEvent, Email
from phishsense.data.seed import seed_content
from phishsense.services import simulation, tracking
from phishsense.services.tracking import TrackingError, derive_outcome, evaluate
from tests.helpers import Clock, make_trainee


@pytest.fixture
def sim(db):
    seed_content(db)
    user = make_trainee(db, "alice")
    return simulation.start_session(db, user)


def email_in(sim, code) -> Email:
    return next(d.email for d in sim.deliveries if d.email.code == code)


LINK_PHISH = "url-1-bank-verify"
ATTACH_PHISH = "att-1-invoice-exe"


# ------------------------------------------------------------- recording
def test_normal_sequence_is_stored(db, sim):
    e = email_in(sim, LINK_PHISH)
    tracking.record_event(db, sim, e, config.EVENT_OPEN)
    tracking.record_event(db, sim, e, config.EVENT_LINK_HOVER, value_ms=1200)
    tracking.record_event(db, sim, e, config.EVENT_REPORT)
    assert tracking.decision_made(db, sim, e) == config.DECISION_REPORTED
    assert len(tracking.events_for(db, sim, e)) == 3


def test_decision_requires_open(db, sim):
    with pytest.raises(TrackingError, match="Open the email"):
        tracking.record_event(db, sim, email_in(sim, LINK_PHISH), config.EVENT_REPORT)


def test_only_first_decision_counts(db, sim):
    e = email_in(sim, LINK_PHISH)
    tracking.record_event(db, sim, e, config.EVENT_OPEN)
    tracking.record_event(db, sim, e, config.EVENT_LINK_CLICK)
    with pytest.raises(TrackingError, match="already been made"):
        tracking.record_event(db, sim, e, config.EVENT_REPORT)
    # non-decision events are still fine (e.g. re-opening to read the feedback)
    tracking.record_event(db, sim, e, config.EVENT_OPEN)


@pytest.mark.parametrize(
    "event_type, value, message",
    [
        (config.EVENT_LINK_HOVER, None, "duration"),
        (config.EVENT_LINK_HOVER, -5, "negative"),
        (config.EVENT_LINK_HOVER, 1.5, "duration"),
        (config.EVENT_LINK_HOVER, True, "duration"),
        (config.EVENT_OPEN, 100, "do not carry"),
        ("teleport", None, "Unknown event"),
    ],
)
def test_event_values_validated(db, sim, event_type, value, message):
    with pytest.raises(TrackingError, match=message):
        tracking.record_event(db, sim, email_in(sim, LINK_PHISH), event_type, value_ms=value)


def test_payload_must_exist(db, sim):
    attach_only = email_in(sim, ATTACH_PHISH)
    link_only = email_in(sim, LINK_PHISH)
    tracking.record_event(db, sim, attach_only, config.EVENT_OPEN)
    tracking.record_event(db, sim, link_only, config.EVENT_OPEN)
    with pytest.raises(TrackingError, match="no link"):
        tracking.record_event(db, sim, attach_only, config.EVENT_LINK_CLICK)
    with pytest.raises(TrackingError, match="no link to hover"):
        tracking.record_event(db, sim, attach_only, config.EVENT_LINK_HOVER, value_ms=10)
    with pytest.raises(TrackingError, match="no attachment"):
        tracking.record_event(db, sim, link_only, config.EVENT_ATTACHMENT_OPEN)


def test_email_must_be_delivered_in_session(db, sim):
    delivered = {d.email_id for d in sim.deliveries}
    other = db.scalar(select(Email).where(Email.id.not_in(delivered)).limit(1))
    with pytest.raises(TrackingError, match="not delivered"):
        tracking.record_event(db, sim, other, config.EVENT_OPEN)


def test_no_events_after_finish(db, sim):
    simulation.finish_session(db, sim)
    with pytest.raises(TrackingError, match="already finished"):
        tracking.record_event(db, sim, email_in(sim, LINK_PHISH), config.EVENT_OPEN)


def test_rejected_events_are_not_stored(db, sim):
    with pytest.raises(TrackingError):
        tracking.record_event(db, sim, email_in(sim, LINK_PHISH), config.EVENT_REPORT)
    assert db.scalars(select(BehaviourEvent)).all() == []


# ------------------------------------------------------------ derivation
T0 = datetime(2026, 1, 5, 9, 0, 0)


def ev(event_type, at_ms, value_ms=None, id_=None):
    return BehaviourEvent(
        event_type=event_type, ts=T0 + timedelta(milliseconds=at_ms), value_ms=value_ms, id=id_
    )


def phishing_email(**kw):
    return Email(is_phishing=True, category=config.VECTOR_URL_SPOOFING,
                 link_url="https://x.test", **kw)


def test_click_after_inspection():
    out = derive_outcome(phishing_email(), [
        ev(config.EVENT_OPEN, 0),
        ev(config.EVENT_SENDER_INSPECT, 400),
        ev(config.EVENT_LINK_HOVER, 1800, value_ms=1400),
        ev(config.EVENT_LINK_CLICK, 3000),
    ])
    assert out.decision == config.DECISION_CLICKED
    assert out.clicked_via == config.CLICK_VIA_LINK
    assert out.correct is False
    assert out.latency_ms == 3000
    assert out.hover_ms == 1400
    assert out.inspected_sender and out.opened


def test_activity_after_decision_is_ignored():
    out = derive_outcome(phishing_email(), [
        ev(config.EVENT_OPEN, 0),
        ev(config.EVENT_LINK_CLICK, 800),
        ev(config.EVENT_LINK_HOVER, 2000, value_ms=1500),   # hover closed after the click
        ev(config.EVENT_SENDER_INSPECT, 2500),
    ])
    assert out.hover_ms == 0 and not out.inspected_sender
    assert out.latency_ms == 800


def test_same_timestamp_resolved_by_insertion_order():
    out = derive_outcome(phishing_email(), [
        ev(config.EVENT_OPEN, 0, id_=1),
        ev(config.EVENT_LINK_CLICK, 500, id_=2),
        ev(config.EVENT_LINK_HOVER, 500, value_ms=900, id_=3),
    ])
    assert out.hover_ms == 0


def test_latency_measured_from_first_open():
    out = derive_outcome(phishing_email(), [
        ev(config.EVENT_OPEN, 0), ev(config.EVENT_OPEN, 10_000), ev(config.EVENT_REPORT, 12_000),
    ])
    assert out.latency_ms == 12_000 and out.correct is True


def test_ignored_email_keeps_all_inspection():
    out = derive_outcome(phishing_email(), [
        ev(config.EVENT_OPEN, 0), ev(config.EVENT_LINK_HOVER, 900, value_ms=900),
    ])
    assert out.decision == config.DECISION_IGNORED
    assert out.latency_ms is None and out.hover_ms == 900
    assert out.correct is False   # a missed phishing email is not a correct outcome


def test_unopened_email():
    out = derive_outcome(phishing_email(), [])
    assert not out.opened and out.decision == config.DECISION_IGNORED


@pytest.mark.parametrize(
    "is_phishing, decision, expected",
    [
        (True, config.DECISION_CLICKED, False),
        (True, config.DECISION_REPORTED, True),
        (True, config.DECISION_MARKED_SAFE, False),
        (True, config.DECISION_IGNORED, False),
        (False, config.DECISION_CLICKED, True),
        (False, config.DECISION_REPORTED, False),
        (False, config.DECISION_MARKED_SAFE, True),
        (False, config.DECISION_IGNORED, None),
    ],
)
def test_evaluation_table(is_phishing, decision, expected):
    assert evaluate(is_phishing, decision) is expected


def test_evaluate_rejects_unknown_decision():
    with pytest.raises(ValueError):
        evaluate(True, "shrugged")
