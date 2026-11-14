"""Behaviour tracking: validate and store raw events, derive per-email outcomes.

Event rules (enforced here, so the database can only hold coherent streams):

* Events are accepted only while the session is open and only for emails
  delivered in that session.
* A decision (link click, attachment open, report, mark safe) requires the
  email to have been opened first, and only the **first** decision counts:
  later decision events for the same email are rejected. The inbox locks an
  email once a decision is made.
* ``link_hover`` carries ``value_ms`` (the hover duration). The inbox records
  a hover when the pointer leaves the link, so it must close any hover in
  progress *before* recording a click on that link; otherwise the inspection
  would be stored after the click and not count as "hover before click".

Outcome rules (DESIGN.md section 3):

=============  ==================  =================
decision       phishing email      legitimate email
=============  ==================  =================
clicked        wrong (compromise)  correct
reported       correct             wrong (false +)
marked_safe    wrong               correct
ignored        wrong (miss)        neutral (None)
=============  ==================  =================

``ignored`` phishing counts as *not correct* for accuracy, but it is a miss,
not an error: the error rates (VSER) only count compromises and phishing
marked as safe.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourEvent,
    Email,
    SessionEmail,
    SimulationSession,
    utcnow,
)


class TrackingError(Exception):
    """An event that cannot happen in a well-behaved inbox."""


# Decision event type -> (decision, clicked_via)
DECISION_EVENTS: dict[str, tuple[str, str | None]] = {
    config.EVENT_LINK_CLICK: (config.DECISION_CLICKED, config.CLICK_VIA_LINK),
    config.EVENT_ATTACHMENT_OPEN: (config.DECISION_CLICKED, config.CLICK_VIA_ATTACHMENT),
    config.EVENT_REPORT: (config.DECISION_REPORTED, None),
    config.EVENT_MARK_SAFE: (config.DECISION_MARKED_SAFE, None),
}


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------
def events_for(session: Session, sim: SimulationSession, email: Email) -> list[BehaviourEvent]:
    return list(
        session.scalars(
            select(BehaviourEvent)
            .where(BehaviourEvent.session_id == sim.id, BehaviourEvent.email_id == email.id)
            .order_by(BehaviourEvent.ts, BehaviourEvent.id)
        )
    )


def record_event(
    session: Session,
    sim: SimulationSession,
    email: Email,
    event_type: str,
    *,
    value_ms: int | None = None,
    ts: datetime | None = None,
) -> BehaviourEvent:
    """Validate and store one interaction. Raises :class:`TrackingError`."""
    if event_type not in config.EVENT_TYPES:
        raise TrackingError(f"Unknown event type {event_type!r}.")
    if sim.is_complete:
        raise TrackingError("This session is already finished.")

    delivered = session.get(SessionEmail, (sim.id, email.id))
    if delivered is None:
        raise TrackingError("That email was not delivered in this session.")

    if event_type == config.EVENT_LINK_HOVER:
        if value_ms is None or isinstance(value_ms, bool) or not isinstance(value_ms, int):
            raise TrackingError("A link hover needs its duration in whole milliseconds.")
        if value_ms < 0:
            raise TrackingError("Hover duration cannot be negative.")
        if not email.link_url:
            raise TrackingError("This email has no link to hover.")
    elif value_ms is not None:
        raise TrackingError(f"{event_type!r} events do not carry a value.")

    if event_type == config.EVENT_LINK_CLICK and not email.link_url:
        raise TrackingError("This email has no link.")
    if event_type == config.EVENT_ATTACHMENT_OPEN and not email.attachment_name:
        raise TrackingError("This email has no attachment.")

    if event_type in DECISION_EVENTS:
        previous = events_for(session, sim, email)
        if not any(e.event_type == config.EVENT_OPEN for e in previous):
            raise TrackingError("Open the email before acting on it.")
        if any(e.event_type in DECISION_EVENTS for e in previous):
            raise TrackingError("A decision has already been made for this email.")

    event = BehaviourEvent(
        session_id=sim.id,
        email_id=email.id,
        event_type=event_type,
        value_ms=value_ms,
        ts=ts or utcnow(),
    )
    session.add(event)
    session.flush()
    return event


def decision_made(session: Session, sim: SimulationSession, email: Email) -> str | None:
    """The decision already taken for ``email`` in ``sim``, or None."""
    for event in events_for(session, sim, email):
        if event.event_type in DECISION_EVENTS:
            return DECISION_EVENTS[event.event_type][0]
    return None


# ---------------------------------------------------------------------------
# Outcome derivation (pure)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DerivedOutcome:
    decision: str
    clicked_via: str | None
    correct: bool | None
    opened: bool
    latency_ms: int | None
    hover_ms: int
    inspected_sender: bool


def evaluate(is_phishing: bool, decision: str) -> bool | None:
    """Correctness of ``decision`` (see the table in the module docstring)."""
    if decision not in config.DECISIONS:
        raise ValueError(f"Unknown decision {decision!r}")
    if is_phishing:
        return decision == config.DECISION_REPORTED
    if decision == config.DECISION_IGNORED:
        return None
    return decision != config.DECISION_REPORTED


def derive_outcome(email: Email, events: Iterable[BehaviourEvent]) -> DerivedOutcome:
    """Reduce one email's event stream to its outcome.

    * latency: first ``open`` -> decision, in ms (None when ignored).
    * hover_ms / inspected_sender: only what happened *before* the decision
      (everything, when the email was ignored).
    """
    ordered = sorted(events, key=lambda e: (e.ts, e.id or 0))

    decision_index = next(
        (i for i, e in enumerate(ordered) if e.event_type in DECISION_EVENTS), None
    )
    before = ordered if decision_index is None else ordered[: decision_index + 1]
    first_open = next((e for e in ordered if e.event_type == config.EVENT_OPEN), None)

    if decision_index is None:
        decision, clicked_via, latency_ms = config.DECISION_IGNORED, None, None
    else:
        decision_event = ordered[decision_index]
        decision, clicked_via = DECISION_EVENTS[decision_event.event_type]
        latency_ms = None
        if first_open is not None:
            delta = decision_event.ts - first_open.ts
            latency_ms = max(0, round(delta.total_seconds() * 1000))

    return DerivedOutcome(
        decision=decision,
        clicked_via=clicked_via,
        correct=evaluate(email.is_phishing, decision),
        opened=first_open is not None,
        latency_ms=latency_ms,
        hover_ms=sum(e.value_ms or 0 for e in before if e.event_type == config.EVENT_LINK_HOVER),
        inspected_sender=any(e.event_type == config.EVENT_SENDER_INSPECT for e in before),
    )
