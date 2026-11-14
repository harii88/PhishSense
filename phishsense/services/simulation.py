"""Simulation sessions: compose an inbox, start a session, finish it.

Composition (DESIGN.md section 7)
---------------------------------
* **Baseline** (the user's first session): the fixed list
  ``content.BASELINE_EMAIL_CODES``, identical for everyone.
* **Adaptive** (every later session): ``SESSION_PHISHING_COUNT`` phishing +
  ``SESSION_LEGITIMATE_COUNT`` genuine emails.

  - ``SESSION_WEAK_VECTOR_SLOTS`` phishing slots go to the user's weakest
    vector (see :func:`features.weakest_vector`); the remaining slots cycle
    through the other vectors in random order. With no weakness, all vectors
    are cycled.
  - Each slot asks for an email of that vector at the user's current level
    for it. Candidates are ranked by (times the user has already seen it,
    distance from the wanted level, random), so unseen emails at the right
    level come first, and the fallback is graceful when the catalogue runs out.
  - Genuine emails use the same ranking around the user's mean level.
  - The final inbox order is shuffled.

Finishing a session turns events into outcomes (tracking.derive_outcome),
marks the session failed if any phishing email was compromised, and stores the
feature snapshot. Machine learning and training assignment run on top of this
in later modules.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data import content
from phishsense.data.models import (
    BehaviourEvent,
    BehaviourFeatures,
    Email,
    EmailOutcome,
    SessionEmail,
    SimulationSession,
    TrainingAssignment,
    User,
    UserVectorLevel,
    utcnow,
)
from phishsense.services import features, tracking


class SimulationError(Exception):
    """The session cannot be started or finished. Message is user-facing."""


@dataclass(frozen=True)
class ReviewItem:
    position: int
    email: Email
    outcome: EmailOutcome


@dataclass(frozen=True)
class SessionSummary:
    session: SimulationSession
    items: list[ReviewItem]
    features: BehaviourFeatures
    history: list[list[features.OutcomeRecord]]

    @property
    def failed(self) -> bool:
        return bool(self.session.failed)

    @property
    def phishing_total(self) -> int:
        return sum(1 for i in self.items if i.email.is_phishing)

    @property
    def phishing_reported(self) -> int:
        return sum(
            1 for i in self.items
            if i.email.is_phishing and i.outcome.decision == config.DECISION_REPORTED
        )

    @property
    def phishing_compromised(self) -> int:
        return sum(
            1 for i in self.items
            if i.email.is_phishing and i.outcome.decision == config.DECISION_CLICKED
        )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
def ensure_vector_levels(session: Session, user: User) -> dict[str, int]:
    """Current level per vector, creating level-1 rows on first use."""
    rows = {
        row.vector: row
        for row in session.scalars(select(UserVectorLevel).where(UserVectorLevel.user_id == user.id))
    }
    for vector in config.VECTORS:
        if vector not in rows:
            rows[vector] = UserVectorLevel(user_id=user.id, vector=vector, level=config.MIN_LEVEL)
            session.add(rows[vector])
    session.flush()
    return {v: rows[v].level for v in config.VECTORS}


def get_open_session(session: Session, user: User) -> SimulationSession | None:
    return session.scalar(
        select(SimulationSession).where(
            SimulationSession.user_id == user.id, SimulationSession.completed_at.is_(None)
        )
    )


def completed_session_count(session: Session, user: User) -> int:
    return session.scalar(
        select(func.count()).where(
            SimulationSession.user_id == user.id, SimulationSession.completed_at.is_not(None)
        )
    )


def pending_mandatory_training(session: Session, user: User) -> list[TrainingAssignment]:
    return list(
        session.scalars(
            select(TrainingAssignment).where(
                TrainingAssignment.user_id == user.id,
                TrainingAssignment.mandatory.is_(True),
                TrainingAssignment.completed_at.is_(None),
            )
        )
    )


def _seen_counts(session: Session, user: User) -> Counter[int]:
    rows = session.scalars(
        select(SessionEmail.email_id)
        .join(SimulationSession, SimulationSession.id == SessionEmail.session_id)
        .where(SimulationSession.user_id == user.id)
    )
    return Counter(rows)


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------
def plan_phishing_slots(weak_vector: str | None, rng: random.Random) -> list[str]:
    """Vectors for the phishing slots of an adaptive session (pure)."""
    if weak_vector is not None and weak_vector not in config.VECTORS:
        raise ValueError(f"Unknown vector {weak_vector!r}")
    slots = [weak_vector] * config.SESSION_WEAK_VECTOR_SLOTS if weak_vector else []
    others = [v for v in config.VECTORS if v != weak_vector]
    rng.shuffle(others)
    i = 0
    while len(slots) < config.SESSION_PHISHING_COUNT:
        slots.append(others[i % len(others)])
        i += 1
    return slots


def _pick(
    candidates: list[Email],
    target_level: int,
    seen: Counter[int],
    used: set[int],
    rng: random.Random,
) -> Email:
    available = [e for e in candidates if e.id not in used]
    if not available:
        raise SimulationError("Not enough training emails are loaded. Run the seed script.")
    best = min(available, key=lambda e: (seen[e.id], abs(e.difficulty - target_level), rng.random()))
    used.add(best.id)
    return best


def compose_baseline(session: Session) -> list[Email]:
    by_code = {
        e.code: e
        for e in session.scalars(select(Email).where(Email.code.in_(content.BASELINE_EMAIL_CODES)))
    }
    missing = [c for c in content.BASELINE_EMAIL_CODES if c not in by_code]
    if missing:
        raise SimulationError("Training content is missing. Run the seed script.")
    return [by_code[c] for c in content.BASELINE_EMAIL_CODES]


def compose_adaptive(
    session: Session,
    user: User,
    levels: dict[str, int],
    weak_vector: str | None,
    rng: random.Random,
) -> list[Email]:
    catalogue = list(session.scalars(select(Email)))
    by_category: dict[str, list[Email]] = {}
    for email in catalogue:
        by_category.setdefault(email.category, []).append(email)

    seen = _seen_counts(session, user)
    used: set[int] = set()

    inbox = [
        _pick(by_category.get(vector, []), levels[vector], seen, used, rng)
        for vector in plan_phishing_slots(weak_vector, rng)
    ]
    genuine_level = round(sum(levels.values()) / len(levels))
    inbox += [
        _pick(by_category.get(config.CATEGORY_LEGITIMATE, []), genuine_level, seen, used, rng)
        for _ in range(config.SESSION_LEGITIMATE_COUNT)
    ]
    rng.shuffle(inbox)
    return inbox


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
def start_session(
    session: Session, user: User, *, rng: random.Random | None = None
) -> SimulationSession:
    """Start the user's next session, or return the one still open."""
    if user.is_admin:
        raise SimulationError("Simulations are for trainee accounts.")

    open_session = get_open_session(session, user)
    if open_session is not None:
        return open_session

    if pending_mandatory_training(session, user):
        raise SimulationError("Finish your required training before the next simulation.")

    rng = rng or random.Random()
    levels = ensure_vector_levels(session, user)

    if completed_session_count(session, user) == 0:
        kind, emails = config.SESSION_KIND_BASELINE, compose_baseline(session)
    else:
        history = features.load_history(session, user)
        weak = features.weakest_vector(history)
        kind, emails = config.SESSION_KIND_ADAPTIVE, compose_adaptive(
            session, user, levels, weak, rng
        )

    sim = SimulationSession(user_id=user.id, kind=kind)
    for position, email in enumerate(emails):
        sim.deliveries.append(SessionEmail(email=email, position=position))
    session.add(sim)
    session.flush()
    return sim


def finish_session(
    session: Session, sim: SimulationSession, *, now: datetime | None = None
) -> SessionSummary:
    """Close the session: derive outcomes, set ``failed``, store features."""
    if sim.is_complete:
        raise SimulationError("This session is already finished.")

    events_by_email: dict[int, list[BehaviourEvent]] = {}
    for event in session.scalars(
        select(BehaviourEvent)
        .where(BehaviourEvent.session_id == sim.id)
        .order_by(BehaviourEvent.ts, BehaviourEvent.id)
    ):
        events_by_email.setdefault(event.email_id, []).append(event)

    items: list[ReviewItem] = []
    for delivery in sim.deliveries:
        derived = tracking.derive_outcome(delivery.email, events_by_email.get(delivery.email_id, []))
        outcome = EmailOutcome(
            session_id=sim.id,
            email_id=delivery.email_id,
            decision=derived.decision,
            clicked_via=derived.clicked_via,
            correct=derived.correct,
            opened=derived.opened,
            latency_ms=derived.latency_ms,
            hover_ms=derived.hover_ms,
            inspected_sender=derived.inspected_sender,
        )
        session.add(outcome)
        items.append(ReviewItem(delivery.position, delivery.email, outcome))

    sim.failed = any(
        i.email.is_phishing and i.outcome.decision == config.DECISION_CLICKED for i in items
    )
    sim.completed_at = now or utcnow()
    session.flush()

    user = session.get(User, sim.user_id)
    features_row, history = features.store_features(session, user, sim)
    return SessionSummary(session=sim, items=items, features=features_row, history=history)
