"""Sample trainees for demonstrating the admin dashboard.

    python -m phishsense.services.sample_data --users 24
    python -m phishsense.services.sample_data --remove

Each sample trainee is a persona from the synthetic behaviour model
(:func:`synthetic.decide`), but unlike the synthetic training rows they go
through the **real application**: real inbox sessions, real behaviour events
with timestamps, the real pipeline (features, K-Means, Random Forest,
adaptive training) and real quizzes. Their history is spread over the past
weeks.

Sample users are flagged ``is_sample``, shown as such everywhere, have
random unusable passwords (nobody can sign in as them) and can be removed
with one command. They are demonstration data, not research data.
"""

from __future__ import annotations

import argparse
import random
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

import numpy as np
from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import QuizQuestion, User, utcnow
from phishsense.services import adaptive, auth, pipeline, quiz, simulation, tracking
from phishsense.services.ml import synthetic

FIRST_NAMES = ["Aarav", "Bianca", "Chen", "Divya", "Elena", "Farid", "Grace", "Hiro", "Isla",
               "Jonas", "Kavya", "Leo", "Maya", "Nikhil", "Olga", "Pedro", "Qin", "Rhea",
               "Samir", "Tara", "Umar", "Vera", "Wen", "Ximena", "Yusuf", "Zoe"]
LAST_NAMES = ["Rao", "Silva", "Novak", "Mensah", "Kowalski", "Haddad", "Iyer", "Lund",
              "Moreau", "Okoro", "Petrov", "Quinn", "Reyes", "Sato", "Tanaka", "Varga"]

IMPROVING = "Improving"
PERSONA_SHARES = {
    config.PROFILE_VIGILANT: 0.25,
    config.PROFILE_IMPULSIVE: 0.25,
    config.PROFILE_PASSIVE: 0.15,
    config.PROFILE_REPEATER: 0.15,
    IMPROVING: 0.20,          # starts impulsive, learns fast from training
}
QUIZ_SKILL = {config.PROFILE_VIGILANT: 0.92, IMPROVING: 0.85, config.PROFILE_IMPULSIVE: 0.7,
              config.PROFILE_PASSIVE: 0.75, config.PROFILE_REPEATER: 0.65}
MAX_QUIZ_ATTEMPTS = 4


@dataclass(frozen=True)
class SampleSummary:
    users: int
    sessions: int
    quiz_attempts: int


def _persona(kind: str, rng: np.random.Generator) -> synthetic.Persona:
    if kind == IMPROVING:
        base = synthetic.sample_persona(config.PROFILE_IMPULSIVE, rng)
        return replace(base, improvement=float(rng.uniform(0.35, 0.55)))
    return synthetic.sample_persona(kind, rng)


def _in_session(kind: str, persona: synthetic.Persona, index: int) -> synthetic.Persona:
    """An improving trainee also changes *how* they act, not only how often
    they err: each session they take longer and inspect links more (what the
    'Pause and inspect' lesson teaches), up to vigilant-like habits."""
    if kind != IMPROVING or index == 0:
        return persona
    return replace(persona,
                   hover_ms=min(persona.hover_ms + 900 * index, 3500),
                   latency_ms=min(persona.latency_ms * (1 + 1.5 * index), 12000))


def _persona_kinds(n_users: int, rng: random.Random) -> list[str]:
    """Exactly the configured share of each persona (largest remainder), shuffled.
    A plain random draw skews badly at demo sizes (24 users)."""
    raw = {k: share * n_users for k, share in PERSONA_SHARES.items()}
    counts = {k: int(v) for k, v in raw.items()}
    for k in sorted(raw, key=lambda k: raw[k] - counts[k], reverse=True)[:n_users - sum(counts.values())]:
        counts[k] += 1
    kinds = [k for k, c in counts.items() for _ in range(c)]
    rng.shuffle(kinds)
    return kinds


def _play(db: Session, sim, persona, index: int, rng: np.random.Generator,
          clock: datetime) -> datetime:
    """Turn the persona's decisions into real inbox events. Returns the clock."""
    inspect_chance = min(0.9, persona.hover_ms / 3000)
    for delivery in sim.deliveries:
        email = delivery.email
        record = synthetic.decide(persona, email.category, index, rng,
                                  has_link=bool(email.link_url))
        clock += timedelta(seconds=float(rng.uniform(3, 20)))  # reading the list
        if record.decision == config.DECISION_IGNORED and rng.random() > 0.6:
            continue                                            # never opened
        tracking.record_event(db, sim, email, config.EVENT_OPEN, ts=clock)
        t = clock
        if record.decision != config.DECISION_IGNORED and rng.random() < inspect_chance:
            t += timedelta(milliseconds=600)
            tracking.record_event(db, sim, email, config.EVENT_SENDER_INSPECT, ts=t)
        latency = timedelta(milliseconds=record.latency_ms or 0)
        if record.hover_ms and email.link_url:
            # A hover cannot outlast the time between opening and deciding.
            hover_ms = record.hover_ms if record.decision == config.DECISION_IGNORED \
                else min(record.hover_ms, int((record.latency_ms or 0) * 0.9))
            hover_end = clock + timedelta(milliseconds=hover_ms)
            tracking.record_event(db, sim, email, config.EVENT_LINK_HOVER,
                                  value_ms=hover_ms, ts=max(hover_end, t))
        if record.decision != config.DECISION_IGNORED:
            event = {
                config.DECISION_REPORTED: config.EVENT_REPORT,
                config.DECISION_MARKED_SAFE: config.EVENT_MARK_SAFE,
                config.DECISION_CLICKED: config.EVENT_LINK_CLICK
                if record.clicked_via == config.CLICK_VIA_LINK else config.EVENT_ATTACHMENT_OPEN,
            }[record.decision]
            tracking.record_event(db, sim, email, event, ts=clock + latency)
        clock += latency
    return clock


def _do_required_training(db: Session, user: User, skill: float, rng: random.Random) -> int:
    attempts = 0
    for assignment in adaptive.open_assignments(db, user):
        if not assignment.mandatory:
            continue
        for _ in range(MAX_QUIZ_ATTEMPTS):
            attempt = quiz.start_quiz(db, user, assignment, rng=rng)
            attempts += 1
            for q in attempt.questions:
                right = db.get(QuizQuestion, q.id).correct_index
                wrong = (right + 1) % len(q.options)
                quiz.answer(db, user, attempt, q, right if rng.random() < skill else wrong,
                            time_ms=int(rng.uniform(4000, 25000)))
            if quiz.finish_quiz(db, user, attempt).passed:
                break
    # Some trainees also do their optional training.
    for assignment in adaptive.open_assignments(db, user):
        if not assignment.mandatory and rng.random() < skill - 0.3:
            attempt = quiz.start_quiz(db, user, assignment, rng=rng)
            attempts += 1
            for q in attempt.questions:
                right = db.get(QuizQuestion, q.id).correct_index
                quiz.answer(db, user, attempt, q, right if rng.random() < skill else
                            (right + 1) % len(q.options))
            quiz.finish_quiz(db, user, attempt)
    return attempts


def _unique_username(db: Session, first: str, last: str) -> str:
    base = f"sample.{first}.{last}".lower()
    name, n = base, 1
    while auth.get_user_by_username(db, name) is not None:
        n += 1
        name = f"{base}{n}"
    return name[:32]


def generate(db: Session, n_users: int = 24, *, seed: int = 7,
             now: datetime | None = None) -> SampleSummary:
    rng_np = np.random.default_rng(seed)
    rng = random.Random(seed)
    now = now or utcnow()
    sessions = quiz_attempts = 0
    names = [(f, l) for f in FIRST_NAMES for l in LAST_NAMES]
    rng.shuffle(names)                      # distinct full names (416 combinations)

    for i, kind in enumerate(_persona_kinds(n_users, rng)):
        persona = _persona(kind, rng_np)
        first, last = names[i % len(names)]
        user = auth.register_user(
            db, username=_unique_username(db, first, last), full_name=f"{first} {last}",
            department=config.DEPARTMENTS[i % len(config.DEPARTMENTS)],
            password=secrets.token_urlsafe(24) + "1a",   # random: nobody can sign in
        )
        user.is_sample = True

        n_sessions = int(rng_np.integers(2, 6))
        clock = now - timedelta(days=int(rng_np.integers(14, 35)))
        for index in range(n_sessions):
            try:
                sim = simulation.start_session(db, user, rng=rng)
            except simulation.SimulationError:
                break  # still blocked by required training it could not pass
            sim.started_at = clock
            clock = _play(db, sim, _in_session(kind, persona, index), index, rng_np, clock)
            pipeline.complete_session(db, sim, now=clock)
            sessions += 1
            quiz_attempts += _do_required_training(db, user, QUIZ_SKILL[kind], rng)
            clock += timedelta(days=float(rng_np.uniform(1, 5)))
            if clock >= now:
                break
    db.flush()
    return SampleSummary(n_users, sessions, quiz_attempts)


def remove(db: Session) -> int:
    """Delete every sample user and all their data. Returns how many."""
    users = list(db.scalars(select(User).where(User.is_sample.is_(True))))
    for user in users:
        db.delete(user)
    db.flush()
    return len(users)


def count(db: Session) -> int:
    return len(db.scalars(select(User.id).where(User.is_sample.is_(True))).all())


def main(argv: list[str] | None = None) -> int:
    from phishsense.data.db import create_db_engine, init_db, make_session_factory, session_scope
    from phishsense.data.seed import seed_content

    parser = argparse.ArgumentParser(description="Create or remove sample trainees.")
    parser.add_argument("--users", type=int, default=24)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--remove", action="store_true", help="delete all sample users")
    args = parser.parse_args(argv)

    engine = create_db_engine()
    try:
        init_db(engine)
        with session_scope(make_session_factory(engine)) as db:
            seed_content(db)
            if args.remove:
                print(f"Removed {remove(db)} sample users.")
            else:
                s = generate(db, args.users, seed=args.seed)
                print(f"Created {s.users} sample users with {s.sessions} sessions and "
                      f"{s.quiz_attempts} quiz attempts.")
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
