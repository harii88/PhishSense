"""Adaptive training (DESIGN.md section 7).

Two mechanisms run after every completed session:

1. **Difficulty control.** For each vector that appeared in the session,
   accuracy = correctly handled phishing emails / phishing emails of that
   vector (an ignored phishing email is not correct). Accuracy >=
   LEVEL_UP_ACCURACY raises the level by one, <= LEVEL_DOWN_ACCURACY lowers it,
   bounded to MIN_LEVEL..MAX_LEVEL. The next inbox is drawn at these levels.

2. **Training recommendations** (:func:`recommend`, pure), in priority order:

   a. *Weakest vector* (features.weakest_vector): that vector's module at the
      user's current level for it.
   b. *Profile module* from the K-Means profile:
        Impulsive Clickers  -> Pause and inspect
        Passive Ignorers    -> Why and how to report
        High-Risk Repeaters -> level-1 (remedial) module of the most repeated
                               vector (falls back to the weakest vector)
        Vigilant Verifiers  -> first level-3 (advanced) module not yet passed,
                               trying impersonation, URL, urgency, attachment
   c. *High risk*: the first recommendation becomes mandatory; the next
      simulation is blocked until its quiz is passed.

   Duplicates (same topic and level) are merged. When an open assignment for
   the same module already exists, no second one is created; it is only made
   mandatory if needed. Each assignment stores a human-readable reason that
   cites the numbers it was based on.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    MLPrediction,
    TrainingAssignment,
    TrainingModule,
    User,
    UserVectorLevel,
)
from phishsense.services import features
from phishsense.services.features import FeatureVector, SessionHistory
from phishsense.services.simulation import ReviewItem, SessionSummary

ADVANCED_ORDER = (
    config.VECTOR_IMPERSONATION,
    config.VECTOR_URL_SPOOFING,
    config.VECTOR_URGENCY,
    config.VECTOR_ATTACHMENT,
)


_PHRASES = {
    config.VECTOR_URL_SPOOFING: "URL-spoofing",
    config.VECTOR_URGENCY: "urgency-based",
    config.VECTOR_IMPERSONATION: "sender-impersonation",
    config.VECTOR_ATTACHMENT: "malicious-attachment",
}


def _label(vector: str) -> str:
    """Phrase used inside reason sentences, e.g. '... of 4 URL-spoofing emails'."""
    return _PHRASES[vector]


# ---------------------------------------------------------------------------
# Difficulty control
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LevelChange:
    vector: str
    old: int
    new: int
    correct: int
    total: int

    @property
    def accuracy(self) -> float:
        return self.correct / self.total


def vector_accuracy(items: list[ReviewItem]) -> dict[str, tuple[int, int]]:
    """(correct, total) per vector over the phishing emails of one session."""
    result: dict[str, tuple[int, int]] = {}
    for item in items:
        if not item.email.is_phishing:
            continue
        correct, total = result.get(item.email.category, (0, 0))
        result[item.email.category] = (correct + bool(item.outcome.correct), total + 1)
    return result


def next_level(level: int, accuracy: float) -> int:
    if accuracy >= config.LEVEL_UP_ACCURACY:
        level += 1
    elif accuracy <= config.LEVEL_DOWN_ACCURACY:
        level -= 1
    return max(config.MIN_LEVEL, min(config.MAX_LEVEL, level))


def update_levels(session: Session, user: User, summary: SessionSummary) -> list[LevelChange]:
    rows = {
        r.vector: r
        for r in session.scalars(select(UserVectorLevel).where(UserVectorLevel.user_id == user.id))
    }
    changes = []
    for vector, (correct, total) in vector_accuracy(summary.items).items():
        row = rows[vector]
        new = next_level(row.level, correct / total)
        changes.append(LevelChange(vector, row.level, new, correct, total))
        row.level = new
    session.flush()
    return changes


def current_levels(session: Session, user: User) -> dict[str, int]:
    rows = session.scalars(select(UserVectorLevel).where(UserVectorLevel.user_id == user.id))
    levels = {r.vector: r.level for r in rows}
    return {v: levels.get(v, config.MIN_LEVEL) for v in config.VECTORS}


# ---------------------------------------------------------------------------
# Recommendations (pure)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Recommendation:
    topic: str
    level: int
    reason: str
    mandatory: bool = False


def recommend(
    *,
    profile: str,
    fail_probability: float,
    risk_level: str,
    vector: FeatureVector,
    history: SessionHistory,
    levels: dict[str, int],
    passed_modules: set[tuple[str, int]],
) -> list[Recommendation]:
    recs: list[Recommendation] = []
    window = vector.window_sessions
    sessions = "session" if window == 1 else f"{window} sessions"

    weak = features.weakest_vector(history)
    if weak is not None:
        exposure = features.vector_exposure(history)[weak]
        recs.append(Recommendation(
            weak, levels[weak],
            f"You fell for {exposure.errors} of {exposure.seen} {_label(weak)} emails "
            f"in your last {sessions}.",
        ))

    if profile == config.PROFILE_IMPULSIVE:
        recs.append(Recommendation(
            config.TOPIC_PAUSE_INSPECT, 1,
            f"Behaviour profile: {profile}. {vector.fast_click_rate:.0%} of your clicks came within "
            f"{config.FAST_DECISION_S:.0f} seconds without checking where the link went.",
        ))
    elif profile == config.PROFILE_PASSIVE:
        recs.append(Recommendation(
            config.TOPIC_REPORTING, 1,
            f"Behaviour profile: {profile}. You left {vector.ignore_rate:.0%} of phishing emails "
            "without reporting them.",
        ))
    elif profile == config.PROFILE_REPEATER:
        repeated = features.repeated_vectors(history)
        target = repeated[0] if repeated else weak
        if target is not None:
            detail = ("you have made mistakes on these emails in more than one session"
                      if repeated else "your mistakes keep coming back")
            recs.append(Recommendation(
                target, config.MIN_LEVEL,
                f"Behaviour profile: {profile}. Back to basics on {_label(target)} emails: {detail}.",
            ))
    elif profile == config.PROFILE_VIGILANT:
        for v in ADVANCED_ORDER:
            if (v, config.MAX_LEVEL) not in passed_modules:
                recs.append(Recommendation(
                    v, config.MAX_LEVEL,
                    f"Behaviour profile: {profile}. You spot the obvious attacks, so the next step "
                    f"is advanced {_label(v)} attacks.",
                ))
                break

    # Merge duplicates, keeping the first (highest-priority) reason.
    unique: dict[tuple[str, int], Recommendation] = {}
    for rec in recs:
        unique.setdefault((rec.topic, rec.level), rec)
    recs = list(unique.values())

    if risk_level == config.RISK_HIGH and recs:
        first = recs[0]
        recs[0] = Recommendation(
            first.topic, first.level,
            f"{first.reason} Required before your next simulation: predicted risk is high "
            f"({fail_probability:.0%} chance of failing it).",
            mandatory=True,
        )
    return recs


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def open_assignments(session: Session, user: User) -> list[TrainingAssignment]:
    return list(session.scalars(
        select(TrainingAssignment)
        .where(TrainingAssignment.user_id == user.id, TrainingAssignment.completed_at.is_(None))
        .order_by(TrainingAssignment.mandatory.desc(), TrainingAssignment.id)
    ))


def passed_modules(session: Session, user: User) -> set[tuple[str, int]]:
    rows = session.execute(
        select(TrainingModule.topic, TrainingModule.level)
        .join(TrainingAssignment, TrainingAssignment.module_id == TrainingModule.id)
        .where(TrainingAssignment.user_id == user.id, TrainingAssignment.completed_at.is_not(None))
    )
    return {(topic, level) for topic, level in rows}


def assign_training(
    session: Session,
    user: User,
    prediction: MLPrediction,
    history: SessionHistory,
    levels: dict[str, int],
) -> list[TrainingAssignment]:
    """Turn recommendations into assignments. Returns the assignments that
    were created or changed in this call."""
    recs = recommend(
        profile=prediction.profile,
        fail_probability=prediction.fail_probability,
        risk_level=prediction.risk_level,
        vector=features.to_vector(prediction.features),
        history=history,
        levels=levels,
        passed_modules=passed_modules(session, user),
    )
    modules = {(m.topic, m.level): m for m in session.scalars(select(TrainingModule))}
    open_by_module = {a.module_id: a for a in open_assignments(session, user)}

    touched = []
    for rec in recs:
        module = modules.get((rec.topic, rec.level))
        if module is None:
            raise LookupError(f"No training module for {rec.topic} level {rec.level}; run the seed.")
        existing = open_by_module.get(module.id)
        if existing is not None:
            if rec.mandatory and not existing.mandatory:
                existing.mandatory = True
                existing.reason = rec.reason
                touched.append(existing)
            continue
        assignment = TrainingAssignment(
            user_id=user.id, module_id=module.id, prediction_id=prediction.id,
            reason=rec.reason, mandatory=rec.mandatory,
        )
        session.add(assignment)
        open_by_module[module.id] = assignment
        touched.append(assignment)
    session.flush()
    return touched
