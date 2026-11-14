"""The closed loop in one call: what happens when a trainee finishes a session.

    finish_session      events -> outcomes -> feature snapshot   (simulation)
    update_levels       per-vector difficulty for the next inbox  (adaptive)
    predict_for         K-Means profile + Random Forest risk      (ml.registry)
    assign_training     recommendations -> assignments            (adaptive)

The UI calls :func:`complete_session` inside one ``session_scope``, so either
every step is saved or none is.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from phishsense.data.models import MLPrediction, SimulationSession, TrainingAssignment, User
from phishsense.services import adaptive, simulation
from phishsense.services.ml import registry


@dataclass(frozen=True)
class CompletedSession:
    summary: simulation.SessionSummary
    level_changes: list[adaptive.LevelChange]
    prediction: MLPrediction
    assignments: list[TrainingAssignment]


def complete_session(
    session: Session, sim: SimulationSession, *, now: datetime | None = None
) -> CompletedSession:
    user = session.get(User, sim.user_id)
    summary = simulation.finish_session(session, sim, now=now)
    level_changes = adaptive.update_levels(session, user, summary)
    prediction = registry.predict_for(session, user, summary.features)
    assignments = adaptive.assign_training(
        session, user, prediction, summary.history, adaptive.current_levels(session, user)
    )
    return CompletedSession(summary, level_changes, prediction, assignments)
