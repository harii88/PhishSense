"""Admin analytics (DESIGN.md section 9, admin tabs). Qt-free, admin-only.

Every public function takes the acting user's id first and raises
:class:`AdminError` unless that user is an admin.

Definitions used throughout
---------------------------
* A trainee's *current* profile/risk is their most recent prediction.
* An *error* is a phishing email that was clicked or marked safe (as in
  features.py); a *report* is a phishing email reported as phishing.
* Sample users (``is_sample``) are included in every figure and counted
  separately so they are never mistaken for real participants.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourFeatures,
    Email,
    EmailOutcome,
    MLPrediction,
    ModelVersion,
    QuizResult,
    SimulationSession,
    TrainingAssignment,
    User,
)
from phishsense.services import facade, features, sample_data
from phishsense.services.features import FEATURE_NAMES
from phishsense.services.ml import registry


class AdminError(Exception):
    """User-facing admin problem."""


def _require_admin(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None or not user.is_admin:
        raise AdminError("Only administrators can see this.")
    return user


def _trainees(session: Session) -> list[User]:
    return list(session.scalars(
        select(User).where(User.role == config.ROLE_TRAINEE).order_by(User.id)))


def _latest_predictions(session: Session) -> dict[int, MLPrediction]:
    latest: dict[int, MLPrediction] = {}
    for p in session.scalars(select(MLPrediction).order_by(MLPrediction.id)):
        latest[p.user_id] = p
    return latest


def _latest_features(session: Session) -> dict[int, BehaviourFeatures]:
    latest: dict[int, BehaviourFeatures] = {}
    rows = session.scalars(select(BehaviourFeatures).order_by(
        BehaviourFeatures.computed_at, BehaviourFeatures.id))
    for f in rows:
        latest[f.user_id] = f
    return latest


def _phishing_outcomes(session: Session):
    """(user_id, department, category, email subject, decision) for every
    phishing email in every completed session."""
    return session.execute(
        select(User.id, User.department, Email.category, Email.subject, EmailOutcome.decision)
        .join(SimulationSession, SimulationSession.user_id == User.id)
        .join(EmailOutcome, EmailOutcome.session_id == SimulationSession.id)
        .join(Email, Email.id == EmailOutcome.email_id)
        .where(Email.is_phishing.is_(True), SimulationSession.completed_at.is_not(None))
    ).all()


def _is_error(decision: str) -> bool:
    return decision in (config.DECISION_CLICKED, config.DECISION_MARKED_SAFE)


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Overview:
    trainees: int
    sample_trainees: int
    assessed: int
    sessions_completed: int
    sessions_failed: int
    risk_counts: dict[str, int]
    profile_counts: dict[str, int]
    training_assigned: int
    training_completed: int
    required_open: int
    quiz_answers: int
    quiz_correct_rate: float | None
    mean_click_rate: float | None
    mean_report_accuracy: float | None


def overview(session: Session, admin_id: int) -> Overview:
    _require_admin(session, admin_id)
    trainees = _trainees(session)
    ids = {u.id for u in trainees}
    latest = {k: v for k, v in _latest_predictions(session).items() if k in ids}
    feats = {k: v for k, v in _latest_features(session).items() if k in ids}
    sessions = session.execute(
        select(SimulationSession.failed).where(SimulationSession.completed_at.is_not(None))
    ).scalars().all()
    assignments = session.scalars(select(TrainingAssignment)).all()
    quiz_rows = session.scalars(select(QuizResult.correct)).all()
    return Overview(
        trainees=len(trainees),
        sample_trainees=sum(u.is_sample for u in trainees),
        assessed=len(latest),
        sessions_completed=len(sessions),
        sessions_failed=sum(bool(f) for f in sessions),
        risk_counts={r: sum(p.risk_level == r for p in latest.values()) for r in config.RISK_LEVELS},
        profile_counts={p: sum(x.profile == p for x in latest.values()) for p in config.PROFILES},
        training_assigned=len(assignments),
        training_completed=sum(a.completed_at is not None for a in assignments),
        required_open=sum(a.mandatory and a.completed_at is None for a in assignments),
        quiz_answers=len(quiz_rows),
        quiz_correct_rate=float(np.mean(quiz_rows)) if quiz_rows else None,
        mean_click_rate=float(np.mean([f.click_rate for f in feats.values()])) if feats else None,
        mean_report_accuracy=float(np.mean([f.report_accuracy for f in feats.values()]))
        if feats else None,
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UserRow:
    id: int
    username: str
    full_name: str
    department: str
    is_sample: bool
    sessions: int
    last_session: datetime | None
    profile: str | None
    risk_level: str | None
    probability: float | None
    click_rate: float | None
    report_accuracy: float | None
    training_open: int
    training_completed: int


def users_table(session: Session, admin_id: int) -> list[UserRow]:
    _require_admin(session, admin_id)
    preds, feats = _latest_predictions(session), _latest_features(session)
    sessions: dict[int, list[datetime]] = defaultdict(list)
    for uid, done in session.execute(
        select(SimulationSession.user_id, SimulationSession.completed_at)
        .where(SimulationSession.completed_at.is_not(None))
    ):
        sessions[uid].append(done)
    training: dict[int, Counter] = defaultdict(Counter)
    for a in session.scalars(select(TrainingAssignment)):
        training[a.user_id]["done" if a.completed_at else "open"] += 1

    rows = []
    for u in _trainees(session):
        p, f = preds.get(u.id), feats.get(u.id)
        rows.append(UserRow(
            id=u.id, username=u.username, full_name=u.full_name, department=u.department,
            is_sample=u.is_sample, sessions=len(sessions[u.id]),
            last_session=max(sessions[u.id]) if sessions[u.id] else None,
            profile=p.profile if p else None, risk_level=p.risk_level if p else None,
            probability=p.fail_probability if p else None,
            click_rate=f.click_rate if f else None,
            report_accuracy=f.report_accuracy if f else None,
            training_open=training[u.id]["open"], training_completed=training[u.id]["done"],
        ))
    return rows


@dataclass(frozen=True)
class UserDetail:
    user: facade.UserInfo
    is_sample: bool
    progress: facade.ProgressData
    training: list[facade.TrainingItem]


def user_detail(session: Session, admin_id: int, user_id: int) -> UserDetail:
    _require_admin(session, admin_id)
    user = session.get(User, user_id)
    if user is None:
        raise AdminError("That user no longer exists.")
    return UserDetail(facade._user_info(user), user.is_sample,
                      facade.progress(session, user_id), facade.training_list(session, user_id))


# ---------------------------------------------------------------------------
# Behaviour: mistakes and the cluster map
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VectorStats:
    vector: str
    label: str
    shown: int
    errors: int
    reported: int
    ignored: int

    @property
    def error_rate(self) -> float:
        return self.errors / self.shown if self.shown else 0.0


@dataclass(frozen=True)
class EmailStats:
    subject: str
    category_label: str
    shown: int
    errors: int

    @property
    def error_rate(self) -> float:
        return self.errors / self.shown


@dataclass(frozen=True)
class Mistakes:
    by_vector: list[VectorStats]
    top_emails: list[EmailStats]


def mistakes(session: Session, admin_id: int, top: int = 8) -> Mistakes:
    _require_admin(session, admin_id)
    rows = _phishing_outcomes(session)
    by_vector = []
    for v in config.VECTORS:
        decisions = [d for _, _, c, _, d in rows if c == v]
        by_vector.append(VectorStats(
            v, config.VECTOR_LABELS[v], len(decisions), sum(map(_is_error, decisions)),
            decisions.count(config.DECISION_REPORTED), decisions.count(config.DECISION_IGNORED)))
    per_email: dict[tuple[str, str], list[str]] = defaultdict(list)
    for _, _, category, subject, decision in rows:
        per_email[(subject, category)].append(decision)
    emails = [EmailStats(s, facade.category_label(c), len(d), sum(map(_is_error, d)))
              for (s, c), d in per_email.items()]
    emails.sort(key=lambda e: (-e.errors, -e.error_rate, e.subject))
    return Mistakes(by_vector, [e for e in emails if e.errors][:top])


@dataclass(frozen=True)
class ClusterPoint:
    label: str
    profile: str
    x: float
    y: float
    is_sample: bool


@dataclass(frozen=True)
class ClusterMap:
    points: list[ClusterPoint]
    centroids: list[tuple[str, float, float]]
    explained_variance: tuple[float, float]
    kmeans_version: int


def cluster_map(session: Session, admin_id: int) -> ClusterMap | None:
    """Trainees' latest features and the K-Means centroids projected to 2-D
    with PCA, in the space the clustering actually uses."""
    _require_admin(session, admin_id)
    models = registry.load_active(session)
    feats = _latest_features(session)
    preds = _latest_predictions(session)
    users = {u.id: u for u in _trainees(session) if u.id in feats}
    if models is None or not users:
        return None
    X = pd.DataFrame([features.to_vector(feats[uid]).as_list() for uid in users],
                     columns=list(FEATURE_NAMES))
    space_users = models.profiles.transform(X)
    space_centroids = models.profiles.kmeans.cluster_centers_
    pca = PCA(n_components=2, random_state=config.RANDOM_SEED)
    pca.fit(np.vstack([space_users, space_centroids]))
    xy_users, xy_centroids = pca.transform(space_users), pca.transform(space_centroids)
    _, profiles = models.profiles.predict(X)
    points = [
        ClusterPoint(u.full_name, preds[uid].profile if uid in preds else profiles[i],
                     float(xy_users[i, 0]), float(xy_users[i, 1]), u.is_sample)
        for i, (uid, u) in enumerate(users.items())
    ]
    centroids = [(models.profiles.cluster_to_profile[i], float(x), float(y))
                 for i, (x, y) in enumerate(xy_centroids)]
    ev = pca.explained_variance_ratio_
    return ClusterMap(points, centroids, (float(ev[0]), float(ev[1])),
                      models.kmeans_version.version)


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DepartmentRow:
    department: str
    trainees: int
    assessed: int
    high_risk: int
    mean_probability: float | None
    phishing_seen: int
    errors: int
    reported: int

    @property
    def error_rate(self) -> float | None:
        return self.errors / self.phishing_seen if self.phishing_seen else None

    @property
    def report_rate(self) -> float | None:
        return self.reported / self.phishing_seen if self.phishing_seen else None


def departments(session: Session, admin_id: int) -> list[DepartmentRow]:
    _require_admin(session, admin_id)
    preds = _latest_predictions(session)
    outcomes = _phishing_outcomes(session)
    trainees = _trainees(session)
    rows = []
    for dept in config.DEPARTMENTS:
        members = [u for u in trainees if u.department == dept]
        if not members:
            continue
        ids = {u.id for u in members}
        probs = [preds[i].fail_probability for i in ids if i in preds]
        decisions = [d for uid, _, _, _, d in outcomes if uid in ids]
        rows.append(DepartmentRow(
            department=dept, trainees=len(members), assessed=len(probs),
            high_risk=sum(preds[i].risk_level == config.RISK_HIGH for i in ids if i in preds),
            mean_probability=float(np.mean(probs)) if probs else None,
            phishing_seen=len(decisions), errors=sum(map(_is_error, decisions)),
            reported=decisions.count(config.DECISION_REPORTED),
        ))
    return rows


# ---------------------------------------------------------------------------
# Models and data
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ModelVersionInfo:
    id: int
    kind: str
    version: int
    trained_at: datetime
    n_synthetic: int
    n_real: int
    is_active: bool
    metrics: dict


@dataclass(frozen=True)
class ModelInfo:
    kmeans: ModelVersionInfo | None
    random_forest: ModelVersionInfo | None
    history: list[ModelVersionInfo]
    real_pairs_available: int
    sample_users: int


def _version_info(v: ModelVersion) -> ModelVersionInfo:
    return ModelVersionInfo(v.id, v.kind, v.version, v.trained_at, v.n_synthetic, v.n_real,
                            v.is_active, dict(v.metrics or {}))


def model_info(session: Session, admin_id: int) -> ModelInfo:
    _require_admin(session, admin_id)
    history = [_version_info(v) for v in session.scalars(
        select(ModelVersion).order_by(ModelVersion.id.desc()))]
    active = {v.kind: v for v in history if v.is_active}
    X_real, _ = registry.real_training_pairs(session)
    return ModelInfo(active.get(config.MODEL_KIND_KMEANS),
                     active.get(config.MODEL_KIND_RANDOM_FOREST), history, len(X_real),
                     sample_data.count(session))


@dataclass(frozen=True)
class RetrainResult:
    kmeans_version: int
    rf_version: int
    real_pairs: int
    rescored_users: int


def retrain(session: Session, admin_id: int, *, rescore: bool = True) -> RetrainResult:
    """Train new model versions on synthetic + real data. With ``rescore``,
    every assessed trainee gets a fresh prediction from the new models (their
    previous predictions stay in the history). Training assignments are not
    changed; the next completed session uses the new models."""
    _require_admin(session, admin_id)
    report = registry.train_models(session)
    rescored = 0
    if rescore:
        feats = _latest_features(session)
        for user in _trainees(session):
            if user.id in feats:
                registry.predict_for(session, user, feats[user.id])
                rescored += 1
    return RetrainResult(report.kmeans_version.version, report.rf_version.version,
                         report.rf_version.n_real, rescored)


def generate_sample_users(session: Session, admin_id: int, n: int, seed: int | None = None):
    _require_admin(session, admin_id)
    if not 1 <= n <= 200:
        raise AdminError("Choose between 1 and 200 sample users.")
    seed = seed if seed is not None else int(session.scalar(select(func.count(User.id)))) + 7
    return sample_data.generate(session, n, seed=seed)


def remove_sample_users(session: Session, admin_id: int) -> int:
    _require_admin(session, admin_id)
    return sample_data.remove(session)
