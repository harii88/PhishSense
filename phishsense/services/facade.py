"""The boundary between the GUI and the services.

Every function takes a SQLAlchemy ``Session`` plus plain ids, does its work
inside the caller's transaction, and returns frozen dataclasses. The GUI never
holds ORM objects across transactions (they detach after commit, and stale
relationships would silently show old data), and everything the screens show
can be tested here without Qt.

Every function that touches a user's data checks ownership.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourFeatures,
    Email,
    MLPrediction,
    QuizQuestion,
    SimulationSession,
    TrainingAssignment,
    User,
)
from phishsense.services import adaptive, auth, features, pipeline, quiz, simulation, tracking
from phishsense.services.ml import registry


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UserInfo:
    id: int
    username: str
    full_name: str
    department: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == config.ROLE_ADMIN


def _user_info(user: User) -> UserInfo:
    return UserInfo(user.id, user.username, user.full_name, user.department, user.role)


def _user(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise auth.AuthError("Your account no longer exists.")
    return user


def login(session: Session, username: str, password: str) -> UserInfo:
    return _user_info(auth.authenticate(session, username, password))


def register(session: Session, *, username: str, full_name: str, department: str,
             password: str) -> UserInfo:
    return _user_info(auth.register_user(
        session, username=username, full_name=full_name, department=department, password=password,
    ))


def change_password(session: Session, user_id: int, current: str, new: str) -> None:
    auth.change_password(session, _user(session, user_id), current, new)


def update_profile(session: Session, user_id: int, *, full_name: str, department: str) -> UserInfo:
    user = _user(session, user_id)
    auth.update_profile(session, user, full_name=full_name, department=department)
    return _user_info(user)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PredictionInfo:
    profile: str
    risk_level: str
    probability: float
    created_at: datetime

    @property
    def description(self) -> str:
        return config.PROFILE_DESCRIPTIONS[self.profile]


def _prediction_info(p: MLPrediction | None) -> PredictionInfo | None:
    if p is None:
        return None
    return PredictionInfo(p.profile, p.risk_level, p.fail_probability, p.created_at)


@dataclass(frozen=True)
class DashboardData:
    user: UserInfo
    sessions_completed: int
    prediction: PredictionInfo | None
    click_rate: float | None
    report_accuracy: float | None
    open_training: int
    required_training: list[str]
    has_open_session: bool
    next_session_kind: str
    levels: dict[str, int]


def dashboard(session: Session, user_id: int) -> DashboardData:
    user = _user(session, user_id)
    completed = simulation.completed_session_count(session, user)
    latest = features.latest_features(session, user)
    open_items = adaptive.open_assignments(session, user)
    return DashboardData(
        user=_user_info(user),
        sessions_completed=completed,
        prediction=_prediction_info(registry.latest_prediction(session, user)),
        click_rate=latest.click_rate if latest else None,
        report_accuracy=latest.report_accuracy if latest else None,
        open_training=len(open_items),
        required_training=[a.module.title for a in open_items if a.mandatory],
        has_open_session=simulation.get_open_session(session, user) is not None,
        next_session_kind=config.SESSION_KIND_BASELINE if completed == 0
        else config.SESSION_KIND_ADAPTIVE,
        levels=adaptive.current_levels(session, user),
    )


# ---------------------------------------------------------------------------
# Inbox
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class InboxEmail:
    id: int
    position: int
    sender_name: str
    sender_address: str
    subject: str
    body_html: str
    link_text: str | None
    link_url: str | None
    attachment_name: str | None
    is_phishing: bool          # NOT shown in the inbox; used only after a decision
    indicators: tuple[str, ...]
    decision: str | None
    opened: bool


@dataclass(frozen=True)
class SessionView:
    id: int
    kind: str
    emails: list[InboxEmail]

    @property
    def handled(self) -> int:
        return sum(1 for e in self.emails if e.decision is not None)


def render_body(email: Email) -> str:
    """Body HTML with the link anchor inserted. The href is the real target
    (shown on hover); the inbox never opens it."""
    if not email.link_url:
        return email.body
    anchor = (f'<a href="{html.escape(email.link_url, quote=True)}">'
              f"{html.escape(email.link_text or email.link_url)}</a>")
    return email.body.replace("{link}", anchor)


def _owned_session(session: Session, user_id: int, sim_id: int) -> SimulationSession:
    sim = session.get(SimulationSession, sim_id)
    if sim is None or sim.user_id != user_id:
        raise simulation.SimulationError("That simulation does not belong to you.")
    return sim


def _session_view(session: Session, sim: SimulationSession) -> SessionView:
    emails = []
    for delivery in sim.deliveries:
        e = delivery.email
        events = tracking.events_for(session, sim, e)
        decision = next((tracking.DECISION_EVENTS[ev.event_type][0]
                         for ev in events if ev.event_type in tracking.DECISION_EVENTS), None)
        emails.append(InboxEmail(
            id=e.id, position=delivery.position, sender_name=e.sender_name,
            sender_address=e.sender_address, subject=e.subject, body_html=render_body(e),
            link_text=e.link_text, link_url=e.link_url, attachment_name=e.attachment_name,
            is_phishing=e.is_phishing, indicators=tuple(e.indicators), decision=decision,
            opened=any(ev.event_type == config.EVENT_OPEN for ev in events),
        ))
    return SessionView(sim.id, sim.kind, emails)


def start_or_resume(session: Session, user_id: int) -> SessionView:
    sim = simulation.start_session(session, _user(session, user_id))
    return _session_view(session, sim)


def record_event(session: Session, user_id: int, sim_id: int, email_id: int, event_type: str,
                 value_ms: int | None = None) -> None:
    sim = _owned_session(session, user_id, sim_id)
    email = session.get(Email, email_id)
    if email is None:
        raise tracking.TrackingError("Unknown email.")
    tracking.record_event(session, sim, email, event_type, value_ms=value_ms)


# ---------------------------------------------------------------------------
# Session results
# ---------------------------------------------------------------------------
def category_label(category: str) -> str:
    return "Genuine email" if category == config.CATEGORY_LEGITIMATE \
        else config.VECTOR_LABELS[category]


@dataclass(frozen=True)
class ReviewRow:
    position: int
    subject: str
    sender_name: str
    sender_address: str
    category_label: str
    is_phishing: bool
    decision: str
    correct: bool | None
    indicators: tuple[str, ...]


@dataclass(frozen=True)
class AssignmentInfo:
    id: int
    title: str
    topic_label: str
    level: int
    reason: str
    mandatory: bool


@dataclass(frozen=True)
class LevelChangeInfo:
    vector_label: str
    old: int
    new: int
    correct: int
    total: int


@dataclass(frozen=True)
class ResultView:
    session_id: int
    kind: str
    failed: bool
    rows: list[ReviewRow]
    prediction: PredictionInfo
    level_changes: list[LevelChangeInfo]
    new_training: list[AssignmentInfo]
    phishing_total: int
    phishing_reported: int
    phishing_compromised: int


def _assignment_info(a: TrainingAssignment) -> AssignmentInfo:
    return AssignmentInfo(a.id, a.module.title, config.TOPIC_LABELS[a.module.topic],
                          a.module.level, a.reason, a.mandatory)


def complete(session: Session, user_id: int, sim_id: int) -> ResultView:
    sim = _owned_session(session, user_id, sim_id)
    done = pipeline.complete_session(session, sim)
    summary = done.summary
    rows = [
        ReviewRow(i.position, i.email.subject, i.email.sender_name, i.email.sender_address,
                  category_label(i.email.category), i.email.is_phishing, i.outcome.decision,
                  i.outcome.correct, tuple(i.email.indicators))
        for i in sorted(summary.items, key=lambda i: i.position)
    ]
    return ResultView(
        session_id=sim.id, kind=sim.kind, failed=summary.failed, rows=rows,
        prediction=_prediction_info(done.prediction),
        level_changes=[LevelChangeInfo(config.VECTOR_LABELS[c.vector], c.old, c.new,
                                       c.correct, c.total) for c in done.level_changes],
        new_training=[_assignment_info(a) for a in done.assignments],
        phishing_total=summary.phishing_total,
        phishing_reported=summary.phishing_reported,
        phishing_compromised=summary.phishing_compromised,
    )


# ---------------------------------------------------------------------------
# Training and quizzes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TrainingItem:
    id: int
    title: str
    summary: str
    topic_label: str
    level: int
    reason: str
    mandatory: bool
    completed: bool
    quiz_score: float | None
    attempts: int
    lesson_html: str
    assigned_at: datetime


def training_list(session: Session, user_id: int) -> list[TrainingItem]:
    user = _user(session, user_id)
    rows = session.scalars(select(TrainingAssignment).where(TrainingAssignment.user_id == user.id))
    items = [
        TrainingItem(a.id, a.module.title, a.module.summary, config.TOPIC_LABELS[a.module.topic],
                     a.module.level, a.reason, a.mandatory, a.completed_at is not None,
                     a.quiz_score, a.attempts, a.module.lesson, a.assigned_at)
        for a in rows
    ]
    # Open required first, then other open, then completed (newest first).
    return sorted(items, key=lambda t: (t.completed, not t.mandatory, -t.assigned_at.timestamp(), -t.id))


@dataclass(frozen=True)
class QuestionView:
    id: int
    kind: str
    prompt: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class QuizView:
    assignment_id: int
    attempt: int
    title: str
    questions: list[QuestionView]

    @property
    def question_ids(self) -> list[int]:
        return [q.id for q in self.questions]


def _owned_assignment(session: Session, user_id: int, assignment_id: int) -> TrainingAssignment:
    a = session.get(TrainingAssignment, assignment_id)
    if a is None or a.user_id != user_id:
        raise quiz.QuizError("That training is not assigned to you.")
    return a


def start_quiz(session: Session, user_id: int, assignment_id: int) -> QuizView:
    user = _user(session, user_id)
    attempt = quiz.start_quiz(session, user, _owned_assignment(session, user_id, assignment_id))
    return QuizView(assignment_id, attempt.attempt, attempt.assignment.module.title,
                    [QuestionView(q.id, q.kind, q.prompt, tuple(q.options)) for q in attempt.questions])


def _rebuild_attempt(session: Session, user_id: int, view_assignment_id: int, attempt_no: int,
                     question_ids: list[int]) -> tuple[User, quiz.QuizAttempt]:
    user = _user(session, user_id)
    assignment = _owned_assignment(session, user_id, view_assignment_id)
    by_id = {q.id: q for q in session.scalars(select(QuizQuestion).where(QuizQuestion.id.in_(question_ids)))}
    return user, quiz.QuizAttempt(assignment, attempt_no, [by_id[i] for i in question_ids if i in by_id])


def answer_question(session: Session, user_id: int, view: QuizView, question_id: int,
                    chosen_index: int, time_ms: int | None = None) -> quiz.AnswerFeedback:
    user, attempt = _rebuild_attempt(session, user_id, view.assignment_id, view.attempt,
                                     view.question_ids)
    question = next((q for q in attempt.questions if q.id == question_id), None)
    if question is None:
        raise quiz.QuizError("That question is not part of this quiz.")
    return quiz.answer(session, user, attempt, question, chosen_index, time_ms=time_ms)


def finish_quiz(session: Session, user_id: int, view: QuizView) -> quiz.QuizOutcome:
    user, attempt = _rebuild_attempt(session, user_id, view.assignment_id, view.attempt,
                                     view.question_ids)
    return quiz.finish_quiz(session, user, attempt)


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProgressPoint:
    number: int
    completed_at: datetime
    kind: str
    failed: bool
    features: dict[str, float]
    probability: float | None
    risk_level: str | None
    profile: str | None


@dataclass(frozen=True)
class ProgressData:
    points: list[ProgressPoint]
    levels: dict[str, int]

    @property
    def latest(self) -> ProgressPoint | None:
        return self.points[-1] if self.points else None


def progress(session: Session, user_id: int) -> ProgressData:
    user = _user(session, user_id)
    rows = session.execute(
        select(SimulationSession, BehaviourFeatures)
        .join(BehaviourFeatures, BehaviourFeatures.session_id == SimulationSession.id)
        .where(SimulationSession.user_id == user.id, SimulationSession.completed_at.is_not(None))
        .order_by(SimulationSession.completed_at, SimulationSession.id)
    ).all()
    points = []
    for number, (sim, feats) in enumerate(rows, start=1):
        pred = session.scalar(
            select(MLPrediction).where(MLPrediction.features_id == feats.id)
            .order_by(MLPrediction.id.desc()).limit(1)
        )
        points.append(ProgressPoint(
            number=number, completed_at=sim.completed_at, kind=sim.kind, failed=bool(sim.failed),
            features={n: getattr(feats, n) for n in features.FEATURE_NAMES},
            probability=pred.fail_probability if pred else None,
            risk_level=pred.risk_level if pred else None,
            profile=pred.profile if pred else None,
        ))
    return ProgressData(points, adaptive.current_levels(session, user))
