"""ORM models (DESIGN.md section 3).

Vocabulary columns (role, category, decision, ...) are plain strings guarded
by CHECK constraints built from the tuples in :mod:`phishsense.config`, so the
database rejects values the code does not know about.

Timestamps are stored as naive UTC (SQLite has no time-zone type).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from phishsense import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _one_of(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join("'" + v.replace("'", "''") + "'" for v in values)
    return f"{column} IN ({quoted})"


_LEVEL_CHECK = f"BETWEEN {config.MIN_LEVEL} AND {config.MAX_LEVEL}"


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(_one_of("role", config.ROLES), name="ck_users_role"),
        CheckConstraint(_one_of("department", config.DEPARTMENTS), name="ck_users_department"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(100))
    department: Mapped[str] = mapped_column(String(50))
    role: Mapped[str] = mapped_column(String(10), default=config.ROLE_TRAINEE)
    password_hash: Mapped[str] = mapped_column(String(60))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Created by the sample-data generator; always shown as such and removable.
    is_sample: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    sessions: Mapped[list[SimulationSession]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="SimulationSession.id"
    )
    vector_levels: Mapped[list[UserVectorLevel]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    assignments: Mapped[list[TrainingAssignment]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="TrainingAssignment.id"
    )

    @property
    def is_admin(self) -> bool:
        return self.role == config.ROLE_ADMIN

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role}>"


# ---------------------------------------------------------------------------
# Content catalogue
# ---------------------------------------------------------------------------
class Email(Base):
    """A simulated email. ``body`` is HTML containing ``{link}`` where the
    link anchor is rendered (only when ``link_url`` is set)."""

    __tablename__ = "emails"
    __table_args__ = (
        CheckConstraint(_one_of("category", config.EMAIL_CATEGORIES), name="ck_emails_category"),
        CheckConstraint(f"difficulty {_LEVEL_CHECK}", name="ck_emails_difficulty"),
        CheckConstraint(
            f"(category = '{config.CATEGORY_LEGITIMATE}') = (is_phishing = 0)",
            name="ck_emails_phishing_matches_category",
        ),
        CheckConstraint(
            "is_phishing = 0 OR link_url IS NOT NULL OR attachment_name IS NOT NULL",
            name="ck_emails_phishing_has_payload",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    category: Mapped[str] = mapped_column(String(20), index=True)
    is_phishing: Mapped[bool] = mapped_column(Boolean)
    difficulty: Mapped[int] = mapped_column(Integer)
    sender_name: Mapped[str] = mapped_column(String(100))
    sender_address: Mapped[str] = mapped_column(String(200))
    subject: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    link_text: Mapped[str | None] = mapped_column(String(200))
    link_url: Mapped[str | None] = mapped_column(String(300))  # real target, shown on hover
    attachment_name: Mapped[str | None] = mapped_column(String(200))
    # Phishing: red flags. Legitimate: the cues that show it is genuine.
    indicators: Mapped[list[str]] = mapped_column(JSON, default=list)

    def __repr__(self) -> str:
        return f"<Email {self.code!r} {self.category} L{self.difficulty}>"


class TrainingModule(Base):
    __tablename__ = "training_modules"
    __table_args__ = (
        CheckConstraint(_one_of("topic", config.TOPICS), name="ck_modules_topic"),
        CheckConstraint(f"level {_LEVEL_CHECK}", name="ck_modules_level"),
        UniqueConstraint("topic", "level", name="uq_modules_topic_level"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    topic: Mapped[str] = mapped_column(String(20))
    level: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(150))
    summary: Mapped[str] = mapped_column(String(300))
    lesson: Mapped[str] = mapped_column(Text)  # HTML

    def __repr__(self) -> str:
        return f"<TrainingModule {self.code!r}>"


class QuizQuestion(Base):
    __tablename__ = "quiz_questions"
    __table_args__ = (
        CheckConstraint(_one_of("topic", config.TOPICS), name="ck_questions_topic"),
        CheckConstraint(_one_of("kind", config.QUIZ_KINDS), name="ck_questions_kind"),
        CheckConstraint(f"level {_LEVEL_CHECK}", name="ck_questions_level"),
        CheckConstraint("correct_index >= 0", name="ck_questions_correct_index"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(40), unique=True)
    topic: Mapped[str] = mapped_column(String(20), index=True)
    level: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(10))
    prompt: Mapped[str] = mapped_column(Text)
    options: Mapped[list[str]] = mapped_column(JSON)
    correct_index: Mapped[int] = mapped_column(Integer)
    explanation: Mapped[str] = mapped_column(Text)


# ---------------------------------------------------------------------------
# Simulation and behaviour
# ---------------------------------------------------------------------------
class SimulationSession(Base):
    __tablename__ = "simulation_sessions"
    __table_args__ = (
        CheckConstraint(_one_of("kind", config.SESSION_KINDS), name="ck_sessions_kind"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(10))
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    # True if at least one phishing link was clicked / attachment opened.
    failed: Mapped[bool | None] = mapped_column(Boolean)

    user: Mapped[User] = relationship(back_populates="sessions")
    deliveries: Mapped[list[SessionEmail]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="SessionEmail.position"
    )
    events: Mapped[list[BehaviourEvent]] = relationship(
        back_populates="session", cascade="all, delete-orphan", order_by="BehaviourEvent.id"
    )
    outcomes: Mapped[list[EmailOutcome]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None


class SessionEmail(Base):
    """Which emails were delivered in a session, in inbox order."""

    __tablename__ = "session_emails"
    __table_args__ = (UniqueConstraint("session_id", "position", name="uq_session_position"),)

    session_id: Mapped[int] = mapped_column(
        ForeignKey("simulation_sessions.id", ondelete="CASCADE"), primary_key=True
    )
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id"), primary_key=True)
    position: Mapped[int] = mapped_column(Integer)

    session: Mapped[SimulationSession] = relationship(back_populates="deliveries")
    email: Mapped[Email] = relationship()


class BehaviourEvent(Base):
    """Append-only raw interaction stream."""

    __tablename__ = "behaviour_events"
    __table_args__ = (
        CheckConstraint(_one_of("event_type", config.EVENT_TYPES), name="ck_events_type"),
        Index("ix_events_session_email", "session_id", "email_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("simulation_sessions.id", ondelete="CASCADE")
    )
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id"))
    event_type: Mapped[str] = mapped_column(String(20))
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    value_ms: Mapped[int | None] = mapped_column(Integer)

    session: Mapped[SimulationSession] = relationship(back_populates="events")


class EmailOutcome(Base):
    """The final decision on one email in one session (derived from events)."""

    __tablename__ = "email_outcomes"
    __table_args__ = (
        CheckConstraint(_one_of("decision", config.DECISIONS), name="ck_outcomes_decision"),
        CheckConstraint(
            f"(decision = '{config.DECISION_CLICKED}') = (clicked_via IS NOT NULL)",
            name="ck_outcomes_clicked_via_iff_clicked",
        ),
        CheckConstraint(
            "clicked_via IS NULL OR " + _one_of("clicked_via", config.CLICK_TARGETS),
            name="ck_outcomes_clicked_via",
        ),
    )

    session_id: Mapped[int] = mapped_column(
        ForeignKey("simulation_sessions.id", ondelete="CASCADE"), primary_key=True
    )
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id"), primary_key=True)
    decision: Mapped[str] = mapped_column(String(15))
    clicked_via: Mapped[str | None] = mapped_column(String(10))  # 'link' / 'attachment'
    # None = neutral (an ignored legitimate email).
    correct: Mapped[bool | None] = mapped_column(Boolean)
    opened: Mapped[bool] = mapped_column(Boolean, default=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)  # open -> decision
    hover_ms: Mapped[int] = mapped_column(Integer, default=0)
    inspected_sender: Mapped[bool] = mapped_column(Boolean, default=False)

    session: Mapped[SimulationSession] = relationship(back_populates="outcomes")
    email: Mapped[Email] = relationship()


class BehaviourFeatures(Base):
    """Feature snapshot taken after each completed session (DESIGN.md section 5)."""

    __tablename__ = "behaviour_features"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("simulation_sessions.id", ondelete="CASCADE"), unique=True
    )
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    window_sessions: Mapped[int] = mapped_column(Integer)

    click_rate: Mapped[float] = mapped_column(Float)
    report_accuracy: Mapped[float] = mapped_column(Float)
    false_positive_rate: Mapped[float] = mapped_column(Float)
    ignore_rate: Mapped[float] = mapped_column(Float)
    hover_to_click_ratio: Mapped[float] = mapped_column(Float)
    fast_click_rate: Mapped[float] = mapped_column(Float)
    mean_decision_latency_s: Mapped[float] = mapped_column(Float)
    vser_url_spoofing: Mapped[float] = mapped_column(Float)
    vser_urgency: Mapped[float] = mapped_column(Float)
    vser_impersonation: Mapped[float] = mapped_column(Float)
    vser_attachment: Mapped[float] = mapped_column(Float)
    repeat_error_measure: Mapped[float] = mapped_column(Float)


# ---------------------------------------------------------------------------
# Machine learning
# ---------------------------------------------------------------------------
class ModelVersion(Base):
    __tablename__ = "model_versions"
    __table_args__ = (
        CheckConstraint(_one_of("kind", config.MODEL_KINDS), name="ck_model_versions_kind"),
        UniqueConstraint("kind", "version", name="uq_model_versions_kind_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(20))
    version: Mapped[int] = mapped_column(Integer)
    trained_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    n_synthetic: Mapped[int] = mapped_column(Integer)
    n_real: Mapped[int] = mapped_column(Integer)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    path: Mapped[str] = mapped_column(String(300))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)


class MLPrediction(Base):
    __tablename__ = "ml_predictions"
    __table_args__ = (
        CheckConstraint(_one_of("profile", config.PROFILES), name="ck_predictions_profile"),
        CheckConstraint(_one_of("risk_level", config.RISK_LEVELS), name="ck_predictions_risk"),
        CheckConstraint(
            "fail_probability >= 0 AND fail_probability <= 1", name="ck_predictions_probability"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    features_id: Mapped[int] = mapped_column(
        ForeignKey("behaviour_features.id", ondelete="CASCADE")
    )
    cluster_id: Mapped[int] = mapped_column(Integer)
    profile: Mapped[str] = mapped_column(String(30))
    fail_probability: Mapped[float] = mapped_column(Float)
    risk_level: Mapped[str] = mapped_column(String(10))
    kmeans_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"))
    rf_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    features: Mapped[BehaviourFeatures] = relationship()


# ---------------------------------------------------------------------------
# Adaptive training and quizzes
# ---------------------------------------------------------------------------
class UserVectorLevel(Base):
    """Current difficulty level of each attack vector for each user."""

    __tablename__ = "user_vector_levels"
    __table_args__ = (
        CheckConstraint(_one_of("vector", config.VECTORS), name="ck_levels_vector"),
        CheckConstraint(f"level {_LEVEL_CHECK}", name="ck_levels_level"),
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    vector: Mapped[str] = mapped_column(String(20), primary_key=True)
    level: Mapped[int] = mapped_column(Integer, default=config.MIN_LEVEL)

    user: Mapped[User] = relationship(back_populates="vector_levels")


class TrainingAssignment(Base):
    __tablename__ = "training_assignments"
    __table_args__ = (
        CheckConstraint(
            "quiz_score IS NULL OR (quiz_score >= 0 AND quiz_score <= 1)",
            name="ck_assignments_score",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    module_id: Mapped[int] = mapped_column(ForeignKey("training_modules.id"))
    prediction_id: Mapped[int | None] = mapped_column(
        ForeignKey("ml_predictions.id", ondelete="SET NULL")
    )
    reason: Mapped[str] = mapped_column(Text)
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    quiz_score: Mapped[float | None] = mapped_column(Float)  # best score so far
    attempts: Mapped[int] = mapped_column(Integer, default=0)

    user: Mapped[User] = relationship(back_populates="assignments")
    module: Mapped[TrainingModule] = relationship()


class QuizResult(Base):
    __tablename__ = "quiz_results"
    __table_args__ = (
        UniqueConstraint("assignment_id", "attempt", "question_id", name="uq_quiz_answer_once"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    assignment_id: Mapped[int | None] = mapped_column(
        ForeignKey("training_assignments.id", ondelete="SET NULL")
    )
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    question_id: Mapped[int] = mapped_column(ForeignKey("quiz_questions.id"))
    chosen_index: Mapped[int] = mapped_column(Integer)
    correct: Mapped[bool] = mapped_column(Boolean)
    time_ms: Mapped[int | None] = mapped_column(Integer)
    answered_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    question: Mapped[QuizQuestion] = relationship()
