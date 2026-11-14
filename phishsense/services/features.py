"""Feature extraction (DESIGN.md section 5).

The computation is a pure function of the user's session history, a
chronological list of sessions, each a list of :class:`OutcomeRecord`.
Most features use only the last ``FEATURE_WINDOW_SESSIONS`` sessions; the
Repeat Error Measure also looks at earlier sessions to know which vectors the
user had already failed.

Notation: P = phishing outcomes in the window, L = legitimate ones.

======================  ==============================================================
click_rate              compromised phishing / |P|
report_accuracy         reported phishing / |P|
false_positive_rate     reported legitimate / |L|
ignore_rate             ignored phishing / |P|
hover_to_click_ratio    link clicks with hover >= INSPECT_HOVER_S / all link clicks
                        (1.0 when there are no link clicks: nothing was clicked blindly)
fast_click_rate         clicks (link or attachment) with latency < FAST_DECISION_S and
                        hover < INSPECT_HOVER_S / all clicks (0.0 when no clicks)
mean_decision_latency_s mean open->decision seconds over decided emails, each clipped
                        to MAX_DECISION_LATENCY_S (the maximum when nothing was decided)
vser_<vector>           errors on vector / phishing emails of vector (0.0 if none seen)
repeat_error_measure    window errors on a vector the user already erred on in an
                        earlier session / window errors (0.0 when no errors)
======================  ==============================================================

An *error* is a phishing email that was clicked (link or attachment) or marked
as safe. Ignoring a phishing email is a *miss*, measured by ignore_rate.
Every ratio with an empty denominator is defined above, so features are always
finite numbers in a fixed range.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourFeatures,
    Email,
    EmailOutcome,
    SimulationSession,
    User,
)

FEATURE_NAMES: tuple[str, ...] = (
    "click_rate",
    "report_accuracy",
    "false_positive_rate",
    "ignore_rate",
    "hover_to_click_ratio",
    "fast_click_rate",
    "mean_decision_latency_s",
    "vser_url_spoofing",
    "vser_urgency",
    "vser_impersonation",
    "vser_attachment",
    "repeat_error_measure",
)


# Plain-language (title, meaning) for each feature, shown to trainees and admins.
FEATURE_LABELS: dict[str, tuple[str, str]] = {
    "click_rate": ("Click rate", "Phishing emails whose link or attachment you opened"),
    "report_accuracy": ("Report accuracy", "Phishing emails you reported"),
    "false_positive_rate": ("False alarms", "Genuine emails you reported as phishing"),
    "ignore_rate": ("Ignored phishing", "Phishing emails you left without any action"),
    "hover_to_click_ratio": ("Inspected before clicking",
                             "Link clicks where you first hovered for at least "
                             f"{config.INSPECT_HOVER_S:.0f} s (100% if you clicked no links)"),
    "fast_click_rate": ("Fast clicks", f"Clicks within {config.FAST_DECISION_S:.0f} s of "
                                       "opening, without inspecting the link"),
    "mean_decision_latency_s": ("Decision time", "Average seconds from opening to deciding"),
    "vser_url_spoofing": ("URL spoofing errors", "Clicked or marked safe, URL-spoofing emails"),
    "vser_urgency": ("Urgency errors", "Clicked or marked safe, urgency emails"),
    "vser_impersonation": ("Impersonation errors", "Clicked or marked safe, impersonation emails"),
    "vser_attachment": ("Attachment errors", "Clicked or marked safe, attachment emails"),
    "repeat_error_measure": ("Repeated mistakes",
                             "Errors on a type of email you had already got wrong before"),
}


@dataclass(frozen=True)
class OutcomeRecord:
    category: str
    decision: str
    clicked_via: str | None = None
    latency_ms: int | None = None
    hover_ms: int = 0

    @property
    def is_phishing(self) -> bool:
        return self.category != config.CATEGORY_LEGITIMATE

    @property
    def is_error(self) -> bool:
        return self.is_phishing and self.decision in (
            config.DECISION_CLICKED,
            config.DECISION_MARKED_SAFE,
        )


SessionHistory = Sequence[Sequence[OutcomeRecord]]


@dataclass(frozen=True)
class FeatureVector:
    click_rate: float
    report_accuracy: float
    false_positive_rate: float
    ignore_rate: float
    hover_to_click_ratio: float
    fast_click_rate: float
    mean_decision_latency_s: float
    vser_url_spoofing: float
    vser_urgency: float
    vser_impersonation: float
    vser_attachment: float
    repeat_error_measure: float
    window_sessions: int

    def as_list(self) -> list[float]:
        """Values in FEATURE_NAMES order (the ML input layout)."""
        return [getattr(self, name) for name in FEATURE_NAMES]

    def vser(self, vector: str) -> float:
        return getattr(self, f"vser_{vector}")


# The dataclass and FEATURE_NAMES must never drift apart.
if [f.name for f in fields(FeatureVector)][:-1] != list(FEATURE_NAMES) \
        or set(FEATURE_LABELS) != set(FEATURE_NAMES):
    raise RuntimeError("FeatureVector, FEATURE_NAMES and FEATURE_LABELS are out of sync")


@dataclass(frozen=True)
class VectorExposure:
    seen: int
    errors: int

    @property
    def error_rate(self) -> float:
        return self.errors / self.seen if self.seen else 0.0


# ---------------------------------------------------------------------------
# Pure computation
# ---------------------------------------------------------------------------
def _ratio(numerator: int, denominator: int, empty: float = 0.0) -> float:
    return numerator / denominator if denominator else empty


def _window(history: SessionHistory) -> list[Sequence[OutcomeRecord]]:
    if not history:
        raise ValueError("Features need at least one completed session.")
    return list(history[-config.FEATURE_WINDOW_SESSIONS:])


def vector_exposure(history: SessionHistory) -> dict[str, VectorExposure]:
    """Phishing emails seen and errors made per vector, over the window."""
    records = [r for s in _window(history) for r in s if r.is_phishing]
    return {
        v: VectorExposure(
            seen=sum(1 for r in records if r.category == v),
            errors=sum(1 for r in records if r.category == v and r.is_error),
        )
        for v in config.VECTORS
    }


def weakest_vector(history: SessionHistory) -> str | None:
    """Vector with the highest error rate among those seen at least
    MIN_EMAILS_FOR_WEAKNESS times in the window; None if there are no errors.
    Ties go to more errors, then to the order of config.VECTORS."""
    exposure = vector_exposure(history)
    candidates = [
        (e.error_rate, e.errors, -config.VECTORS.index(v), v)
        for v, e in exposure.items()
        if e.seen >= config.MIN_EMAILS_FOR_WEAKNESS and e.errors > 0
    ]
    return max(candidates)[3] if candidates else None


def repeated_vectors(history: SessionHistory) -> list[str]:
    """Vectors with errors in at least two different sessions (whole history),
    most-repeated first, ties in config order. Used for remedial training."""
    sessions_with_error = {
        v: sum(1 for s in history if any(r.is_error and r.category == v for r in s))
        for v in config.VECTORS
    }
    repeated = [v for v in config.VECTORS if sessions_with_error[v] >= 2]
    return sorted(repeated, key=lambda v: -sessions_with_error[v])  # stable: keeps config order


def _repeat_error_measure(history: SessionHistory) -> float:
    window_start = len(history) - len(_window(history))
    failed_before: set[str] = set()
    repeats = total = 0
    for index, session in enumerate(history):
        errors = [r for r in session if r.is_error]
        if index >= window_start:
            total += len(errors)
            repeats += sum(1 for r in errors if r.category in failed_before)
        failed_before.update(r.category for r in errors)
    return _ratio(repeats, total)


def compute_features(history: SessionHistory) -> FeatureVector:
    window = _window(history)
    records = [r for s in window for r in s]
    phishing = [r for r in records if r.is_phishing]
    legitimate = [r for r in records if not r.is_phishing]

    def count(items, decision):
        return sum(1 for r in items if r.decision == decision)

    clicks = [r for r in records if r.decision == config.DECISION_CLICKED]
    link_clicks = [r for r in clicks if r.clicked_via == config.CLICK_VIA_LINK]
    inspect_ms = config.INSPECT_HOVER_S * 1000
    fast_ms = config.FAST_DECISION_S * 1000

    inspected_link_clicks = sum(1 for r in link_clicks if r.hover_ms >= inspect_ms)
    fast_clicks = sum(
        1
        for r in clicks
        if r.latency_ms is not None and r.latency_ms < fast_ms and r.hover_ms < inspect_ms
    )

    latencies = [
        min(r.latency_ms / 1000, config.MAX_DECISION_LATENCY_S)
        for r in records
        if r.decision != config.DECISION_IGNORED and r.latency_ms is not None
    ]
    mean_latency = (
        sum(latencies) / len(latencies) if latencies else config.MAX_DECISION_LATENCY_S
    )

    exposure = vector_exposure(history)

    return FeatureVector(
        click_rate=_ratio(count(phishing, config.DECISION_CLICKED), len(phishing)),
        report_accuracy=_ratio(count(phishing, config.DECISION_REPORTED), len(phishing)),
        false_positive_rate=_ratio(count(legitimate, config.DECISION_REPORTED), len(legitimate)),
        ignore_rate=_ratio(count(phishing, config.DECISION_IGNORED), len(phishing)),
        hover_to_click_ratio=_ratio(inspected_link_clicks, len(link_clicks), empty=1.0),
        fast_click_rate=_ratio(fast_clicks, len(clicks)),
        mean_decision_latency_s=mean_latency,
        vser_url_spoofing=exposure[config.VECTOR_URL_SPOOFING].error_rate,
        vser_urgency=exposure[config.VECTOR_URGENCY].error_rate,
        vser_impersonation=exposure[config.VECTOR_IMPERSONATION].error_rate,
        vser_attachment=exposure[config.VECTOR_ATTACHMENT].error_rate,
        repeat_error_measure=_repeat_error_measure(history),
        window_sessions=len(window),
    )


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------
def load_history(session: Session, user: User) -> list[list[OutcomeRecord]]:
    """The user's completed sessions, oldest first, as outcome records."""
    rows = session.execute(
        select(SimulationSession.id, Email.category, EmailOutcome)
        .join(EmailOutcome, EmailOutcome.session_id == SimulationSession.id)
        .join(Email, Email.id == EmailOutcome.email_id)
        .where(
            SimulationSession.user_id == user.id,
            SimulationSession.completed_at.is_not(None),
        )
        .order_by(SimulationSession.completed_at, SimulationSession.id, EmailOutcome.email_id)
    )
    history: dict[int, list[OutcomeRecord]] = {}
    for session_id, category, outcome in rows:
        history.setdefault(session_id, []).append(
            OutcomeRecord(
                category=category,
                decision=outcome.decision,
                clicked_via=outcome.clicked_via,
                latency_ms=outcome.latency_ms,
                hover_ms=outcome.hover_ms,
            )
        )
    return list(history.values())  # dicts keep insertion (= chronological) order


def store_features(
    session: Session, user: User, sim: SimulationSession
) -> tuple[BehaviourFeatures, list[list[OutcomeRecord]]]:
    """Compute the snapshot after ``sim`` completed and persist it.

    Returns the stored row and the history it was computed from (callers such
    as the adaptive engine reuse it instead of querying again).
    """
    if not sim.is_complete:
        raise ValueError("Features are computed only for completed sessions.")
    history = load_history(session, user)
    vector = compute_features(history)
    row = BehaviourFeatures(user_id=user.id, session_id=sim.id, **asdict(vector))
    session.add(row)
    session.flush()
    return row, history


def to_vector(row: BehaviourFeatures) -> FeatureVector:
    return FeatureVector(
        **{name: getattr(row, name) for name in FEATURE_NAMES},
        window_sessions=row.window_sessions,
    )


def latest_features(session: Session, user: User) -> BehaviourFeatures | None:
    return session.scalar(
        select(BehaviourFeatures)
        .where(BehaviourFeatures.user_id == user.id)
        .order_by(BehaviourFeatures.computed_at.desc(), BehaviourFeatures.id.desc())
        .limit(1)
    )
