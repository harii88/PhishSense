"""Downloadable reports: users CSV, sessions CSV and a PDF summary.

The PDF is drawn with matplotlib (``PdfPages``), so no extra dependency is
needed. Every report states where its numbers come from and labels sample
users.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure
from sqlalchemy import select
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourFeatures,
    Email,
    EmailOutcome,
    MLPrediction,
    SimulationSession,
    User,
)
from phishsense.services import admin
from phishsense.services.features import FEATURE_LABELS

DISCLAIMER = (
    "Profiles come from K-Means and risk from a Random Forest, trained on synthetic behaviour "
    "data plus sessions recorded in this installation. Rows marked 'sample' are generated "
    "demonstration users. These figures describe this installation; they are not research results."
)


def users_frame(session: Session, admin_id: int) -> pd.DataFrame:
    rows = admin.users_table(session, admin_id)
    return pd.DataFrame([{
        "username": r.username, "full_name": r.full_name, "department": r.department,
        "sample_user": r.is_sample, "sessions_completed": r.sessions,
        "last_session": r.last_session, "profile": r.profile, "risk_level": r.risk_level,
        "fail_probability": None if r.probability is None else round(r.probability, 4),
        "click_rate": r.click_rate, "report_accuracy": r.report_accuracy,
        "training_open": r.training_open, "training_completed": r.training_completed,
    } for r in rows])


def sessions_frame(session: Session, admin_id: int) -> pd.DataFrame:
    admin._require_admin(session, admin_id)
    sims = session.execute(
        select(SimulationSession, User)
        .join(User, User.id == SimulationSession.user_id)
        .where(SimulationSession.completed_at.is_not(None))
        .order_by(SimulationSession.completed_at, SimulationSession.id)
    ).all()
    preds = {}
    for p in session.scalars(select(MLPrediction).order_by(MLPrediction.id)):
        preds.setdefault(p.features_id, p)   # prediction made when the session finished
    rows = []
    for sim, user in sims:
        outcomes = session.execute(
            select(Email.is_phishing, EmailOutcome.decision)
            .join(Email, Email.id == EmailOutcome.email_id)
            .where(EmailOutcome.session_id == sim.id)
        ).all()
        phishing = [d for is_p, d in outcomes if is_p]
        feats = session.scalar(select(BehaviourFeatures).where(BehaviourFeatures.session_id == sim.id))
        pred = preds.get(feats.id) if feats else None
        rows.append({
            "session_id": sim.id, "username": user.username, "department": user.department,
            "sample_user": user.is_sample, "kind": sim.kind, "completed_at": sim.completed_at,
            "failed": bool(sim.failed), "emails": len(outcomes), "phishing": len(phishing),
            "phishing_reported": phishing.count(config.DECISION_REPORTED),
            "phishing_clicked": phishing.count(config.DECISION_CLICKED),
            "phishing_marked_safe": phishing.count(config.DECISION_MARKED_SAFE),
            "phishing_ignored": phishing.count(config.DECISION_IGNORED),
            "profile_after": pred.profile if pred else None,
            "risk_after": pred.risk_level if pred else None,
            "fail_probability_after": round(pred.fail_probability, 4) if pred else None,
        })
    return pd.DataFrame(rows)


def write_csv(frame: pd.DataFrame, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    return path


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def _page(title: str) -> Figure:
    fig = Figure(figsize=(8.27, 11.69))  # A4 portrait, inches
    fig.text(0.07, 0.95, title, fontsize=16, fontweight="bold")
    fig.text(0.07, 0.03, DISCLAIMER, fontsize=7, color="#64748b", wrap=True)
    return fig


RISK_COLOURS = {config.RISK_LOW: "#16a34a", config.RISK_MODERATE: "#d97706",
                config.RISK_HIGH: "#dc2626"}
PROFILE_COLOURS = {config.PROFILE_VIGILANT: "#16a34a", config.PROFILE_IMPULSIVE: "#dc2626",
                   config.PROFILE_PASSIVE: "#7c3aed", config.PROFILE_REPEATER: "#d97706"}


def _bar(ax, labels, values, title, *, percent=False, colour="#2563eb"):
    """``colour`` may be one colour or one per bar."""
    ax.barh(labels, values, color=colour, alpha=0.85)
    ax.invert_yaxis()
    ax.set_title(title, fontsize=10, loc="left")
    for i, v in enumerate(values):
        ax.text(v, i, f" {v:.0%}" if percent else f" {v:g}", va="center", fontsize=8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(labelsize=8)


def _table(fig, rect, header, rows, font=8, widths=None):
    """``widths``: relative column widths (normalised to the table width)."""
    ax = fig.add_axes(rect)
    ax.axis("off")
    if not rows:
        ax.text(0, 0.9, "No data yet.", fontsize=font)
        return
    col_widths = None
    if widths:
        col_widths = [w / sum(widths) for w in widths]
    table = ax.table(cellText=rows, colLabels=header, loc="upper left", cellLoc="left",
                     colWidths=col_widths)
    table.auto_set_font_size(False)
    table.set_fontsize(font)
    table.scale(1, 1.3)


def write_pdf(session: Session, admin_id: int, path: Path) -> Path:
    o = admin.overview(session, admin_id)
    depts = admin.departments(session, admin_id)
    errs = admin.mistakes(session, admin_id)
    models = admin.model_info(session, admin_id)
    users = admin.users_table(session, admin_id)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def pct(v):
        return "-" if v is None else f"{v:.0%}"

    with PdfPages(path) as pdf:
        # Page 1: overview
        fig = _page("PhishSense - training summary")
        lines = [
            f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
            f"Trainees: {o.trainees} ({o.sample_trainees} sample)   Assessed: {o.assessed}",
            f"Simulations completed: {o.sessions_completed}   failed: {o.sessions_failed}",
            f"Training assigned: {o.training_assigned}   completed: {o.training_completed}   "
            f"required and open: {o.required_open}",
            f"Average click rate: {pct(o.mean_click_rate)}   average report accuracy: "
            f"{pct(o.mean_report_accuracy)}   quiz answers correct: {pct(o.quiz_correct_rate)}",
        ]
        for i, line in enumerate(lines):
            fig.text(0.07, 0.90 - i * 0.025, line, fontsize=10)
        _bar(fig.add_axes([0.25, 0.55, 0.65, 0.18]), list(o.risk_counts), list(o.risk_counts.values()),
             "Trainees by current risk level", colour=[RISK_COLOURS[r] for r in o.risk_counts])
        _bar(fig.add_axes([0.25, 0.30, 0.65, 0.18]), list(o.profile_counts),
             list(o.profile_counts.values()), "Trainees by behaviour profile",
             colour=[PROFILE_COLOURS[p] for p in o.profile_counts])
        pdf.savefig(fig)

        # Page 2: departments and mistakes
        fig = _page("Departments and common mistakes")
        _table(fig, [0.07, 0.62, 0.86, 0.28],
               ["Department", "Trainees", "High risk", "Mean risk", "Error rate", "Report rate"],
               [[d.department, d.trainees, d.high_risk, pct(d.mean_probability),
                 pct(d.error_rate), pct(d.report_rate)] for d in depts])
        _bar(fig.add_axes([0.30, 0.42, 0.60, 0.16]), [v.label for v in errs.by_vector],
             [v.error_rate for v in errs.by_vector], "Error rate by attack type",
             percent=True, colour="#dc2626")
        _table(fig, [0.07, 0.07, 0.86, 0.28], ["Most often fallen for", "Type", "Errors", "Shown"],
               [[e.subject[:60], e.category_label, e.errors, e.shown] for e in errs.top_emails],
               widths=[6, 2.6, 1, 1])
        pdf.savefig(fig)

        # Page 3: models
        fig = _page("Machine-learning models")
        y = 0.90
        for name, v in [("K-Means", models.kmeans), ("Random Forest", models.random_forest)]:
            if v is None:
                fig.text(0.07, y, f"{name}: not trained yet", fontsize=10)
                y -= 0.03
                continue
            fig.text(0.07, y, f"{name} v{v.version}  trained {v.trained_at:%Y-%m-%d %H:%M}  "
                     f"({v.n_synthetic} synthetic + {v.n_real} real rows)", fontsize=10)
            y -= 0.025
            if v.kind == config.MODEL_KIND_KMEANS:
                fig.text(0.09, y, f"silhouette {v.metrics.get('silhouette', 0):.3f};  synthetic "
                         f"profile-name accuracy {v.metrics.get('synthetic_profile_name_accuracy', 0):.1%}",
                         fontsize=9)
            else:
                cv = v.metrics.get("cross_validation", {})
                fig.text(0.09, y, f"cross-validated ROC-AUC {cv.get('roc_auc', 0):.3f};  "
                         f"accuracy {cv.get('accuracy_at_0_5', 0):.3f};  Brier {cv.get('brier', 0):.3f}",
                         fontsize=9)
                y -= 0.02
                for band, info in cv.get("risk_bands", {}).items():
                    rate = info.get("observed_failure_rate")
                    fig.text(0.11, y, f"{band}: n={info['n']}, observed failure rate "
                             f"{'-' if rate is None else f'{rate:.0%}'}", fontsize=9)
                    y -= 0.02
                imp = v.metrics.get("feature_importances", {})
                if imp:
                    names = list(imp)[:8]
                    _bar(fig.add_axes([0.35, 0.25, 0.55, 0.3]),
                         [FEATURE_LABELS[n][0] for n in names], [imp[n] for n in names],
                         "Random Forest feature importances", percent=True)
            y -= 0.04
        fig.text(0.07, 0.20, f"Real labelled pairs available for training: "
                 f"{models.real_pairs_available}", fontsize=9)
        pdf.savefig(fig)

        # Page 4: users
        fig = _page("Trainees")
        _table(fig, [0.04, 0.07, 0.92, 0.84],
               ["Name", "Department", "Sample", "Sessions", "Profile", "Risk", "Click", "Report"],
               [[u.full_name[:24], u.department, "yes" if u.is_sample else "", u.sessions,
                 u.profile or "-", u.risk_level or "-", pct(u.click_rate),
                 pct(u.report_accuracy)] for u in users[:40]], font=7,
               widths=[2.2, 2.2, 0.9, 1, 2.4, 1.1, 0.9, 0.9])
        pdf.savefig(fig)
    return path


def default_path(name: str) -> Path:
    return config.REPORTS_DIR / f"{datetime.now():%Y%m%d-%H%M}-{name}"
