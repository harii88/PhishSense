"""Training, versioning, persistence and prediction (DESIGN.md sections 6.1-6.4).

Training data
-------------
* Synthetic users from :mod:`synthetic` (always).
* Real labelled pairs from this installation: for every user, each completed
  session after the first gives one pair *(feature snapshot after the previous
  session, did this session fail?)*. Real pairs get ``REAL_SAMPLE_WEIGHT``.
* K-Means is fitted on synthetic rows plus every real feature snapshot.

Persistence
-----------
Each training run writes one joblib file per model to ``config.MODELS_DIR``
and one ``model_versions`` row per model, then makes the new versions the
active ones. Older versions stay on disk and in the table for the audit trail;
every prediction records which versions produced it.

joblib files are pickles: only files this application wrote to its own
models directory are ever loaded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from phishsense import config
from phishsense.data.models import (
    BehaviourFeatures,
    MLPrediction,
    ModelVersion,
    SimulationSession,
    User,
)
from phishsense.services import features
from phishsense.services.features import FEATURE_NAMES
from phishsense.services.ml import clustering, risk_model, synthetic


class ModelError(Exception):
    """Models are missing or unusable. Message is user-facing."""


@dataclass
class ActiveModels:
    kmeans_version: ModelVersion
    rf_version: ModelVersion
    profiles: clustering.ProfileModel
    risk: risk_model.RiskModel


@dataclass
class TrainingReport:
    kmeans_version: ModelVersion
    rf_version: ModelVersion

    @property
    def kmeans_metrics(self) -> dict:
        return self.kmeans_version.metrics

    @property
    def rf_metrics(self) -> dict:
        return self.rf_version.metrics


# Loaded model objects keyed by ModelVersion.id (immutable once written).
_cache: dict[int, object] = {}


# ---------------------------------------------------------------------------
# Real data
# ---------------------------------------------------------------------------
def _completed_sessions_with_features(session: Session) -> list[tuple[int, bool, BehaviourFeatures]]:
    rows = session.execute(
        select(SimulationSession.user_id, SimulationSession.failed, BehaviourFeatures)
        .join(BehaviourFeatures, BehaviourFeatures.session_id == SimulationSession.id)
        .where(SimulationSession.completed_at.is_not(None))
        .order_by(SimulationSession.user_id, SimulationSession.completed_at, SimulationSession.id)
    )
    return [(user_id, bool(failed), feats) for user_id, failed, feats in rows]


def _frame(rows: list[BehaviourFeatures]) -> pd.DataFrame:
    return pd.DataFrame(
        [features.to_vector(r).as_list() for r in rows], columns=list(FEATURE_NAMES)
    )


def real_feature_rows(session: Session) -> pd.DataFrame:
    return _frame([feats for _, _, feats in _completed_sessions_with_features(session)])


def real_training_pairs(session: Session) -> tuple[pd.DataFrame, pd.Series]:
    """(features before session k, session k failed) for consecutive sessions."""
    inputs, labels = [], []
    previous: tuple[int, BehaviourFeatures] | None = None
    for user_id, failed, feats in _completed_sessions_with_features(session):
        if previous is not None and previous[0] == user_id:
            inputs.append(previous[1])
            labels.append(failed)
        previous = (user_id, feats)
    return _frame(inputs), pd.Series(labels, dtype=bool, name="failed_next")


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
def _next_version(session: Session, kind: str) -> int:
    current = session.scalar(select(func.max(ModelVersion.version)).where(ModelVersion.kind == kind))
    return (current or 0) + 1


def _save(obj: object, filename: str) -> None:
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    target = config.MODELS_DIR / filename
    temp = target.with_suffix(".tmp")
    joblib.dump(obj, temp)
    os.replace(temp, target)  # never leave a half-written model behind


def _load(version: ModelVersion) -> object:
    if version.id in _cache:
        return _cache[version.id]
    path = config.MODELS_DIR / Path(version.path).name
    if not path.exists():
        raise ModelError(
            f"Model file {path.name} is missing. Retrain the models from the admin dashboard."
        )
    obj = joblib.load(path)
    _cache[version.id] = obj
    return obj


def _register(
    session: Session, kind: str, obj: object, metrics: dict, n_synthetic: int, n_real: int
) -> ModelVersion:
    version = _next_version(session, kind)
    filename = f"{kind}_v{version}.joblib"
    _save(obj, filename)
    session.execute(update(ModelVersion).where(ModelVersion.kind == kind).values(is_active=False))
    row = ModelVersion(
        kind=kind, version=version, n_synthetic=n_synthetic, n_real=n_real,
        metrics=metrics, path=filename, is_active=True,
    )
    session.add(row)
    session.flush()
    _cache[row.id] = obj
    return row


def _to_json(value):
    """Make metrics safe for a JSON column (numpy scalars, NaN)."""
    if isinstance(value, dict):
        return {str(k): _to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json(v) for v in value]
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, float) and not np.isfinite(value):
        return None
    return value


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_models(
    session: Session,
    *,
    n_synthetic: int | None = None,
    include_real: bool = True,
    seed: int | None = None,
) -> TrainingReport:
    n_synthetic = config.SYNTHETIC_USERS if n_synthetic is None else n_synthetic
    seed = config.RANDOM_SEED if seed is None else seed
    data = synthetic.generate(n_synthetic, seed)
    X_syn, y_syn = data[list(FEATURE_NAMES)], data["failed_next"].astype(bool)

    if include_real:
        X_real, y_real = real_training_pairs(session)
        X_real_all = real_feature_rows(session)
    else:
        X_real, y_real = pd.DataFrame(columns=list(FEATURE_NAMES)), pd.Series(dtype=bool)
        X_real_all = pd.DataFrame(columns=list(FEATURE_NAMES))

    def stack(*frames):
        return pd.concat([f for f in frames if len(f)], ignore_index=True)

    # --- K-Means ----------------------------------------------------------
    X_cluster = stack(X_syn, X_real_all).astype(float)
    profile_model = clustering.fit(X_cluster, seed)
    kmeans_metrics = clustering.evaluate(profile_model, X_cluster, seed=seed)
    synthetic_check = clustering.evaluate(profile_model, X_syn, data["archetype"], seed=seed)
    kmeans_metrics["synthetic_adjusted_rand_index"] = synthetic_check["adjusted_rand_index"]
    kmeans_metrics["synthetic_profile_name_accuracy"] = synthetic_check["profile_name_accuracy"]

    # --- Random Forest ----------------------------------------------------
    X_rf = stack(X_syn, X_real).astype(float)
    y_rf = stack(y_syn, y_real).astype(bool)
    weights = np.concatenate([np.ones(len(y_syn)), np.full(len(y_real), config.REAL_SAMPLE_WEIGHT)])
    is_real = np.concatenate([np.zeros(len(y_syn), bool), np.ones(len(y_real), bool)])

    oof = risk_model.cross_validated_probabilities(X_rf, y_rf, weights, seed)
    rf = risk_model.fit(X_rf, y_rf, weights, seed)
    rf_metrics = {
        "cross_validation": risk_model.score(y_rf, oof),
        "cross_validation_real_only": None,
        "feature_importances": risk_model.feature_importances(rf),
        "real_sample_weight": config.REAL_SAMPLE_WEIGHT,
    }
    real_y = y_rf[is_real]
    if len(real_y) >= config.MIN_REAL_SAMPLES_FOR_REPORT and real_y.nunique() == 2:
        rf_metrics["cross_validation_real_only"] = risk_model.score(real_y, oof[is_real])

    km_row = _register(session, config.MODEL_KIND_KMEANS, profile_model,
                       _to_json(kmeans_metrics), len(X_syn), len(X_real_all))
    rf_row = _register(session, config.MODEL_KIND_RANDOM_FOREST, rf,
                       _to_json(rf_metrics), len(X_syn), len(X_real))
    return TrainingReport(km_row, rf_row)


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------
def active_versions(session: Session) -> dict[str, ModelVersion]:
    rows = session.scalars(select(ModelVersion).where(ModelVersion.is_active.is_(True)))
    return {row.kind: row for row in rows}


def load_active(session: Session) -> ActiveModels | None:
    versions = active_versions(session)
    if set(versions) != set(config.MODEL_KINDS):
        return None
    km, rf = versions[config.MODEL_KIND_KMEANS], versions[config.MODEL_KIND_RANDOM_FOREST]
    return ActiveModels(km, rf, _load(km), _load(rf))


def ensure_models(session: Session) -> ActiveModels:
    """Active models, training the first versions on a cold start."""
    models = load_active(session)
    if models is None:
        train_models(session)
        models = load_active(session)
    return models


def predict_for(session: Session, user: User, features_row: BehaviourFeatures) -> MLPrediction:
    """Run both models on one feature snapshot and store the prediction."""
    models = ensure_models(session)
    X = pd.DataFrame([features.to_vector(features_row).as_list()], columns=list(FEATURE_NAMES))
    clusters, profiles = models.profiles.predict(X)
    probability = float(np.clip(models.risk.predict_proba(X)[0], 0.0, 1.0))
    prediction = MLPrediction(
        user_id=user.id,
        features_id=features_row.id,
        cluster_id=int(clusters[0]),
        profile=profiles[0],
        fail_probability=probability,
        risk_level=risk_model.risk_level(probability),
        kmeans_version_id=models.kmeans_version.id,
        rf_version_id=models.rf_version.id,
    )
    session.add(prediction)
    session.flush()
    return prediction


def latest_prediction(session: Session, user: User) -> MLPrediction | None:
    return session.scalar(
        select(MLPrediction)
        .where(MLPrediction.user_id == user.id)
        .order_by(MLPrediction.created_at.desc(), MLPrediction.id.desc())
        .limit(1)
    )


def clear_cache() -> None:
    _cache.clear()
