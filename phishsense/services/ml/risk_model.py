"""Random Forest failure-probability model (DESIGN.md section 6.3).

Target: will the user compromise at least one phishing email in their next
simulation? Input: the feature snapshot taken before that simulation.

The risk bands are thresholds on the predicted probability, so the probability
itself must be meaningful. For that reason the forest is trained **without**
``class_weight="balanced"`` (re-weighting classes shifts probabilities away from
observed frequencies), and the evaluation reports the observed failure rate
inside each risk band on cross-validated predictions.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, brier_score_loss, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold

from phishsense import config
from phishsense.services.features import FEATURE_NAMES


def risk_level(probability: float) -> str:
    """Low: p < 0.25, High: p > 0.60, Moderate otherwise (both bounds inclusive)."""
    if not 0.0 <= probability <= 1.0:
        raise ValueError(f"probability out of range: {probability}")
    if probability < config.RISK_LOW_BELOW:
        return config.RISK_LOW
    if probability > config.RISK_HIGH_ABOVE:
        return config.RISK_HIGH
    return config.RISK_MODERATE


def _new_forest(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=config.RF_N_ESTIMATORS,
        max_depth=config.RF_MAX_DEPTH,
        min_samples_leaf=config.RF_MIN_SAMPLES_LEAF,
        random_state=seed,
        n_jobs=-1,
    )


@dataclass
class RiskModel:
    forest: RandomForestClassifier
    feature_names: tuple[str, ...] = FEATURE_NAMES

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Probability of failing the next simulation, one value per row."""
        failed_column = list(self.forest.classes_).index(True)
        return self.forest.predict_proba(X[list(self.feature_names)])[:, failed_column]


def fit(
    X: pd.DataFrame, y: pd.Series, sample_weight: np.ndarray | None = None,
    seed: int = config.RANDOM_SEED,
) -> RiskModel:
    y = y.astype(bool)
    if y.nunique() < 2:
        raise ValueError("Training data needs both failed and passed examples.")
    forest = _new_forest(seed).fit(X[list(FEATURE_NAMES)], y, sample_weight=sample_weight)
    return RiskModel(forest)


def cross_validated_probabilities(
    X: pd.DataFrame, y: pd.Series, sample_weight: np.ndarray | None = None,
    seed: int = config.RANDOM_SEED,
) -> np.ndarray:
    """Out-of-fold probability for every row (each row predicted by a model
    that never saw it)."""
    X = X[list(FEATURE_NAMES)].reset_index(drop=True)
    y = y.astype(bool).reset_index(drop=True)
    weights = np.ones(len(y)) if sample_weight is None else np.asarray(sample_weight)
    out = np.zeros(len(y))
    folds = StratifiedKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=seed)
    for train_idx, test_idx in folds.split(X, y):
        model = fit(X.iloc[train_idx], y.iloc[train_idx], weights[train_idx], seed)
        out[test_idx] = model.predict_proba(X.iloc[test_idx])
    return out


def score(y: pd.Series, probabilities: np.ndarray) -> dict:
    y = np.asarray(y, dtype=bool)
    predicted = probabilities >= 0.5
    bands = np.array([risk_level(float(p)) for p in probabilities])
    by_band = {}
    for band in config.RISK_LEVELS:
        mask = bands == band
        by_band[band] = {
            "n": int(mask.sum()),
            "observed_failure_rate": float(y[mask].mean()) if mask.any() else None,
        }
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[False, True]).ravel()
    return {
        "n": int(len(y)),
        "positive_rate": float(y.mean()),
        "roc_auc": float(roc_auc_score(y, probabilities)) if len(set(y)) == 2 else None,
        "accuracy_at_0_5": float(accuracy_score(y, predicted)),
        "brier": float(brier_score_loss(y, probabilities)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "risk_bands": by_band,
    }


def feature_importances(model: RiskModel) -> dict[str, float]:
    pairs = zip(model.feature_names, model.forest.feature_importances_)
    return {name: round(float(v), 4) for name, v in sorted(pairs, key=lambda p: -p[1])}
