"""K-Means behavioural profiles (DESIGN.md section 6.2).

K-Means returns anonymous clusters 0..3. To give them the paper's names, each
profile has a *prototype*: the paper's verbal description written as feature
values (``PROFILE_PROTOTYPES``). Centroids and prototypes are compared in the
standardised feature space and matched one-to-one with the Hungarian algorithm
(minimum total Euclidean distance), so every name is used exactly once and the
naming does not depend on K-Means' arbitrary cluster numbering.

Why the prototypes look the way they do
---------------------------------------
* **Vigilant Verifiers**: report most phishing, inspect links, take their time.
* **Impulsive Clickers**: click most phishing *fast* and *without hovering*.
* **Passive Ignorers**: leave most phishing untouched (high ignore rate), report
  little, rarely decide anything (long or capped decision latency).
* **High-Risk Repeaters**: frequent errors concentrated in the same vectors, at a
  normal pace and with some inspection. Their repeat-error measure is not
  higher than an impulsive clicker's (someone who clicks everything repeats
  errors too); what separates the two is speed and inspection.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy.optimize import linear_sum_assignment
from sklearn.cluster import KMeans
from sklearn.metrics import adjusted_rand_score, silhouette_score
from sklearn.preprocessing import StandardScaler

from phishsense import config
from phishsense.services.features import FEATURE_NAMES


def _proto(cr, ra, fpr, ir, hcr, fcr, mdl, vser, rem) -> dict[str, float]:
    return dict(
        click_rate=cr, report_accuracy=ra, false_positive_rate=fpr, ignore_rate=ir,
        hover_to_click_ratio=hcr, fast_click_rate=fcr, mean_decision_latency_s=mdl,
        vser_url_spoofing=vser, vser_urgency=vser, vser_impersonation=vser,
        vser_attachment=vser, repeat_error_measure=rem,
    )


PROFILE_PROTOTYPES: dict[str, dict[str, float]] = {
    #                                 CR    RA    FPR   IR    HCR   FCR   MDL   VSER  REM
    config.PROFILE_VIGILANT:  _proto(0.05, 0.85, 0.10, 0.05, 0.80, 0.00, 11.0, 0.05, 0.00),
    config.PROFILE_IMPULSIVE: _proto(0.55, 0.30, 0.02, 0.05, 0.05, 0.90, 2.0, 0.55, 0.40),
    config.PROFILE_PASSIVE:   _proto(0.05, 0.20, 0.02, 0.75, 0.50, 0.00, 15.0, 0.05, 0.05),
    config.PROFILE_REPEATER:  _proto(0.35, 0.50, 0.05, 0.10, 0.30, 0.10, 6.0, 0.40, 0.40),
}


LOG_SCALED_FEATURES = ("mean_decision_latency_s",)


def prepare(X: pd.DataFrame) -> pd.DataFrame:
    """Feature preprocessing before standardisation.

    Decision latency is right-skewed and capped at MAX_DECISION_LATENCY_S for
    users who decided nothing. On a linear scale a handful of capped users sit
    far from everyone else and K-Means spends a whole cluster on them; log1p
    keeps their ordering but removes that leverage. (The Random Forest needs no
    such step: trees depend only on the order of values.)
    """
    X = X[list(FEATURE_NAMES)].astype(float).copy()
    for name in LOG_SCALED_FEATURES:
        X[name] = np.log1p(X[name])
    return X


def default_feature_weights() -> np.ndarray:
    """Weight of each standardised feature in the K-Means distance.

    Five of the twelve features measure error level (click rate and the four
    vector error rates). Unweighted, K-Means would treat error level as five
    times more important than speed or inspection, and fast blind clickers
    with a modest error rate were grouped with repeaters. Each VSER gets weight
    0.5, so the block of four contributes like one feature (4 x 0.5^2 = 1 in
    squared distance). The Random Forest still sees all four separately.
    """
    return np.array([0.5 if name.startswith("vser_") else 1.0 for name in FEATURE_NAMES])


@dataclass
class ProfileModel:
    """Fitted scaler + feature weights + K-Means + cluster-to-profile mapping."""

    scaler: StandardScaler
    weights: np.ndarray
    kmeans: KMeans
    cluster_to_profile: dict[int, str]
    feature_names: tuple[str, ...] = FEATURE_NAMES

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """prepare -> standardise -> weight: the space K-Means works in."""
        return self.scaler.transform(prepare(X)) * self.weights

    def predict(self, X: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
        clusters = self.kmeans.predict(self.transform(X))
        return clusters, [self.cluster_to_profile[int(c)] for c in clusters]

    def centroids_raw(self) -> pd.DataFrame:
        """Centroids back in original feature units (for display)."""
        prepared = self.scaler.inverse_transform(self.kmeans.cluster_centers_ / self.weights)
        raw = pd.DataFrame(prepared, columns=list(self.feature_names))
        for name in LOG_SCALED_FEATURES:
            raw[name] = np.expm1(raw[name])
        raw.index = [self.cluster_to_profile[i] for i in range(len(raw))]
        return raw


def map_clusters_to_profiles(
    centroids_scaled: np.ndarray, prototypes_scaled: np.ndarray, profiles: list[str]
) -> dict[int, str]:
    """One-to-one assignment minimising total centroid-prototype distance."""
    cost = np.linalg.norm(centroids_scaled[:, None, :] - prototypes_scaled[None, :, :], axis=2)
    rows, cols = linear_sum_assignment(cost)
    return {int(r): profiles[c] for r, c in zip(rows, cols)}


def fit(
    X: pd.DataFrame, seed: int = config.RANDOM_SEED, weights: np.ndarray | None = None
) -> ProfileModel:
    weights = default_feature_weights() if weights is None else np.asarray(weights, float)
    scaler = StandardScaler().fit(prepare(X))
    kmeans = KMeans(
        n_clusters=config.KMEANS_CLUSTERS, n_init=config.KMEANS_N_INIT, random_state=seed
    )
    model = ProfileModel(scaler=scaler, weights=weights, kmeans=kmeans, cluster_to_profile={})
    kmeans.fit(model.transform(X))

    # Prototypes go through exactly the same transform as the data.
    profiles = list(PROFILE_PROTOTYPES)
    prototypes = pd.DataFrame([PROFILE_PROTOTYPES[p] for p in profiles])
    model.cluster_to_profile = map_clusters_to_profiles(
        kmeans.cluster_centers_, model.transform(prototypes), profiles
    )
    return model


def evaluate(
    model: ProfileModel,
    X: pd.DataFrame,
    true_profiles: pd.Series | None = None,
    seed: int = config.RANDOM_SEED,
) -> dict:
    """Silhouette, cluster sizes, centroids and (for synthetic data) agreement
    between assigned profile names and the generator's archetypes."""
    scaled = model.transform(X)
    labels = model.kmeans.predict(scaled)
    _, names = model.predict(X)
    metrics = {
        "silhouette": float(
            silhouette_score(scaled, labels, sample_size=min(len(X), 1000), random_state=seed)
        ),
        "inertia": float(model.kmeans.inertia_),
        "profile_sizes": pd.Series(names).value_counts().reindex(config.PROFILES, fill_value=0)
        .astype(int).to_dict(),
        "centroids": model.centroids_raw().round(4).to_dict(orient="index"),
    }
    if true_profiles is not None:
        truth = list(true_profiles)
        metrics["adjusted_rand_index"] = float(adjusted_rand_score(truth, labels))
        metrics["profile_name_accuracy"] = float(np.mean(np.array(names) == np.array(truth)))
    return metrics
