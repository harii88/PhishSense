"""Synthetic data, K-Means profiles, Random Forest risk and the model registry."""

from __future__ import annotations

import json
import random
from collections import Counter

import numpy as np
import pandas as pd
import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.models import MLPrediction, ModelVersion
from phishsense.data.seed import seed_content
from phishsense.services import simulation
from phishsense.services.features import FEATURE_NAMES
from phishsense.services.ml import clustering, registry, risk_model, synthetic
from tests.helpers import Clock, make_trainee, play_impulsive, play_vigilant


@pytest.fixture(scope="module")
def synth() -> pd.DataFrame:
    return synthetic.generate(600, seed=7)


def prototype_frame() -> pd.DataFrame:
    return pd.DataFrame(list(clustering.PROFILE_PROTOTYPES.values()))[list(FEATURE_NAMES)]


# --------------------------------------------------------------- synthetic
def test_synthetic_is_reproducible():
    a, b = synthetic.generate(50, seed=1), synthetic.generate(50, seed=1)
    pd.testing.assert_frame_equal(a, b)
    assert not a.equals(synthetic.generate(50, seed=2))


def test_synthetic_shape_and_bounds(synth):
    assert list(synth.columns[: len(FEATURE_NAMES)]) == list(FEATURE_NAMES)
    assert set(synth.archetype) == set(config.PROFILES)
    assert synth.n_sessions.between(1, config.SYNTHETIC_MAX_HISTORY_SESSIONS).all()
    for name in FEATURE_NAMES:
        upper = config.MAX_DECISION_LATENCY_S if name == "mean_decision_latency_s" else 1.0
        assert synth[name].between(0, upper).all(), name
    assert 0.3 < synth.failed_next.mean() < 0.75   # both classes well represented


def test_synthetic_archetypes_behave_as_described(synth):
    means = synth.groupby("archetype")[list(FEATURE_NAMES) + ["failed_next"]].mean()
    assert means.fast_click_rate.idxmax() == config.PROFILE_IMPULSIVE
    assert means.ignore_rate.idxmax() == config.PROFILE_PASSIVE
    assert means.report_accuracy.idxmax() == config.PROFILE_VIGILANT
    assert means.failed_next[config.PROFILE_VIGILANT] < means.failed_next[config.PROFILE_REPEATER]


def test_baseline_layout_matches_the_app():
    rng = np.random.default_rng(0)
    persona = synthetic.sample_persona(config.PROFILE_VIGILANT, rng)
    records = synthetic.simulate_session(persona, 0, rng)
    counts = Counter(r.category for r in records)
    assert all(counts[v] == 2 for v in config.VECTORS)
    assert counts[config.CATEGORY_LEGITIMATE] == 4
    later = synthetic.simulate_session(persona, 1, rng)
    assert len(later) == config.SESSION_PHISHING_COUNT + config.SESSION_LEGITIMATE_COUNT


# -------------------------------------------------------------- clustering
def test_hungarian_mapping_recovers_permutation():
    profiles = list(config.PROFILES)
    prototypes = np.eye(4)
    centroids = prototypes[[2, 0, 3, 1]] + 0.01
    mapping = clustering.map_clusters_to_profiles(centroids, prototypes, profiles)
    assert mapping == {0: profiles[2], 1: profiles[0], 2: profiles[3], 3: profiles[1]}


def test_profiles_recovered_on_synthetic_data(synth):
    model = clustering.fit(synth)
    metrics = clustering.evaluate(model, synth, synth.archetype)
    assert sorted(model.cluster_to_profile.values()) == sorted(config.PROFILES)
    assert metrics["profile_name_accuracy"] > 0.85
    assert metrics["adjusted_rand_index"] > 0.7
    assert -1 <= metrics["silhouette"] <= 1


def test_each_prototype_lands_in_its_own_profile(synth):
    model = clustering.fit(synth)
    _, names = model.predict(prototype_frame())
    assert names == list(clustering.PROFILE_PROTOTYPES)


def test_prepare_log_scales_latency_without_mutating_input(synth):
    original = synth.copy()
    prepared = clustering.prepare(synth)
    pd.testing.assert_frame_equal(synth, original)
    assert np.allclose(prepared.mean_decision_latency_s, np.log1p(synth.mean_decision_latency_s))


def test_centroids_reported_in_original_units(synth):
    model = clustering.fit(synth)
    centroids = model.centroids_raw()
    assert set(centroids.index) == set(config.PROFILES)
    latency = centroids.mean_decision_latency_s
    assert latency[config.PROFILE_IMPULSIVE] < config.FAST_DECISION_S < latency[config.PROFILE_VIGILANT]


def test_vser_block_weighted_as_one_feature():
    w = clustering.default_feature_weights()
    vser = [w[i] for i, n in enumerate(FEATURE_NAMES) if n.startswith("vser_")]
    assert sum(x * x for x in vser) == pytest.approx(1.0)


# --------------------------------------------------------------- risk model
@pytest.mark.parametrize(
    "p, level",
    [(0.0, "Low"), (0.2499, "Low"), (0.25, "Moderate"), (0.60, "Moderate"),
     (0.6001, "High"), (1.0, "High")],
)
def test_risk_level_thresholds(p, level):
    assert risk_model.risk_level(p) == level


@pytest.mark.parametrize("p", [-0.01, 1.01])
def test_risk_level_rejects_invalid(p):
    with pytest.raises(ValueError):
        risk_model.risk_level(p)


def test_fit_needs_both_classes(synth):
    with pytest.raises(ValueError, match="both"):
        risk_model.fit(synth, pd.Series([True] * len(synth)))


def test_cross_validated_quality_and_score_report(synth, monkeypatch):
    monkeypatch.setattr(config, "RF_N_ESTIMATORS", 80)
    oof = risk_model.cross_validated_probabilities(synth, synth.failed_next)
    report = risk_model.score(synth.failed_next, oof)
    assert report["roc_auc"] > 0.8
    assert sum(report["confusion_matrix"].values()) == len(synth)
    assert sum(b["n"] for b in report["risk_bands"].values()) == len(synth)
    bands = report["risk_bands"]
    assert (bands["Low"]["observed_failure_rate"]
            < bands["Moderate"]["observed_failure_rate"]
            < bands["High"]["observed_failure_rate"])


def test_impulsive_prototype_riskier_than_vigilant(synth, monkeypatch):
    monkeypatch.setattr(config, "RF_N_ESTIMATORS", 80)
    model = risk_model.fit(synth, synth.failed_next)
    p = dict(zip(clustering.PROFILE_PROTOTYPES, model.predict_proba(prototype_frame())))
    assert p[config.PROFILE_IMPULSIVE] > 0.6 > 0.25 > p[config.PROFILE_VIGILANT]
    assert list(risk_model.feature_importances(model))[0] in FEATURE_NAMES


# ----------------------------------------------------------------- registry
def test_train_registers_active_versions(db, ml_env):
    report = registry.train_models(db)
    versions = registry.active_versions(db)
    assert set(versions) == set(config.MODEL_KINDS)
    assert report.kmeans_version.version == report.rf_version.version == 1
    for row in versions.values():
        assert (ml_env / row.path).exists()
        json.dumps(row.metrics)  # stored metrics are plain JSON
        assert row.n_synthetic == 300 and row.n_real == 0
    assert report.rf_metrics["cross_validation_real_only"] is None


def test_retraining_creates_new_versions_and_keeps_old(db, ml_env):
    registry.train_models(db)
    registry.train_models(db)
    rows = db.scalars(select(ModelVersion).order_by(ModelVersion.id)).all()
    assert [(r.kind, r.version, r.is_active) for r in rows] == [
        ("kmeans", 1, False), ("random_forest", 1, False),
        ("kmeans", 2, True), ("random_forest", 2, True),
    ]
    assert all((ml_env / r.path).exists() for r in rows)


def test_missing_model_file_is_reported(db, ml_env):
    report = registry.train_models(db)
    (ml_env / report.rf_version.path).unlink()
    registry.clear_cache()
    with pytest.raises(registry.ModelError, match="missing"):
        registry.load_active(db)


def _user_with_sessions(db, name, play, n, clock):
    user = make_trainee(db, name)
    for i in range(n):
        sim = simulation.start_session(db, user, rng=random.Random(i))
        play(db, sim, clock)
        simulation.finish_session(db, sim, now=clock(1000))
    return user


def test_real_training_pairs(db):
    seed_content(db)
    clock = Clock()
    a = _user_with_sessions(db, "anna", play_impulsive, 3, clock)
    _user_with_sessions(db, "ben", play_vigilant, 1, clock)
    X, y = registry.real_training_pairs(db)
    assert len(X) == len(y) == 2                       # anna: (s1->s2), (s2->s3); ben: none
    sessions = [s for s in a.sessions if s.is_complete]
    assert list(y) == [sessions[1].failed, sessions[2].failed]
    assert list(X.columns) == list(FEATURE_NAMES)
    assert len(registry.real_feature_rows(db)) == 4    # every snapshot is used for clustering


def test_real_pairs_enter_training(db, ml_env):
    seed_content(db)
    clock = Clock()
    _user_with_sessions(db, "anna", play_impulsive, 3, clock)
    report = registry.train_models(db)
    assert report.rf_version.n_real == 2 and report.kmeans_version.n_real == 3
    report = registry.train_models(db, include_real=False)
    assert report.rf_version.n_real == 0


def test_predict_for_cold_start_and_behaviour(db, ml_env):
    seed_content(db)
    clock = Clock()
    assert registry.load_active(db) is None                          # cold start
    users, predictions = {}, {}
    for name, play in [("ivan", play_impulsive), ("vera", play_vigilant)]:
        users[name] = user = make_trainee(db, name)
        sim = simulation.start_session(db, user)
        play(db, sim, clock)
        summary = simulation.finish_session(db, sim, now=clock(1000))
        predictions[name] = registry.predict_for(db, user, summary.features)

    ivan, vera = predictions["ivan"], predictions["vera"]
    assert registry.load_active(db) is not None                      # trained on demand
    assert ivan.profile == config.PROFILE_IMPULSIVE and ivan.risk_level == config.RISK_HIGH
    assert vera.profile == config.PROFILE_VIGILANT and vera.risk_level == config.RISK_LOW
    assert ivan.fail_probability > vera.fail_probability
    assert ivan.kmeans_version_id == vera.kmeans_version_id
    assert db.scalars(select(MLPrediction)).all() == [ivan, vera]
    assert registry.latest_prediction(db, users["ivan"]) is ivan
