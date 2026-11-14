"""Train the models from the command line and print their evaluation.

    python -m phishsense.services.ml [--synthetic-only] [--synthetic-users N]
"""

from __future__ import annotations

import argparse

from phishsense import config
from phishsense.data.db import create_db_engine, init_db, make_session_factory, session_scope
from phishsense.services.ml import registry


def _print_report(report: registry.TrainingReport) -> None:
    km, rf = report.kmeans_metrics, report.rf_metrics
    print(f"\nK-Means v{report.kmeans_version.version} "
          f"({report.kmeans_version.n_synthetic} synthetic + "
          f"{report.kmeans_version.n_real} real rows)")
    print(f"  silhouette                      {km['silhouette']:.3f}")
    print(f"  synthetic: adjusted Rand index  {km['synthetic_adjusted_rand_index']:.3f}")
    print(f"  synthetic: profile name match   {km['synthetic_profile_name_accuracy']:.1%}")
    print("  profile sizes                  ", km["profile_sizes"])

    cv = rf["cross_validation"]
    print(f"\nRandom Forest v{report.rf_version.version} "
          f"({report.rf_version.n_synthetic} synthetic + {report.rf_version.n_real} real pairs, "
          f"{config.CV_FOLDS}-fold CV)")
    print(f"  ROC-AUC {cv['roc_auc']:.3f}   accuracy@0.5 {cv['accuracy_at_0_5']:.3f}   "
          f"Brier {cv['brier']:.3f}   positive rate {cv['positive_rate']:.2f}")
    print(f"  confusion matrix {cv['confusion_matrix']}")
    for band, info in cv["risk_bands"].items():
        rate = info["observed_failure_rate"]
        shown = "-" if rate is None else f"{rate:.1%}"
        print(f"  {band:<9} n={info['n']:<4} observed failure rate {shown}")
    if rf["cross_validation_real_only"]:
        print(f"  real pairs only: ROC-AUC {rf['cross_validation_real_only']['roc_auc']}")
    else:
        print(f"  real pairs only: not reported (needs >= {config.MIN_REAL_SAMPLES_FOR_REPORT} "
              "pairs with both outcomes)")
    print("  top features:", dict(list(rf["feature_importances"].items())[:5]))
    print("\nThese metrics come from synthetic data (plus any demo users). "
          "They show the pipeline works; they are not research results.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the PhishSense models.")
    parser.add_argument("--synthetic-only", action="store_true",
                        help="ignore real interaction data from the database")
    parser.add_argument("--synthetic-users", type=int, default=config.SYNTHETIC_USERS)
    args = parser.parse_args(argv)

    engine = create_db_engine()
    try:
        init_db(engine)
        with session_scope(make_session_factory(engine)) as session:
            report = registry.train_models(
                session, n_synthetic=args.synthetic_users, include_real=not args.synthetic_only
            )
            _print_report(report)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
