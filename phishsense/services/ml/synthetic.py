"""Synthetic behavioural dataset for the cold start.

How it works
------------
Each synthetic user is a small *behavioural simulation*, not a row of random
numbers:

1. An archetype is drawn (shares in ``ARCHETYPE_SHARES``) and a persona is
   sampled from that archetype's parameter ranges (``ARCHETYPE_RANGES``).
2. The persona plays 1..``SYNTHETIC_MAX_HISTORY_SESSIONS`` inbox sessions with
   the same composition as the real app (a 12-email baseline, then 5 phishing +
   3 genuine). Every email becomes an :class:`OutcomeRecord`.
3. Features are computed from that history by the **same**
   :func:`features.compute_features` used for real users.
4. The label ``failed_next`` comes from simulating one more session: True if
   any phishing link or attachment is clicked, which is exactly how a real
   session is marked failed.

Persona model, per phishing email of vector ``v`` in session ``t``:

* with probability ``engage`` the persona acts on it, otherwise ignores it;
* when acting, it errs with ``p = susceptibility * weight[v] * improvement**t``
  (clipped), else it reports the email;
* an error is a click (link, or attachment for the attachment vector) with
  probability ``click_share``, otherwise the email is marked safe;
* hover time before acting ~ exponential(``hover_ms``); decision latency ~
  ``latency_ms * lognormal(0, 0.4)``.

Genuine emails: when engaged, the persona reports them with probability
``false_positive``, otherwise clicks the link (if any) or marks them safe.

Limitations (stated in the app and README): every parameter below is an
assumption chosen to produce the four behaviours described in the paper. The
data shows that the pipeline works end to end; it is **not** evidence about how
real people behave, and metrics on it are not research results.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from phishsense import config
from phishsense.services.features import FEATURE_NAMES, OutcomeRecord, compute_features

ARCHETYPE_SHARES: dict[str, float] = {
    config.PROFILE_VIGILANT: 0.30,
    config.PROFILE_IMPULSIVE: 0.30,
    config.PROFILE_PASSIVE: 0.20,
    config.PROFILE_REPEATER: 0.20,
}

# (low, high) uniform ranges per persona parameter.
ARCHETYPE_RANGES: dict[str, dict[str, tuple[float, float]]] = {
    config.PROFILE_VIGILANT: dict(
        susceptibility=(0.02, 0.15), engage=(0.85, 1.00), hover_ms=(1500, 4000),
        latency_ms=(6000, 15000), improvement=(0.70, 0.90), false_positive=(0.05, 0.20),
        click_share=(0.6, 0.8),
    ),
    config.PROFILE_IMPULSIVE: dict(
        susceptibility=(0.50, 0.85), engage=(0.85, 1.00), hover_ms=(0, 400),
        latency_ms=(800, 2500), improvement=(0.80, 0.95), false_positive=(0.00, 0.05),
        click_share=(0.90, 1.00),
    ),
    config.PROFILE_PASSIVE: dict(
        susceptibility=(0.05, 0.30), engage=(0.10, 0.40), hover_ms=(300, 1500),
        latency_ms=(5000, 20000), improvement=(0.90, 1.00), false_positive=(0.00, 0.05),
        click_share=(0.6, 0.9),
    ),
    config.PROFILE_REPEATER: dict(
        susceptibility=(0.35, 0.70), engage=(0.80, 1.00), hover_ms=(400, 1500),
        latency_ms=(3000, 8000), improvement=(0.98, 1.05), false_positive=(0.02, 0.10),
        click_share=(0.7, 0.9),
    ),
}

GENUINE_LINK_SHARE = 0.7  # share of genuine emails in the catalogue that carry a link
MAX_ERROR_PROBABILITY = 0.97


@dataclass(frozen=True)
class Persona:
    archetype: str
    susceptibility: float
    engage: float
    hover_ms: float
    latency_ms: float
    improvement: float
    false_positive: float
    click_share: float
    vector_weight: dict[str, float]


def sample_persona(archetype: str, rng: np.random.Generator) -> Persona:
    params = {k: rng.uniform(lo, hi) for k, (lo, hi) in ARCHETYPE_RANGES[archetype].items()}
    if archetype == config.PROFILE_REPEATER:
        # One or two persistent blind spots, the rest comparatively fine.
        weak = set(rng.choice(config.VECTORS, size=rng.integers(1, 3), replace=False))
        weights = {v: rng.uniform(1.3, 1.6) if v in weak else rng.uniform(0.3, 0.6)
                   for v in config.VECTORS}
    else:
        weights = {v: rng.uniform(0.6, 1.4) for v in config.VECTORS}
    return Persona(archetype=archetype, vector_weight=weights, **params)


def _session_layout(index: int, rng: np.random.Generator) -> list[str]:
    """Categories in session ``index`` (0 = baseline), mirroring the real app."""
    if index == 0:
        return [v for v in config.VECTORS for _ in range(2)] + [config.CATEGORY_LEGITIMATE] * 4
    phishing = list(rng.choice(config.VECTORS, size=config.SESSION_PHISHING_COUNT))
    return phishing + [config.CATEGORY_LEGITIMATE] * config.SESSION_LEGITIMATE_COUNT


def _latency(p: Persona, rng: np.random.Generator) -> int:
    return int(p.latency_ms * rng.lognormal(0.0, 0.4))


def decide(
    p: Persona, category: str, index: int, rng: np.random.Generator,
    has_link: bool | None = None,
) -> OutcomeRecord:
    """The persona's behaviour on one email in session ``index``.

    ``has_link`` is drawn for genuine emails when not given (synthetic data);
    the sample-data generator passes the real email's value. The order of
    random draws is part of the contract: it keeps the synthetic dataset
    reproducible for a given seed.
    """
    if rng.random() >= p.engage:
        return OutcomeRecord(category, config.DECISION_IGNORED)

    is_attachment = category == config.VECTOR_ATTACHMENT
    if has_link is None:
        has_link = (
            not is_attachment
            if category != config.CATEGORY_LEGITIMATE
            else rng.random() < GENUINE_LINK_SHARE
        )
    hover = int(rng.exponential(p.hover_ms)) if has_link and p.hover_ms > 0 else 0
    latency = _latency(p, rng)

    if category == config.CATEGORY_LEGITIMATE:
        if rng.random() < p.false_positive:
            decision, via = config.DECISION_REPORTED, None
        elif has_link:
            decision, via = config.DECISION_CLICKED, config.CLICK_VIA_LINK
        else:
            decision, via = config.DECISION_MARKED_SAFE, None
    else:
        p_error = min(
            p.susceptibility * p.vector_weight[category] * p.improvement**index,
            MAX_ERROR_PROBABILITY,
        )
        if rng.random() < p_error:
            if rng.random() < p.click_share:
                decision = config.DECISION_CLICKED
                via = config.CLICK_VIA_ATTACHMENT if is_attachment else config.CLICK_VIA_LINK
            else:
                decision, via = config.DECISION_MARKED_SAFE, None
        else:
            decision, via = config.DECISION_REPORTED, None

    return OutcomeRecord(category, decision, via, latency, hover)


def simulate_session(p: Persona, index: int, rng: np.random.Generator) -> list[OutcomeRecord]:
    return [decide(p, category, index, rng) for category in _session_layout(index, rng)]


def generate(n_users: int = config.SYNTHETIC_USERS, seed: int = config.RANDOM_SEED) -> pd.DataFrame:
    """One row per synthetic user: FEATURE_NAMES + archetype, n_sessions, failed_next."""
    rng = np.random.default_rng(seed)
    archetypes = list(ARCHETYPE_SHARES)
    shares = np.array(list(ARCHETYPE_SHARES.values()))
    rows = []
    for archetype in rng.choice(archetypes, size=n_users, p=shares / shares.sum()):
        persona = sample_persona(str(archetype), rng)
        n_sessions = int(rng.integers(1, config.SYNTHETIC_MAX_HISTORY_SESSIONS + 1))
        history = [simulate_session(persona, t, rng) for t in range(n_sessions)]
        nxt = simulate_session(persona, n_sessions, rng)
        failed_next = any(r.is_phishing and r.decision == config.DECISION_CLICKED for r in nxt)
        vector = compute_features(history)
        rows.append(
            {**dict(zip(FEATURE_NAMES, vector.as_list())),
             "archetype": str(archetype), "n_sessions": n_sessions, "failed_next": failed_next}
        )
    return pd.DataFrame(rows)
