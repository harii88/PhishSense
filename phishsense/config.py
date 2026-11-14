"""Single source of truth for paths, vocabularies and tunable thresholds.

Every number that changes the behaviour of the research pipeline lives here,
so the values reported in the project write-up can be traced to one file.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent

# All generated state (database, trained models, exported reports) goes under
# one directory. Override with the PHISHSENSE_HOME environment variable.
DATA_DIR = Path(os.environ.get("PHISHSENSE_HOME", PROJECT_DIR / "instance"))
DB_PATH = DATA_DIR / "phishsense.db"
MODELS_DIR = DATA_DIR / "models"
REPORTS_DIR = DATA_DIR / "reports"

# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------
ROLE_ADMIN = "admin"
ROLE_TRAINEE = "trainee"
ROLES = (ROLE_ADMIN, ROLE_TRAINEE)

DEPARTMENTS = (
    "Administration",
    "Engineering",
    "Finance",
    "Human Resources",
    "IT",
    "Operations",
    "Sales & Marketing",
)

# Phishing attack vectors studied in the paper.
VECTOR_URL_SPOOFING = "url_spoofing"
VECTOR_URGENCY = "urgency"
VECTOR_IMPERSONATION = "impersonation"
VECTOR_ATTACHMENT = "attachment"
VECTORS = (VECTOR_URL_SPOOFING, VECTOR_URGENCY, VECTOR_IMPERSONATION, VECTOR_ATTACHMENT)

VECTOR_LABELS = {
    VECTOR_URL_SPOOFING: "URL spoofing",
    VECTOR_URGENCY: "Urgency / pressure",
    VECTOR_IMPERSONATION: "Sender impersonation",
    VECTOR_ATTACHMENT: "Malicious attachment",
}

TOPIC_LABELS = {
    **VECTOR_LABELS,
    "pause_inspect": "Pause and inspect",
    "reporting": "Reporting",
}

PROFILE_DESCRIPTIONS = {
    "Vigilant Verifiers": "You check senders and links before acting and report what looks wrong.",
    "Impulsive Clickers": "You tend to click quickly, often before checking where a link goes.",
    "Passive Ignorers": "You rarely click, but you also leave suspicious emails unreported.",
    "High-Risk Repeaters": "You keep making mistakes on the same kinds of phishing email.",
}

# Email categories = the four vectors plus genuine mail.
CATEGORY_LEGITIMATE = "legitimate"
EMAIL_CATEGORIES = VECTORS + (CATEGORY_LEGITIMATE,)

# Training topics = one per vector plus two behaviour-focused topics that are
# assigned from the K-Means profile rather than from a vector error rate.
TOPIC_PAUSE_INSPECT = "pause_inspect"
TOPIC_REPORTING = "reporting"
TOPICS = VECTORS + (TOPIC_PAUSE_INSPECT, TOPIC_REPORTING)

MIN_LEVEL = 1
MAX_LEVEL = 3
LEVELS = tuple(range(MIN_LEVEL, MAX_LEVEL + 1))

SESSION_KIND_BASELINE = "baseline"
SESSION_KIND_ADAPTIVE = "adaptive"
SESSION_KINDS = (SESSION_KIND_BASELINE, SESSION_KIND_ADAPTIVE)

# Raw behaviour events captured by the simulated inbox.
EVENT_OPEN = "open"
EVENT_LINK_HOVER = "link_hover"          # value_ms = hover duration
EVENT_SENDER_INSPECT = "sender_inspect"
EVENT_LINK_CLICK = "link_click"
EVENT_ATTACHMENT_OPEN = "attachment_open"
EVENT_REPORT = "report"
EVENT_MARK_SAFE = "mark_safe"
EVENT_TYPES = (
    EVENT_OPEN,
    EVENT_LINK_HOVER,
    EVENT_SENDER_INSPECT,
    EVENT_LINK_CLICK,
    EVENT_ATTACHMENT_OPEN,
    EVENT_REPORT,
    EVENT_MARK_SAFE,
)

# One final decision per delivered email.
DECISION_CLICKED = "clicked"         # followed the link or opened the attachment
DECISION_REPORTED = "reported"
DECISION_MARKED_SAFE = "marked_safe"
DECISION_IGNORED = "ignored"         # no action before the session was finished
DECISIONS = (DECISION_CLICKED, DECISION_REPORTED, DECISION_MARKED_SAFE, DECISION_IGNORED)

CLICK_VIA_LINK = "link"
CLICK_VIA_ATTACHMENT = "attachment"
CLICK_TARGETS = (CLICK_VIA_LINK, CLICK_VIA_ATTACHMENT)

# Behavioural profiles produced by K-Means (names from the paper).
PROFILE_VIGILANT = "Vigilant Verifiers"
PROFILE_IMPULSIVE = "Impulsive Clickers"
PROFILE_PASSIVE = "Passive Ignorers"
PROFILE_REPEATER = "High-Risk Repeaters"
PROFILES = (PROFILE_VIGILANT, PROFILE_IMPULSIVE, PROFILE_PASSIVE, PROFILE_REPEATER)

RISK_LOW = "Low"
RISK_MODERATE = "Moderate"
RISK_HIGH = "High"
RISK_LEVELS = (RISK_LOW, RISK_MODERATE, RISK_HIGH)

MODEL_KIND_KMEANS = "kmeans"
MODEL_KIND_RANDOM_FOREST = "random_forest"
MODEL_KINDS = (MODEL_KIND_KMEANS, MODEL_KIND_RANDOM_FOREST)

QUIZ_KIND_JUDGE = "judge"   # phishing or legitimate?
QUIZ_KIND_URL = "url"       # which link is genuine / where does it really go?
QUIZ_KIND_FLAG = "flag"     # spot the red flag / best response
QUIZ_KINDS = (QUIZ_KIND_JUDGE, QUIZ_KIND_URL, QUIZ_KIND_FLAG)

# ---------------------------------------------------------------------------
# Thresholds (see DESIGN.md sections 5-8)
# ---------------------------------------------------------------------------
INSPECT_HOVER_S = 1.0           # a hover at least this long counts as inspecting a link
FAST_DECISION_S = 3.0           # a click sooner than this after opening is "fast"
MAX_DECISION_LATENCY_S = 120.0  # latencies are clipped to this value
FEATURE_WINDOW_SESSIONS = 3     # features use the user's last N completed sessions

SESSION_PHISHING_COUNT = 5      # adaptive sessions
SESSION_LEGITIMATE_COUNT = 3
SESSION_WEAK_VECTOR_SLOTS = 2   # phishing slots reserved for the weakest vector
# The baseline is larger (2 phishing emails per vector + 4 genuine, see
# content.BASELINE_EMAIL_CODES) so every vector reaches MIN_EMAILS_FOR_WEAKNESS
# after one session and the first adaptive session can target any vector.

RISK_LOW_BELOW = 0.25           # p < 0.25          -> Low
RISK_HIGH_ABOVE = 0.60          # p > 0.60          -> High, otherwise Moderate

LEVEL_UP_ACCURACY = 0.80        # vector accuracy >= this -> level + 1
LEVEL_DOWN_ACCURACY = 0.40      # vector accuracy <= this -> level - 1
MIN_EMAILS_FOR_WEAKNESS = 2     # need this many emails of a vector to call it a weakness

QUIZ_LENGTH = 5
QUIZ_PASS_SCORE = 0.70

RANDOM_SEED = 42

# Machine learning (DESIGN.md section 6)
SYNTHETIC_USERS = 800
SYNTHETIC_MAX_HISTORY_SESSIONS = 4     # each synthetic user has 1..N past sessions
KMEANS_CLUSTERS = 4
KMEANS_N_INIT = 20
RF_N_ESTIMATORS = 300
RF_MAX_DEPTH = 8
RF_MIN_SAMPLES_LEAF = 5
CV_FOLDS = 5
REAL_SAMPLE_WEIGHT = 5.0               # weight of a real labelled pair vs a synthetic one
MIN_REAL_SAMPLES_FOR_REPORT = 10       # report real-only metrics from this many pairs

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
USERNAME_PATTERN = r"^[a-z0-9._-]{3,32}$"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_BYTES = 72          # bcrypt ignores anything beyond 72 bytes
BCRYPT_ROUNDS = 12
