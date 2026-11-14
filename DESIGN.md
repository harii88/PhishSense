# PhishSense — Design Document

**Behavior-Driven Adaptive Phishing Training Using Machine Learning**
Desktop application (Windows), Python 3.12 + PySide6. Status: **draft for approval** — no code is written until this is agreed.

---

## 1. Goals and non-goals

**Goal.** Demonstrate the closed loop from the paper as working software:

```
simulate → observe behaviour → extract features → K-Means + Random Forest
        → risk level + behavioural profile → adaptive training + quiz
        → harder/easier next simulation → (repeat, features update)
```

**What the demo must prove to evaluators**
1. Behaviour is measured (hover time, latency, clicks, reports), not just quiz scores.
2. Real scikit-learn models produce a cluster and a failure probability per user.
3. Two users with different behaviour get **different** training and different next simulations.

**Non-goals**
- Not a website. No web server, no browser, no network access at all.
- No real email. Every email is a record in a local SQLite database.
- No credential capture. "Clicking" a link never opens a URL; it records an event and shows a teaching screen.
- The paper's experiment (120 participants, 2,400 sessions) is **not** reproduced. Any metric the app shows is labelled as coming from either *synthetic data* or *this installation's demo users*, never as paper results.

---

## 2. Architecture

Three layers. The lower two contain no Qt code, so they can be tested with pytest without opening a window.

```
┌───────────────────────────────────────────────────────────┐
│ UI layer (PySide6)          phishsense/ui/                 │
│ windows, pages, matplotlib charts; calls services only     │
├───────────────────────────────────────────────────────────┤
│ Service layer               phishsense/services/           │
│ auth · simulation · tracking · features · ml · adaptive ·  │
│ quiz · reports                                             │
├───────────────────────────────────────────────────────────┤
│ Data layer                  phishsense/data/               │
│ SQLAlchemy 2.x models · SQLite file · seed content         │
└───────────────────────────────────────────────────────────┘
```

### Project layout

```
phishsense/
  __main__.py              python -m phishsense  → launches the app
  config.py                paths, thresholds, constants (one place)
  data/
    db.py                  engine, session factory, init_db()
    models.py              ORM tables (section 3)
    content/               emails.py, modules.py, questions.py, trusted domains
    seed.py                python -m phishsense.data.seed [--reset]
  services/
    auth.py                register, login, bcrypt hashing, roles
    simulation.py          build session, deliver emails, close session
    tracking.py            record raw behaviour events
    features.py            events → feature vector (section 5)
    ml/
      synthetic.py         synthetic behavioural dataset generator
      clustering.py        K-Means + centroid-to-archetype mapping
      risk_model.py        Random Forest, probability, risk level
      registry.py          save/load models with joblib, versions
    adaptive.py            recommendations + difficulty control
    quiz.py                question selection, scoring, feedback
    reports.py             CSV and PDF export
  ui/
    app.py, login_dialog.py, main_window.py, theme.qss
    pages/ dashboard.py inbox.py training.py quiz.py progress.py admin.py
    widgets/ email_view.py charts.py
tests/                     pytest, one file per service + e2e scenario
instance/                  generated: phishsense.db, models/*.joblib, reports/
                           (override location with PHISHSENSE_HOME)
requirements.txt, pyproject.toml, README.md
```

### Technology (paper stack adapted to desktop)

| Concern | Choice | Replaces (web spec) |
|---|---|---|
| GUI | PySide6 (Qt 6) | HTML/Tailwind/JS |
| Charts | matplotlib embedded in Qt | Chart.js |
| Persistence | SQLite + SQLAlchemy 2.x | same |
| ML | scikit-learn, pandas, numpy | same |
| Passwords | bcrypt | same idea |
| Reports | CSV (pandas), PDF (matplotlib PdfPages) | — |
| Tests | pytest | — |

---

## 3. Data model

| Table | Key columns | Notes |
|---|---|---|
| `users` | id, username (unique), full_name, department, role (`admin`/`trainee`), password_hash, created_at | bcrypt hash only |
| `emails` | id, code, category (4 vectors or `legitimate`), is_phishing, difficulty (1–3), sender_name, sender_address, subject, body (HTML with `{link}` placeholder), link_text (visible), link_url (real target, shown on hover), attachment_name, indicators (JSON) | content catalogue |
| `simulation_sessions` | id, user_id, kind (`baseline`/`adaptive`), started_at, completed_at, failed (bool) | one inbox run |
| `session_emails` | session_id, email_id, position | which emails were delivered |
| `behaviour_events` | id, session_id, email_id, event_type, ts, value_ms | raw stream, append-only |
| `email_outcomes` | session_id, email_id, decision, clicked_via (`link`/`attachment`, set iff clicked), correct, opened, latency_ms, hover_ms, inspected_sender | derived when a session closes; only activity *before* the decision counts toward hover/inspection |
| `behaviour_features` | id, user_id, session_id, computed_at, + every feature in §5 | one snapshot per completed session |
| `ml_predictions` | id, user_id, features_id, cluster_id, profile, fail_probability, risk_level, model_version | |
| `user_vector_levels` | user_id, vector, level (1–3) | adaptive difficulty state |
| `training_modules` | id, code, topic, level, title, summary, lesson (HTML) | topic = a vector, `pause_inspect` or `reporting` |
| `training_assignments` | id, user_id, module_id, prediction_id, reason, mandatory, assigned_at, completed_at, quiz_score, attempts | the "why" is stored |
| `quiz_questions` | id, code, topic, level, kind, prompt, options (JSON), correct_index, explanation | |
| `quiz_results` | id, user_id, assignment_id, attempt, question_id, chosen_index, correct, time_ms | stored per answer; unique per (assignment, attempt, question) |
| `model_versions` | id, kind, trained_at, n_synthetic, n_real, metrics (JSON) | audit trail for retraining |

**Vectors:** `url_spoofing`, `urgency`, `impersonation`, `attachment`, plus `legitimate` emails.

**Event types:** `open`, `link_hover` (value_ms = hover duration), `sender_inspect`, `link_click`, `attachment_open`, `report`, `mark_safe`.

**Decisions** (one per email per session): `clicked` (link or attachment), `reported`, `marked_safe`, `ignored` (no action when the session was closed).

| | phishing email | legitimate email |
|---|---|---|
| clicked | **error (compromise)** | correct |
| reported | correct | false positive |
| marked_safe | **error** | correct |
| ignored | miss | neutral |

A session is **failed** if the user compromised at least one phishing email (clicked a link or opened an attachment). This is the label the Random Forest learns to predict.

---

## 4. Simulated inbox (how behaviour is observed)

Gmail-like three-pane window: folder list · message list · reading pane.

- The reading pane is a `QTextBrowser` with `setOpenLinks(False)` and `setOpenExternalLinks(False)`, so no URL is ever opened.
- **Hover inspection:** Qt's `highlighted(QUrl)` signal fires when the pointer enters/leaves a link. While hovering, the status bar at the bottom shows the *real* target (`link_actual_url`), exactly as a real mail client does. Hover start/end gives `link_hover` duration. A spoofed email's visible text says one domain; the status bar shows another — the user only sees it if they inspect.
- **Sender inspection:** the header shows the display name; a "details ▾" toggle reveals the actual address → `sender_inspect` event.
- **Actions:** click the link, open the attachment, *Report phishing*, *Mark as safe*.
- **Teachable moment:** clicking a phishing link or attachment immediately shows an in-app "This was a simulated phishing email" panel listing the red flags (`indicators`). Nothing leaves the app.
- **Ending a session:** *Finish session* converts all unanswered emails to `ignored`, writes `email_outcomes`, computes features, runs both models, and creates training assignments. A results screen then reviews every email.

All sender names, organisations and domains are fictional (no real banks or brands).

---

## 5. Features (exact definitions)

Computed from `email_outcomes` over a **rolling window of the user's last 3 completed sessions**, so improvement shows up quickly and old mistakes age out. `P` = phishing emails in the window, `L` = legitimate ones. `T_inspect = 1.0 s`, `T_fast = 3.0 s`.

| Feature | Formula | Range |
|---|---|---|
| Click Rate (CR) | compromised phishing / \|P\| | 0–1 |
| Report Accuracy (RA) | correctly reported phishing / \|P\| | 0–1 |
| False Positive Rate (FPR) | reported legitimate / \|L\| | 0–1 |
| Ignore Rate (IR) | ignored phishing / \|P\| | 0–1 |
| Hover-to-Click Ratio (HCR) | link clicks preceded by ≥ T_inspect hover / all link clicks (1.0 if no clicks — note this makes a user who never clicks look like an inspector on this one feature; IR, RA and MDL separate them) | 0–1 |
| Fast Click Rate (FCR) | clicks with latency < T_fast and hover < T_inspect / all clicks (0 if none) | 0–1 |
| Mean Decision Latency (MDL) | mean seconds from `open` to decision, clipped at 120 s | 0–120 |
| Vector-Specific Error Rate (VSER_v) | errors on vector v / phishing emails of v (4 values) | 0–1 each |
| Repeat Error Measure (REM) | errors on a vector already failed in an *earlier* session / all errors (0 if none) | 0–1 |

Feature vector used by both models (11 values): CR, RA, FPR, IR, HCR, FCR, MDL, VSER×4. REM is included for the Random Forest and the High-Risk Repeater mapping.

---

## 6. Machine learning

### 6.1 Synthetic dataset (cold start)
`synthetic.py` simulates 800 users *behaviourally* (changed in Module 3 from "draw features from distributions"). Each user gets an archetype and a persona (susceptibility, engagement, hover time, decision speed, improvement per session, per-vector weaknesses). The persona plays 1–4 inbox sessions with the app's real composition. Its actions become `OutcomeRecord`s, and the **same `compute_features`** used for real users turns them into features. The label comes from simulating one more session: did the user compromise any phishing email? That is exactly how a real session is marked failed. Fixed seed → reproducible. **Metrics on this data only show the pipeline works; they are not evidence about real people.**

### 6.2 K-Means (behaviour profile)
- Pipeline: `log1p(decision latency)` → `StandardScaler` → feature weights (each VSER × 0.5) → `KMeans(n_clusters=4, n_init=20, random_state=42)` on all 12 features.
  - *log latency*: users who decided nothing sit at the 120 s cap; on a linear scale a handful of them took a whole cluster.
  - *VSER × 0.5*: 5 of the 12 features measure error level; the four VSERs together now count as one feature (4 × 0.5² = 1), so speed and inspection are not outvoted. The Random Forest still sees all four separately.
  - Ablation over 10 synthetic seeds (profile-name accuracy mean/min): as designed 0.863/0.787 · VSER weight only 0.856/0.767 · log latency only 0.928/0.853 · **both 0.958/0.922**.
- Clusters are named by matching centroids to prototype profiles with the Hungarian algorithm (one name per cluster), in the same transformed space:

| Profile | Prototype |
|---|---|
| Vigilant Verifiers | high RA, high HCR, low CR, slow decisions |
| Impulsive Clickers | high CR, high FCR, near-zero HCR, very fast decisions |
| Passive Ignorers | high IR, low RA, low CR |
| High-Risk Repeaters | frequent errors and high REM at a *normal* pace with some inspection |

  Finding behind the last row: on synthetic data an impulsive clicker's REM (0.42) is *higher* than a repeater's (0.34). Anyone who clicks everything repeats errors too, so speed and inspection, not REM, separate the two.
- Recorded metrics: silhouette, inertia, profile sizes, centroids in original units, and on synthetic rows the adjusted Rand index and profile-name accuracy against the generator's archetypes.

### 6.3 Random Forest (failure probability)
- `RandomForestClassifier(n_estimators=300, max_depth=8, min_samples_leaf=5, random_state=42)` on all 12 features. **No `class_weight="balanced"`** (changed in Module 3): the risk bands are thresholds on the probability, and class re-weighting distorts probabilities. Synthetic classes are about 53/47 anyway.
- Stratified 5-fold out-of-fold predictions: ROC-AUC, accuracy@0.5, Brier score, confusion matrix, and the **observed failure rate inside each risk band** (shows whether the probabilities can be trusted). Feature importances come from the final fit. Real-only metrics are reported once there are ≥ 10 real pairs with both outcomes.
- `predict_proba` → fail probability → **Low < 0.25 ≤ Moderate ≤ 0.60 < High**.

### 6.4 Learning from real demo data
Each completed session yields a real labelled pair: *(feature snapshot before the session, did the session fail?)*. The admin's **Retrain models** button refits on synthetic + real pairs (real pairs weighted ×5), saves a new version, and shows before/after metrics. Predictions always record which model version produced them.

---

## 7. Adaptive training

Run after every completed session, using the newest prediction and features.

**Recommendations (stored with a human-readable reason):**
1. **Weakest vector:** the vector with the highest VSER (needs ≥ 2 emails of that vector seen). Assign that vector's module at the user's current level for it. *Reason example: "You compromised 3 of 4 URL-spoofing emails."*
2. **Profile module:**
   - Impulsive Clickers → *Pause and Inspect: reading links before you click*
   - Passive Ignorers → *Why reporting matters and how to do it*
   - High-Risk Repeaters → remedial module for the repeated vector at level 1
   - Vigilant Verifiers → advanced module (spear-phishing / impersonation, level 3)
3. **High risk** additionally gets a mandatory quiz before the next simulation unlocks.

No duplicate open assignments; finished ones are kept for history.

**Difficulty control (per user, per vector, level 1–3):**
- Session accuracy on a vector ≥ 80 % → level + 1; ≤ 40 % → level − 1; otherwise unchanged.
- Next session = 8 emails: 5 phishing + 3 legitimate. Phishing slots: 2 from the weakest vector, 3 spread over the others; each drawn at that vector's level, avoiding emails the user has already seen when possible.
- Baseline session: 12 emails — 2 phishing per vector (levels 1 and 2) + 4 genuine, identical for every user so baselines are comparable. *(Changed in Module 2: with only 5 phishing emails no more than one vector could reach the 2-email minimum, so the first adaptive session could only ever target URL spoofing.)*
- Candidate ranking for each slot: (times already seen by this user, distance from the wanted level, random). Unseen emails therefore win over an exact level match once the catalogue at that level is used up.

**Implementation notes (Module 4)**
- `services/pipeline.complete_session` runs finish → level update → prediction → assignments in one transaction.
- Repeater remedial target = the vector with errors in the most sessions (`features.repeated_vectors`), falling back to the weakest vector. Duplicate (topic, level) recommendations are merged; an existing open assignment is upgraded to mandatory rather than duplicated. A completed module can be assigned again if the weakness returns.
- Reasons quote the evidence, e.g. *"You fell for 2 of 2 URL-spoofing emails in your last session. Required before your next simulation: predicted risk is high (99% chance of failing it)."*
- **Observed behaviour of the rolling window** (two-user trace): after a fully impulsive baseline, a user who then behaves perfectly stays High for two sessions (99% → 94% → 91%) and drops to Low (16%) at the fourth session, when the baseline leaves the 3-session window. When the user clicks nothing, the click-based features (HCR, FCR) are computed only from the old clicks, which adds to this lag. **Decision (after Module 4): kept as designed.** One good session does not cancel out a history of blind clicks; the write-up should explain the step change at the window boundary rather than presenting it as gradual improvement. Recency weighting was considered and not adopted.

## 8. Quiz

- Each module ends with 5 questions from that vector/level: "phishing or legitimate?" email snippets, "which URL is genuine?", and "spot the red flag".
- Instant feedback after every answer with the explanation of *why* and how to spot similar attacks.
- Score ≥ 70 % completes the assignment; otherwise it stays open and can be retried with different questions.
- Selection ranks the topic's questions by (already answered correctly, distance from module level, times seen, random), so a retry brings unseen questions plus the ones answered wrongly. Each answer is stored immediately with its attempt number; the best score is kept on the assignment.

---

## 9. Screens

**Login / Register** — username, name, department (dropdown), password; role is trainee (admins are created by the seed script).

**Trainee**
| Page | Content |
|---|---|
| Dashboard | risk gauge (probability), profile badge, sessions completed, CR, RA, open training, "Start next simulation" |
| Inbox | simulated mail client (§4) |
| Session results | per-email review: your action, correct action, red flags |
| Analytics | behaviour features with plain-language meaning, per-vector error bars |
| Training | assigned modules with reasons, lesson view, start quiz |
| Quiz | one question at a time, instant feedback |
| Progress | risk probability over sessions, CR/RA over sessions, level per vector |

**Admin**
| Tab | Content |
|---|---|
| Overview | total users, sessions, risk distribution (Low/Moderate/High), training completion |
| Users | sortable table: department, profile, risk, CR, RA, last session; drill-down to that user's charts |
| Behaviour | cluster scatter (PCA to 2-D) coloured by profile, most common mistakes by vector |
| Departments | mean risk and error rate per department |
| Model | current version, CV metrics, confusion matrix, feature importances, silhouette, **Retrain** button |
| Reports | export users/sessions CSV, export summary PDF |

---

**Implementation notes (Module 5)**
- `services/facade.py` is the only thing the GUI calls. Each function takes a `Session` plus ids, runs in one transaction and returns frozen dataclasses. ORM objects never cross a transaction boundary in the GUI, ownership is checked on every call, and everything the screens show is testable without Qt.
- Inbox events are committed one by one as they happen. A running hover is stored before the click that ends it, and hovers after a decision are not tracked.
- Slow work (finishing a session; model training on first use) runs on a worker thread behind a busy dialog. Results return through slots of a QObject on the GUI thread (a bare lambda would run on the worker thread).
- Content is synced on every launch (`seed_content` is idempotent). Trainees self-register; admins come from the seed script.
- Run: `python -m phishsense`. Tests drive the real widgets on Qt's offscreen platform.

**Implementation notes (Module 6)**
- Admin screens (sidebar): Overview, Users (search, sample filter, sortable, double-click → the trainee's own Progress view plus training history), Behaviour (PCA map of the K-Means space with centroids, error rate per attack type, emails most often fallen for), Departments, Models and data (versions, CV metrics, risk-band check, feature importances, **Retrain** with optional re-scoring, sample-data controls), Reports (users CSV, sessions CSV, 4-page PDF). Data comes from `services/admin.py` (Qt-free, admin-only) and `services/reports.py`.
- **Retrain** trains new versions on synthetic data plus all real pairs. With re-scoring, every assessed trainee gets a new prediction from the new models; old predictions stay in the history. Training assignments are not rewritten; the next completed session uses the new models.
- **Sample data** (`services/sample_data.py`, also `python -m phishsense.services.sample_data`): trainees driven by the synthetic persona model (`synthetic.decide`, shared so synthetic rows and sample users behave alike) through the real inbox events, pipeline and quizzes, spread over past weeks. They are flagged `users.is_sample`, shown as sample everywhere, have random unusable passwords, and are removed with one action. Persona mix is allocated exactly (largest remainder), because a random draw skewed badly at 24 users. The "Improving" persona also slows down and hovers more each session; it typically passes through *High-Risk Repeater* while its early mistakes are still in the 3-session window. 24 users ≈ 80 sessions in about 5 s.
- **Schema upgrades:** `init_db` adds missing columns that are nullable or have a server default (`ALTER TABLE ... ADD COLUMN`). Anything else raises `SchemaError` with instructions instead of guessing. Tested on a copy of a real database.

## 10. Safety

- No network code in the project. Links are data; `QTextBrowser` link-opening is disabled.
- No password fields inside simulated content; the "landing page" is an in-app teaching panel.
- Fictional organisations and domains only.
- App passwords stored as bcrypt hashes; the database is local to the machine.

---

## 11. Testing strategy

- **Unit tests** per service: feature formulas on hand-computed event fixtures; cluster naming on constructed centroids; risk thresholds at 0.25 / 0.60 boundaries; difficulty transitions; recommendation rules; auth (hashing, duplicate username, wrong password).
- **End-to-end scenario test** (no GUI) reproducing the demo script: User A clicks quickly without hovering; User B hovers, inspects senders and reports. Assert: A's risk > B's, A is an Impulsive Clicker or High-Risk Repeater, A gets URL training, B gets the advanced module, and both next sessions differ in composition/difficulty.
- **Manual GUI checklist** in the README for the demo walk-through.

---

## 12. Build plan (each module stops for your review)

| # | Module | Deliverable you can check |
|---|---|---|
| 1 | Foundation: layout, config, DB models, seed content, auth | `pytest` passes; seed creates DB with ~30 emails, modules, questions |
| 2 | Simulation, tracking, features | service-level session run produces correct features in tests |
| 3 | ML: synthetic data, K-Means, Random Forest, registry | trained models + printed CV metrics |
| 4 | Adaptive training + quiz + e2e scenario test | the two-user scenario test passes |
| 5 | Trainee desktop UI | app launches; full trainee loop works by hand |
| 6 | Admin UI, retraining, reports | charts, CSV/PDF export, retrain |
| 7 | README (VS Code setup, run, demo script), final pass | fresh-venv install works |

---

**Status (2026-11-14): all seven modules built.** Setup, running and the demonstration are in `README.md`.

## 13. Decisions to confirm

1. App name **PhishSense** (change freely).
2. Python **3.12** for the virtual environment (3.14 is installed too, but 3.12 has the most reliable wheels for PySide6 and scikit-learn).
3. Rolling window of **3 sessions** for features; session size **8 emails (5 phishing / 3 legitimate)**.
4. "Failed session" = at least one phishing link click or attachment open.
5. Feedback: immediate teachable moment on a compromise, full review at session end.
