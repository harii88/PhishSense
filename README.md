# PhishSense

**Behaviour-Driven Adaptive Phishing Training Using Machine Learning** — a desktop application (Windows, Python, PySide6).

Trainees work through a simulated email inbox. The app records *how* they behave — whether they hover over links before clicking, check who really sent an email, how fast they decide, what they report — and turns that behaviour into twelve measurements. A **K-Means** model groups each trainee into one of four behaviour profiles and a **Random Forest** predicts the chance they will fail their next simulation. From that, the app assigns personalised training with quizzes and adjusts the difficulty of the next inbox. Every completed session updates the measurements, the predictions and the training plan.

> **About the numbers.** The models start from *synthetic* behaviour data (simulated people) and then also learn from sessions recorded in this installation. Every metric the app shows describes this installation. None of it reproduces or replaces the results of the research paper's 120-participant study.

> **Safety.** No real email is sent and nothing leaves the computer. Links in simulated emails are never opened — hovering shows where they would go; clicking shows a teaching screen. All organisations and domains are fictional.

---

## Contents

1. [Requirements](#1-requirements)
2. [Setup in VS Code](#2-setup-in-vs-code)
3. [First run](#3-first-run)
4. [Demonstration script](#4-demonstration-script)
5. [Tests](#5-tests)
6. [Command reference](#6-command-reference)
7. [How it works](#7-how-it-works)
8. [Project structure](#8-project-structure)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Requirements

| | |
|---|---|
| Operating system | Windows 10 or 11 |
| Python | **3.12** (tested). 3.11 should work. Newer versions are untested. |
| Editor | Visual Studio Code with the **Python** extension (Microsoft) |
| Disk | about 1 GB for the virtual environment (mostly Qt) |

Check Python from a terminal:

```bash
py -3.12 --version
```

If that fails, install Python 3.12 from python.org and tick **"Add python.exe to PATH"**.

**Keep the project folder at a short path**, for example `C:\Projects\phishsense`. Windows limits file paths to 260 characters by default, and some compiled library files inside the virtual environment fail to load when the project sits deep inside other folders (see [Troubleshooting](#9-troubleshooting)).

## 2. Setup in VS Code

1. **Open the folder.** VS Code → *File → Open Folder…* → select the project folder (the one containing `README.md`).
2. **Open a terminal.** *Terminal → New Terminal*. The commands below run in that terminal, from the project folder.
3. **Create a virtual environment** in a folder named `.venv`:

   ```bash
   py -3.12 -m venv .venv
   ```

4. **Install the dependencies:**

   ```bash
   .venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

   This is a large download (mostly Qt) and takes a few minutes. `requirements-lock.txt` lists the exact versions the project was tested with; use it instead (`-r requirements-lock.txt`) if a newer release ever breaks something.

5. **Select the interpreter.** Press `Ctrl+Shift+P` → *Python: Select Interpreter* → choose the one under `.venv`. (The included `.vscode/settings.json` already points VS Code at it.) New terminals will now activate it automatically.

6. **Check the installation** by running the test suite:

   ```bash
   .venv\Scripts\python.exe -m pytest
   ```

   Expected: `371 passed` in under a minute.

## 3. First run

**a) Create the administrator account** (once). You will be asked to choose the admin password:

```bash
.venv\Scripts\python.exe -m phishsense.data.seed
```

This creates the database in `instance\phishsense.db`, loads the training content (34 emails, 14 lessons, 42 quiz questions) and creates the user `admin`.

**b) Start the application:**

```bash
.venv\Scripts\python.exe -m phishsense
```

Or in VS Code: *Run and Debug* (`Ctrl+Shift+D`) → choose **PhishSense app** → ▶.

**c) Trainees register themselves** on the *Create account* tab of the sign-in window. Admins sign in with `admin` and the password from step a.

The first time a trainee finishes a simulation, the models train themselves (about 10 seconds, shown with a progress dialog).

## 4. Demonstration script

This follows the project's ten-step demonstration. Allow about 15 minutes.

| Step | What to do | What to point out |
|---|---|---|
| 1 | Register **User A** and **User B** (*Create account* tab). Use *Log out* in the sidebar to switch users. | Department selection; password rules. |
| 2 | Each user: *Simulated inbox* → *Start baseline*. | Everyone gets the same 12-email baseline, so results are comparable. |
| 3 | **User A:** open emails and click the links and attachments straight away. **User B:** hover over every link and read the status line under the email, click *details ▾* to see the real sender, then *Report phishing* or *Mark as safe*. | Hovering reveals the real destination: for example the link text says `portal.corvane.com/password` but the status line shows `portal.corvane.com.reset-account.info`. Clicking a phishing link shows a teaching screen; nothing is opened. |
| 4 | Each user clicks *Finish session*. | Every interaction was stored as it happened (open, sender check, hover with duration, click, report). |
| 5–7 | Read the *Session review*. | Per-email results with red flags; the **K-Means profile** (A: *Impulsive Clickers*, B: *Vigilant Verifiers*) and the **Random Forest risk** (A: High, B: Low) with the probability. |
| 8 | Open *Training* for each user. | A gets **required** URL training plus *Pause and inspect*, with the reason quoted ("You fell for 2 of 2 URL-spoofing emails…"). B gets advanced *impersonation* training. A cannot start another simulation until the required quiz is passed. |
| 9 | User A: take the quiz (instant feedback, 70 % to pass). Then both users start their next simulation. | A's inbox has two URL-spoofing emails, mostly at level 1; B's is harder (levels 2–3). |
| 10 | Finish the sessions, then open *Dashboard* and *Progress*. | Risk, click rate, report accuracy and difficulty levels update after every session. |

**Admin view.** Sign in as `admin`. To give the dashboard more than two users, go to *Models and data* → *Generate sample users* (24 is a good number). Then walk through:

- *Overview* — risk and profile distribution, training completion.
- *Users* — sortable table; double-click a trainee for their charts and training history.
- *Behaviour* — the K-Means map (each dot a trainee, X marks a cluster centre), error rate per attack type, emails most often fallen for.
- *Departments* — risk and error rates per department.
- *Models and data* — model versions, cross-validated metrics, feature importances; **Retrain models** to learn from the recorded sessions.
- *Reports* — export the users/sessions CSV and the PDF summary.

Sample users are labelled *sample* everywhere, cannot sign in, and are removed with *Remove sample users*.

**Points to explain to evaluators**

- *Improving trainees change profile with a delay.* Measurements use the last three sessions, so a trainee who starts behaving well keeps a High risk for one or two sessions until the old mistakes leave the window (a deliberate design choice; see `DESIGN.md` §7). In the sample data, improving trainees often appear as *High-Risk Repeaters* during this phase.
- *Profile and risk are different questions.* The profile describes behaviour style (K-Means); the risk is the predicted chance of failing the next simulation (Random Forest). A careful trainee who still made several mistakes can be a *Repeater* with Low risk.

## 5. Tests

```bash
.venv\Scripts\python.exe -m pytest
```

Or in VS Code: the *Testing* panel (flask icon) discovers the tests automatically.

| File | Covers |
|---|---|
| `test_content.py` | Every phishing email has a detectable cue (bad sender domain, bad link domain or dangerous attachment); no genuine email has one; lessons and quizzes cover every topic and level. |
| `test_auth.py`, `test_data_layer.py` | Registration, password hashing, login, database constraints, seeding, schema upgrades. |
| `test_tracking.py`, `test_features.py` | Event rules, outcome derivation, every feature formula against hand-computed values. |
| `test_simulation.py`, `test_adaptive.py`, `test_quiz.py` | Inbox composition, difficulty levels, training recommendations, quizzes. |
| `test_ml.py` | Synthetic data, K-Means profile naming, Random Forest, risk thresholds, model versioning. |
| `test_scenario.py` | The two-user demonstration above, end to end. |
| `test_facade.py`, `test_admin.py` | Everything the screens display, permissions, reports, sample data. |
| `test_ui.py` | The real windows on Qt's off-screen platform: event order (hover saved before click), links never opened, background work, admin pages. |

## 6. Command reference

All commands run from the project folder.

| Command | Does |
|---|---|
| `.venv\Scripts\python.exe -m phishsense` | Start the app |
| `.venv\Scripts\python.exe -m phishsense.data.seed` | Create the database and the admin account (asks for a password); safe to re-run |
| `.venv\Scripts\python.exe -m phishsense.data.seed --reset` | **Delete all data** and start again |
| `.venv\Scripts\python.exe -m phishsense.services.ml` | Train new model versions and print their evaluation |
| `.venv\Scripts\python.exe -m phishsense.services.sample_data --users 24` | Add sample trainees |
| `.venv\Scripts\python.exe -m phishsense.services.sample_data --remove` | Remove all sample trainees |
| `.venv\Scripts\python.exe -m pytest` | Run the tests |

The *Run and Debug* panel has entries for the first five.

Data lives in `instance\` (database, trained models, exported reports). Set the environment variable `PHISHSENSE_HOME` to keep it somewhere else.

## 7. How it works

`DESIGN.md` is the full design, including every formula, threshold and the reasons behind changes made during development. In short:

**Behaviour → features.** Each email ends with one decision (clicked, reported, marked safe, ignored). Over the last three sessions the app computes: click rate, report accuracy, false-alarm rate, ignore rate, hover-to-click ratio (links inspected ≥ 1 s before clicking), fast-click rate (< 3 s without inspecting), mean decision time, error rate per attack type (four values) and repeat-error measure.

**K-Means (behaviour profile).** Four clusters on the twelve features (decision time on a log scale; the four per-type error rates count together as one feature). Clusters are named by matching their centres to written prototypes of the four profiles with the Hungarian algorithm. On synthetic data the names match the simulated behaviour type for 95 % of users.

**Random Forest (risk).** Predicts the probability of clicking at least one phishing email in the next simulation: **Low < 25 % ≤ Moderate ≤ 60 % < High**. Cross-validated ROC-AUC on synthetic data ≈ 0.88; the Models page shows that each band's observed failure rate matches its range.

**Adaptive training.** The weakest attack type gets a lesson at the trainee's level; the profile adds a behaviour lesson (*Pause and inspect*, *Why report*, back-to-basics, or advanced material); high risk makes the first lesson required. Difficulty per attack type rises at ≥ 80 % accuracy and falls at ≤ 40 %.

**Continuous learning.** Each finished session gives a real training example (*features before → did this session fail?*). *Retrain models* adds them to the synthetic data with five times the weight; every model version and the version behind every prediction are kept.

How the project's seven modules map to the code:

| Module | Code |
|---|---|
| 1 Authentication | `services/auth.py`, `ui/login.py`, account settings dialog |
| 2 Simulated email environment | `data/content/emails.py`, `services/simulation.py`, `ui/pages/inbox.py` |
| 3 Behavioural tracking | `services/tracking.py`, `services/features.py` |
| 4 Machine learning | `services/ml/` (synthetic data, clustering, risk model, registry) |
| 5 Adaptive training | `services/adaptive.py`, `services/pipeline.py`, `ui/pages/training.py` |
| 6 Interactive learning and quiz | `data/content/modules.py`, `data/content/questions.py`, `services/quiz.py` |
| 7 Admin dashboard | `services/admin.py`, `services/reports.py`, `ui/pages/admin.py` |

## 8. Project structure

```
phishsense/
  __main__.py            python -m phishsense
  config.py              every threshold and vocabulary in one place
  data/
    models.py            database tables (SQLAlchemy)
    db.py                engine, sessions, schema upgrades
    seed.py              database + content + admin account
    content/             emails, lessons, quiz questions (fictional organisations)
  services/              application logic, no GUI code
    auth.py  simulation.py  tracking.py  features.py  adaptive.py  quiz.py
    pipeline.py          what happens when a session finishes
    facade.py            everything the trainee screens call
    admin.py  reports.py  sample_data.py
    ml/                  synthetic.py  clustering.py  risk_model.py  registry.py
  ui/                    PySide6 windows, pages, dialogs, charts
tests/                   pytest suite (371 tests)
DESIGN.md                full design and decision log
requirements.txt         dependencies (version ranges)
requirements-lock.txt    exact versions tested
```

## 9. Troubleshooting

**`ImportError: DLL load failed ... The filename or extension is too long`**
The project (and so `.venv`) is too deep in the folder tree. Move the project to a short path such as `C:\Projects\phishsense`, delete `.venv` and repeat setup steps 3–4. Alternatively enable long paths in Windows (*Group Policy → Enable Win32 long paths*) — that needs administrator rights.

**`py` is not recognised** — Python is not installed or not on PATH; reinstall Python 3.12 with *Add python.exe to PATH* ticked, then open a new terminal.

**PowerShell refuses to activate the virtual environment** ("running scripts is disabled") — you do not need to activate it: every command in this README calls `.venv\Scripts\python.exe` directly.

**"Database column ... cannot be added automatically"** — the database was created by an incompatible older version. Back up `instance\phishsense.db` if you need it, then run `python -m phishsense.data.seed --reset`.

**"Model file ... is missing"** — a trained model was deleted from `instance\models`. Sign in as admin → *Models and data* → *Retrain models*.

**The first *Finish session* takes a while** — the models train on first use (about 10 s). Later sessions finish in about a second.
