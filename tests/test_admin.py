"""Admin analytics, retraining, sample data and reports.

Scenario: alice (Finance) clicks everything in the baseline, bob (Engineering)
inspects and reports everything, carol (IT) has registered but not played.
Every expected number below follows from that by hand.
"""

from __future__ import annotations

import sqlite3

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.db import create_db_engine, init_db
from phishsense.data.models import BehaviourEvent, MLPrediction, User
from phishsense.data.seed import ensure_admin, seed_content
from phishsense.services import admin, auth, pipeline, reports, sample_data, simulation
from phishsense.services.admin import AdminError
from tests.helpers import Clock, make_trainee, play_impulsive, play_vigilant


@pytest.fixture
def world(db, ml_env):
    seed_content(db)
    boss = ensure_admin(db, username="root", password="admin-pass1")
    clock = Clock()
    alice = make_trainee(db, "alice", department="Finance")
    bob = make_trainee(db, "bob", department="Engineering")
    carol = make_trainee(db, "carol", department="IT")
    for user, play in [(alice, play_impulsive), (bob, play_vigilant)]:
        sim = simulation.start_session(db, user)
        play(db, sim, clock)
        pipeline.complete_session(db, sim, now=clock(1000))
    return db, boss, alice, bob, carol


def test_only_admins(world):
    db, boss, alice, *_ = world
    for fn in (admin.overview, admin.users_table, admin.departments, admin.mistakes,
               admin.cluster_map, admin.model_info, admin.remove_sample_users):
        with pytest.raises(AdminError):
            fn(db, alice.id)
    with pytest.raises(AdminError):
        admin.overview(db, 999_999)
    with pytest.raises(AdminError):
        reports.sessions_frame(db, alice.id)


def test_overview(world):
    db, boss, *_ = world
    o = admin.overview(db, boss.id)
    assert (o.trainees, o.sample_trainees, o.assessed) == (3, 0, 2)
    assert (o.sessions_completed, o.sessions_failed) == (2, 1)
    assert o.risk_counts == {"Low": 1, "Moderate": 0, "High": 1}
    assert o.profile_counts[config.PROFILE_IMPULSIVE] == 1
    assert o.profile_counts[config.PROFILE_VIGILANT] == 1
    # alice: URL L1 (required) + pause; bob: advanced impersonation
    assert (o.training_assigned, o.training_completed, o.required_open) == (3, 0, 1)
    assert o.mean_click_rate == pytest.approx(0.5)            # (1.0 + 0.0) / 2
    assert o.mean_report_accuracy == pytest.approx(0.5)
    assert o.quiz_answers == 0 and o.quiz_correct_rate is None


def test_users_table(world):
    db, boss, alice, bob, carol = world
    rows = {r.username: r for r in admin.users_table(db, boss.id)}
    assert set(rows) == {"alice", "bob", "carol"}              # admins are not listed
    assert rows["alice"].risk_level == "High" and rows["bob"].risk_level == "Low"
    assert rows["alice"].probability > rows["bob"].probability
    assert (rows["alice"].click_rate, rows["bob"].report_accuracy) == (1.0, 1.0)
    assert rows["carol"].profile is None and rows["carol"].sessions == 0
    assert (rows["alice"].training_open, rows["bob"].training_open) == (2, 1)
    detail = admin.user_detail(db, boss.id, alice.id)
    assert len(detail.progress.points) == 1 and len(detail.training) == 2


def test_departments(world):
    db, boss, *_ = world
    d = {r.department: r for r in admin.departments(db, boss.id)}
    assert set(d) == {"Finance", "Engineering", "IT"}           # empty departments omitted
    assert (d["Finance"].phishing_seen, d["Finance"].errors, d["Finance"].error_rate) == (8, 8, 1.0)
    assert d["Finance"].high_risk == 1
    assert (d["Engineering"].error_rate, d["Engineering"].report_rate) == (0.0, 1.0)
    assert d["IT"].assessed == 0 and d["IT"].mean_probability is None
    assert d["IT"].error_rate is None


def test_mistakes(world):
    db, boss, *_ = world
    m = admin.mistakes(db, boss.id)
    for v in m.by_vector:                 # 2 per vector per user; alice errs, bob reports
        assert (v.shown, v.errors, v.reported, v.ignored) == (4, 2, 2, 0)
        assert v.error_rate == 0.5
    assert len(m.top_emails) == 8
    assert all((e.errors, e.shown) == (1, 2) for e in m.top_emails)


def test_cluster_map(world):
    db, boss, *_ = world
    cmap = admin.cluster_map(db, boss.id)
    assert len(cmap.points) == 2 and len(cmap.centroids) == 4
    assert {p.profile for p in cmap.points} == {config.PROFILE_IMPULSIVE, config.PROFILE_VIGILANT}
    assert {c[0] for c in cmap.centroids} == set(config.PROFILES)
    assert 0 < sum(cmap.explained_variance) <= 1


def test_model_info_and_retrain_rescores(world):
    db, boss, alice, bob, _ = world
    info = admin.model_info(db, boss.id)
    assert info.kmeans.version == info.random_forest.version == 1
    assert len(info.history) == 2 and info.real_pairs_available == 0

    result = admin.retrain(db, boss.id)
    assert (result.kmeans_version, result.rf_version, result.rescored_users) == (2, 2, 2)
    info = admin.model_info(db, boss.id)
    assert info.random_forest.version == 2 and len(info.history) == 4
    latest = {r.username: r for r in admin.users_table(db, boss.id)}
    assert latest["alice"].risk_level == "High"
    preds = db.scalars(select(MLPrediction).where(MLPrediction.user_id == alice.id)).all()
    assert len(preds) == 2 and preds[-1].rf_version_id == info.random_forest.id


# ------------------------------------------------------------- sample data
def test_sample_users_play_real_sessions_and_can_be_removed(world):
    db, boss, alice, bob, carol = world
    summary = admin.generate_sample_users(db, boss.id, 6, seed=3)
    assert summary.users == 6 and summary.sessions >= 6
    samples = db.scalars(select(User).where(User.is_sample.is_(True))).all()
    assert len(samples) == 6
    assert all(u.username.startswith("sample.") for u in samples)
    assert all(u.sessions and all(s.is_complete for s in u.sessions) for u in samples)
    with pytest.raises(auth.AuthError):          # nobody knows their passwords
        auth.authenticate(db, samples[0].username, "secret123")

    # events are ordered like a real person's: open first, decision last
    for sim in samples[0].sessions:
        for d in sim.deliveries:
            evs = sorted((e for e in sim.events if e.email_id == d.email_id),
                         key=lambda e: (e.ts, e.id))
            if evs:
                assert evs[0].event_type == config.EVENT_OPEN

    o = admin.overview(db, boss.id)
    assert o.sample_trainees == 6 and o.trainees == 9
    assert len({r.profile for r in admin.users_table(db, boss.id) if r.profile}) >= 2

    assert admin.remove_sample_users(db, boss.id) == 6
    remaining = {u.username for u in db.scalars(select(User))}
    assert remaining == {"root", "alice", "bob", "carol"}
    assert db.scalars(select(BehaviourEvent).where(
        BehaviourEvent.session_id.not_in([s.id for s in alice.sessions + bob.sessions]))).all() == []


def test_sample_count_validated(world):
    db, boss, *_ = world
    with pytest.raises(AdminError):
        admin.generate_sample_users(db, boss.id, 0)


# ----------------------------------------------------------------- reports
def test_reports(world, tmp_path):
    db, boss, *_ = world
    users = reports.users_frame(db, boss.id)
    assert list(users.columns)[:4] == ["username", "full_name", "department", "sample_user"]
    assert len(users) == 3
    sessions = reports.sessions_frame(db, boss.id)
    assert len(sessions) == 2
    alice_row = sessions[sessions.username == "alice"].iloc[0]
    assert (alice_row.phishing, alice_row.phishing_clicked, alice_row.failed) == (8, 8, True)
    assert alice_row.risk_after == "High"

    csv_path = reports.write_csv(sessions, tmp_path / "out" / "sessions.csv")
    assert csv_path.read_text().splitlines()[0].startswith("session_id,username")
    pdf = reports.write_pdf(db, boss.id, tmp_path / "summary.pdf")
    data = pdf.read_bytes()
    assert data.startswith(b"%PDF") and data.count(b"/Type /Page") >= 4


# --------------------------------------------------------------- migration
def test_missing_column_is_added_to_existing_database(tmp_path):
    path = tmp_path / "old.db"
    engine = create_db_engine(f"sqlite:///{path}")
    init_db(engine)
    engine.dispose()
    # Recreate the users table as it was before is_sample existed.
    con = sqlite3.connect(path)
    con.executescript("""
        PRAGMA foreign_keys=OFF;
        CREATE TABLE users_old AS SELECT id, username, full_name, department, role,
            password_hash, is_active, created_at FROM users;
        DROP TABLE users;
        ALTER TABLE users_old RENAME TO users;
        INSERT INTO users VALUES (1, 'old', 'Old User', 'IT', 'trainee', 'x', 1, '2026-01-01');
    """)
    con.commit()
    con.close()

    engine = create_db_engine(f"sqlite:///{path}")
    assert init_db(engine) == ["users.is_sample"]
    assert init_db(engine) == []                       # idempotent
    engine.dispose()
    con = sqlite3.connect(path)
    assert con.execute("select username, is_sample from users").fetchall() == [("old", 0)]
    con.close()
