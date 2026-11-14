"""Schema constraints and the seed script."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from phishsense import config
from phishsense.data import content, seed
from phishsense.data.db import create_db_engine, init_db, make_session_factory
from phishsense.data.models import (
    BehaviourEvent,
    Email,
    QuizQuestion,
    SessionEmail,
    SimulationSession,
    TrainingModule,
    User,
    UserVectorLevel,
)
from phishsense.services import auth


def count(db, model) -> int:
    return db.scalar(select(func.count()).select_from(model))


def make_user(db, username="alice") -> User:
    return auth.register_user(
        db, username=username, full_name="Alice Example", department="IT", password="secret123"
    )


# ------------------------------------------------------------ constraints
def _email(**overrides) -> Email:
    fields = dict(
        code="x", category=config.VECTOR_URGENCY, is_phishing=True, difficulty=1,
        sender_name="s", sender_address="a@b.c", subject="s", body="b",
        link_url="https://x.test", link_text="x", indicators=[],
    )
    return Email(**{**fields, **overrides})


@pytest.mark.parametrize(
    "overrides",
    [
        dict(category="spam"),
        dict(difficulty=4),
        dict(is_phishing=False),                        # urgency email must be phishing
        dict(category=config.CATEGORY_LEGITIMATE),      # legitimate email must not be
        dict(link_url=None, link_text=None),            # phishing needs a payload
    ],
)
def test_email_constraints(db, overrides):
    db.add(_email(**overrides))
    with pytest.raises(IntegrityError):
        db.flush()


def test_valid_email_accepted(db):
    db.add(_email())
    db.flush()


def test_user_role_and_department_constraints(db):
    db.add(User(username="x1", full_name="X", department="IT", role="root", password_hash="h"))
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    db.add(User(username="x2", full_name="X", department="Moon", role="trainee", password_hash="h"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_foreign_keys_enforced(db):
    db.add(SessionEmail(session_id=999, email_id=999, position=0))
    with pytest.raises(IntegrityError):
        db.flush()


def test_vector_level_bounds(db):
    user = make_user(db)
    db.add(UserVectorLevel(user_id=user.id, vector=config.VECTOR_URGENCY, level=config.MAX_LEVEL + 1))
    with pytest.raises(IntegrityError):
        db.flush()


def test_event_type_constraint(db):
    seed.seed_content(db)
    user = make_user(db)
    sim = SimulationSession(user_id=user.id, kind=config.SESSION_KIND_BASELINE)
    db.add(sim)
    db.flush()
    email_id = db.scalar(select(Email.id).limit(1))
    db.add(BehaviourEvent(session_id=sim.id, email_id=email_id, event_type="teleport"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_deleting_user_cascades_to_sessions(db):
    seed.seed_content(db)
    user = make_user(db)
    sim = SimulationSession(user_id=user.id, kind=config.SESSION_KIND_BASELINE)
    db.add(sim)
    db.flush()
    email_id = db.scalar(select(Email.id).limit(1))
    db.add(BehaviourEvent(session_id=sim.id, email_id=email_id, event_type=config.EVENT_OPEN))
    db.flush()
    db.delete(user)
    db.flush()
    assert count(db, SimulationSession) == 0
    assert count(db, BehaviourEvent) == 0
    assert count(db, Email) == len(content.EMAILS)  # catalogue untouched


# ------------------------------------------------------------------- seed
def test_seed_loads_all_content(db):
    results = seed.seed_content(db)
    assert results["emails"].inserted == len(content.EMAILS)
    assert count(db, Email) == len(content.EMAILS)
    assert count(db, TrainingModule) == len(content.MODULES)
    assert count(db, QuizQuestion) == len(content.QUESTIONS)
    phishing = db.scalar(select(func.count()).where(Email.is_phishing))
    assert phishing == sum(1 for e in content.EMAILS if e["category"] != "legitimate")


def test_seed_is_idempotent(db):
    seed.seed_content(db)
    again = seed.seed_content(db)
    for result in again.values():
        assert result.inserted == 0 and result.updated == 0
    assert count(db, Email) == len(content.EMAILS)


def test_seed_updates_changed_content_without_changing_ids(db, monkeypatch):
    seed.seed_content(db)
    original = db.scalar(select(Email).where(Email.code == "leg-1-canteen"))
    original_id = original.id

    edited = [dict(e) for e in content.EMAILS]
    next(e for e in edited if e["code"] == "leg-1-canteen")["subject"] = "New subject"
    monkeypatch.setattr(content, "EMAILS", edited)

    result = seed.seed_content(db)["emails"]
    assert result.updated == 1 and result.inserted == 0
    row = db.scalar(select(Email).where(Email.code == "leg-1-canteen"))
    assert row.id == original_id and row.subject == "New subject"


def test_ensure_admin_creates_once(db):
    admin = seed.ensure_admin(db, username="admin", password="admin-pass1")
    assert admin is not None and admin.is_admin
    assert seed.ensure_admin(db, username="admin2", password="admin-pass1") is None
    assert db.scalar(select(func.count()).where(User.role == config.ROLE_ADMIN)) == 1


def test_seed_main_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")

    assert seed.main(["--admin-password", "admin-pass1"]) == 0
    assert (tmp_path / "test.db").exists()
    # Second run: no prompt needed because the admin exists.
    assert seed.main([]) == 0
    # An invalid admin password is rejected before anything is touched,
    # so even --reset does not delete the existing database.
    assert seed.main(["--reset", "--admin-password", "weak"]) == 1
    assert (tmp_path / "test.db").exists()
    # An invalid admin username rolls back the whole seed transaction.
    assert seed.main(["--reset", "--admin-username", "x", "--admin-password", "admin-pass1"]) == 1
    engine = create_db_engine()
    init_db(engine)
    with make_session_factory(engine)() as s:
        assert count(s, Email) == 0
    engine.dispose()
