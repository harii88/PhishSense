from __future__ import annotations

import pytest
from sqlalchemy import select

from phishsense import config
from phishsense.data.models import BehaviourEvent, Email, QuizQuestion
from phishsense.data.seed import seed_content
from phishsense.services import facade
from phishsense.services.auth import AuthError
from phishsense.services.quiz import QuizError
from phishsense.services.simulation import SimulationError


@pytest.fixture
def db_seeded(db):
    seed_content(db)
    return db


def new_user(db, name="alice"):
    return facade.register(db, username=name, full_name=f"{name.title()} Example",
                           department="Finance", password="secret123")


def act_all(db, user, view, event_for):
    for email in view.emails:
        facade.record_event(db, user.id, view.id, email.id, config.EVENT_OPEN)
        event = event_for(email)
        if event:
            facade.record_event(db, user.id, view.id, email.id, event)


def impulsive(email):
    return config.EVENT_LINK_CLICK if email.link_url else (
        config.EVENT_ATTACHMENT_OPEN if email.attachment_name else None)


def test_register_login_and_profile(db):
    user = new_user(db)
    assert not user.is_admin and user.username == "alice"
    assert facade.login(db, "ALICE", "secret123") == user
    with pytest.raises(AuthError):
        facade.login(db, "alice", "wrong-pass1")
    updated = facade.update_profile(db, user.id, full_name="Alice B", department="IT")
    assert (updated.full_name, updated.department) == ("Alice B", "IT")
    facade.change_password(db, user.id, "secret123", "better-pass2")
    assert facade.login(db, "alice", "better-pass2").id == user.id


def test_dashboard_for_new_user(db_seeded):
    user = new_user(db_seeded)
    d = facade.dashboard(db_seeded, user.id)
    assert d.sessions_completed == 0 and d.prediction is None
    assert d.click_rate is None and d.open_training == 0 and not d.required_training
    assert d.next_session_kind == config.SESSION_KIND_BASELINE and not d.has_open_session
    assert d.levels == {v: 1 for v in config.VECTORS}


def test_inbox_view_renders_links_and_resumes(db_seeded):
    user = new_user(db_seeded)
    view = facade.start_or_resume(db_seeded, user.id)
    assert len(view.emails) == len(set(e.id for e in view.emails)) == 12
    for e in view.emails:
        assert "{link}" not in e.body_html
        if e.link_url:
            assert f'href="{e.link_url}"' in e.body_html
    first = view.emails[0]
    facade.record_event(db_seeded, user.id, view.id, first.id, config.EVENT_OPEN)
    facade.record_event(db_seeded, user.id, view.id, first.id, config.EVENT_MARK_SAFE)

    resumed = facade.start_or_resume(db_seeded, user.id)
    assert resumed.id == view.id and resumed.handled == 1
    assert resumed.emails[0].opened and resumed.emails[0].decision == config.DECISION_MARKED_SAFE
    assert facade.dashboard(db_seeded, user.id).has_open_session


def test_render_body_escapes_link_text():
    email = Email(body="<p>{link}</p>", link_text='<b>"click"</b>', link_url='https://x.test/?a=1&b="2"')
    out = facade.render_body(email)
    assert "&lt;b&gt;" in out and 'href="https://x.test/?a=1&amp;b=&quot;2&quot;"' in out


def test_users_cannot_touch_each_others_sessions(db_seeded):
    alice, bob = new_user(db_seeded, "alice"), new_user(db_seeded, "bob")
    view = facade.start_or_resume(db_seeded, alice.id)
    with pytest.raises(SimulationError, match="does not belong"):
        facade.record_event(db_seeded, bob.id, view.id, view.emails[0].id, config.EVENT_OPEN)
    with pytest.raises(SimulationError, match="does not belong"):
        facade.complete(db_seeded, bob.id, view.id)
    assert db_seeded.scalars(select(BehaviourEvent)).all() == []


def test_complete_training_quiz_and_progress(db_seeded, ml_env):
    user = new_user(db_seeded)
    view = facade.start_or_resume(db_seeded, user.id)
    act_all(db_seeded, user, view, impulsive)
    result = facade.complete(db_seeded, user.id, view.id)

    assert result.failed and result.kind == config.SESSION_KIND_BASELINE
    assert [r.position for r in result.rows] == list(range(12))
    assert result.phishing_total == 8 and result.phishing_compromised == 8
    assert result.prediction.risk_level == config.RISK_HIGH
    assert any(a.mandatory for a in result.new_training)
    assert all(r.indicators for r in result.rows)

    d = facade.dashboard(db_seeded, user.id)
    assert d.sessions_completed == 1 and d.prediction.risk_level == config.RISK_HIGH
    assert d.click_rate == 1.0 and d.required_training

    items = facade.training_list(db_seeded, user.id)
    required = items[0]
    assert required.mandatory and not required.completed      # required listed first
    quiz_view = facade.start_quiz(db_seeded, user.id, required.id)
    assert len(quiz_view.questions) == config.QUIZ_LENGTH
    for q in quiz_view.questions:
        right = db_seeded.get(QuizQuestion, q.id).correct_index
        feedback = facade.answer_question(db_seeded, user.id, quiz_view, q.id, right, 3000)
        assert feedback.correct and feedback.explanation
    assert facade.finish_quiz(db_seeded, user.id, quiz_view).passed

    after = {t.id: t for t in facade.training_list(db_seeded, user.id)}
    assert after[required.id].completed and after[required.id].quiz_score == 1.0
    assert list(after.values())[-1].id == required.id            # completed listed last
    assert not facade.dashboard(db_seeded, user.id).required_training

    progress = facade.progress(db_seeded, user.id)
    assert len(progress.points) == 1
    point = progress.latest
    assert point.probability == pytest.approx(result.prediction.probability)
    assert point.profile == result.prediction.profile and point.failed
    assert set(point.features) >= {"click_rate", "repeat_error_measure"}


def test_quiz_ownership(db_seeded, ml_env):
    alice, bob = new_user(db_seeded, "alice"), new_user(db_seeded, "bob")
    view = facade.start_or_resume(db_seeded, alice.id)
    act_all(db_seeded, alice, view, impulsive)
    facade.complete(db_seeded, alice.id, view.id)
    assignment = facade.training_list(db_seeded, alice.id)[0]
    with pytest.raises(QuizError, match="not assigned to you"):
        facade.start_quiz(db_seeded, bob.id, assignment.id)
