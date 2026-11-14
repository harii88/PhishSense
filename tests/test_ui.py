"""GUI smoke and behaviour tests on Qt's offscreen platform (no window shown).

They drive the real widgets and check what reaches the database: event order,
hover-before-click, links never opened, worker-thread results delivered on the
GUI thread.
"""

from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QThread, QThreadPool, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QDialog
from sqlalchemy import select

from phishsense import config
from phishsense.data.db import session_scope
from phishsense.data.models import BehaviourEvent, QuizQuestion
from phishsense.data.seed import seed_content
from phishsense.services import facade
from phishsense.ui.context import AppContext
from phishsense.ui.dialogs import ConsequenceDialog, QuizDialog, ResultsDialog
from phishsense.ui.login import LoginDialog
from phishsense.ui.main_window import MainWindow
from phishsense.ui.theme import STYLE_SHEET


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(STYLE_SHEET)
    return app


@pytest.fixture
def ctx(qapp, session_factory):
    with session_scope(session_factory) as s:
        seed_content(s)
    return AppContext(session_factory)


@pytest.fixture
def trainee(ctx):
    ctx.user = ctx.call(facade.register, username="alice", full_name="Alice Example",
                        department="Finance", password="secret123")
    return ctx


def events(ctx) -> list[tuple[int, str]]:
    with session_scope(ctx.factory) as s:
        return [(e.email_id, e.event_type)
                for e in s.scalars(select(BehaviourEvent).order_by(BehaviourEvent.id))]


def wait_for_workers(qapp) -> None:
    QThreadPool.globalInstance().waitForDone(60_000)
    for _ in range(5):
        qapp.processEvents()


@pytest.fixture
def window(trainee, monkeypatch):
    win = MainWindow(trainee)
    inbox = win.page("Simulated inbox")
    inbox.consequences = []
    inbox.results = []
    monkeypatch.setattr(inbox, "show_consequence", lambda e, t: inbox.consequences.append((e, t)))
    monkeypatch.setattr(inbox, "show_results", lambda r: inbox.results.append(r))
    monkeypatch.setattr(inbox, "confirm_finish", lambda n: True)
    yield win
    win.close()


# ----------------------------------------------------------------- sign-in
def test_register_and_sign_in(ctx):
    dlg = LoginDialog(ctx)
    dlg.reg_username.setText("Bob")
    dlg.reg_full_name.setText("Bob Example")
    dlg.reg_password.setText("secret123")
    dlg.reg_confirm.setText("different1")
    dlg.register_button.click()
    assert "do not match" in dlg.error.text() and ctx.user is None
    dlg.reg_confirm.setText("secret123")
    dlg.register_button.click()
    assert dlg.result() == QDialog.DialogCode.Accepted and ctx.user.username == "bob"

    ctx.user = None
    dlg = LoginDialog(ctx)
    dlg.login_username.setText("bob")
    dlg.login_password.setText("wrong-pass1")
    dlg.sign_in_button.click()
    assert "Incorrect" in dlg.error.text() and ctx.user is None
    dlg.login_password.setText("secret123")
    dlg.sign_in_button.click()
    assert ctx.user.username == "bob"


# --------------------------------------------------------------- pages
def test_all_pages_render_for_new_trainee(window):
    for title in ["Dashboard", "Simulated inbox", "Training", "Progress"]:
        window.navigate(title)
        assert window.stack.currentWidget() is window.page(title)
    inbox = window.page("Simulated inbox")
    assert inbox.modes.currentIndex() == 0 and inbox.start_button.isEnabled()
    assert inbox.start_title.text() == "Baseline assessment"
    assert window.page("Training").empty.isVisibleTo(window.page("Training"))


@pytest.fixture
def admin_window(ctx, ml_env, monkeypatch):
    """Admin signed in, with two trainees who have played a baseline."""
    from phishsense.data.seed import ensure_admin
    for name, clicks in [("ann", True), ("ben", False)]:
        user = ctx.call(facade.register, username=name, full_name=name.title() + " T",
                        department="Finance", password="secret123")
        view = ctx.call(facade.start_or_resume, user.id)
        for e in view.emails:
            ctx.call(facade.record_event, user.id, view.id, e.id, config.EVENT_OPEN)
            event = (config.EVENT_LINK_CLICK if e.link_url else config.EVENT_ATTACHMENT_OPEN) \
                if clicks and (e.link_url or e.attachment_name) else \
                (config.EVENT_REPORT if e.is_phishing else config.EVENT_MARK_SAFE)
            ctx.call(facade.record_event, user.id, view.id, e.id, event)
        ctx.call(facade.complete, user.id, view.id)
    with session_scope(ctx.factory) as s:
        ctx.user = facade._user_info(ensure_admin(s, username="root", password="admin-pass1"))
    win = MainWindow(ctx)
    yield win
    win.close()


def test_admin_pages_render_with_data(admin_window):
    win = admin_window
    assert list(win.pages) == ["Overview", "Users", "Behaviour", "Departments",
                               "Models and data", "Reports"]
    for title in win.pages:
        win.navigate(title)
    assert win.page("Overview").trainees.value.text() == "2"
    users = win.page("Users")
    assert users.table.rowCount() == 2
    users.search.setText("ann")
    visible = [r for r in range(2) if not users.table.isRowHidden(r)]
    assert len(visible) == 1 and users.table.item(visible[0], 1).text() == "ann"
    assert win.page("Departments").table.rowCount() == 1
    assert "Version 1" in win.page("Models and data").rf_text.text()


def test_user_drill_down(admin_window, monkeypatch):
    from PySide6.QtCore import Qt

    from phishsense.ui.pages.admin import UserDetailDialog
    users = admin_window.page("Users")
    admin_window.navigate("Users")
    opened = []
    monkeypatch.setattr(users, "open_user", opened.append)
    users.table.cellDoubleClicked.emit(0, 3)
    expected = users.table.item(0, 0).data(Qt.ItemDataRole.UserRole + 1)
    assert opened == [expected]

    dlg = UserDetailDialog(admin_window.ctx, expected)
    name = users.table.item(0, 0).text()
    assert name in dlg.windowTitle()
    n_training = int(users.table.item(0, 11).text()) + int(users.table.item(0, 12).text())
    assert [dlg.tabs.tabText(i) for i in range(dlg.tabs.count())] == [
        "Progress", f"Training ({n_training})"]
    progress = dlg.tabs.widget(0)
    assert progress.table.item(0, 1).text() in {"0%", "100%"}   # click rate shown
    dlg.close()


def test_retrain_from_admin_page(admin_window, qapp, monkeypatch):
    page = admin_window.page("Models and data")
    admin_window.navigate("Models and data")
    notes = []
    monkeypatch.setattr(page, "notify", notes.append)
    page.retrain_button.click()
    wait_for_workers(qapp)
    assert notes and "Random Forest v2" in notes[0] and "Re-scored 2" in notes[0]
    assert "Version 2" in page.rf_text.text()
    assert page.history.rowCount() == 4


def test_reports_export(admin_window, tmp_path, monkeypatch):
    page = admin_window.page("Reports")
    monkeypatch.setattr(page, "ask_path", lambda default, _f: tmp_path / default.name)
    for export in (page.export_users, page.export_sessions, page.export_pdf):
        path = export()
        assert path is not None and path.exists() and path.stat().st_size > 0
    assert "Saved" in page.last.text()


# --------------------------------------------------------------- inbox
def test_inbox_records_inspection_before_click(window):
    inbox = window.page("Simulated inbox")
    window.navigate("Simulated inbox")
    inbox.start()
    assert inbox.modes.currentIndex() == 1 and inbox.message_list.count() == 12

    row = next(i for i, e in enumerate(inbox.view.emails) if e.link_url and e.is_phishing)
    email = inbox.view.emails[row]
    inbox.message_list.setCurrentRow(row)
    inbox.details_button.setChecked(True)
    assert email.sender_address in inbox.sender_address.text()

    inbox._on_highlighted(QUrl(email.link_url))
    assert email.link_url in inbox.link_status.text()       # real target shown on hover
    inbox._hover_start = time.monotonic() - 1.5             # pretend 1.5 s of hovering
    inbox._on_link_clicked(QUrl(email.link_url))            # still hovering when clicking
    inbox._on_highlighted(QUrl())                           # pointer leaves afterwards

    mine = [t for eid, t in events(window.ctx) if eid == email.id]
    assert mine == [config.EVENT_OPEN, config.EVENT_SENDER_INSPECT,
                    config.EVENT_LINK_HOVER, config.EVENT_LINK_CLICK]
    with session_scope(window.ctx.factory) as s:
        hover = s.scalar(select(BehaviourEvent).where(
            BehaviourEvent.event_type == config.EVENT_LINK_HOVER))
        assert 1400 <= hover.value_ms <= 3000
    assert inbox.consequences == [(email, config.EVENT_LINK_CLICK)]
    assert not inbox.report_button.isEnabled()              # decision is locked

    inbox._on_link_clicked(QUrl(email.link_url))            # second click is ignored
    assert len([1 for eid, t in events(window.ctx) if eid == email.id]) == 4


def test_links_are_never_opened(window, monkeypatch):
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url))
    inbox = window.page("Simulated inbox")
    window.navigate("Simulated inbox")
    inbox.start()
    assert not inbox.body.openLinks() and not inbox.body.openExternalLinks()
    row = next(i for i, e in enumerate(inbox.view.emails) if e.link_url)
    inbox.message_list.setCurrentRow(row)
    inbox.body.anchorClicked.emit(QUrl(inbox.view.emails[row].link_url))
    assert opened == []
    assert "Select an email" not in inbox.subject.text()     # still showing the email


def test_full_session_through_the_ui(window, qapp, ml_env):
    inbox = window.page("Simulated inbox")
    window.navigate("Simulated inbox")
    inbox.start()
    for row, email in enumerate(inbox.view.emails):
        inbox.message_list.setCurrentRow(row)
        (inbox.report_button if email.is_phishing else inbox.safe_button).click()
    assert inbox.progress.text().startswith("12 of 12")

    inbox.finish_button.click()
    wait_for_workers(qapp)
    assert len(inbox.results) == 1, "worker result was not delivered"
    result = inbox.results[0]
    assert not result.failed and result.phishing_reported == 8
    assert result.prediction.profile == config.PROFILE_VIGILANT
    assert window.stack.currentWidget() is window.page("Dashboard")
    assert inbox.view is None

    dash = window.page("Dashboard")
    assert dash.risk.value.text() == result.prediction.risk_level
    assert dash.sessions.value.text() == "1"

    window.navigate("Training")
    training = window.page("Training")
    assert training.list.count() == len(result.new_training) >= 1
    window.navigate("Progress")
    assert window.page("Progress").table.item(1, 1).text() == "100%"   # report accuracy

    ResultsDialog(result).close()                            # dialogs build without errors


def test_worker_delivers_on_gui_thread(window, qapp):
    from phishsense.ui.worker import run_with_progress
    seen = []
    run_with_progress(window, "working", lambda: QThread.currentThread(),
                      lambda worker_thread: seen.append((worker_thread, QThread.currentThread())),
                      lambda exc, tb: seen.append(exc))
    wait_for_workers(qapp)
    worker_thread, delivered_on = seen[0]
    assert worker_thread is not qapp.thread()
    assert delivered_on is qapp.thread()


# --------------------------------------------------------- quiz dialog
def test_quiz_dialog_feedback_and_pass(trainee, ml_env):
    ctx = trainee
    view = ctx.call(facade.start_or_resume, ctx.user_id)
    for e in view.emails:   # impulsive baseline -> required training
        ctx.call(facade.record_event, ctx.user_id, view.id, e.id, config.EVENT_OPEN)
        if e.link_url:
            ctx.call(facade.record_event, ctx.user_id, view.id, e.id, config.EVENT_LINK_CLICK)
    ctx.call(facade.complete, ctx.user_id, view.id)
    item = ctx.call(facade.training_list, ctx.user_id)[0]
    quiz_view = ctx.call(facade.start_quiz, ctx.user_id, item.id)

    dlg = QuizDialog(ctx, quiz_view)
    with session_scope(ctx.factory) as s:
        answers = [s.get(QuizQuestion, q.id).correct_index for q in quiz_view.questions]
    wrong = (answers[0] + 1) % len(quiz_view.questions[0].options)
    feedback = dlg.answer(wrong)
    assert not feedback.correct and "Not quite" in dlg.feedback.text()
    assert dlg.button.text() == "Next question"
    for i in range(1, len(answers)):
        dlg._on_button()                     # next question
        assert dlg.answer(answers[i]).correct
    assert dlg.button.text() == "See result"
    outcome = dlg.finish()
    assert (outcome.correct, outcome.total, outcome.passed) == (4, 5, True)


def test_consequence_dialog_builds(trainee):
    view = trainee.call(facade.start_or_resume, trainee.user_id)
    phishing = next(e for e in view.emails if e.is_phishing and e.link_url)
    genuine = next(e for e in view.emails if not e.is_phishing and e.link_url)
    for email in (phishing, genuine):
        dlg = ConsequenceDialog(email, config.EVENT_LINK_CLICK)
        dlg.close()
