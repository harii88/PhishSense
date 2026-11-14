"""The simulated inbox: where behaviour is observed (DESIGN.md section 4).

What is recorded and when
-------------------------
* selecting an email                 -> ``open``
* opening the sender details         -> ``sender_inspect``
* pointer enters a link              -> hover timer starts (nothing stored yet)
* pointer leaves the link            -> ``link_hover`` with the duration
* clicking the link                  -> the running hover is stored *first*,
                                        then ``link_click``
* attachment button                  -> ``attachment_open``
* Report phishing / Mark as safe     -> ``report`` / ``mark_safe``

Each event is committed immediately in its own transaction, so a crash loses
nothing already done. Hovers are only tracked until the email has a
decision; after that they cannot affect the outcome.

Safety: the reading pane is a QTextBrowser with link opening disabled. Links
are only data: the target is displayed in the status line while hovering and
nothing is ever opened, fetched or handed to the operating system.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from phishsense import config
from phishsense.services import facade
from phishsense.ui.context import AppContext
from phishsense.ui.dialogs import ConsequenceDialog, ResultsDialog, show_error
from phishsense.ui.widgets import Card, label
from phishsense.ui.worker import run_with_progress

DECISION_TEXT = {
    config.DECISION_CLICKED: "Opened link / attachment",
    config.DECISION_REPORTED: "Reported as phishing",
    config.DECISION_MARKED_SAFE: "Marked as safe",
}
HOVER_HINT = "Hover over a link to see where it really goes."


class InboxPage(QWidget):
    def __init__(self, ctx: AppContext, navigate: Callable[[str], None]):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate
        self.view: facade.SessionView | None = None
        self.current: facade.InboxEmail | None = None
        self.decisions: dict[int, str] = {}
        self.opened: set[int] = set()
        self._hover_start: float | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        top = QHBoxLayout()
        top.addWidget(label("Simulated inbox", "PageTitle"))
        top.addStretch()
        self.progress = label("", "Muted")
        top.addWidget(self.progress)
        self.finish_button = QPushButton("Finish session")
        self.finish_button.setObjectName("Primary")
        self.finish_button.clicked.connect(self.finish)
        top.addWidget(self.finish_button)
        outer.addLayout(top)

        self.modes = QStackedWidget()
        self.modes.addWidget(self._start_panel())
        self.modes.addWidget(self._mail_client())
        outer.addWidget(self.modes, 1)

    # ------------------------------------------------------------- layout
    def _start_panel(self) -> QWidget:
        panel = QWidget()
        col = QVBoxLayout(panel)
        card = Card()
        self.start_title = label("", "PageTitle")
        self.start_text = label("", wrap=True)
        self.start_button = QPushButton("Start simulation")
        self.start_button.setObjectName("Primary")
        self.start_button.clicked.connect(self.start)
        card.body.addWidget(self.start_title)
        card.body.addWidget(self.start_text)
        card.body.addSpacing(8)
        card.body.addWidget(self.start_button, alignment=Qt.AlignmentFlag.AlignLeft)
        col.addWidget(card)
        col.addStretch()
        return panel

    def _mail_client(self) -> QWidget:
        splitter = QSplitter()
        self.message_list = QListWidget()
        self.message_list.setObjectName("MessageList")
        self.message_list.setMinimumWidth(300)
        self.message_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.message_list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.message_list.currentItemChanged.connect(self._on_select)
        splitter.addWidget(self.message_list)

        pane = QWidget()
        col = QVBoxLayout(pane)
        col.setContentsMargins(12, 0, 0, 0)
        self.subject = label("", "PageTitle", wrap=True)
        col.addWidget(self.subject)

        sender_row = QHBoxLayout()
        self.sender_name = label("")
        self.sender_name.setStyleSheet("font-weight: 600;")
        self.details_button = QToolButton()
        self.details_button.setText("details ▾")
        self.details_button.setCheckable(True)
        self.details_button.toggled.connect(self._on_details)
        sender_row.addWidget(self.sender_name)
        sender_row.addWidget(self.details_button)
        sender_row.addStretch()
        self.received = label("", "Muted")
        sender_row.addWidget(self.received)
        col.addLayout(sender_row)
        self.sender_address = label("", "Muted")
        self.sender_address.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        col.addWidget(self.sender_address)

        self.attachment_button = QPushButton()
        self.attachment_button.setObjectName("Attachment")
        self.attachment_button.clicked.connect(self._on_attachment)
        col.addWidget(self.attachment_button, alignment=Qt.AlignmentFlag.AlignLeft)

        self.body = QTextBrowser()
        self.body.setOpenLinks(False)
        self.body.setOpenExternalLinks(False)
        self.body.highlighted.connect(self._on_highlighted)
        self.body.anchorClicked.connect(self._on_link_clicked)
        col.addWidget(self.body, 1)

        self.link_status = label(HOVER_HINT, "StatusBarLink")
        col.addWidget(self.link_status)

        actions = QHBoxLayout()
        self.report_button = QPushButton("Report phishing")
        self.report_button.setObjectName("Danger")
        self.report_button.clicked.connect(lambda: self._decide(config.EVENT_REPORT))
        self.safe_button = QPushButton("Mark as safe")
        self.safe_button.setObjectName("Safe")
        self.safe_button.clicked.connect(lambda: self._decide(config.EVENT_MARK_SAFE))
        self.decision_label = label("", "Muted")
        actions.addWidget(self.report_button)
        actions.addWidget(self.safe_button)
        actions.addSpacing(12)
        actions.addWidget(self.decision_label, 1)
        col.addLayout(actions)

        splitter.addWidget(pane)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([340, 800])
        return splitter

    # ------------------------------------------------------------ lifecycle
    def refresh(self) -> None:
        if self.view is not None:
            return
        data = self.ctx.try_call(self, facade.dashboard, self.ctx.user_id)
        if data is None:
            return
        if data.has_open_session:  # resume where the user left off
            self.start()
            return
        self.modes.setCurrentIndex(0)
        self.finish_button.setVisible(False)
        self.progress.setText("")
        if data.next_session_kind == config.SESSION_KIND_BASELINE:
            self.start_title.setText("Baseline assessment")
            self.start_text.setText(
                "Your first session has 12 emails, some genuine and some simulated phishing. "
                "Treat them as you would at work: open them, check what you need to, then "
                "report phishing or mark genuine mail as safe. Everyone gets the same "
                "baseline so results can be compared.")
        else:
            self.start_title.setText("Next simulation")
            self.start_text.setText(
                f"{config.SESSION_PHISHING_COUNT + config.SESSION_LEGITIMATE_COUNT} emails "
                "chosen for you, with more of the attack types you find hardest and a "
                "difficulty that follows your performance.")
        blocked = bool(data.required_training)
        self.start_button.setEnabled(not blocked)
        if blocked:
            self.start_text.setText(self.start_text.text() + "\n\nComplete your required "
                                    f"training first: {', '.join(data.required_training)}.")

    def start(self) -> None:
        view = self.ctx.try_call(self, facade.start_or_resume, self.ctx.user_id)
        if view is None:
            return
        self.view = view
        self.decisions = {e.id: e.decision for e in view.emails if e.decision}
        self.opened = {e.id for e in view.emails if e.opened}
        self.modes.setCurrentIndex(1)
        self.finish_button.setVisible(True)
        self.message_list.blockSignals(True)
        self.message_list.clear()
        for email in view.emails:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, email.id)
            self.message_list.addItem(item)
            self._style_item(item, email)
        self.message_list.blockSignals(False)
        self._clear_reader()
        self._update_progress()

    def reset(self) -> None:
        self.flush_hover()
        self.view = None
        self.current = None
        self.decisions.clear()
        self.opened.clear()
        self.message_list.clear()

    # ---------------------------------------------------------------- helpers
    def _email(self, email_id: int) -> facade.InboxEmail:
        return next(e for e in self.view.emails if e.id == email_id)

    def _received(self, email: facade.InboxEmail) -> str:
        minutes = 8 * 60 + 5 + email.position * 23
        return f"{minutes // 60:02d}:{minutes % 60:02d}"

    def _style_item(self, item: QListWidgetItem, email: facade.InboxEmail) -> None:
        decision = self.decisions.get(email.id)
        status = {None: "", config.DECISION_CLICKED: "  • opened",
                  config.DECISION_REPORTED: "  ⚑ reported",
                  config.DECISION_MARKED_SAFE: "  ✓ safe"}[decision]
        item.setText(f"{email.sender_name}{status}\n{email.subject}")
        font = QFont()
        font.setBold(email.id not in self.opened)
        item.setFont(font)

    def _update_progress(self) -> None:
        if self.view:
            handled = sum(1 for e in self.view.emails if e.id in self.decisions)
            self.progress.setText(f"{handled} of {len(self.view.emails)} emails handled")

    def _record(self, event_type: str, value_ms: int | None = None) -> bool:
        if self.view is None or self.current is None:
            return False
        try:
            self.ctx.call(facade.record_event, self.ctx.user_id, self.view.id, self.current.id,
                          event_type, value_ms)
        except Exception as exc:  # noqa: BLE001 - shown to the user, session stays usable
            show_error(self, exc)
            return False
        return True

    def _clear_reader(self) -> None:
        self.current = None
        self.subject.setText("Select an email to read it.")
        for widget in (self.sender_name, self.sender_address, self.received, self.decision_label):
            widget.setText("")
        self.details_button.setVisible(False)
        self.attachment_button.setVisible(False)
        self.body.clear()
        self.link_status.setText(HOVER_HINT)
        self.report_button.setEnabled(False)
        self.safe_button.setEnabled(False)

    def _show(self, email: facade.InboxEmail) -> None:
        self.current = email
        self.subject.setText(email.subject)
        self.sender_name.setText(email.sender_name)
        self.received.setText(self._received(email))
        self.details_button.setVisible(True)
        self.details_button.blockSignals(True)
        self.details_button.setChecked(False)
        self.details_button.blockSignals(False)
        self.sender_address.setText("")
        if email.attachment_name:
            self.attachment_button.setText(f"\U0001F4CE  {email.attachment_name}")
            self.attachment_button.setVisible(True)
        else:
            self.attachment_button.setVisible(False)
        self.body.setHtml(email.body_html)
        self.link_status.setText(HOVER_HINT)
        self._apply_decision_state()

    def _apply_decision_state(self) -> None:
        decided = self.current is not None and self.current.id in self.decisions
        self.report_button.setEnabled(not decided)
        self.safe_button.setEnabled(not decided)
        self.attachment_button.setEnabled(not decided)
        self.decision_label.setText(
            f"Your decision: {DECISION_TEXT[self.decisions[self.current.id]]}. "
            "You will see the full review when you finish the session." if decided else "")

    # ---------------------------------------------------------------- events
    def flush_hover(self) -> None:
        """Store the hover in progress (called before any click or switch)."""
        if self._hover_start is None:
            return
        duration_ms = int((time.monotonic() - self._hover_start) * 1000)
        self._hover_start = None
        if self.current is not None and self.current.id not in self.decisions:
            self._record(config.EVENT_LINK_HOVER, duration_ms)

    def _on_select(self, item: QListWidgetItem | None, _previous=None) -> None:
        self.flush_hover()
        if item is None or self.view is None:
            self._clear_reader()
            return
        email = self._email(item.data(Qt.ItemDataRole.UserRole))
        self.current = email
        if self._record(config.EVENT_OPEN):
            self.opened.add(email.id)
            self._style_item(item, email)
        self._show(email)

    def _on_details(self, shown: bool) -> None:
        if self.current is None:
            return
        if shown:
            self.sender_address.setText(f"From: {self.current.sender_name} "
                                        f"<{self.current.sender_address}>")
            if self.current.id not in self.decisions:
                self._record(config.EVENT_SENDER_INSPECT)
        else:
            self.sender_address.setText("")

    def _on_highlighted(self, url: QUrl) -> None:
        if url.isEmpty():
            self.flush_hover()
            self.link_status.setText(HOVER_HINT)
            return
        self.flush_hover()  # moving straight from one link to another
        self.link_status.setText(f"Link goes to:  {url.toString()}")
        if self.current is not None and self.current.id not in self.decisions:
            self._hover_start = time.monotonic()

    def _on_link_clicked(self, _url: QUrl) -> None:
        self.flush_hover()  # inspection before the click must be stored before it
        if self.current is None or self.current.id in self.decisions:
            return
        self._decide(config.EVENT_LINK_CLICK)

    def _on_attachment(self) -> None:
        self.flush_hover()
        if self.current is not None and self.current.id not in self.decisions:
            self._decide(config.EVENT_ATTACHMENT_OPEN)

    def _decide(self, event_type: str) -> None:
        self.flush_hover()
        email = self.current
        if email is None or email.id in self.decisions:
            return
        if not self._record(event_type):
            return
        decision = {config.EVENT_LINK_CLICK: config.DECISION_CLICKED,
                    config.EVENT_ATTACHMENT_OPEN: config.DECISION_CLICKED,
                    config.EVENT_REPORT: config.DECISION_REPORTED,
                    config.EVENT_MARK_SAFE: config.DECISION_MARKED_SAFE}[event_type]
        self.decisions[email.id] = decision
        self._style_item(self.message_list.currentItem(), email)
        self._apply_decision_state()
        self._update_progress()
        if decision == config.DECISION_CLICKED:
            self.show_consequence(email, event_type)

    def show_consequence(self, email: facade.InboxEmail, event_type: str) -> None:
        """Teachable moment after a click (replaced in tests)."""
        ConsequenceDialog(email, event_type, self).exec()

    # ---------------------------------------------------------------- finish
    def confirm_finish(self, unanswered: int) -> bool:
        if unanswered == 0:
            return True
        answer = QMessageBox.question(
            self, "Finish session",
            f"{unanswered} email(s) have no decision yet. They will count as ignored. "
            "Finish anyway?")
        return answer == QMessageBox.StandardButton.Yes

    def finish(self) -> None:
        self.flush_hover()
        if self.view is None:
            return
        unanswered = len(self.view.emails) - len(self.decisions)
        if not self.confirm_finish(unanswered):
            return
        sim_id, user_id = self.view.id, self.ctx.user_id
        run_with_progress(
            self, "Analysing your behaviour and updating your training plan...",
            lambda: self.ctx.call(facade.complete, user_id, sim_id),
            self._on_finished, lambda exc, tb: show_error(self, exc, tb),
        )

    def _on_finished(self, result: facade.ResultView) -> None:
        self.reset()
        self.show_results(result)
        self.navigate("Dashboard")

    def show_results(self, result: facade.ResultView) -> None:
        """Session review (replaced in tests)."""
        ResultsDialog(result, self).exec()
