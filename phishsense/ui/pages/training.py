"""Assigned training: why it was assigned, the lesson, and its quiz."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from phishsense.services import facade
from phishsense.ui import theme
from phishsense.ui.context import AppContext
from phishsense.ui.dialogs import QuizDialog
from phishsense.ui.widgets import Card, badge, label


class TrainingPage(QWidget):
    def __init__(self, ctx: AppContext, navigate: Callable[[str], None]):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate
        self.items: list[facade.TrainingItem] = []

        col = QVBoxLayout(self)
        col.setContentsMargins(24, 20, 24, 20)
        col.addWidget(label("Training", "PageTitle"))
        col.addWidget(label("Assigned automatically from your behaviour in the simulations.",
                            "Muted"))

        splitter = QSplitter()
        self.list = QListWidget()
        self.list.setObjectName("MessageList")
        self.list.setMinimumWidth(300)
        self.list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.list.currentRowChanged.connect(self._show)
        splitter.addWidget(self.list)

        pane = QWidget()
        right = QVBoxLayout(pane)
        right.setContentsMargins(12, 0, 0, 0)
        self.title = label("", "PageTitle", wrap=True)
        right.addWidget(self.title)
        self.badges = QHBoxLayout()
        right.addLayout(self.badges)
        self.reason_card = Card("Why this was assigned")
        self.reason = label("", wrap=True)
        self.reason_card.body.addWidget(self.reason)
        right.addWidget(self.reason_card)
        self.lesson = QTextBrowser()
        self.lesson.setOpenLinks(False)
        right.addWidget(self.lesson, 1)
        bottom = QHBoxLayout()
        self.status = label("", "Muted")
        self.quiz_button = QPushButton("Take the quiz")
        self.quiz_button.setObjectName("Primary")
        self.quiz_button.clicked.connect(self.take_quiz)
        bottom.addWidget(self.status, 1)
        bottom.addWidget(self.quiz_button)
        right.addLayout(bottom)
        splitter.addWidget(pane)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([320, 820])
        col.addWidget(splitter, 1)

        self.empty = label("No training assigned yet. Complete a simulation and your training "
                           "plan will appear here.", "Muted", wrap=True)
        col.addWidget(self.empty)

    def refresh(self, select_id: int | None = None) -> None:
        items = self.ctx.try_call(self, facade.training_list, self.ctx.user_id)
        if items is None:
            return
        self.items = items
        self.empty.setVisible(not items)
        self.list.blockSignals(True)
        self.list.clear()
        for t in items:
            state = "Completed" if t.completed else ("REQUIRED" if t.mandatory else "To do")
            item = QListWidgetItem(f"{t.title}\n{state} - {t.topic_label}, level {t.level}")
            if t.mandatory and not t.completed:
                item.setForeground(Qt.GlobalColor.darkRed)
            self.list.addItem(item)
        row = -1
        if items:
            row = 0 if select_id is None else next(
                (i for i, t in enumerate(items) if t.id == select_id), 0)
            self.list.setCurrentRow(row)       # signals blocked: draw exactly once below
        self.list.blockSignals(False)
        self._show(row)

    def _clear_badges(self) -> None:
        while self.badges.count():
            widget = self.badges.takeAt(0).widget()
            if widget is not None:
                # Detach now: deleteLater only runs on the next event-loop pass, and a
                # widget outside the layout would stay painted until then.
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()

    def _show(self, row: int) -> None:
        self._clear_badges()
        if not 0 <= row < len(self.items):
            self.title.setText("")
            self.reason.setText("")
            self.lesson.clear()
            self.status.setText("")
            self.quiz_button.setEnabled(False)
            self.reason_card.setVisible(False)
            return
        t = self.items[row]
        self.reason_card.setVisible(True)
        self.title.setText(t.title)
        if t.mandatory and not t.completed:
            self.badges.addWidget(badge("Required", theme.BAD))
        if t.completed:
            self.badges.addWidget(badge("Completed", theme.GOOD))
        self.badges.addWidget(badge(f"{t.topic_label} - level {t.level}", theme.ACCENT))
        self.badges.addStretch()
        self.reason.setText(t.reason)
        self.lesson.setHtml(theme.rich(f"<p><i>{t.summary}</i></p>{t.lesson_html}"))
        score = "-" if t.quiz_score is None else f"{t.quiz_score:.0%}"
        self.status.setText(f"Quiz attempts: {t.attempts}   Best score: {score}   "
                            "Pass mark: 70%")
        self.quiz_button.setEnabled(not t.completed)
        self.quiz_button.setText("Completed" if t.completed else
                                 ("Retry the quiz" if t.attempts else "Take the quiz"))

    def take_quiz(self) -> None:
        row = self.list.currentRow()
        if not 0 <= row < len(self.items):
            return
        t = self.items[row]
        view = self.ctx.try_call(self, facade.start_quiz, self.ctx.user_id, t.id)
        if view is None:
            return
        self.run_quiz(view)
        self.refresh(select_id=t.id)

    def run_quiz(self, view: facade.QuizView) -> None:
        """Show the quiz dialog (replaced in tests)."""
        QuizDialog(self.ctx, view, self).exec()
