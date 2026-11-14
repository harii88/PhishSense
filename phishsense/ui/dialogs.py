"""Dialogs: errors, the teachable moment, session review, quiz, account."""

from __future__ import annotations

import html
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from phishsense import config
from phishsense.services import facade
from phishsense.ui import theme
from phishsense.ui.context import USER_ERRORS, AppContext
from phishsense.ui.widgets import Card, badge, label


def show_error(parent: QWidget | None, exc: Exception, details: str | None = None) -> None:
    if isinstance(exc, USER_ERRORS):
        QMessageBox.warning(parent, "PhishSense", str(exc))
        return
    box = QMessageBox(QMessageBox.Icon.Critical, "PhishSense",
                      "Something went wrong. Your earlier actions are saved.", parent=parent)
    box.setDetailedText(details or repr(exc))
    box.exec()


def _bullets(items) -> str:
    return "<ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in items) + "</ul>"


# ---------------------------------------------------------------------------
class ConsequenceDialog(QDialog):
    """Shown right after a link click or attachment open (teachable moment)."""

    def __init__(self, email: facade.InboxEmail, event_type: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Simulation")
        self.setMinimumWidth(480)
        col = QVBoxLayout(self)
        what = (f"the link to <code>{html.escape(email.link_url or '')}</code>"
                if event_type == config.EVENT_LINK_CLICK
                else f"the attachment <code>{html.escape(email.attachment_name or '')}</code>")
        if email.is_phishing:
            title = label("This was a simulated phishing email", "PageTitle")
            title.setStyleSheet(f"color: {theme.BAD};")
            text = (f"You opened {what}. In a real attack this could have given the attacker "
                    "your password or installed malware. Nothing was opened here.<br><br>"
                    "<b>What gave it away:</b>" + _bullets(email.indicators))
        else:
            title = label("This email was genuine", "PageTitle")
            title.setStyleSheet(f"color: {theme.GOOD};")
            text = (f"You opened {what}. That was safe this time. In the simulation nothing "
                    "is opened.<br><br><b>Why it is genuine:</b>" + _bullets(email.indicators))
        col.addWidget(title)
        body = label(theme.rich(text), wrap=True)
        body.setTextFormat(Qt.TextFormat.RichText)
        col.addWidget(body)
        col.addStretch()
        ok = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        ok.accepted.connect(self.accept)
        col.addWidget(ok)


# ---------------------------------------------------------------------------
_DECISIONS = {
    config.DECISION_CLICKED: "Clicked / opened",
    config.DECISION_REPORTED: "Reported",
    config.DECISION_MARKED_SAFE: "Marked safe",
    config.DECISION_IGNORED: "No action",
}


def _verdict(row: facade.ReviewRow) -> tuple[str, str]:
    if row.correct is None:
        return "Neutral", theme.SLATE
    if row.correct:
        return "Correct", theme.GOOD
    if row.is_phishing and row.decision == config.DECISION_IGNORED:
        return "Missed", theme.WARN
    return "Wrong", theme.BAD


class ResultsDialog(QDialog):
    """Per-email review, the model output and the new training plan."""

    def __init__(self, result: facade.ResultView, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Session review")
        self.resize(980, 720)
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        col = QVBoxLayout(content)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        headline = ("You compromised at least one phishing email in this session."
                    if result.failed else "No phishing email got through. Well done.")
        col.addWidget(label("Session review", "PageTitle"))
        col.addWidget(label(
            f"{headline}  Phishing emails: {result.phishing_total}, reported "
            f"{result.phishing_reported}, clicked/opened {result.phishing_compromised}.",
            wrap=True))

        tree = QTreeWidget()
        tree.setHeaderLabels(["#", "From", "Subject", "Type", "Your action", "Result"])
        tree.setRootIsDecorated(True)
        tree.setMinimumHeight(300)
        for row in result.rows:
            verdict, colour = _verdict(row)
            item = QTreeWidgetItem([
                str(row.position + 1), f"{row.sender_name} <{row.sender_address}>",
                row.subject, row.category_label, _DECISIONS[row.decision], verdict,
            ])
            item.setForeground(5, QBrush(QColor(colour)))
            heading = "Red flags:" if row.is_phishing else "Why it is genuine:"
            tree.addTopLevelItem(item)
            for text in (heading, *[f"• {t}" for t in row.indicators]):
                child = QTreeWidgetItem(item, [text])
                child.setFirstColumnSpanned(True)   # explanations use the full width
                if text == heading:
                    child.setForeground(0, QBrush(QColor(theme.SLATE)))
            if row.correct is False:                 # mistakes open with their red flags
                item.setExpanded(True)
        for column, width in enumerate([40, 270, 260, 150, 140, 80]):
            tree.setColumnWidth(column, width)
        col.addWidget(tree)

        model = Card("Behaviour analysis")
        p = result.prediction
        row = QHBoxLayout()
        row.addWidget(badge(p.profile, theme.PROFILE_COLOURS[p.profile]))
        row.addWidget(badge(f"{p.risk_level} risk - {p.probability:.0%}",
                            theme.RISK_COLOURS[p.risk_level]))
        row.addStretch()
        model.body.addLayout(row)
        model.body.addWidget(label(p.description, wrap=True))
        if result.level_changes:
            changes = ", ".join(
                f"{c.vector_label} {c.old}→{c.new} ({c.correct}/{c.total})"
                for c in result.level_changes)
            model.body.addWidget(label(f"Difficulty levels: {changes}", "Muted", wrap=True))
        model.body.addWidget(label(
            "The profile comes from K-Means clustering and the risk from a Random Forest, "
            "trained on synthetic behaviour data plus sessions recorded in this installation. "
            "They support training decisions; they are not a judgement of you.",
            "Disclaimer", wrap=True))
        col.addWidget(model)

        plan = Card("Your training plan")
        if result.new_training:
            for a in result.new_training:
                prefix = "REQUIRED - " if a.mandatory else ""
                title = label(f"{prefix}{a.title}  ({a.topic_label}, level {a.level})")
                title.setStyleSheet("font-weight: 600;" + (f"color: {theme.BAD};" if a.mandatory else ""))
                plan.body.addWidget(title)
                plan.body.addWidget(label(a.reason, "Muted", wrap=True))
        else:
            plan.body.addWidget(label("No new training this time. Keep it up.", "Muted"))
        col.addWidget(plan)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.accept)
        outer.addWidget(close)


# ---------------------------------------------------------------------------
class QuizDialog(QDialog):
    """One question at a time; instant feedback after each answer."""

    def __init__(self, ctx: AppContext, view: facade.QuizView, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx, self.view = ctx, view
        self.index = 0
        self.correct = 0
        self.outcome = None
        self._shown_at = time.monotonic()
        self.setWindowTitle(f"Quiz - {view.title}")
        self.setMinimumSize(640, 460)

        col = QVBoxLayout(self)
        self.counter = label("", "Muted")
        self.prompt = label("", wrap=True)
        self.prompt.setTextFormat(Qt.TextFormat.RichText)
        self.prompt.setStyleSheet("font-size: 11pt;")
        col.addWidget(self.counter)
        col.addWidget(self.prompt)
        self.options_box = QVBoxLayout()
        col.addLayout(self.options_box)
        self.group = QButtonGroup(self)
        self.feedback = label("", wrap=True)
        self.feedback.setTextFormat(Qt.TextFormat.RichText)
        col.addWidget(self.feedback)
        col.addStretch()
        self.button = QPushButton("Check answer")
        self.button.setObjectName("Primary")
        self.button.clicked.connect(self._on_button)
        col.addWidget(self.button, alignment=Qt.AlignmentFlag.AlignRight)
        self._show_question()

    @property
    def question(self) -> facade.QuestionView:
        return self.view.questions[self.index]

    def _show_question(self) -> None:
        q = self.question
        self.counter.setText(f"Question {self.index + 1} of {len(self.view.questions)}")
        self.prompt.setText(theme.rich(q.prompt))
        for button in self.group.buttons():
            self.group.removeButton(button)
            button.deleteLater()
        for i, option in enumerate(q.options):
            radio = QRadioButton(option)
            self.group.addButton(radio, i)
            self.options_box.addWidget(radio)
        self.feedback.setText("")
        self.feedback.setStyleSheet("")
        self.button.setText("Check answer")
        self._shown_at = time.monotonic()

    def answer(self, chosen: int) -> facade.quiz.AnswerFeedback | None:
        """Submit ``chosen`` for the current question and show the feedback."""
        elapsed = int((time.monotonic() - self._shown_at) * 1000)
        result = self.ctx.try_call(self, facade.answer_question, self.ctx.user_id, self.view,
                                   self.question.id, chosen, elapsed)
        if result is None:
            return None
        self.correct += result.correct
        for button in self.group.buttons():
            button.setEnabled(False)
        verdict = "Correct." if result.correct else (
            f"Not quite. The answer is: <b>{html.escape(result.correct_option)}</b>")
        colour, background = (theme.GOOD, "#dcfce7") if result.correct else (theme.BAD, "#fee2e2")
        self.feedback.setText(f"<b style='color:{colour}'>{verdict}</b><br>{result.explanation}")
        self.feedback.setStyleSheet(f"background: {background}; border-radius: 8px; padding: 10px;")
        last = self.index == len(self.view.questions) - 1
        self.button.setText("See result" if last else "Next question")
        return result

    def _on_button(self) -> None:
        text = self.button.text()
        if text == "Check answer":
            if self.group.checkedId() < 0:
                self.feedback.setText("Choose an answer first.")
                return
            self.answer(self.group.checkedId())
        elif text == "Next question":
            self.index += 1
            self._show_question()
        elif text == "See result":
            self.finish()
        else:
            self.accept()

    def finish(self) -> facade.quiz.QuizOutcome | None:
        outcome = self.ctx.try_call(self, facade.finish_quiz, self.ctx.user_id, self.view)
        if outcome is None:
            return None
        self.outcome = outcome
        for button in self.group.buttons():
            button.hide()
        self.counter.setText("Quiz complete")
        self.prompt.setText(f"You scored <b>{outcome.correct} / {outcome.total}</b> "
                            f"({outcome.score:.0%}).")
        if outcome.passed:
            self.feedback.setText("Passed - this training is complete.")
            self.feedback.setStyleSheet("background: #dcfce7; border-radius: 8px; padding: 10px;")
        else:
            self.feedback.setText(
                f"You need {config.QUIZ_PASS_SCORE:.0%} to pass. Review the lesson and try "
                "again - you will get a different set of questions.")
            self.feedback.setStyleSheet("background: #fef3c7; border-radius: 8px; padding: 10px;")
        self.button.setText("Close")
        return outcome


# ---------------------------------------------------------------------------
class AccountDialog(QDialog):
    def __init__(self, ctx: AppContext, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("Account settings")
        self.setMinimumWidth(420)
        col = QVBoxLayout(self)

        profile = QFormLayout()
        self.full_name = QLineEdit(ctx.user.full_name)
        self.department = QComboBox()
        self.department.addItems(config.DEPARTMENTS)
        self.department.setCurrentText(ctx.user.department)
        save = QPushButton("Save profile")
        save.clicked.connect(self._save_profile)
        profile.addRow("Username", label(ctx.user.username))
        profile.addRow("Full name", self.full_name)
        profile.addRow("Department", self.department)
        profile.addRow("", save)
        col.addLayout(profile)

        col.addWidget(label("Change password", "CardTitle"))
        pw = QFormLayout()
        self.current = QLineEdit()
        self.new = QLineEdit()
        self.confirm = QLineEdit()
        for field in (self.current, self.new, self.confirm):
            field.setEchoMode(QLineEdit.EchoMode.Password)
        change = QPushButton("Change password")
        change.clicked.connect(self._change_password)
        pw.addRow("Current", self.current)
        pw.addRow("New", self.new)
        pw.addRow("Confirm new", self.confirm)
        pw.addRow("", change)
        col.addLayout(pw)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        col.addWidget(close)

    def _save_profile(self) -> None:
        user = self.ctx.try_call(self, facade.update_profile, self.ctx.user_id,
                                 full_name=self.full_name.text(),
                                 department=self.department.currentText())
        if user is not None:
            self.ctx.user = user
            QMessageBox.information(self, "PhishSense", "Profile saved.")

    def _change_password(self) -> None:
        if self.new.text() != self.confirm.text():
            QMessageBox.warning(self, "PhishSense", "The new passwords do not match.")
            return
        try:
            self.ctx.call(facade.change_password, self.ctx.user_id,
                          self.current.text(), self.new.text())
        except USER_ERRORS as exc:
            QMessageBox.warning(self, "PhishSense", str(exc))
            return
        for field in (self.current, self.new, self.confirm):
            field.clear()
        QMessageBox.information(self, "PhishSense", "Password changed.")
