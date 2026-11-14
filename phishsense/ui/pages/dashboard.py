"""Trainee dashboard: risk, profile, key rates and the next step."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from phishsense import config
from phishsense.services import facade
from phishsense.ui import theme
from phishsense.ui.charts import Chart
from phishsense.ui.context import AppContext
from phishsense.ui.widgets import Card, StatCard, label, pct


class DashboardPage(QWidget):
    def __init__(self, ctx: AppContext, navigate: Callable[[str], None]):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate

        col = QVBoxLayout(self)
        col.setContentsMargins(24, 20, 24, 20)
        col.setSpacing(14)
        self.greeting = label("", "PageTitle")
        col.addWidget(self.greeting)

        self.banner = Card()
        self.banner.setObjectName("Banner")
        self.banner_text = label("", wrap=True)
        go = QPushButton("Go to training")
        go.clicked.connect(lambda: self.navigate("Training"))
        row = QHBoxLayout()
        row.addWidget(self.banner_text, 1)
        row.addWidget(go)
        self.banner.body.addLayout(row)
        col.addWidget(self.banner)

        grid = QGridLayout()
        grid.setSpacing(14)
        self.risk = StatCard("Risk level")
        self.profile = StatCard("Behaviour profile")
        self.sessions = StatCard("Simulations completed")
        self.click_rate = StatCard("Click rate")
        self.report_rate = StatCard("Report accuracy")
        for i, card in enumerate([self.risk, self.profile, self.sessions,
                                  self.click_rate, self.report_rate]):
            grid.addWidget(card, 0, i)
        col.addLayout(grid)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        gauge_card = Card()
        self.gauge = Chart(6.0, 1.9)
        gauge_card.body.addWidget(self.gauge)
        lower.addWidget(gauge_card, 3)

        next_card = Card("Next step")
        self.next_text = label("", wrap=True)
        self.next_button = QPushButton("Open simulated inbox")
        self.next_button.setObjectName("Primary")
        self.next_button.clicked.connect(lambda: self.navigate("Simulated inbox"))
        self.levels_text = label("", "Muted", wrap=True)
        next_card.body.addWidget(self.next_text)
        next_card.body.addWidget(self.next_button)
        next_card.body.addSpacing(6)
        next_card.body.addWidget(self.levels_text)
        next_card.body.addStretch()
        lower.addWidget(next_card, 2)
        col.addLayout(lower)
        col.addStretch()

    def refresh(self) -> None:
        data = self.ctx.try_call(self, facade.dashboard, self.ctx.user_id)
        if data is None:
            return
        self.greeting.setText(f"Welcome, {data.user.full_name}")

        self.banner.setVisible(bool(data.required_training))
        self.banner_text.setText(
            "Required training before your next simulation: "
            + ", ".join(data.required_training))

        p = data.prediction
        if p is None:
            self.risk.set("-", "Shown after your first simulation.")
            self.profile.set("-", "Shown after your first simulation.")
        else:
            self.risk.set(p.risk_level, f"{p.probability:.0%} predicted chance of failing "
                          "the next simulation", theme.RISK_COLOURS[p.risk_level])
            self.profile.set(p.profile, p.description, theme.PROFILE_COLOURS[p.profile])
            self.profile.value.setStyleSheet(
                self.profile.value.styleSheet() + "font-size: 13pt;")
        self.sessions.set(str(data.sessions_completed),
                          "baseline + adaptive sessions" if data.sessions_completed else "")
        window = f"over your last {config.FEATURE_WINDOW_SESSIONS} sessions"
        self.click_rate.set(pct(data.click_rate), f"phishing emails clicked, {window}")
        self.report_rate.set(pct(data.report_accuracy), f"phishing emails reported, {window}")
        self.gauge.risk_gauge(p.probability if p else None)

        if data.has_open_session:
            self.next_text.setText("You have a simulation in progress.")
            self.next_button.setText("Continue simulation")
        elif data.required_training:
            self.next_text.setText("Complete your required training to unlock the next "
                                   "simulation.")
            self.next_button.setText("Open simulated inbox")
        elif data.next_session_kind == config.SESSION_KIND_BASELINE:
            self.next_text.setText("Start with the baseline assessment: 12 emails, the same "
                                   "for everyone.")
            self.next_button.setText("Start baseline")
        else:
            self.next_text.setText("Your next simulation is personalised to your weak spots.")
            self.next_button.setText("Start next simulation")
        self.levels_text.setText("Difficulty levels: " + ", ".join(
            f"{config.VECTOR_LABELS[v]} {lvl}/{config.MAX_LEVEL}" for v, lvl in data.levels.items()))
