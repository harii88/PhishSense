"""Progress over time and the behaviour features in plain language."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QGridLayout,
    QHeaderView,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from phishsense import config
from phishsense.services import facade
from phishsense.services.features import FEATURE_LABELS as FEATURE_TEXT
from phishsense.services.features import FEATURE_NAMES
from phishsense.ui.charts import Chart
from phishsense.ui.context import AppContext
from phishsense.ui.widgets import Card, label


class ProgressView(QWidget):
    """Charts and measurement table for one trainee (used by the trainee's
    Progress page and by the admin's user drill-down)."""

    def __init__(self, title: str = "Progress"):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        content = QWidget()
        scroll.setWidget(content)
        col = QVBoxLayout(content)
        col.setContentsMargins(24, 20, 24, 20)
        self.title = label(title, "PageTitle")
        col.addWidget(self.title)
        self.summary = label("", "Muted", wrap=True)
        col.addWidget(self.summary)

        grid = QGridLayout()
        grid.setSpacing(14)
        self.risk_chart, self.rate_chart = Chart(), Chart()
        self.vser_chart, self.level_chart = Chart(), Chart()
        for i, chart in enumerate([self.risk_chart, self.rate_chart,
                                   self.vser_chart, self.level_chart]):
            card = Card()
            card.body.addWidget(chart)
            grid.addWidget(card, i // 2, i % 2)
        col.addLayout(grid)

        table_card = Card("Your behaviour measurements (latest)")
        self.table = QTableWidget(len(FEATURE_NAMES), 3)
        self.table.setHorizontalHeaderLabels(["Measure", "Value", "Meaning"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 200)
        self.table.setMinimumHeight(390)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table_card.body.addWidget(self.table)
        col.addWidget(table_card)

    def show_data(self, data: facade.ProgressData) -> None:
        points = data.points
        numbers = [p.number for p in points]
        if points:
            last = points[-1]
            self.summary.setText(
                f"{len(points)} completed simulation(s). Measurements use your last "
                f"{config.FEATURE_WINDOW_SESSIONS} sessions, so older mistakes stop counting "
                "once three newer sessions have replaced them."
                + (f" Current profile: {last.profile}." if last.profile else ""))
        else:
            self.summary.setText("Complete a simulation to see your progress.")

        self.risk_chart.risk_history(numbers, [p.probability for p in points])
        self.rate_chart.rate_history(numbers, {
            "Click rate": [p.features["click_rate"] for p in points],
            "Report accuracy": [p.features["report_accuracy"] for p in points],
        })
        if points:
            latest = points[-1].features
            self.vser_chart.bars("Error rate by attack type (latest)",
                                 [config.VECTOR_LABELS[v] for v in config.VECTORS],
                                 [latest[f"vser_{v}"] for v in config.VECTORS],
                                 colour="#dc2626")
        else:
            self.vser_chart.bars("Error rate by attack type (latest)", [], [])
        self.level_chart.bars("Current difficulty level",
                              [config.VECTOR_LABELS[v] for v in config.VECTORS],
                              [data.levels[v] for v in config.VECTORS],
                              maximum=config.MAX_LEVEL + 0.4, percent=False)

        for row, name in enumerate(FEATURE_NAMES):
            title, meaning = FEATURE_TEXT[name]
            if points:
                value = points[-1].features[name]
                shown = f"{value:.1f} s" if name == "mean_decision_latency_s" else f"{value:.0%}"
            else:
                shown = "-"
            for column, text in enumerate([title, shown, meaning]):
                self.table.setItem(row, column, QTableWidgetItem(text))


class ProgressPage(ProgressView):
    """The signed-in trainee's own progress."""

    def __init__(self, ctx: AppContext):
        super().__init__("Progress")
        self.ctx = ctx

    def refresh(self) -> None:
        data = self.ctx.try_call(self, facade.progress, self.ctx.user_id)
        if data is not None:
            self.show_data(data)
