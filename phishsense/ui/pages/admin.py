"""Admin screens: overview, users (with drill-down), behaviour, departments,
models and data, reports. All data comes from :mod:`phishsense.services.admin`."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from phishsense import config
from phishsense.services import admin, reports
from phishsense.ui import theme
from phishsense.ui.charts import Chart
from phishsense.ui.context import AppContext
from phishsense.ui.dialogs import show_error
from phishsense.ui.pages.progress import FEATURE_TEXT, ProgressView
from phishsense.ui.widgets import Card, StatCard, label, pct
from phishsense.ui.worker import run_with_progress


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
class _Page(QWidget):
    """Scrollable page with a title; subclasses fill ``self.col``."""

    def __init__(self, ctx: AppContext, title: str, subtitle: str = ""):
        super().__init__()
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        content = QWidget()
        scroll.setWidget(content)
        self.col = QVBoxLayout(content)
        self.col.setContentsMargins(24, 20, 24, 20)
        self.col.setSpacing(14)
        self.col.addWidget(label(title, "PageTitle"))
        if subtitle:
            self.col.addWidget(label(subtitle, "Muted", wrap=True))

    def load(self, fn, *args):
        return self.ctx.try_call(self, fn, self.ctx.user_id, *args)


class _SortItem(QTableWidgetItem):
    """Shows formatted text but sorts by the underlying value (so 9% < 10%)."""

    def __lt__(self, other):
        a, b = self.data(Qt.ItemDataRole.UserRole), other.data(Qt.ItemDataRole.UserRole)
        if a is None:
            return b is not None          # missing values sort first
        if b is None:
            return False
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)


def _cell(value, text: str | None = None) -> QTableWidgetItem:
    """Table cell showing ``text`` (default: the value) and sorting by ``value``."""
    item = _SortItem("-" if value is None else (text if text is not None else str(value)))
    item.setData(Qt.ItemDataRole.UserRole, value)
    return item


def _table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setStretchLastSection(True)
    return table


def _fill(table: QTableWidget, rows: list[list[QTableWidgetItem]],
          sort_column: int | None = None, descending: bool = False) -> None:
    """Fill ``table``. Enabling sorting re-sorts by the header's sort
    indicator, so it is set explicitly: ``sort_column`` or none (keep the
    given order). The user can still click headers to re-sort."""
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for r, cells in enumerate(rows):
        for c, cell in enumerate(cells):
            table.setItem(r, c, cell)
    order = Qt.SortOrder.DescendingOrder if descending else Qt.SortOrder.AscendingOrder
    table.horizontalHeader().setSortIndicator(-1 if sort_column is None else sort_column, order)
    table.setSortingEnabled(True)


# ---------------------------------------------------------------------------
class AdminOverviewPage(_Page):
    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Overview", "All trainees, including sample users (counted separately).")
        grid = QGridLayout()
        grid.setSpacing(14)
        self.trainees = StatCard("Trainees")
        self.sessions = StatCard("Simulations completed")
        self.high = StatCard("High risk")
        self.training = StatCard("Training completed")
        self.rates = StatCard("Average click rate")
        for i, card in enumerate([self.trainees, self.sessions, self.high, self.training, self.rates]):
            grid.addWidget(card, 0, i)
        self.col.addLayout(grid)
        charts = QHBoxLayout()
        self.risk_chart, self.profile_chart = Chart(5, 2.6), Chart(5, 2.6)
        for chart in (self.risk_chart, self.profile_chart):
            card = Card()
            card.body.addWidget(chart)
            charts.addWidget(card)
        self.col.addLayout(charts)
        self.col.addStretch()

    def refresh(self) -> None:
        o = self.load(admin.overview)
        if o is None:
            return
        self.trainees.set(str(o.trainees), f"{o.sample_trainees} sample users, "
                          f"{o.assessed} assessed")
        self.sessions.set(str(o.sessions_completed), f"{o.sessions_failed} failed "
                          "(at least one phishing email clicked)")
        self.high.set(str(o.risk_counts[config.RISK_HIGH]), f"of {o.assessed} assessed trainees",
                      theme.BAD if o.risk_counts[config.RISK_HIGH] else None)
        done = (o.training_completed / o.training_assigned) if o.training_assigned else None
        self.training.set(pct(done), f"{o.training_completed} of {o.training_assigned} "
                          f"assignments; {o.required_open} required still open")
        self.rates.set(pct(o.mean_click_rate), f"report accuracy {pct(o.mean_report_accuracy)}; "
                       f"quiz answers correct {pct(o.quiz_correct_rate)}")
        self.risk_chart.bars("Trainees by current risk level", list(o.risk_counts),
                             list(o.risk_counts.values()),
                             maximum=max(1, *o.risk_counts.values()) * 1.15, percent=False,
                             colour=[theme.RISK_COLOURS[r] for r in o.risk_counts])
        self.profile_chart.bars("Trainees by behaviour profile", list(o.profile_counts),
                                list(o.profile_counts.values()),
                                maximum=max(1, *o.profile_counts.values()) * 1.15, percent=False,
                                colour=[theme.PROFILE_COLOURS[p] for p in o.profile_counts])


# ---------------------------------------------------------------------------
class UserDetailDialog(QDialog):
    def __init__(self, ctx: AppContext, user_id: int, parent: QWidget | None = None):
        super().__init__(parent)
        self.resize(1100, 800)
        detail = ctx.try_call(self, admin.user_detail, ctx.user_id, user_id)
        col = QVBoxLayout(self)
        tabs = self.tabs = QTabWidget()
        col.addWidget(tabs)
        if detail is None:
            return
        u = detail.user
        self.setWindowTitle(f"{u.full_name} ({u.username})")
        view = ProgressView(f"{u.full_name} - {u.department}"
                            + ("  [sample user]" if detail.is_sample else ""))
        view.show_data(detail.progress)
        tabs.addTab(view, "Progress")

        table = _table(["Training", "Status", "Quiz score", "Attempts", "Why it was assigned"])
        _fill(table, [[
            _cell(t.title),
            _cell("Completed" if t.completed else ("Required" if t.mandatory else "Open")),
            _cell(t.quiz_score, pct(t.quiz_score)),
            _cell(t.attempts),
            _cell(t.reason),
        ] for t in detail.training])
        tabs.addTab(table, f"Training ({len(detail.training)})")
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.accept)
        col.addWidget(close)


class AdminUsersPage(_Page):
    HEADERS = ["Name", "Username", "Department", "Sample", "Sessions", "Last session",
               "Profile", "Risk", "P(fail)", "Click rate", "Report acc.", "Training open",
               "Training done"]

    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Users", "Double-click a trainee to see their progress and training.")
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, username or department")
        self.search.textChanged.connect(self._apply_filter)
        self.show_sample = QCheckBox("Show sample users")
        self.show_sample.setChecked(True)
        self.show_sample.toggled.connect(self._apply_filter)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.show_sample)
        self.col.addLayout(bar)
        self.table = _table(self.HEADERS)
        self.table.setMinimumHeight(520)
        self.table.cellDoubleClicked.connect(self._open)
        self.col.addWidget(self.table, 1)
        self.rows: list[admin.UserRow] = []

    def refresh(self) -> None:
        rows = self.load(admin.users_table)
        if rows is None:
            return
        self.rows = rows
        cells = []
        for r in rows:
            risk = _cell(r.risk_level)
            if r.risk_level:
                risk.setForeground(Qt.GlobalColor.white)
                risk.setBackground(QColor(theme.RISK_COLOURS[r.risk_level]))
            name = _cell(r.full_name)
            name.setData(Qt.ItemDataRole.UserRole + 1, r.id)
            cells.append([
                name, _cell(r.username), _cell(r.department), _cell("sample" if r.is_sample else ""),
                _cell(r.sessions), _cell(r.last_session, r.last_session.strftime("%Y-%m-%d")
                                         if r.last_session else None),
                _cell(r.profile), risk, _cell(r.probability, pct(r.probability)),
                _cell(r.click_rate, pct(r.click_rate)),
                _cell(r.report_accuracy, pct(r.report_accuracy)),
                _cell(r.training_open), _cell(r.training_completed),
            ])
        _fill(self.table, cells, sort_column=8, descending=True)   # highest risk first
        self._apply_filter()

    def _apply_filter(self) -> None:
        needle = self.search.text().strip().lower()
        for row in range(self.table.rowCount()):
            text = " ".join(self.table.item(row, c).text().lower() for c in (0, 1, 2))
            sample = self.table.item(row, 3).text() == "sample"
            hidden = (needle and needle not in text) or (sample and not self.show_sample.isChecked())
            self.table.setRowHidden(row, bool(hidden))

    def _open(self, row: int, _column: int) -> None:
        user_id = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole + 1)
        self.open_user(user_id)

    def open_user(self, user_id: int) -> None:
        UserDetailDialog(self.ctx, user_id, self).exec()


# ---------------------------------------------------------------------------
class AdminBehaviourPage(_Page):
    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Behavioural analytics",
                         "Where trainees sit in the K-Means feature space, and which attacks "
                         "catch them out.")
        top = QHBoxLayout()
        cluster_card, vector_card = Card(), Card()
        self.cluster_chart = Chart(6, 4.2)
        self.vector_chart = Chart(4.5, 4.2)
        cluster_card.body.addWidget(self.cluster_chart)
        self.cluster_note = label("", "Disclaimer", wrap=True)
        cluster_card.body.addWidget(self.cluster_note)
        vector_card.body.addWidget(self.vector_chart)
        top.addWidget(cluster_card, 3)
        top.addWidget(vector_card, 2)
        self.col.addLayout(top)
        card = Card("Emails most often fallen for")
        self.emails = _table(["Subject", "Attack type", "Errors", "Times shown", "Error rate"])
        self.emails.setMinimumHeight(280)
        card.body.addWidget(self.emails)
        self.col.addWidget(card)

    def refresh(self) -> None:
        cmap = self.load(admin.cluster_map)
        groups = {p: [] for p in config.PROFILES}
        centroids, axes = [], ("component 1", "component 2")
        if cmap is not None:
            for point in cmap.points:
                groups[point.profile].append((point.x, point.y))
            centroids = cmap.centroids
            axes = (f"PCA component 1 ({cmap.explained_variance[0]:.0%} of variance)",
                    f"component 2 ({cmap.explained_variance[1]:.0%})")
            self.cluster_note.setText(
                f"Each dot is a trainee's latest feature snapshot; X marks a K-Means centroid "
                f"(model v{cmap.kmeans_version}). Projected to 2-D with PCA for display only; "
                "clustering uses all 12 features.")
        else:
            self.cluster_note.setText("")
        self.cluster_chart.scatter("Trainees by behaviour profile", groups,
                                   theme.PROFILE_COLOURS, centroids, axes,
                                   "No assessed trainees yet.")
        m = self.load(admin.mistakes)
        if m is None:
            return
        self.vector_chart.bars("Error rate by attack type", [v.label for v in m.by_vector],
                               [v.error_rate for v in m.by_vector], colour=theme.BAD)
        _fill(self.emails, [[
            _cell(e.subject), _cell(e.category_label), _cell(e.errors), _cell(e.shown),
            _cell(e.error_rate, pct(e.error_rate)),
        ] for e in m.top_emails], sort_column=2, descending=True)


# ---------------------------------------------------------------------------
class AdminDepartmentsPage(_Page):
    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Departments",
                         "Mean risk is the average predicted failure probability of assessed "
                         "trainees; rates are over every phishing email they have seen.")
        self.table = _table(["Department", "Trainees", "Assessed", "High risk", "Mean risk",
                             "Phishing seen", "Error rate", "Report rate"])
        self.table.setMinimumHeight(260)
        self.col.addWidget(self.table)
        charts = QHBoxLayout()
        self.risk_chart, self.error_chart = Chart(5, 3), Chart(5, 3)
        for chart in (self.risk_chart, self.error_chart):
            card = Card()
            card.body.addWidget(chart)
            charts.addWidget(card)
        self.col.addLayout(charts)
        self.col.addStretch()

    def refresh(self) -> None:
        rows = self.load(admin.departments)
        if rows is None:
            return
        _fill(self.table, [[
            _cell(d.department), _cell(d.trainees), _cell(d.assessed), _cell(d.high_risk),
            _cell(d.mean_probability, pct(d.mean_probability)), _cell(d.phishing_seen),
            _cell(d.error_rate, pct(d.error_rate)), _cell(d.report_rate, pct(d.report_rate)),
        ] for d in rows])
        assessed = [d for d in rows if d.mean_probability is not None]
        self.risk_chart.bars("Mean predicted risk", [d.department for d in assessed],
                             [d.mean_probability for d in assessed], colour=theme.WARN,
                             empty="No assessed trainees yet.")
        seen = [d for d in rows if d.error_rate is not None]
        self.error_chart.bars("Phishing error rate", [d.department for d in seen],
                              [d.error_rate for d in seen], colour=theme.BAD,
                              empty="No simulations yet.")


# ---------------------------------------------------------------------------
class AdminModelPage(_Page):
    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Models and data",
                         "Metrics come from cross-validation on synthetic data plus real "
                         "sessions from this installation. They show the pipeline works; they "
                         "are not research results.")
        cards = QHBoxLayout()
        self.kmeans_card, self.rf_card = Card("K-Means (behaviour profile)"), \
            Card("Random Forest (failure probability)")
        self.kmeans_text, self.rf_text = label("", wrap=True), label("", wrap=True)
        self.kmeans_card.body.addWidget(self.kmeans_text)
        self.rf_card.body.addWidget(self.rf_text)
        cards.addWidget(self.kmeans_card)
        cards.addWidget(self.rf_card)
        self.col.addLayout(cards)

        middle = QHBoxLayout()
        band_card = Card("Do the risk bands mean something? (cross-validated)")
        self.bands = _table(["Band", "Trainees in band", "Observed failure rate"])
        self.bands.setFixedHeight(130)
        band_card.body.addWidget(self.bands)
        band_card.body.addWidget(label(
            "Each band should contain trainees who actually failed at about the rate the band "
            "promises (Low < 25%, High > 60%). Rows are cross-validated: every prediction was "
            "made by a model that had not seen that trainee.", "Disclaimer", wrap=True))
        band_card.body.addStretch()
        imp_card = Card()
        self.importance = Chart(5, 3)
        imp_card.body.addWidget(self.importance)
        middle.addWidget(band_card, 2)
        middle.addWidget(imp_card, 3)
        self.col.addLayout(middle)

        actions = Card("Retrain and data")
        row = QHBoxLayout()
        self.retrain_button = QPushButton("Retrain models")
        self.retrain_button.setObjectName("Primary")
        self.retrain_button.clicked.connect(self.retrain)
        self.rescore = QCheckBox("Re-score all trainees with the new models")
        self.rescore.setChecked(True)
        self.data_note = label("", "Muted", wrap=True)
        row.addWidget(self.retrain_button)
        row.addWidget(self.rescore)
        row.addStretch()
        actions.body.addLayout(row)
        actions.body.addWidget(self.data_note)
        sample_row = QHBoxLayout()
        self.sample_count = QSpinBox()
        self.sample_count.setRange(1, 200)
        self.sample_count.setValue(24)
        generate = QPushButton("Generate sample users")
        generate.clicked.connect(self.generate_samples)
        remove = QPushButton("Remove sample users")
        remove.clicked.connect(self.remove_samples)
        sample_row.addWidget(label("Sample trainees:"))
        sample_row.addWidget(self.sample_count)
        sample_row.addWidget(generate)
        sample_row.addWidget(remove)
        sample_row.addStretch()
        actions.body.addLayout(sample_row)
        actions.body.addWidget(label(
            "Sample users are simulated trainees who play real sessions through the app with "
            "the synthetic behaviour model. They are marked 'sample' everywhere, cannot sign in, "
            "and can be removed at any time.", "Disclaimer", wrap=True))
        self.col.addWidget(actions)

        history_card = Card("Version history")
        self.history = _table(["Model", "Version", "Trained", "Synthetic rows", "Real rows",
                               "Active", "Key metric"])
        self.history.setMinimumHeight(200)
        history_card.body.addWidget(self.history)
        self.col.addWidget(history_card)

    def refresh(self) -> None:
        info = self.load(admin.model_info)
        if info is None:
            return
        km, rf = info.kmeans, info.random_forest
        if km is None:
            self.kmeans_text.setText("Not trained yet. Models train automatically after the "
                                     "first completed simulation, or use Retrain.")
        else:
            m = km.metrics
            self.kmeans_text.setText(
                f"<b>Version {km.version}</b> - {km.trained_at:%Y-%m-%d %H:%M}<br>"
                f"{km.n_synthetic} synthetic + {km.n_real} real feature snapshots<br>"
                f"Silhouette: {m.get('silhouette', 0):.3f}<br>"
                f"Synthetic profile-name accuracy: {m.get('synthetic_profile_name_accuracy', 0):.1%} "
                f"(adjusted Rand {m.get('synthetic_adjusted_rand_index', 0):.3f})")
        if rf is None:
            self.rf_text.setText("Not trained yet.")
            self.bands.setRowCount(0)
            self.importance.bars("Feature importance", [], [])
        else:
            cv = rf.metrics.get("cross_validation", {})
            real = rf.metrics.get("cross_validation_real_only")
            cm = cv.get("confusion_matrix", {})
            self.rf_text.setText(
                f"<b>Version {rf.version}</b> - {rf.trained_at:%Y-%m-%d %H:%M}<br>"
                f"{rf.n_synthetic} synthetic + {rf.n_real} real labelled pairs "
                f"(real weighted x{rf.metrics.get('real_sample_weight', config.REAL_SAMPLE_WEIGHT):g})<br>"
                f"ROC-AUC {cv.get('roc_auc', 0):.3f}, accuracy {cv.get('accuracy_at_0_5', 0):.3f}, "
                f"Brier {cv.get('brier', 0):.3f}<br>"
                f"Confusion matrix: TN {cm.get('tn')}, FP {cm.get('fp')}, FN {cm.get('fn')}, "
                f"TP {cm.get('tp')}<br>"
                + (f"Real pairs only: ROC-AUC {real['roc_auc']:.3f} (n={real['n']})" if real else
                   f"Real-only metrics appear once there are {config.MIN_REAL_SAMPLES_FOR_REPORT}+ "
                   "real pairs with both outcomes."))
            _fill(self.bands, [[
                _cell(band), _cell(b["n"]),
                _cell(b["observed_failure_rate"], pct(b["observed_failure_rate"])),
            ] for band, b in cv.get("risk_bands", {}).items()])
            imp = rf.metrics.get("feature_importances", {})
            names = list(imp)[:8]
            self.importance.bars("Random Forest feature importance",
                                 [FEATURE_TEXT[n][0] for n in names],
                                 [imp[n] for n in names], maximum=max(imp.values()) * 1.25)
        self.data_note.setText(
            f"Real labelled pairs available now: {info.real_pairs_available}. "
            f"Sample users: {info.sample_users}.")
        _fill(self.history, [[
            _cell("K-Means" if v.kind == config.MODEL_KIND_KMEANS else "Random Forest"),
            _cell(v.version), _cell(v.trained_at, f"{v.trained_at:%Y-%m-%d %H:%M}"),
            _cell(v.n_synthetic), _cell(v.n_real), _cell("yes" if v.is_active else ""),
            _cell(self._key_metric(v)),
        ] for v in info.history])

    @staticmethod
    def _key_metric(v: admin.ModelVersionInfo) -> str:
        if v.kind == config.MODEL_KIND_KMEANS:
            return f"silhouette {v.metrics.get('silhouette', 0):.3f}"
        return f"ROC-AUC {v.metrics.get('cross_validation', {}).get('roc_auc', 0):.3f}"

    # ------------------------------------------------------------ actions
    def _background(self, message: str, fn, done_text) -> None:
        admin_id = self.ctx.user_id
        run_with_progress(
            self, message, lambda: self.ctx.call(fn, admin_id),
            lambda result: (self.refresh(), self.notify(done_text(result))),
            lambda exc, tb: show_error(self, exc, tb))

    def notify(self, text: str) -> None:
        QMessageBox.information(self, "PhishSense", text)

    def retrain(self) -> None:
        rescore = self.rescore.isChecked()
        self._background(
            "Training new model versions...",
            lambda s, admin_id: admin.retrain(s, admin_id, rescore=rescore),
            lambda r: f"Trained K-Means v{r.kmeans_version} and Random Forest v{r.rf_version} "
                      f"with {r.real_pairs} real pairs. Re-scored {r.rescored_users} trainees.")

    def generate_samples(self) -> None:
        n = self.sample_count.value()
        self._background(
            f"Creating {n} sample trainees and playing their sessions...",
            lambda s, admin_id: admin.generate_sample_users(s, admin_id, n),
            lambda r: f"Created {r.users} sample users with {r.sessions} sessions.")

    def confirm(self, text: str) -> bool:
        return QMessageBox.question(self, "PhishSense", text) == QMessageBox.StandardButton.Yes

    def remove_samples(self) -> None:
        if not self.confirm("Delete all sample users and their sessions? Real users are not "
                            "affected. This cannot be undone."):
            return
        removed = self.load(admin.remove_sample_users)
        if removed is not None:
            self.refresh()
            self.notify(f"Removed {removed} sample users.")


# ---------------------------------------------------------------------------
class AdminReportsPage(_Page):
    def __init__(self, ctx: AppContext):
        super().__init__(ctx, "Reports", f"Default folder: {config.REPORTS_DIR}")
        for title, text, handler in [
            ("Users (CSV)", "One row per trainee: department, sessions, profile, risk, rates, "
             "training.", self.export_users),
            ("Sessions (CSV)", "One row per completed simulation, with the prediction made "
             "after it.", self.export_sessions),
            ("Summary report (PDF)", "Overview, departments, common mistakes, model metrics and "
             "trainee list.", self.export_pdf),
        ]:
            card = Card(title)
            row = QHBoxLayout()
            row.addWidget(label(text, wrap=True), 1)
            button = QPushButton("Export...")
            button.clicked.connect(handler)
            row.addWidget(button)
            card.body.addLayout(row)
            self.col.addWidget(card)
        self.last = label("", "Muted", wrap=True)
        self.col.addWidget(self.last)
        self.col.addStretch()

    def ask_path(self, default: Path, file_filter: str) -> Path | None:
        default.parent.mkdir(parents=True, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(self, "Save report", str(default), file_filter)
        return Path(path) if path else None

    def _export(self, name: str, file_filter: str, write) -> Path | None:
        path = self.ask_path(reports.default_path(name), file_filter)
        if path is None:
            return None
        try:
            self.ctx.call(lambda s: write(s, path))
        except Exception as exc:  # noqa: BLE001 - show and keep the app running
            show_error(self, exc)
            return None
        self.last.setText(f"Saved {path}")
        return path

    def export_users(self):
        return self._export("users.csv", "CSV (*.csv)", lambda s, p: reports.write_csv(
            reports.users_frame(s, self.ctx.user_id), p))

    def export_sessions(self):
        return self._export("sessions.csv", "CSV (*.csv)", lambda s, p: reports.write_csv(
            reports.sessions_frame(s, self.ctx.user_id), p))

    def export_pdf(self):
        return self._export("summary.pdf", "PDF (*.pdf)",
                            lambda s, p: reports.write_pdf(s, self.ctx.user_id, p))
