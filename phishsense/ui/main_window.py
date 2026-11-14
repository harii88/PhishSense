"""Main window: sidebar navigation and one page per area."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QListWidget,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from phishsense.ui.context import AppContext
from phishsense.ui.dialogs import AccountDialog
from phishsense.ui.pages.dashboard import DashboardPage
from phishsense.ui.pages.inbox import InboxPage
from phishsense.ui.pages.admin import (
    AdminBehaviourPage,
    AdminDepartmentsPage,
    AdminModelPage,
    AdminOverviewPage,
    AdminReportsPage,
    AdminUsersPage,
)
from phishsense.ui.pages.progress import ProgressPage
from phishsense.ui.pages.training import TrainingPage
from phishsense.ui.widgets import label


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext):
        super().__init__()
        self.ctx = ctx
        self.logged_out = False
        self.setWindowTitle("PhishSense")
        self.resize(1280, 800)

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._sidebar())
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.pages: dict[str, QWidget] = {}
        if ctx.user.is_admin:
            self._add_page("Overview", AdminOverviewPage(ctx))
            self._add_page("Users", AdminUsersPage(ctx))
            self._add_page("Behaviour", AdminBehaviourPage(ctx))
            self._add_page("Departments", AdminDepartmentsPage(ctx))
            self._add_page("Models and data", AdminModelPage(ctx))
            self._add_page("Reports", AdminReportsPage(ctx))
        else:
            self._add_page("Dashboard", DashboardPage(ctx, self.navigate))
            self._add_page("Simulated inbox", InboxPage(ctx, self.navigate))
            self._add_page("Training", TrainingPage(ctx, self.navigate))
            self._add_page("Progress", ProgressPage(ctx))
        self.nav.currentRowChanged.connect(self._show_row)
        self.nav.setCurrentRow(0)

    # ------------------------------------------------------------- layout
    def _sidebar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Sidebar")
        bar.setFixedWidth(230)
        col = QVBoxLayout(bar)
        col.setContentsMargins(0, 20, 0, 16)
        title = label("PhishSense", "AppTitle")
        title.setContentsMargins(18, 0, 0, 0)
        subtitle = label("Adaptive phishing training", "AppSubtitle")
        subtitle.setContentsMargins(18, 0, 0, 12)
        col.addWidget(title)
        col.addWidget(subtitle)

        self.nav = QListWidget()
        self.nav.setObjectName("NavList")
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        col.addWidget(self.nav, 1)

        user = self.ctx.user
        who = label(f"{user.full_name}\n{user.department} - {user.role}", "AppSubtitle")
        who.setContentsMargins(18, 0, 0, 8)
        col.addWidget(who)
        account = QPushButton("Account settings")
        account.setObjectName("SidebarButton")
        account.clicked.connect(self._open_account)
        logout = QPushButton("Log out")
        logout.setObjectName("SidebarButton")
        logout.clicked.connect(self._log_out)
        col.addWidget(account)
        col.addSpacing(6)
        col.addWidget(logout)
        return bar

    def _add_page(self, title: str, page: QWidget) -> None:
        self.pages[title] = page
        self.stack.addWidget(page)
        self.nav.addItem(title)

    # ---------------------------------------------------------- navigation
    def _show_row(self, row: int) -> None:
        page = self.stack.widget(row)
        self.stack.setCurrentIndex(row)
        if hasattr(page, "refresh"):
            page.refresh()

    def navigate(self, title: str) -> None:
        row = list(self.pages).index(title)
        if self.nav.currentRow() == row:
            self._show_row(row)
        else:
            self.nav.setCurrentRow(row)

    def page(self, title: str) -> QWidget:
        return self.pages[title]

    # ------------------------------------------------------------ actions
    def _open_account(self) -> None:
        AccountDialog(self.ctx, self).exec()

    def _log_out(self) -> None:
        inbox = self.pages.get("Simulated inbox")
        if inbox is not None:
            inbox.flush_hover()
        self.logged_out = True
        self.ctx.user = None
        self.close()

    def closeEvent(self, event) -> None:
        inbox = self.pages.get("Simulated inbox")
        if inbox is not None and self.ctx.user is not None:
            inbox.flush_hover()
        super().closeEvent(event)
