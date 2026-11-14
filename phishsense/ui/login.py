"""Sign-in and registration dialog."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from phishsense import config
from phishsense.services import facade
from phishsense.ui.context import AppContext
from phishsense.ui.widgets import label


def _password_field() -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    return field


class LoginDialog(QDialog):
    def __init__(self, ctx: AppContext, parent: QWidget | None = None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("PhishSense - sign in")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.addWidget(label("PhishSense", "PageTitle"))
        layout.addWidget(label("Behaviour-driven adaptive phishing training", "Muted"))
        layout.addSpacing(8)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._sign_in_tab(), "Sign in")
        self.tabs.addTab(self._register_tab(), "Create account")
        layout.addWidget(self.tabs)

        self.error = label("", wrap=True)
        self.error.setStyleSheet("color: #dc2626;")
        layout.addWidget(self.error)
        layout.addWidget(label(
            "This is a training simulation. No real email is sent and no link is ever opened.",
            "Disclaimer", wrap=True))

    # ------------------------------------------------------------------ tabs
    def _sign_in_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        self.login_username = QLineEdit()
        self.login_password = _password_field()
        self.login_password.returnPressed.connect(self.sign_in)
        button = QPushButton("Sign in")
        button.setObjectName("Primary")
        button.setAutoDefault(False)  # Enter is handled by returnPressed only
        button.clicked.connect(self.sign_in)
        self.sign_in_button = button
        form.addRow("Username", self.login_username)
        form.addRow("Password", self.login_password)
        form.addRow("", button)
        return tab

    def _register_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        self.reg_username = QLineEdit()
        self.reg_username.setPlaceholderText("3-32 characters: a-z 0-9 . _ -")
        self.reg_full_name = QLineEdit()
        self.reg_department = QComboBox()
        self.reg_department.addItems(config.DEPARTMENTS)
        self.reg_password = _password_field()
        self.reg_password.setPlaceholderText(
            f"at least {config.PASSWORD_MIN_LENGTH} characters, a letter and a digit")
        self.reg_confirm = _password_field()
        self.reg_confirm.returnPressed.connect(self.register)
        button = QPushButton("Create account")
        button.setObjectName("Primary")
        button.setAutoDefault(False)
        button.clicked.connect(self.register)
        self.register_button = button
        form.addRow("Username", self.reg_username)
        form.addRow("Full name", self.reg_full_name)
        form.addRow("Department", self.reg_department)
        form.addRow("Password", self.reg_password)
        form.addRow("Confirm password", self.reg_confirm)
        form.addRow("", button)
        return tab

    # --------------------------------------------------------------- actions
    def _attempt(self, fn, *args, **kwargs) -> None:
        self.error.setText("")
        try:
            self.ctx.user = self.ctx.call(fn, *args, **kwargs)
        except facade.auth.AuthError as exc:
            self.error.setText(str(exc))
            return
        self.accept()

    def sign_in(self) -> None:
        self._attempt(facade.login, self.login_username.text(), self.login_password.text())

    def register(self) -> None:
        if self.reg_password.text() != self.reg_confirm.text():
            self.error.setText("The two passwords do not match.")
            return
        self._attempt(
            facade.register,
            username=self.reg_username.text(),
            full_name=self.reg_full_name.text(),
            department=self.reg_department.currentText(),
            password=self.reg_password.text(),
        )

    def keyPressEvent(self, event) -> None:  # Enter must not close the dialog
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return
        super().keyPressEvent(event)
