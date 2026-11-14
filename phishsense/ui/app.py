"""Application entry point: database, sign-in loop, main window."""

from __future__ import annotations

import sys

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QDialog

from phishsense.data.db import create_db_engine, init_db, make_session_factory, session_scope
from phishsense.data.seed import seed_content
from phishsense.ui.context import AppContext
from phishsense.ui.login import LoginDialog
from phishsense.ui.main_window import MainWindow
from phishsense.ui.theme import STYLE_SHEET


def main(argv: list[str] | None = None) -> int:
    app = QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("PhishSense")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(STYLE_SHEET)

    engine = create_db_engine()
    init_db(engine)
    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        seed_content(session)  # idempotent: keeps content in sync with the code

    ctx = AppContext(factory)
    try:
        while True:
            if LoginDialog(ctx).exec() != QDialog.DialogCode.Accepted:
                return 0
            window = MainWindow(ctx)
            window.show()
            app.exec()
            if not window.logged_out:
                return 0
    finally:
        engine.dispose()
