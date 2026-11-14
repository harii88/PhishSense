"""Application context shared by all windows: database access and the
signed-in user, plus uniform handling of user-facing errors."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from PySide6.QtWidgets import QMessageBox, QWidget
from sqlalchemy.orm import Session, sessionmaker

from phishsense.data.db import session_scope
from phishsense.services.admin import AdminError
from phishsense.services.auth import AuthError
from phishsense.services.facade import UserInfo
from phishsense.services.ml.registry import ModelError
from phishsense.services.quiz import QuizError
from phishsense.services.simulation import SimulationError
from phishsense.services.tracking import TrackingError

T = TypeVar("T")

# Errors whose message is written for the user; anything else is a bug.
USER_ERRORS = (AuthError, SimulationError, TrackingError, QuizError, ModelError, AdminError)


class AppContext:
    def __init__(self, factory: sessionmaker[Session]):
        self.factory = factory
        self.user: UserInfo | None = None

    @property
    def user_id(self) -> int:
        if self.user is None:
            raise RuntimeError("No user is signed in.")
        return self.user.id

    def call(self, fn: Callable[..., T], *args, **kwargs) -> T:
        """Run one facade function in its own transaction."""
        with session_scope(self.factory) as session:
            return fn(session, *args, **kwargs)

    def try_call(self, parent: QWidget | None, fn: Callable[..., T], *args, **kwargs) -> T | None:
        """Like :meth:`call`, but shows user-facing errors and returns None."""
        try:
            return self.call(fn, *args, **kwargs)
        except USER_ERRORS as exc:
            QMessageBox.warning(parent, "PhishSense", str(exc))
            return None
