"""Run slow work (model training on first use, session analysis) off the GUI
thread, with a busy dialog so the window never freezes.

The work function opens its own database transaction inside the worker
thread; SQLAlchemy sessions are never shared between threads.

Threading detail: results come back through slots of a ``_Bridge`` QObject
created on the GUI thread. Qt then delivers the worker's signals as queued
calls on the GUI thread. (Connecting a signal to a bare lambda would run the
lambda on the worker thread, and touching widgets from there crashes Qt.)
"""

from __future__ import annotations

import traceback
from collections.abc import Callable

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal, Slot
from PySide6.QtWidgets import QProgressDialog, QWidget


class _Bridge(QObject):
    done = Signal(object)
    failed = Signal(object, str)

    def __init__(self, on_done, on_error, finish):
        super().__init__()
        self._on_done, self._on_error, self._finish = on_done, on_error, finish
        self.done.connect(self._deliver_done)
        self.failed.connect(self._deliver_failed)

    @Slot(object)
    def _deliver_done(self, result) -> None:
        self._finish()
        self._on_done(result)

    @Slot(object, str)
    def _deliver_failed(self, exc, tb) -> None:
        self._finish()
        self._on_error(exc, tb)


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], object], bridge: _Bridge):
        super().__init__()
        self.fn, self.bridge = fn, bridge
        self.setAutoDelete(False)

    def run(self) -> None:  # worker thread
        try:
            result = self.fn()
        except Exception as exc:
            self.bridge.failed.emit(exc, traceback.format_exc())
        else:
            self.bridge.done.emit(result)


_running: set[_Task] = set()  # keep tasks and bridges alive until delivered


def run_with_progress(
    parent: QWidget,
    message: str,
    fn: Callable[[], object],
    on_done: Callable[[object], None],
    on_error: Callable[[Exception, str], None],
) -> None:
    dialog = QProgressDialog(message, None, 0, 0, parent)
    dialog.setWindowTitle("PhishSense")
    dialog.setWindowModality(Qt.WindowModality.WindowModal)
    dialog.setMinimumDuration(300)
    dialog.setCancelButton(None)

    task: _Task | None = None

    def finish() -> None:
        dialog.reset()
        _running.discard(task)

    bridge = _Bridge(on_done, on_error, finish)
    task = _Task(fn, bridge)
    _running.add(task)
    QThreadPool.globalInstance().start(task)
