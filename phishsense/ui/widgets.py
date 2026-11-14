"""Small reusable widgets."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


def label(text: str = "", name: str | None = None, *, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


class Card(QFrame):
    """White rounded panel with an optional small uppercase title."""

    def __init__(self, title: str | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(16, 14, 16, 14)
        self.body.setSpacing(6)
        if title:
            self.body.addWidget(label(title, "CardTitle"))


class StatCard(Card):
    """Title, big value, small caption."""

    def __init__(self, title: str, parent: QWidget | None = None):
        super().__init__(title, parent)
        self.value = label("-", "CardValue")
        self.caption = label("", "Muted", wrap=True)
        self.body.addWidget(self.value)
        self.body.addWidget(self.caption)
        self.body.addStretch()

    def set(self, value: str, caption: str = "", colour: str | None = None) -> None:
        self.value.setText(value)
        self.value.setStyleSheet(f"color: {colour};" if colour else "")
        self.caption.setText(caption)


def badge(text: str, colour: str) -> QLabel:
    widget = QLabel(text)
    widget.setStyleSheet(
        f"background: {colour}; color: white; border-radius: 9px; padding: 3px 10px;"
        "font-weight: 600; font-size: 9pt;"
    )
    return widget


def pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"
