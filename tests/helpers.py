"""Shared test helpers: a controllable clock and scripted inbox behaviour."""

from __future__ import annotations

from datetime import datetime, timedelta

from phishsense import config
from phishsense.services import auth, tracking


class Clock:
    """Monotonic fake time. ``clock(ms)`` advances by ``ms`` and returns the time."""

    def __init__(self, start: datetime = datetime(2026, 1, 5, 9, 0, 0)):
        self.now = start

    def __call__(self, advance_ms: int = 0) -> datetime:
        self.now += timedelta(milliseconds=advance_ms)
        return self.now


def make_trainee(db, username: str, department: str = "Finance"):
    return auth.register_user(
        db, username=username, full_name=username.title() + " Tester",
        department=department, password="secret123",
    )


def act(db, sim, email, clock, *, action=None, hover_ms=0, inspect_sender=False, think_ms=1000):
    """Open ``email``, optionally inspect, then take ``action`` (an event type) or nothing."""
    tracking.record_event(db, sim, email, config.EVENT_OPEN, ts=clock(500))
    if inspect_sender:
        tracking.record_event(db, sim, email, config.EVENT_SENDER_INSPECT, ts=clock(300))
    if hover_ms and email.link_url:
        tracking.record_event(
            db, sim, email, config.EVENT_LINK_HOVER, value_ms=hover_ms, ts=clock(hover_ms)
        )
    if action is not None:
        tracking.record_event(db, sim, email, action, ts=clock(think_ms))


def click_action(email) -> str:
    return config.EVENT_LINK_CLICK if email.link_url else config.EVENT_ATTACHMENT_OPEN


def play_impulsive(db, sim, clock):
    """Clicks every link/attachment about a second after opening, never inspects."""
    for d in sim.deliveries:
        if d.email.link_url or d.email.attachment_name:
            act(db, sim, d.email, clock, action=click_action(d.email), think_ms=900)
        else:
            act(db, sim, d.email, clock)  # nothing to click: opened, then ignored


def play_vigilant(db, sim, clock):
    """Inspects sender and link, reports phishing, marks genuine mail safe."""
    for d in sim.deliveries:
        action = config.EVENT_REPORT if d.email.is_phishing else config.EVENT_MARK_SAFE
        act(db, sim, d.email, clock, action=action, hover_ms=2000,
            inspect_sender=True, think_ms=6000)


def play_passive(db, sim, clock):
    """Opens everything and acts on nothing."""
    for d in sim.deliveries:
        act(db, sim, d.email, clock)
