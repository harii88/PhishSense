"""Matplotlib charts embedded in Qt (the desktop counterpart of Chart.js).

Uses ``matplotlib.figure.Figure`` directly (no pyplot), so there is no global
plotting state and no backend switching.
"""

from __future__ import annotations

from collections.abc import Sequence

import matplotlib
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

# Match the Qt font where it exists; fall back silently elsewhere.
matplotlib.rcParams["font.family"] = ["Segoe UI", "DejaVu Sans"]
matplotlib.rcParams["font.size"] = 9

from phishsense import config
from phishsense.ui import theme


class Chart(FigureCanvasQTAgg):
    def __init__(self, width: float = 4.8, height: float = 2.8):
        self.figure = Figure(figsize=(width, height), dpi=100, facecolor=theme.CARD)
        super().__init__(self.figure)
        self.setMinimumHeight(int(height * 70))

    def _axes(self, title: str):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.set_title(title, fontsize=10, loc="left", color=theme.TEXT)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        for side in ("left", "bottom"):
            ax.spines[side].set_color(theme.BORDER)
        ax.tick_params(colors=theme.SLATE, labelsize=8)
        ax.set_facecolor(theme.CARD)
        return ax

    def _empty(self, title: str, message: str) -> None:
        ax = self._axes(title)
        ax.axis("off")
        ax.text(0.5, 0.5, message, ha="center", va="center", color=theme.SLATE, fontsize=9,
                transform=ax.transAxes)
        self.draw_idle()

    def _finish(self) -> None:
        self.figure.tight_layout()
        self.draw_idle()

    # ------------------------------------------------------------------ charts
    def risk_gauge(self, probability: float | None) -> None:
        """Horizontal bar across the three risk bands with a marker."""
        title = "Predicted chance of failing the next simulation"
        if probability is None:
            return self._empty(title, "Complete your first simulation to get a prediction.")
        ax = self._axes(title)
        bands = [(0, config.RISK_LOW_BELOW, theme.GOOD, config.RISK_LOW),
                 (config.RISK_LOW_BELOW, config.RISK_HIGH_ABOVE, theme.WARN, config.RISK_MODERATE),
                 (config.RISK_HIGH_ABOVE, 1.0, theme.BAD, config.RISK_HIGH)]
        for lo, hi, colour, name in bands:
            ax.barh(0, hi - lo, left=lo, height=0.35, color=colour, alpha=0.35)
            ax.text((lo + hi) / 2, -0.38, name, ha="center", va="top", fontsize=8,
                    color=theme.SLATE)
        # Marker: a vertical line through the bar, with the value above it.
        ax.plot([probability, probability], [-0.22, 0.22], color=theme.NAVY, linewidth=3)
        ax.plot(probability, 0.3, marker="v", color=theme.NAVY, markersize=9)
        ax.text(probability, 0.42, f"{probability:.0%}", ha="center", va="bottom",
                fontsize=12, fontweight="bold", color=theme.TEXT)
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.6, 0.75)
        ax.set_yticks([])
        ax.set_xticks([0, config.RISK_LOW_BELOW, config.RISK_HIGH_ABOVE, 1.0])
        ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
        ax.spines["left"].set_visible(False)
        self._finish()

    def risk_history(self, numbers: Sequence[int], probabilities: Sequence[float | None]) -> None:
        title = "Predicted risk after each session"
        pairs = [(n, p) for n, p in zip(numbers, probabilities) if p is not None]
        if not pairs:
            return self._empty(title, "No predictions yet.")
        ax = self._axes(title)
        ax.axhspan(0, config.RISK_LOW_BELOW, color=theme.GOOD, alpha=0.08)
        ax.axhspan(config.RISK_LOW_BELOW, config.RISK_HIGH_ABOVE, color=theme.WARN, alpha=0.08)
        ax.axhspan(config.RISK_HIGH_ABOVE, 1, color=theme.BAD, alpha=0.08)
        xs, ys = zip(*pairs)
        ax.plot(xs, ys, marker="o", color=theme.NAVY, linewidth=2)
        ax.set_ylim(0, 1)
        ax.set_xticks(list(xs))
        ax.set_xlabel("session", fontsize=8, color=theme.SLATE)
        ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
        self._finish()

    def rate_history(self, numbers: Sequence[int], series: dict[str, Sequence[float]]) -> None:
        title = "Click rate and report accuracy (rolling window)"
        if not numbers:
            return self._empty(title, "No sessions yet.")
        ax = self._axes(title)
        colours = [theme.BAD, theme.GOOD, theme.ACCENT, theme.WARN]
        for (label, values), colour in zip(series.items(), colours):
            ax.plot(numbers, values, marker="o", label=label, color=colour, linewidth=2)
        ax.set_ylim(-0.02, 1.02)
        ax.set_xticks(list(numbers))
        ax.set_xlabel("session", fontsize=8, color=theme.SLATE)
        ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
        ax.legend(fontsize=8, frameon=False)
        self._finish()

    def scatter(self, title: str, groups: dict[str, list[tuple[float, float]]],
                colours: dict[str, str], centroids: Sequence[tuple[str, float, float]],
                axis_labels: tuple[str, str], empty: str) -> None:
        if not any(groups.values()):
            return self._empty(title, empty)
        ax = self._axes(title)
        for name, pts in groups.items():
            if pts:
                xs, ys = zip(*pts)
                ax.scatter(xs, ys, s=36, color=colours[name], alpha=0.75, label=f"{name} ({len(pts)})",
                           edgecolors="white", linewidths=0.6)
        for name, x, y in centroids:
            ax.scatter([x], [y], marker="X", s=140, color=colours[name], edgecolors=theme.NAVY,
                       linewidths=1.2)
        ax.set_xlabel(axis_labels[0], fontsize=8, color=theme.SLATE)
        ax.set_ylabel(axis_labels[1], fontsize=8, color=theme.SLATE)
        ax.legend(fontsize=7, frameon=False, loc="best")
        self._finish()

    def bars(self, title: str, labels: Sequence[str], values: Sequence[float], *,
             maximum: float = 1.0, percent: bool = True,
             colour: str | Sequence[str] = theme.ACCENT, empty: str = "No data yet.") -> None:
        if not labels:
            return self._empty(title, empty)
        ax = self._axes(title)
        ax.barh(list(labels), list(values), color=colour, alpha=0.85)
        ax.set_xlim(0, maximum)
        ax.invert_yaxis()
        for i, v in enumerate(values):
            ax.text(v + maximum * 0.02, i, f"{v:.0%}" if percent else f"{v:g}", va="center",
                    fontsize=8, color=theme.TEXT)
        if percent:
            ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0%}")
        self._finish()
