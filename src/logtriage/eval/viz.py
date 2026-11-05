"""Figures of the evaluation notebooks (plan 6.8). They are drawn from ground truth.

Colors follow the reference data-viz palette: fixed categorical order, one sequential hue,
neutral bands for periods. Each figure sits next to a table of the same numbers.
"""

from collections.abc import Mapping
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap, LogNorm
from matplotlib.figure import Figure
from matplotlib.ticker import FuncFormatter, PercentFormatter

from logtriage.data.periods import Periods

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_SECONDARY = "#52514e"
GRID = "#e6e5e0"
BAND = "#ecebe6"
SERIES = "#2a78d6"
# Fixed slot per log type, so a log type keeps its color and marker in every figure.
LOG_TYPE_STYLE = {
    "apache_access": ("#2a78d6", "o"),
    "apache_error": ("#eb6834", "s"),
    "audit": ("#1baf7a", "^"),
    "auth": ("#eda100", "D"),
    "dns": ("#e87ba4", "v"),
    "vpn": ("#008300", "P"),
}
SEQUENTIAL = LinearSegmentedColormap.from_list(
    "blue", ["#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"]
)
LINE_POINTS = 1.5


def _style(axes: plt.Axes, grid: str = "y") -> None:
    """Apply the recessive axes style."""
    axes.set_facecolor(SURFACE)
    for side in ("top", "right"):
        axes.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        axes.spines[side].set_color(GRID)
    axes.tick_params(colors=INK_SECONDARY, labelsize=8, length=0)
    if grid:
        axes.grid(axis=grid, color=GRID, linewidth=0.6)
        axes.set_axisbelow(True)


def _finish(figure: Figure, path: Path | None) -> Figure:
    """Save a figure as PNG when a path is given."""
    figure.patch.set_facecolor(SURFACE)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        figure.savefig(path, dpi=110, facecolor=SURFACE, bbox_inches="tight")
    return figure


def _shade_periods(
    axes: plt.Axes, periods: Periods, labels: bool = False, height: float = 1.04
) -> None:
    """Shade the calib period and mark where the evaluation period starts."""
    axes.axvspan(periods.fit_end, periods.train_end, color=BAND, linewidth=0, zorder=0)
    axes.axvline(periods.eval_start, color=INK_SECONDARY, linewidth=0.8)
    if labels:
        top = axes.get_xaxis_transform()
        spans = (
            ("fit", periods.train_start, periods.fit_end),
            ("calib", periods.fit_end, periods.train_end),
            ("evaluation", periods.eval_start, periods.eval_end),
        )
        for name, start, end in spans:
            middle = start + (end - start) / 2
            axes.text(
                middle, height, name, transform=top, ha="center", fontsize=8, color=INK_SECONDARY
            )


def plot_hourly_lines(
    table: pd.DataFrame, periods: Periods, title: str, path: Path | None = None
) -> Figure:
    """Draw parsed lines per hour, one panel per log type with its own scale."""
    log_types = sorted(table["log_type"].unique())
    hours = pd.date_range(periods.sim_start, periods.sim_end, freq="h", inclusive="left")
    figure, panels = plt.subplots(len(log_types), 1, figsize=(9, 7.2), sharex=True)
    for index, (axes, log_type) in enumerate(zip(panels, log_types, strict=True)):
        part = table[table["log_type"] == log_type].set_index("hour")["lines"]
        series = part.reindex(hours, fill_value=0)
        _style(axes)
        axes.plot(hours, series.to_numpy(), color=SERIES, linewidth=LINE_POINTS)
        axes.set_xlim(hours[0], periods.sim_end)
        axes.set_ylim(bottom=0)
        axes.yaxis.set_major_locator(plt.MaxNLocator(3, integer=True))
        axes.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:,.0f}"))
        axes.text(0, 1.03, log_type, transform=axes.transAxes, fontsize=9, color=INK)
        _shade_periods(axes, periods, labels=index == 0, height=1.24)
    panels[-1].xaxis.set_major_locator(mdates.DayLocator())
    panels[-1].xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    figure.suptitle(title, x=0.02, ha="left", fontsize=11, color=INK)
    figure.tight_layout(rect=(0, 0, 1, 0.98))
    return _finish(figure, path)


def plot_phase_log_types(
    traces: pd.DataFrame,
    phases: list[str],
    no_baseline: list[str],
    title: str,
    path: Path | None = None,
) -> Figure:
    """Draw labeled evaluation-period lines per phase and log type as an annotated grid."""
    log_types = list(LOG_TYPE_STYLE)
    grid = (
        traces.pivot_table(
            index="phase", columns="log_type", values="labeled_eval", aggfunc="sum", fill_value=0
        )
        .reindex(index=phases, columns=log_types, fill_value=0)
        .to_numpy()
    )
    figure, axes = plt.subplots(figsize=(7.4, 0.36 * len(phases) + 1.3))
    axes.imshow(
        np.ma.masked_equal(grid, 0),
        cmap=SEQUENTIAL,
        norm=LogNorm(vmin=1, vmax=max(int(grid.max()), 10)),
        aspect="auto",
    )
    axes.set_facecolor(SURFACE)
    for row, column in np.ndindex(grid.shape):
        value = int(grid[row, column])
        strong = value >= 300
        text = f"{value:,}" if value else "·"
        color = "white" if strong else (INK if value else INK_SECONDARY)
        axes.text(column, row, text, ha="center", va="center", fontsize=8, color=color)
    axes.set_xticks(
        range(len(log_types)),
        [f"{name}\n(no baseline)" if name in no_baseline else name for name in log_types],
    )
    axes.set_yticks(range(len(phases)), phases)
    axes.xaxis.tick_top()
    axes.tick_params(colors=INK_SECONDARY, labelsize=8, length=0)
    axes.set_xticks(np.arange(-0.5, len(log_types)), minor=True)
    axes.set_yticks(np.arange(-0.5, len(phases)), minor=True)
    axes.grid(which="minor", color=SURFACE, linewidth=2)
    axes.tick_params(which="minor", length=0)
    for spine in axes.spines.values():
        spine.set_visible(False)
    figure.suptitle(title, x=0.02, ha="left", fontsize=11, color=INK)
    figure.tight_layout(rect=(0, 0, 1, 0.97))
    return _finish(figure, path)


def plot_phase_timeline(
    intervals: pd.DataFrame,
    bins: pd.DataFrame,
    periods: Periods,
    title: str,
    path: Path | None = None,
) -> Figure:
    """Draw the phases over the simulation, then the main attack chain with its log types."""
    figure, (left, right) = plt.subplots(
        1, 2, figsize=(11.5, 4.6), gridspec_kw={"width_ratios": [1, 1.35]}
    )
    rows = list(intervals["phase"])[::-1]
    _style(left, "x")
    _shade_periods(left, periods, labels=True)
    for row, phase in enumerate(rows):
        item = intervals[intervals["phase"] == phase].iloc[0]
        start, end = max(item["start"], periods.sim_start), item["end"]
        left.plot([start, end], [row, row], color=SERIES, linewidth=4, solid_capstyle="round")
        # A phase can last seconds, far less than a pixel here, and must not vanish.
        left.scatter([start], [row], color=SERIES, s=26, zorder=3)
    left.set_yticks(range(len(rows)), rows)
    left.set_xlim(periods.sim_start, periods.sim_end)
    left.xaxis.set_major_locator(mdates.DayLocator())
    left.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))

    published = intervals[intervals["source"].str.startswith("ait_ads")]
    chain = published[~published["phase"].isin(["service_stop", "dnsteal"])]
    start, end = chain["start"].min(), chain["end"].max()
    inside = bins[(bins["bin"] >= start) & (bins["bin"] <= end)]
    inside = inside[inside["phase"].isin(chain["phase"])]
    names = list(chain["phase"])[::-1]
    _style(right, "x")
    for row, phase in enumerate(names):
        item = chain[chain["phase"] == phase].iloc[0]
        right.plot(
            [item["start"], item["end"]],
            [row, row],
            color=BAND,
            linewidth=11,
            solid_capstyle="butt",
            zorder=1,
        )
    offsets = dict(zip(LOG_TYPE_STYLE, np.linspace(-0.3, 0.3, len(LOG_TYPE_STYLE)), strict=True))
    for log_type, (color, marker) in LOG_TYPE_STYLE.items():
        part = inside[inside["log_type"] == log_type]
        if part.empty:
            continue
        rows_y = [names.index(phase) + offsets[log_type] for phase in part["phase"]]
        right.scatter(
            part["bin"],
            rows_y,
            color=color,
            marker=marker,
            s=30,
            edgecolors=SURFACE,
            linewidths=0.8,
            label=log_type,
            zorder=3,
        )
    right.set_yticks(range(len(names)), names)
    right.set_ylim(-0.7, len(names) - 0.3)
    right.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    right.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.09),
        ncols=6,
        frameon=False,
        fontsize=8,
        labelcolor=INK_SECONDARY,
        handletextpad=0.2,
        columnspacing=1.0,
    )
    right.set_title(
        f"Main attack chain, {start:%d %b}: labeled lines per 30 s",
        loc="left",
        fontsize=9,
        color=INK,
    )
    figure.suptitle(title, x=0.02, ha="left", fontsize=11, color=INK)
    figure.tight_layout(rect=(0, 0, 1, 0.97))
    return _finish(figure, path)


def plot_dns_contamination(
    tables: Mapping[str, tuple[pd.DataFrame, Periods]], path: Path | None = None
) -> Figure:
    """Draw the exfiltration share of `inet-firewall` DNS lines per training hour."""
    figure, panels = plt.subplots(len(tables), 1, figsize=(9, 2.3 * len(tables) + 0.6))
    for axes, (testbed, (table, periods)) in zip(panels, tables.items(), strict=True):
        _style(axes)
        axes.axvspan(periods.fit_end, periods.train_end, color=BAND, linewidth=0, zorder=0)
        axes.plot(table["hour"], table["labeled_host_share"], color=SERIES, linewidth=LINE_POINTS)
        axes.set_ylim(0, 1)
        axes.set_xlim(periods.train_start, periods.train_end)
        axes.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
        axes.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %H:%M"))
        axes.text(0, 1.04, testbed, transform=axes.transAxes, fontsize=9, color=INK)
        top = axes.get_xaxis_transform()
        middle = periods.fit_end + (periods.train_end - periods.fit_end) / 2
        axes.text(
            middle, 1.04, "calib", transform=top, ha="center", fontsize=8, color=INK_SECONDARY
        )
    figure.suptitle(
        "DNS exfiltration share of inet-firewall lines, per hour of the training period",
        x=0.02,
        ha="left",
        fontsize=11,
        color=INK,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.97))
    return _finish(figure, path)
