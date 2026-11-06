"""Charts of the dashboard (plan 9.1, 6.8)."""

from datetime import datetime, timedelta

import pandas as pd
import plotly.graph_objects as go

# Categorical slots in fixed order, a palette validated for color vision deficiency.
SERIES_COLORS = (
    "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948",
)  # fmt: skip
SURFACE = "#fcfcfb"
TEXT = "#52514e"
GRID = "#e6e5e1"
SPAN = "rgba(82, 81, 78, 0.10)"
MAX_STREAMS = len(SERIES_COLORS)


def incident_streams(windows: pd.DataFrame, incident_id: str) -> list[tuple[str, str]]:
    """Return the `(host, log_type)` of an incident, highest score first, at most `MAX_STREAMS`.

    Args:
        windows: Scored windows.
        incident_id: The incident.

    Returns:
        The streams. Colors follow this list, which has no dependence on the replay clock once the
        incident is closed.
    """
    own = windows[windows["incident_id"] == incident_id]
    peak = own.groupby(["host", "log_type"])["score"].max().reset_index()
    ordered = peak.sort_values(["score", "host", "log_type"], ascending=[False, True, True])
    return list(zip(ordered["host"], ordered["log_type"], strict=True))[:MAX_STREAMS]


def stream_windows(
    windows: pd.DataFrame,
    streams: list[tuple[str, str]],
    start: datetime,
    end: datetime,
    context: timedelta,
) -> pd.DataFrame:
    """Return the windows of some streams around an incident."""
    keys = pd.MultiIndex.from_frame(windows[["host", "log_type"]])
    near = windows["window_start"].between(start - context, end + context)
    return windows[keys.isin(streams) & near]


def with_gaps(part: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    """Add an empty row where windows are missing, so that a line does not bridge quiet minutes."""
    ordered = part.sort_values("window_start")
    jumps = ordered["window_start"].diff() > timedelta(seconds=window_seconds)
    holes = ordered.loc[jumps, ["window_start"]].copy()
    holes["window_start"] -= timedelta(seconds=window_seconds)
    joined = pd.concat([ordered, holes]).sort_values("window_start", kind="stable")
    return joined.reset_index(drop=True)


def timeline_figure(
    windows: pd.DataFrame,
    streams: list[tuple[str, str]],
    start: datetime,
    end: datetime,
    threshold: float,
    window_seconds: int,
) -> go.Figure:
    """Draw window scores per host and log type around an incident.

    Args:
        windows: Windows to draw, already limited by the replay clock.
        streams: Streams, in color order.
        start: Incident start, for the shaded span.
        end: Incident end.
        threshold: Score from which a window is anomalous.
        window_seconds: Window length.

    Returns:
        The figure: one axis, score from 0 to 1.
    """
    figure = go.Figure()
    for index, (host, log_type) in enumerate(streams):
        part = windows[(windows["host"] == host) & (windows["log_type"] == log_type)]
        name = f"{host} · {log_type}"
        color = SERIES_COLORS[index]
        lined = with_gaps(part, window_seconds)
        figure.add_scatter(
            x=lined["window_start"],
            y=lined["score"],
            name=name,
            legendgroup=name,
            mode="lines",
            line={"color": color, "width": 2},
            hovertemplate="%{y:.3f}<extra>" + name + "</extra>",
        )
        flagged = part[part["is_anomalous"].astype(bool)]
        figure.add_scatter(
            x=flagged["window_start"],
            y=flagged["score"],
            name=f"{name} anomalous",
            legendgroup=name,
            showlegend=False,
            mode="markers",
            marker={
                "color": color,
                "size": 11,
                "symbol": "diamond",
                "line": {"color": SURFACE, "width": 2},
            },
            hovertemplate="%{y:.3f} anomalous<extra>" + name + "</extra>",
        )
    figure.add_vrect(x0=start, x1=end, fillcolor=SPAN, line_width=0, layer="below")
    figure.add_hline(
        y=threshold,
        line={"color": TEXT, "width": 1, "dash": "dot"},
        annotation_text=f"threshold {threshold}",
        annotation_position="bottom right",
        annotation_font={"color": TEXT, "size": 11},
    )
    figure.update_layout(
        height=340,
        margin={"l": 48, "r": 16, "t": 16, "b": 40},
        plot_bgcolor=SURFACE,
        paper_bgcolor=SURFACE,
        font={"color": TEXT},
        hovermode="x unified",
        showlegend=len(streams) >= 2,
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "x": 0},
    )
    figure.update_xaxes(showgrid=False, linecolor=GRID, title_text="window start (UTC)")
    figure.update_yaxes(range=[0, 1.04], gridcolor=GRID, zeroline=False, title_text="score")
    return figure
