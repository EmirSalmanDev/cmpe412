"""Shared Streamlit parts: cached resources, the replay panel, and report rendering.

Log text and model output are attacker-influenced, so they are shown with `st.text`, `st.code` or
in tables, never as Markdown. An image in rendered Markdown would be fetched by the browser.
"""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb
import streamlit as st

from logtriage.agents.chat import ChatAgent, open_memory
from logtriage.agents.runner import run_incidents
from logtriage.agents.schemas import Claim, IncidentReport
from logtriage.agents.tools import AgentTools
from logtriage.app.data import (
    AppOptions,
    Dataset,
    View,
    build_view,
    database_path,
    evidence_by_eid,
    load_dataset,
    reports_path,
)
from logtriage.app.replay import (
    ReplayClock,
    check_live,
    missing_reports,
    needs_rerun,
    replay_bounds,
)
from logtriage.config import Settings, load_settings
from logtriage.data.store import connect_agent

CLOCK = "replay_clock"
VIEW = "view"
SELECTED = "selected_incident"
SHOWN_CLOSED = "shown_closed"
DRAWING = "drawing_page"
ATTEMPTED = "live_attempted"
LIVE_STOP = "live_stopped"
VERDICTS = {
    "malicious": ("red", ":material/gpp_bad:"),
    "uncertain": ("orange", ":material/help:"),
    "benign": ("green", ":material/verified_user:"),
}


@st.cache_resource(show_spinner=False)
def settings_of(config: str) -> Settings:
    """Load the settings once."""
    return load_settings(Path(config))


@st.cache_resource(show_spinner=False)
def connection_of(path: str) -> duckdb.DuckDBPyConnection:
    """Open the locked connection, once: a process can hold only one per file."""
    return connect_agent(path)


@st.cache_resource(show_spinner=False)
def dataset_of(path: str) -> Dataset:
    """Read incidents and windows once."""
    return load_dataset(connection_of(path))


@st.cache_resource(show_spinner=False)
def memory_of(config: str) -> Any:
    """Open the chat memory once."""
    return open_memory(settings_of(config))


@st.cache_resource(show_spinner="Loading the agent tools...")
def tools_of(testbed: str, config: str) -> AgentTools:
    """Open the agent tools once, on the shared connection. This loads the embedding model."""
    settings = settings_of(config)
    connection = connection_of(str(database_path(settings, testbed)))
    return AgentTools.open(testbed, settings, connection=connection)


@st.cache_resource(show_spinner=False)
def chat_agent_of(testbed: str, config: str) -> ChatAgent:
    """Open the chat agent once, so that `llm.max_usd_per_run` covers the whole app session."""
    return ChatAgent.open(
        testbed, settings_of(config), tools=tools_of(testbed, config), saver=memory_of(config)
    )


def utc(moment: datetime) -> str:
    """Render a time."""
    return f"{moment:%Y-%m-%d %H:%M:%S} UTC"


def _start_clock(start: datetime, end: datetime, speed: float) -> ReplayClock:
    """Return a stopped clock at the start."""
    return ReplayClock(start, end, speed, start, time.monotonic())


def _clock_panel(ends: list[datetime], follows_clock: bool) -> None:
    """Show the simulated time. In a fragment, this is what ticks; it redraws the page if needed."""
    clock: ReplayClock = st.session_state[CLOCK]
    wall = time.monotonic()
    moment = clock.now(wall)
    span = (clock.end - clock.start).total_seconds()
    done = (moment - clock.start).total_seconds() / span if span else 1.0
    st.text(utc(moment))
    st.progress(min(max(done, 0.0), 1.0))
    closed = sum(item <= moment for item in ends)
    st.caption(f"{closed} incidents closed")
    if st.session_state[DRAWING] or not clock.running:
        return
    if clock.finished(wall):
        st.session_state[CLOCK] = clock.pause(wall)
        st.rerun()
    if needs_rerun(follows_clock, st.session_state.get(SHOWN_CLOSED, 0), closed):
        st.rerun()


def replay_sidebar(dataset: Dataset, settings: Settings, follows_clock: bool) -> datetime:
    """Draw the replay controls and return the simulated time.

    Args:
        dataset: Incidents and windows.
        settings: Loaded settings.
        follows_clock: The current page draws windows, so each tick redraws it.

    Returns:
        The simulated time. With replay off it is the end, so that all data shows.
    """
    app = settings.app
    start, end = replay_bounds(
        dataset.incidents,
        dataset.scores,
        settings.features.window_seconds,
        timedelta(minutes=app.replay_lead_minutes),
    )
    st.sidebar.subheader("Replay")
    if not st.sidebar.toggle("Replay mode", key="replay_on"):
        st.sidebar.caption("Showing all data.")
        return end
    if CLOCK not in st.session_state:
        st.session_state[CLOCK] = _start_clock(start, end, app.default_speed)
    clock: ReplayClock = st.session_state[CLOCK]

    speed = st.sidebar.select_slider(
        "Speed", app.speeds, value=app.default_speed, format_func=lambda value: f"{value}×"
    )
    if speed != clock.speed:
        clock = clock.with_speed(speed, time.monotonic())
        st.session_state[CLOCK] = clock
    chosen = st.sidebar.datetime_input(
        "Start (UTC)",
        value=start.replace(tzinfo=None),
        min_value=start.replace(tzinfo=None) - timedelta(days=7),
        max_value=end.replace(tzinfo=None),
        key="replay_start",
    )
    first = chosen.replace(tzinfo=UTC)
    if first != clock.start:
        clock = ReplayClock(first, end, clock.speed, first, time.monotonic())
        st.session_state[CLOCK] = clock

    play, reset = st.sidebar.columns(2)
    wall = time.monotonic()
    if clock.running:
        if play.button("Pause", icon=":material/pause:", width="stretch"):
            st.session_state[CLOCK] = clock.pause(wall)
            st.rerun()
    elif not clock.finished(wall) and play.button(
        "Play", icon=":material/play_arrow:", width="stretch"
    ):
        st.session_state[CLOCK] = clock.play(wall)
        st.rerun()
    if reset.button("Reset", icon=":material/replay:", width="stretch"):
        st.session_state[CLOCK] = clock.restart(clock.start, wall)
        st.rerun()

    ends = [item.to_pydatetime() for item in dataset.incidents["end"]]
    every = app.tick_seconds if clock.running else None
    # A fragment also runs inline in a full run. A rerun from there would never end, so only the
    # timer's own runs may ask for one.
    st.session_state[DRAWING] = True
    with st.sidebar:
        st.fragment(_clock_panel, run_every=every)(ends, follows_clock)
    st.session_state[DRAWING] = False
    return st.session_state[CLOCK].now(time.monotonic())


def current_view(
    options: AppOptions, settings: Settings, dataset: Dataset, moment: datetime
) -> View:
    """Build and store the view of this run."""
    view = build_view(
        dataset,
        reports_path(settings, options.testbed),
        moment,
        settings.features.window_seconds,
    )
    st.session_state[VIEW] = view
    st.session_state[SHOWN_CLOSED] = len(view.incidents)
    return view


def run_live(options: AppOptions, settings: Settings, view: View) -> View:
    """Compute one missing report of a closed incident, for `--live` (plan 9.1).

    The refusal of `logtriage app --live` is repeated here, at the point of the paid call, and no
    re-run reason is ever passed, so the guard of the runner stays in force as well.

    Returns:
        The view, with the new report if one came.
    """
    check_live(options.testbed)
    if LIVE_STOP in st.session_state:
        st.sidebar.warning(st.session_state[LIVE_STOP])
        return view
    attempted: set[str] = st.session_state.setdefault(ATTEMPTED, set())
    waiting = missing_reports(view.incidents, view.reports, attempted)
    if not waiting:
        return view
    incident_id = waiting[0]
    attempted.add(incident_id)
    tools = tools_of(options.testbed, str(options.config))
    agent = chat_agent_of(options.testbed, str(options.config))
    with st.sidebar, st.spinner(f"Investigating {incident_id}..."), agent.lock:
        summary = run_incidents(options.testbed, settings, [incident_id], tools=tools)
    if summary.aborted:
        st.session_state[LIVE_STOP] = summary.aborted
    return current_view(
        options, settings, dataset_of(str(database_path(settings, options.testbed))), view.moment
    )


def get_view() -> View:
    """Return the view of this run."""
    return st.session_state[VIEW]


def pick_incident(view: View, page: str) -> str | None:
    """Draw the incident selector, over closed incidents only.

    Args:
        view: The view.
        page: Page name, to key the widget.

    Returns:
        The selected incident, or None if no incident has closed yet.
    """
    ordered = view.incidents.sort_values(["priority", "start"], ascending=[False, True])
    ids = ordered["incident_id"].tolist()
    if not ids:
        st.info("No incident has closed yet.")
        return None
    current = st.session_state.get(SELECTED)
    index = ids.index(current) if current in ids else 0
    chosen = st.selectbox("Incident", ids, index=index, key=f"pick_{page}")
    st.session_state[SELECTED] = chosen
    return chosen


def verdict_badge(verdict: str, confidence: float) -> None:
    """Show a verdict: always its word and an icon, not color alone."""
    color, icon = VERDICTS[verdict]
    st.badge(f"{verdict} · confidence {confidence:.2f}", icon=icon, color=color)


def show_line(eid: str, line_id: str, stamp: str, host: str, log_type: str, raw: str) -> None:
    """Show one cited line: its eid, its real `line_id` and the raw text, unrendered."""
    st.text(f"{eid} · {stamp} · {host} · {log_type} · {line_id}")
    st.code(raw, language=None, wrap_lines=True)


def show_claim(claim: Claim, report: IncidentReport, prefix: str = "") -> None:
    """Show a claim with its evidence lines behind an expander (plan 9.1)."""
    st.text(f"{prefix}{claim.text}")
    lines = evidence_by_eid(report)
    with st.expander("Evidence"):
        for eid in claim.evidence:
            item = lines.get(eid)
            if item is None:
                st.text(f"{eid} · not in the evidence of this report")
                continue
            show_line(item.eid, item.line_id, utc(item.ts), item.host, item.log_type, item.raw)
            if item.note:
                st.text(f"Investigator's note: {item.note}")


def show_turn(turn: dict[str, Any]) -> None:
    """Show one question and its cited answer."""
    with st.chat_message("user"):
        st.text(turn["question"])
    with st.chat_message("assistant"):
        for claim in turn["claims"]:
            eids = ", ".join(item["eid"] for item in claim["citations"])
            st.text(f"{claim['text']} [{eids}]")
            with st.expander("Cited lines"):
                for item in claim["citations"]:
                    show_line(
                        item["eid"],
                        item["line_id"],
                        item["ts"],
                        item["host"],
                        item["log_type"],
                        item["raw"],
                    )
        if turn["remark"]:
            st.caption("Note, not a cited claim:")
            st.text(turn["remark"])
        tools = ", ".join(turn["tools"]) or "none"
        st.caption(f"Tools: {tools} · {turn['llm_calls']} calls · {turn['cost_usd']:.4f} USD")
