"""Dashboard (plan 9.1): every page runs headless on a small database, without a browser."""

import json
import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pandas as pd
import pytest
import yaml
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from agent_fakes import INCIDENT, TS, FakeChat, chat_answer, make_runtime, open_tools
from logtriage.agents.chat import ChatAgent, open_memory
from logtriage.agents.graph import IncidentState
from logtriage.agents.runner import REPORTS_DIR, RUN_FILE, RunSummary
from logtriage.app import charts, data, ui
from logtriage.app.data import ENV_CONFIG, ENV_LIVE, ENV_TESTBED
from logtriage.cli import STREAMLIT_SCRIPT, app, streamlit_command
from logtriage.config import load_settings

SECOND = "x-0002"
THIRD = "x-0003"
TESTBED = "x"
PAGES = {
    "views/incidents.py": "Incidents",
    "views/detail.py": "Incident detail",
    "views/chat.py": "Chat",
    "views/monitoring.py": "Monitoring",
}
runner = CliRunner()


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A testbed with three incidents, the third one without a report."""
    processed = tmp_path / "processed" / TESTBED
    processed.mkdir(parents=True)
    tools = open_tools(processed, incidents=3)
    _, graph = make_runtime(tmp_path, tools, FakeChat())
    reports = processed / REPORTS_DIR
    reports.mkdir()
    for incident in (INCIDENT, SECOND):
        report = graph.invoke(IncidentState(incident_id=incident))["report"]
        (reports / f"{incident}.json").write_text(report.model_dump_json(), encoding="utf-8")
    (reports / RUN_FILE).write_text(json.dumps({"testbed": TESTBED}), encoding="utf-8")
    tools.close()
    path = tmp_path / "config.yaml"
    paths = {"processed_dir": str(tmp_path / "processed"), "cache_dir": str(tmp_path / "cache")}
    path.write_text(yaml.safe_dump({"paths": paths}), encoding="utf-8")
    monkeypatch.setenv(ENV_TESTBED, TESTBED)
    monkeypatch.setenv(ENV_CONFIG, str(path))
    monkeypatch.delenv(ENV_LIVE, raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)  # so that no `.env` of the developer is read
    yield path


def open_app() -> AppTest:
    return AppTest.from_file(str(STREAMLIT_SCRIPT), default_timeout=30).run()


def replay(at: AppTest) -> AppTest:
    return at.sidebar.toggle[0].set_value(True).run()


def seek(at: AppTest, minutes: float) -> AppTest:
    """Stop the clock a number of minutes after the first incident starts."""
    clock = at.session_state[ui.CLOCK]
    at.session_state[ui.CLOCK] = clock.seek(TS + timedelta(minutes=minutes), 0.0)
    return at.run()


def visible_text(at: AppTest) -> str:
    return "\n".join(
        [item.value for item in at.text]
        + [item.value for item in at.info]
        + [item.value for item in at.caption]
    )


@pytest.mark.parametrize(("page", "title"), PAGES.items())
def test_each_page_runs(config: Path, page: str, title: str):
    at = open_app().switch_page(page).run()
    assert not at.exception
    assert [item.value for item in at.title] == [title]


def test_the_sidebar_stays_after_a_page_change(config: Path):
    """A folder named `pages` beside the script makes Streamlit route around the entry script."""
    at = open_app()
    for page in PAGES:
        at.switch_page(page).run()
        assert len(at.sidebar.toggle) == 1
    assert not (STREAMLIT_SCRIPT.parent / "pages").exists()


def test_the_incidents_table_is_by_priority_with_the_verdict(config: Path):
    at = open_app()
    table = at.dataframe[0].value
    assert table["incident"].tolist() == [INCIDENT, SECOND, THIRD]
    assert table["verdict"].tolist() == ["malicious", "malicious", data.NO_REPORT]
    assert table["confidence"].iloc[0] == 0.8
    assert pd.isna(table["confidence"].iloc[2])
    assert {"hosts", "log types", "score"} <= set(table.columns)


def test_the_detail_page_shows_claims_evidence_and_technique_links(config: Path):
    at = open_app().switch_page("views/detail.py").run()
    text = visible_text(at)
    assert "a login page was requested" in text
    assert "web|logs/access.log|1" in text
    assert [item.value for item in at.code]
    assert "T1110" in [item.label for item in at.get("link_button")]


def test_log_text_is_never_rendered_as_markdown(config: Path, tmp_path: Path):
    """A report quotes attacker-controlled text; as Markdown an image would be fetched."""
    path = tmp_path / "processed" / TESTBED / REPORTS_DIR / f"{INCIDENT}.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    planted = "![x](http://evil.test/p.png)"
    report["summary"][0]["text"] = planted
    report["evidence"][0]["raw"] = planted
    path.write_text(json.dumps(report), encoding="utf-8")
    at = open_app().switch_page("views/detail.py").run()
    assert planted in [item.value for item in at.text]
    assert not any(planted in item.value for item in at.markdown)


def test_an_incident_without_a_report_says_so(config: Path):
    at = open_app().switch_page("views/detail.py").run()
    at.selectbox[0].set_value(THIRD).run()
    assert not at.exception
    assert "This incident has no report." in visible_text(at)


def test_monitoring_shows_totals_and_rows(config: Path):
    at = open_app().switch_page("views/monitoring.py").run()
    assert at.dataframe[0].value["incident_id"].tolist() == [INCIDENT, SECOND]
    assert {"cost_usd", "latency_s", "tokens_in", "tokens_out", "verifier_rounds"} <= set(
        at.dataframe[0].value.columns
    )
    assert any(item.label == "Paid over all runs" for item in at.metric)


def test_the_replay_starts_before_the_first_incident_with_nothing_visible(config: Path):
    at = replay(open_app())
    assert not at.exception
    assert at.session_state[ui.VIEW].incidents.empty
    # The fixture's first window is its first incident, and a replay starts at no earlier window.
    assert at.session_state[ui.VIEW].moment == TS
    assert "No incident has closed yet." in visible_text(at)
    for page in PAGES:
        at.switch_page(page).run()
        assert not at.exception


def test_a_report_appears_when_its_incident_closes_and_not_before(config: Path):
    """Incidents last two minutes and start one hour apart."""
    at = replay(open_app())
    seek(at, 1)
    view = at.session_state[ui.VIEW]
    assert view.incidents.empty
    assert view.reports == {}
    seek(at, 2)
    view = at.session_state[ui.VIEW]
    assert view.incidents["incident_id"].tolist() == [INCIDENT]
    assert list(view.reports) == [INCIDENT]
    seek(at, 62)
    assert list(at.session_state[ui.VIEW].reports) == [INCIDENT, SECOND]


def test_later_incidents_stay_out_of_every_page_during_a_replay(config: Path):
    at = seek(replay(open_app()), 2)
    assert at.dataframe[0].value["incident"].tolist() == [INCIDENT]
    at.switch_page("views/monitoring.py").run()
    assert at.dataframe[0].value["incident_id"].tolist() == [INCIDENT]
    for page in ("views/detail.py", "views/chat.py"):
        at.switch_page(page).run()
        assert at.selectbox[0].options == [INCIDENT]


def test_a_selection_past_the_clock_falls_back_to_a_closed_incident(config: Path):
    at = open_app().switch_page("views/detail.py").run()
    at.selectbox[0].set_value(SECOND).run()
    replay(at)
    seek(at, 2).switch_page("views/chat.py").run()
    assert at.selectbox[0].value == INCIDENT


def test_a_page_that_follows_the_clock_ends_its_run_while_the_replay_plays(config: Path):
    """The timer's fragment also runs inline; a rerun from there would loop for ever."""
    at = replay(open_app())
    at.sidebar.button[0].click().run()
    assert [item.label for item in at.sidebar.button] == ["Pause", "Reset"]
    at.switch_page("views/detail.py").run()
    assert not at.exception
    clock = at.session_state[ui.CLOCK]
    at.session_state[ui.CLOCK] = clock.seek(TS + timedelta(minutes=3), 0.0)
    at.run()  # an incident closed since the last draw
    assert not at.exception


def test_pause_and_reset_buttons(config: Path):
    at = replay(open_app())
    at.sidebar.button[0].click().run()
    at.sidebar.button[0].click().run()
    assert [item.label for item in at.sidebar.button] == ["Play", "Reset"]
    seek(at, 30)
    at.sidebar.button[1].click().run()
    assert at.session_state[ui.CLOCK].position == TS


def test_the_speed_control_offers_the_configured_speeds_and_defaults_to_600x(config: Path):
    at = replay(open_app())
    slider = at.sidebar.select_slider[0]
    assert slider.options == ["60×", "600×", "3600×"]
    assert slider.value == 600
    assert at.session_state[ui.CLOCK].speed == 600


def test_chat_shows_the_thread_of_the_incident_and_needs_no_model_for_it(config: Path):
    settings = load_settings(config)
    saver = open_memory(settings)
    tools = open_tools(settings.paths.processed_dir / TESTBED / "chat", incidents=1)
    agent = ChatAgent.open(
        TESTBED, settings, tools=tools, saver=saver, backend=FakeChat(
            {"chat": [chat_answer("the login page was requested", ("E1",))]}
        ),
    )  # fmt: skip
    agent.ask(INCIDENT, "what happened?")
    saver.conn.close()
    tools.close()

    at = open_app().switch_page("views/chat.py").run()
    assert not at.exception
    assert at.selectbox[0].value == INCIDENT
    assert "what happened?" in visible_text(at)
    assert "the login page was requested [E1]" in visible_text(at)
    assert "web|logs/access.log|1" in visible_text(at)
    at.selectbox[0].set_value(SECOND).run()
    assert "what happened?" not in visible_text(at)


def test_chat_without_an_api_key_cannot_be_asked(config: Path):
    at = open_app().switch_page("views/chat.py").run()
    assert any("DEEPSEEK_API_KEY" in item.value for item in at.warning)
    assert at.chat_input[0].disabled


def test_a_question_reaches_the_agent_and_its_answer_is_shown(
    config: Path, monkeypatch: pytest.MonkeyPatch
):
    settings = load_settings(config)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "fake-key")
    chat = FakeChat({"chat": [chat_answer("answered from the report", ("E1",))]})
    tools = open_tools(settings.paths.processed_dir / TESTBED / "chat", incidents=1)

    def fake_agent(testbed: str, path: str) -> ChatAgent:
        return ChatAgent.open(
            testbed, settings, tools=tools, saver=ui.memory_of(path), backend=chat
        )

    monkeypatch.setattr(ui, "chat_agent_of", fake_agent)
    at = open_app().switch_page("views/chat.py").run()
    at.chat_input[0].set_value("what happened?").run()
    assert not at.exception
    assert "answered from the report [E1]" in visible_text(at)
    assert chat.count("chat") == 1


def test_live_reports_are_computed_once_per_closed_incident_on_dev(
    config: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[list[str]] = []

    class Agent:
        lock = threading.Lock()

    def fake_run(testbed: str, settings: object, ids: list[str], **kwargs: object) -> RunSummary:
        calls.append(ids)
        return RunSummary(testbed, "run", failed={ids[0]: "no"})

    monkeypatch.setenv(ENV_LIVE, "1")
    monkeypatch.setattr(ui, "run_incidents", fake_run)
    monkeypatch.setattr(ui, "tools_of", lambda *args: object())
    monkeypatch.setattr(ui, "chat_agent_of", lambda *args: Agent())
    at = replay(open_app())
    assert calls == []
    seek(at, 122)  # the third incident, which has no report, is closed
    assert calls == [[THIRD]]
    at.run()
    at.run()
    assert calls == [[THIRD]]  # it failed and is not paid for again


def test_live_stops_for_good_at_a_spending_limit(config: Path, monkeypatch: pytest.MonkeyPatch):
    class Agent:
        lock = threading.Lock()

    summary = RunSummary(TESTBED, "run", aborted="total spend reached the limit")
    monkeypatch.setenv(ENV_LIVE, "1")
    monkeypatch.setattr(ui, "run_incidents", lambda *args, **kwargs: summary)
    monkeypatch.setattr(ui, "tools_of", lambda *args: object())
    monkeypatch.setattr(ui, "chat_agent_of", lambda *args: Agent())
    at = seek(replay(open_app()), 122)
    at.run()
    assert any("reached the limit" in item.value for item in at.sidebar.warning)


def test_live_on_the_test_testbed_is_refused_inside_the_app_too(
    config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The environment can be set by hand, past the command line."""
    (tmp_path / "processed" / TESTBED).rename(tmp_path / "processed" / "santos")
    monkeypatch.setenv(ENV_TESTBED, "santos")
    monkeypatch.setenv(ENV_LIVE, "1")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("the agent graph ran on the test testbed")

    monkeypatch.setattr(ui, "run_incidents", forbidden)
    at = seek(replay(open_app()), 122)
    assert not at.exception
    assert any("--live" in item.value for item in at.sidebar.error)


def test_a_missing_database_is_reported(config: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ENV_TESTBED, "nope")
    at = open_app()
    assert not at.exception
    assert "agent database not found" in at.error[0].value


def test_technique_links_use_the_sub_path():
    assert data.technique_url("T1046") == "https://attack.mitre.org/techniques/T1046/"
    assert data.technique_url("T1548.003") == "https://attack.mitre.org/techniques/T1548/003/"


def scored_windows() -> pd.DataFrame:
    """Two streams: one with a quiet stretch, one holding the anomalous window."""
    minute = timedelta(minutes=1)
    rows = [("web", "audit", TS + i * minute, 0.2, False, None) for i in (0, 1, 5, 6)]
    rows += [("web", "apache_access", TS + i * minute, 0.3, False, None) for i in (0, 1)]
    rows += [("web", "apache_access", TS + 2 * minute, 0.999, True, "i")]
    rows += [("db", "dns", TS, 0.4, False, None)]
    columns = ["host", "log_type", "window_start", "score", "is_anomalous", "incident_id"]
    return pd.DataFrame(rows, columns=columns)


def test_the_timeline_shows_the_streams_of_the_incident_on_one_axis():
    windows = scored_windows()
    streams = charts.incident_streams(windows, "i")
    assert streams == [("web", "apache_access")]
    near = charts.stream_windows(windows, streams, TS, TS, timedelta(minutes=10))
    assert set(near["log_type"]) == {"apache_access"}
    figure = charts.timeline_figure(near, streams, TS, TS, 0.999, 60)
    assert figure.layout.yaxis.range == (0, 1.04)
    assert "yaxis2" not in figure.to_dict()["layout"]
    assert figure.layout.showlegend is False  # one series: the page names it
    assert [len(trace.x) for trace in figure.data] == [3, 1]


def test_a_line_does_not_bridge_minutes_without_windows():
    part = scored_windows().query("log_type == 'audit'")
    gaps = charts.with_gaps(part, 60)
    assert len(gaps) == 5
    assert gaps["score"].isna().tolist() == [False, False, True, False, False]


def test_the_timeline_has_at_most_eight_streams_in_fixed_colors():
    rows = [
        (f"h{i}", "audit", TS, 0.99 - i / 100, True, "i", )
        for i in range(10)
    ]  # fmt: skip
    columns = ["host", "log_type", "window_start", "score", "is_anomalous", "incident_id"]
    windows = pd.DataFrame(rows, columns=columns)
    streams = charts.incident_streams(windows, "i")
    assert len(streams) == 8
    assert streams[0] == ("h0", "audit")
    figure = charts.timeline_figure(windows, streams, TS, TS, 0.999, 60)
    colors = [trace.line.color for trace in figure.data if trace.mode == "lines"]
    assert colors == list(charts.SERIES_COLORS)
    assert figure.layout.showlegend is True


def test_the_incident_table_has_no_row_past_the_given_incidents():
    frame = pd.DataFrame(columns=["priority", "start"])
    assert data.incident_table(frame, {}).empty


def test_the_app_command_starts_streamlit_with_its_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    processed = tmp_path / "t"
    processed.mkdir()
    (processed / "agent.duckdb").touch()
    config = tmp_path / "c.yaml"
    config.write_text(f"paths:\n  processed_dir: {tmp_path}\n", encoding="utf-8")
    seen = {}

    def fake_run(command: list[str], env: dict, check: bool) -> object:
        seen.update(command=command, env=env)
        return type("Done", (), {"returncode": 0})()

    monkeypatch.setattr("logtriage.cli.subprocess.run", fake_run)
    result = runner.invoke(app, ["app", "--testbed", "t", "--config", str(config), "--live"])
    assert result.exit_code == 0
    assert seen["env"][ENV_TESTBED] == "t"
    assert seen["env"][ENV_CONFIG] == str(config)
    assert seen["env"][ENV_LIVE] == "1"
    assert str(STREAMLIT_SCRIPT) in seen["command"]


def test_the_app_command_binds_locally_and_sends_no_statistics():
    default = Path(__file__).parents[1] / "configs" / "default.yaml"
    command = streamlit_command(load_settings(default, env_file=None))
    assert command[command.index("--server.address") + 1] == "127.0.0.1"
    assert command[command.index("--browser.gatherUsageStats") + 1] == "false"
    assert "DEEPSEEK_API_KEY" not in " ".join(command)


def test_app_live_is_refused_on_santos_before_anything_starts(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Streamlit was started")

    monkeypatch.setattr("logtriage.cli.subprocess.run", forbidden)
    result = runner.invoke(app, ["app", "--testbed", "santos", "--live"])
    assert result.exit_code == 1
    assert "--live would run the agent graph again" in result.output


def test_app_refuses_a_testbed_without_a_database(monkeypatch: pytest.MonkeyPatch):
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Streamlit was started")

    monkeypatch.setattr("logtriage.cli.subprocess.run", forbidden)
    result = runner.invoke(app, ["app", "--testbed", "nope"])
    assert result.exit_code == 1
    assert "no agent database" in result.output
