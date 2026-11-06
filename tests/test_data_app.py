"""The dashboard on real santos data. No test here reaches the model or the embedding model."""

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from logtriage.app import ui
from logtriage.app.data import ENV_CONFIG, ENV_LIVE, ENV_TESTBED
from logtriage.cli import STREAMLIT_SCRIPT
from logtriage.config import TEST_TESTBED, load_settings

pytestmark = pytest.mark.data

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "configs" / "default.yaml"
PAGES = {
    "views/incidents.py": "Incidents",
    "views/detail.py": "Incident detail",
    "views/chat.py": "Chat",
    "views/monitoring.py": "Monitoring",
}


@pytest.fixture(autouse=True)
def santos(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    settings = load_settings(CONFIG)
    if not (settings.paths.processed_dir / TEST_TESTBED / "agent.duckdb").is_file():
        pytest.skip("santos is not prepared")
    monkeypatch.setenv(ENV_TESTBED, TEST_TESTBED)
    monkeypatch.setenv(ENV_CONFIG, str(CONFIG))
    monkeypatch.delenv(ENV_LIVE, raising=False)
    yield
    # The cached connection locks the file for this process, and other data tests open it too.
    ui.connection_of(str(_database())).close()
    st.cache_resource.clear()


def open_app() -> AppTest:
    return AppTest.from_file(str(STREAMLIT_SCRIPT), default_timeout=60).run()


def test_all_four_pages_show_santos_data():
    at = open_app()
    assert at.dataframe[0].value["incident"].tolist() == [
        "santos-0002", "santos-0003", "santos-0001",
    ]  # fmt: skip
    assert "no report" not in at.dataframe[0].value["verdict"].tolist()
    for page, title in PAGES.items():
        at.switch_page(page).run()
        assert not at.exception
        assert [item.value for item in at.title] == [title]
        assert not at.info


def test_every_santos_report_opens_on_the_detail_page():
    at = open_app().switch_page("views/detail.py").run()
    for incident in at.selectbox[0].options:
        at.selectbox[0].set_value(incident).run()
        assert not at.exception
        assert at.code
        assert at.get("link_button") or "No technique was mapped." in [t.value for t in at.text]


def test_a_600x_replay_reveals_the_santos_reports_in_closing_order():
    at = open_app()
    at.sidebar.toggle[0].set_value(True).run()
    clock = at.session_state[ui.CLOCK]
    assert clock.speed == 600
    assert at.session_state[ui.VIEW].incidents.empty
    closes = sorted(ui.dataset_of(str(_database())).incidents["end"])
    assert clock.start == closes[0] - timedelta(minutes=61)  # one hour before the first start
    seen = []
    tick = timedelta(seconds=settings_tick() * 600)
    moment = clock.start
    while moment < clock.end:
        at.session_state[ui.CLOCK] = clock.seek(moment, 0.0)
        at.run()
        assert not at.exception
        view = at.session_state[ui.VIEW]
        assert (view.incidents["end"] <= moment).all()
        assert set(view.reports) == set(view.incidents["incident_id"])
        seen.append(len(view.reports))
        moment += tick * 12  # a sample of the ticks keeps the test short
    assert seen == sorted(seen)
    assert seen[0] == 0
    assert seen[-1] == 3


def _database() -> Path:
    return load_settings(CONFIG).paths.processed_dir / TEST_TESTBED / "agent.duckdb"


def settings_tick() -> float:
    return load_settings(CONFIG).app.tick_seconds
