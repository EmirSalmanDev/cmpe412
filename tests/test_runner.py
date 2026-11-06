"""The incident queue (plan 7.2) with a fake LLM."""

import csv
from collections.abc import Iterator
from pathlib import Path

import pytest

from agent_fakes import FakeChat, draft, llm_config, open_tools, settings_for
from logtriage.agents.prompting import load_prompts
from logtriage.agents.runner import RUN_FILE, run_incidents, run_name
from logtriage.agents.tools import AgentTools
from logtriage.config import TEST_TESTBED

DEV = "dev"


@pytest.fixture
def tools(tmp_path: Path) -> Iterator[AgentTools]:
    instance = open_tools(tmp_path, incidents=3)
    yield instance
    instance.close()


def reports_of(tmp_path: Path, testbed: str = DEV) -> list[str]:
    folder = tmp_path / "processed" / testbed / "reports"
    return sorted(path.stem for path in folder.glob("x-*.json"))


def test_incidents_run_by_priority_and_each_gets_a_report(
    tmp_path: Path, tools: AgentTools
) -> None:
    chat = FakeChat()
    summary = run_incidents(DEV, settings_for(tmp_path), backend=chat, tools=tools)
    assert summary.finished == ["x-0001", "x-0002", "x-0003"]
    assert summary.failed == {}
    assert summary.aborted is None
    assert reports_of(tmp_path) == summary.finished
    assert (tmp_path / "processed" / DEV / "reports" / RUN_FILE).is_file()


def test_the_run_table_counts_the_claims_of_each_report(tmp_path: Path, tools: AgentTools) -> None:
    run_incidents(DEV, settings_for(tmp_path), backend=FakeChat(), tools=tools)
    with (tmp_path / "out" / "results" / f"agents_{DEV}.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["claims"] for row in rows] == ["3", "3", "3"]
    assert rows[0]["techniques"] == "T1110"
    assert rows[0]["draft_unknown_eid_claims"] == "0"


def test_a_failed_incident_does_not_stop_the_queue(tmp_path: Path, tools: AgentTools) -> None:
    good = draft()
    chat = FakeChat({"reporter": ["bad", "bad", "bad", good]})
    summary = run_incidents(DEV, settings_for(tmp_path), backend=chat, tools=tools)
    assert list(summary.failed) == ["x-0001"]
    assert summary.finished == ["x-0002", "x-0003"]
    assert reports_of(tmp_path) == ["x-0002", "x-0003"]


def test_the_budget_guard_stops_the_run_cleanly(tmp_path: Path, tools: AgentTools) -> None:
    """One incident makes 5 calls, so the guard stops inside the second one."""
    settings = settings_for(tmp_path)
    settings.llm = llm_config(max_usd_per_run=0.0055)
    chat = FakeChat()
    summary = run_incidents(DEV, settings, backend=chat, tools=tools)
    assert "max_usd_per_run" in summary.aborted
    assert summary.finished == ["x-0001"]
    assert reports_of(tmp_path) == ["x-0001"]
    assert summary.spent_usd >= 0.0055
    assert len(chat.calls) < 15
    assert (tmp_path / "processed" / DEV / "reports" / RUN_FILE).is_file()


def test_a_second_run_is_answered_by_the_cache(tmp_path: Path, tools: AgentTools) -> None:
    settings = settings_for(tmp_path)
    first = run_incidents(DEV, settings, ["x-0001"], backend=FakeChat(), tools=tools)
    chat = FakeChat()
    second = run_incidents(DEV, settings, ["x-0001"], backend=chat, tools=tools)
    assert first.spent_usd > 0
    assert second.spent_usd == 0
    assert chat.calls == []


def test_a_condition_never_reuses_another_conditions_answers(
    tmp_path: Path, tools: AgentTools
) -> None:
    run_incidents(DEV, settings_for(tmp_path), ["x-0001"], backend=FakeChat(), tools=tools)
    chat = FakeChat()
    settings = settings_for(tmp_path, verifier=False)
    run_incidents(DEV, settings, ["x-0001"], backend=chat, tools=tools)
    assert chat.count("investigator") == 2


def test_the_run_name_changes_with_condition_and_prompts(tmp_path: Path) -> None:
    prompts = load_prompts()
    base = run_name(settings_for(tmp_path), prompts)
    assert base != run_name(settings_for(tmp_path, rag=False), prompts)
    changed = {**prompts, "reporter": prompts["reporter"].__class__("reporter-99", "json")}
    assert base != run_name(settings_for(tmp_path), changed)


def test_the_test_testbed_needs_frozen_prompts(tmp_path: Path, tools: AgentTools) -> None:
    chat = FakeChat()
    with pytest.raises(ValueError, match="freeze"):
        run_incidents(TEST_TESTBED, settings_for(tmp_path), backend=chat, tools=tools)
    assert chat.calls == []


def test_the_test_testbed_runs_once_without_a_reason(tmp_path: Path, tools: AgentTools) -> None:
    settings = settings_for(tmp_path, prompts_frozen=True)
    run_incidents(TEST_TESTBED, settings, ["x-0001"], backend=FakeChat(), tools=tools)
    with pytest.raises(ValueError, match="rerun-reason"):
        run_incidents(TEST_TESTBED, settings, ["x-0001"], backend=FakeChat(), tools=tools)
    again = run_incidents(
        TEST_TESTBED,
        settings,
        ["x-0001"],
        rerun_reason="network failure",
        backend=FakeChat(),
        tools=tools,
    )
    assert again.rerun_reason == "network failure"
