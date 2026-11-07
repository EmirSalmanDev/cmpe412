"""Ablations on santos (plan 10.4, D65), with a fake LLM."""

import hashlib
import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pytest
from langchain_core.messages import AIMessage

from agent_fakes import FakeChat, open_tools, settings_for
from logtriage import guards
from logtriage.agents import tools as tools_module
from logtriage.agents.cache import LlmCache
from logtriage.agents.llm import CacheMissError, FingerprintChangedError
from logtriage.agents.runner import run_incidents
from logtriage.agents.tools import AgentTools
from logtriage.config import TEST_TESTBED
from logtriage.eval import ablations
from logtriage.eval.ablations import BASE, RefusingBackend, check_ablation, run_ablation
from rag_fakes import FakeEmbedder

FINGERPRINT = ablations.EXPECTED_FINGERPRINT


class PinnedChat(FakeChat):
    """A fake model that reports a fingerprint and keeps the usage of FakeChat."""

    def __init__(self, fingerprint: str = FINGERPRINT) -> None:
        super().__init__()
        self.fingerprint = fingerprint

    def invoke(self, messages, **kwargs) -> AIMessage:
        reply = super().invoke(messages, **kwargs)
        reply.response_metadata = {
            **reply.response_metadata,
            "system_fingerprint": self.fingerprint,
        }
        return reply


@pytest.fixture
def tools(tmp_path: Path) -> Iterator[AgentTools]:
    instance = open_tools(tmp_path, incidents=2)
    yield instance
    instance.close()


def frozen(tmp_path: Path):
    return settings_for(tmp_path, prompts_frozen=True)


def official(tmp_path: Path, tools: AgentTools) -> Path:
    """Run the official reports once, and return their directory."""
    run_incidents(TEST_TESTBED, frozen(tmp_path), backend=FakeChat(), tools=tools)
    return tmp_path / "processed" / TEST_TESTBED / "reports"


def digests(directory: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*"))
    }


def ledger_rows(tmp_path: Path) -> list[tuple]:
    cache = LlmCache(tmp_path / "cache" / "llm.sqlite")
    rows = cache.connection.execute("SELECT * FROM spend").fetchall()
    cache.close()
    return rows


def test_the_container_refuses_before_anything_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "container"
    marker.touch()
    monkeypatch.setattr(guards, "CONTAINER_MARKER", marker)
    with pytest.raises(ValueError, match="container"):
        check_ablation("no such condition", "", settings_for(tmp_path))


@pytest.mark.parametrize(
    ("condition", "reason", "testbed", "frozen_prompts", "message"),
    [
        ("verifier0", "why", "wardbeck", True, "santos only"),
        ("other", "why", TEST_TESTBED, True, "unknown condition"),
        ("verifier0", "why", TEST_TESTBED, False, "freeze"),
        ("verifier0", "   ", TEST_TESTBED, True, "needs a reason"),
    ],
)
def test_the_checks_refuse(
    tmp_path: Path,
    condition: str,
    reason: str,
    testbed: str,
    frozen_prompts: bool,
    message: str,
) -> None:
    settings = settings_for(tmp_path, prompts_frozen=frozen_prompts)
    with pytest.raises(ValueError, match=message):
        check_ablation(condition, reason, settings, testbed)
    assert guards.recorded_runs(settings) == []


def test_a_condition_runs_once_with_no_override(tmp_path: Path, tools: AgentTools) -> None:
    settings = frozen(tmp_path)
    run_ablation("verifier0", "first", settings, backend=PinnedChat(), tools=tools)
    chat = PinnedChat()
    with pytest.raises(ValueError, match="never runs twice"):
        run_ablation("verifier0", "again", settings, backend=chat, tools=tools)
    assert chat.calls == []
    assert [row["stage"] for row in guards.recorded_runs(settings)] == ["ablation:verifier0"]


def test_the_ledger_row_is_written_before_the_run(tmp_path: Path, tools: AgentTools) -> None:
    settings = frozen(tmp_path)

    class Crash(PinnedChat):
        def invoke(self, messages, **kwargs) -> AIMessage:
            assert guards.recorded_runs(settings)[-1]["stage"] == "ablation:rag0"
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_ablation("rag0", "why", settings, backend=Crash(), tools=tools)
    with pytest.raises(ValueError, match="never runs twice"):
        check_ablation("rag0", "why", settings)


def test_an_ablation_neither_opens_nor_blocks_the_investigate_guard(
    tmp_path: Path, tools: AgentTools
) -> None:
    settings = frozen(tmp_path)
    run_ablation("verifier0", "why", settings, backend=PinnedChat(), tools=tools)
    report_dir = tmp_path / "processed" / TEST_TESTBED / "reports"
    guards.check_run(guards.INVESTIGATE, TEST_TESTBED, settings, [report_dir / "x"], None)


def test_the_base_condition_replays_at_no_cost(tmp_path: Path, tools: AgentTools) -> None:
    saved = official(tmp_path, tools)
    settings = frozen(tmp_path)
    before, spend = digests(saved), ledger_rows(tmp_path)
    summary = run_ablation(BASE, "proof", settings, tools=tools)
    assert summary.spent_usd == 0
    assert summary.failed == {}
    assert ledger_rows(tmp_path) == spend
    assert digests(saved) == before
    proof = ablations.replay_proof(settings)
    assert len(proof) == 2
    assert proof["identical"].all()
    assert (proof["cached_calls"] == proof["llm_calls"]).all()
    assert (proof["spent_usd"] == 0).all()


def test_a_miss_of_the_base_condition_stops_at_no_cost(tmp_path: Path, tools: AgentTools) -> None:
    settings = frozen(tmp_path)
    with pytest.raises(CacheMissError):
        run_ablation(BASE, "proof", settings, tools=tools)
    assert ledger_rows(tmp_path) == []
    assert [row["stage"] for row in guards.recorded_runs(settings)] == ["ablation:base"]


def test_the_replay_proof_sees_a_difference(tmp_path: Path, tools: AgentTools) -> None:
    saved = official(tmp_path, tools)
    settings = frozen(tmp_path)
    run_ablation(BASE, "proof", settings, tools=tools)
    path = saved / "x-0001.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["verdict"] = "benign"
    path.write_text(json.dumps(report), encoding="utf-8")
    proof = ablations.replay_proof(settings).set_index("incident_id")
    assert not proof.loc["x-0001", "identical"]
    assert proof.loc["x-0002", "identical"]


def test_the_refusing_backend_refuses() -> None:
    with pytest.raises(RuntimeError, match="reached the model"):
        RefusingBackend().invoke([])


def test_a_condition_writes_only_in_its_own_place(tmp_path: Path, tools: AgentTools) -> None:
    saved = official(tmp_path, tools)
    settings = frozen(tmp_path)
    table = tmp_path / "out" / "results" / f"agents_{TEST_TESTBED}.csv"
    before, rows = digests(saved), table.read_bytes()
    summary = run_ablation("verifier0", "why", settings, backend=PinnedChat(), tools=tools)
    assert summary.run.startswith("verifier0-rag1-few_shot0-")
    assert digests(saved) == before
    assert table.read_bytes() == rows
    target = ablations.output_dir(settings, "verifier0")
    assert sorted(path.stem for path in ablations.report_files(target)) == ["x-0001", "x-0002"]
    assert ablations.table_path(settings, "verifier0").is_file()
    written = json.loads((target / "x-0001.json").read_text(encoding="utf-8"))
    assert written["meta"]["verifier"] is False


def test_the_memory_of_a_condition_is_apart_from_the_official_one(
    tmp_path: Path, tools: AgentTools, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = frozen(tmp_path)
    settings.paths.index_dir = tmp_path / "index"
    directory = settings.paths.processed_dir / TEST_TESTBED
    directory.mkdir(parents=True)
    shutil.copy(tmp_path / "agent.duckdb", directory / "agent.duckdb")
    monkeypatch.setattr(tools_module, "BgeEmbedder", lambda _: FakeEmbedder())
    report = {"incident_id": "x-0001", "summary": [], "techniques": [], "verdict": "benign"}
    start = datetime(2022, 1, 24, tzinfo=UTC)
    own = AgentTools.open(TEST_TESTBED, settings, memory_dir=tmp_path / "own")
    own.incidents.add(report, TEST_TESTBED, start, "run")
    own.close()
    official_store = AgentTools.open(TEST_TESTBED, settings)
    assert official_store.incidents.collection.count() == 0
    official_store.close()
    again = AgentTools.open(TEST_TESTBED, settings, memory_dir=tmp_path / "own")
    assert again.incidents.collection.count() == 1
    again.close()


def test_the_settings_change_only_in_a_copy(tmp_path: Path) -> None:
    settings = frozen(tmp_path)
    changed = ablations.condition_settings(settings, "few_shot1")
    assert changed.agents.few_shot is True
    assert changed.llm.max_usd_per_run == ablations.MAX_USD_PER_CONDITION
    assert settings.agents.few_shot is False
    assert settings.llm.max_usd_per_run != ablations.MAX_USD_PER_CONDITION


def test_each_condition_is_one_switch() -> None:
    assert ablations.CONDITIONS == {
        "base": {},
        "verifier0": {"verifier": False},
        "rag0": {"rag": False},
        "few_shot1": {"few_shot": True},
    }


def test_another_served_model_stops_the_run_and_the_call_stays_in_the_ledger(
    tmp_path: Path, tools: AgentTools
) -> None:
    settings = frozen(tmp_path)
    with pytest.raises(FingerprintChangedError):
        run_ablation("rag0", "why", settings, backend=PinnedChat("other"), tools=tools)
    assert len(ledger_rows(tmp_path)) == 1


def test_a_failed_incident_ends_an_ablation(tmp_path: Path, tools: AgentTools) -> None:
    settings = frozen(tmp_path)
    chat = PinnedChat()
    chat.script["mapper"] = ["not json", "not json", "not json"]
    summary = run_ablation("verifier0", "why", settings, backend=chat, tools=tools)
    assert list(summary.failed) == ["x-0001"]
    assert summary.aborted
    assert summary.finished == []


def test_the_ledger_file_holds_both_states(tmp_path: Path, tools: AgentTools) -> None:
    settings = frozen(tmp_path)
    run_ablation("verifier0", "why", settings, backend=PinnedChat(), tools=tools)
    target = ablations.output_dir(settings, "verifier0") / ablations.LEDGER_FILE
    state = json.loads(target.read_text(encoding="utf-8"))
    assert state["after"]["rows"] > state["before"]["rows"]


def test_the_replay_proof_of_nothing_is_empty(tmp_path: Path) -> None:
    assert isinstance(ablations.replay_proof(frozen(tmp_path)), pd.DataFrame)
