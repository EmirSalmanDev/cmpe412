"""The dev-only candidate recall diagnostic (M8)."""

import pandas as pd
import pytest

from logtriage.config import TEST_TESTBED, Settings, load_settings
from logtriage.eval.detection import dev_candidate_recall
from logtriage.eval.metrics import candidate_recall, incident_phases

GOLD = {"dirb": ["T1595.003"], "webshell": ["T1190", "T1505.003"]}


def report(incident: str, retrieved: list[str]) -> dict:
    meta = {
        "retrieved_techniques": retrieved,
        "mapped_techniques": retrieved[:1],
        "behavior_summary": "summary",
    }
    return {"incident_id": incident, "meta": meta}


def test_a_gold_technique_in_the_list_is_found_with_its_rank() -> None:
    table = candidate_recall([report("a", ["T1", "T1505.003"])], {"a": ["webshell"]}, GOLD)
    row = table.iloc[0]
    assert row["gold_in_top_k"]
    assert row["best_rank"] == 2
    assert row["gold_retrieved"] == "T1505.003"
    assert row["behavior_summary"] == "summary"


def test_the_gold_set_is_the_union_over_the_phases_of_the_incident() -> None:
    table = candidate_recall([report("a", ["T1595.003"])], {"a": ["dirb", "webshell"]}, GOLD)
    assert table.iloc[0]["gold"] == "T1190 T1505.003 T1595.003"
    assert table.iloc[0]["gold_in_top_k"]


def test_a_miss_is_reported_as_a_miss() -> None:
    table = candidate_recall([report("a", ["T1"])], {"a": ["dirb"]}, GOLD)
    assert not table.iloc[0]["gold_in_top_k"]
    assert pd.isna(table.iloc[0]["best_rank"])


def test_a_parent_technique_is_not_an_exact_match() -> None:
    table = candidate_recall([report("a", ["T1505"])], {"a": ["webshell"]}, GOLD)
    assert not table.iloc[0]["gold_in_top_k"]


def test_an_incident_without_phases_has_no_answer() -> None:
    table = candidate_recall([report("a", ["T1"])], {}, GOLD)
    assert table.iloc[0]["gold_in_top_k"] is None


def test_incident_phases_are_the_union_of_its_windows() -> None:
    table = pd.DataFrame(
        {
            "incident_id": ["a", "a", "b", None],
            "phases": [["x"], ["y", "x"], [], ["z"]],
        }
    )
    assert incident_phases(table) == {"a": ["x", "y"], "b": []}


def test_the_diagnostic_refuses_the_test_testbed() -> None:
    with pytest.raises(ValueError, match="only"):
        dev_candidate_recall(Settings(_env_file=None), TEST_TESTBED)


@pytest.mark.data
def test_the_diagnostic_covers_every_dev_incident() -> None:
    settings = load_settings()
    table = dev_candidate_recall(settings)
    assert len(table) == len(pd.read_parquet("data/processed/russellmitchell/incidents.parquet"))
    assert table["retrieved"].str.split().str.len().eq(settings.agents.mapper_k).all()
