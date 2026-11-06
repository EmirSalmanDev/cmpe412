"""The guard on the real `agent.duckdb` files (plan 5.2, 7.3). Nothing here reads ground truth."""

from pathlib import Path

import duckdb
import pytest

from logtriage.agents.sql_guard import SqlRejected, agent_tables, run_guarded
from logtriage.data.store import AGENT_HIDDEN_COLUMNS, connect_agent

ROOT = Path(__file__).parents[1]
TESTBEDS = ["russellmitchell", "santos"]

pytestmark = [pytest.mark.data, pytest.mark.parametrize("testbed", TESTBEDS)]


def open_agent(testbed: str) -> duckdb.DuckDBPyConnection:
    return connect_agent(ROOT / "data" / "processed" / testbed / "agent.duckdb")


def ground_truth_paths(testbed: str) -> list[str]:
    labels = f"data/processed/{testbed}/labels.parquet"
    phases = f"data_meta/phases_{testbed}.csv"
    return [labels, phases, str(ROOT / labels), str(ROOT / phases)]


def test_the_ground_truth_files_exist_so_the_refusals_mean_something(testbed: str) -> None:
    for path in ground_truth_paths(testbed)[2:]:
        assert Path(path).is_file()


def test_the_real_database_holds_only_plain_tables(testbed: str) -> None:
    with open_agent(testbed) as agent:
        views = agent.execute("SELECT count(*) FROM duckdb_views() WHERE NOT internal").fetchone()
        rows = agent.execute("SELECT column_name FROM duckdb_columns() WHERE NOT internal")
        columns = {row[0] for row in rows.fetchall()}
        names = agent_tables(agent)
    assert views == (0,)
    assert not columns & set(AGENT_HIDDEN_COLUMNS)
    assert not any("label" in name or "phase" in name for name in names)
    assert not any(name.endswith("labels") or "phase" in name for name in columns)


def test_ground_truth_is_unreachable_by_any_path(
    testbed: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    with open_agent(testbed) as agent:
        tables = agent_tables(agent)
        for path in ground_truth_paths(testbed):
            reader = "read_csv" if path.endswith(".csv") else "read_parquet"
            for query in (f"SELECT * FROM {reader}('{path}')", f"SELECT * FROM '{path}'"):
                with pytest.raises(duckdb.PermissionException):
                    agent.execute(query)
                with pytest.raises(SqlRejected):
                    run_guarded(agent, query, tables, 200, 10)


def test_normal_reads_work_on_the_real_tables(testbed: str) -> None:
    with open_agent(testbed) as agent:
        tables = agent_tables(agent)
        query = "SELECT i.incident_id FROM incidents i JOIN scores s USING (incident_id)"
        assert not run_guarded(agent, query, tables, 200, 10).empty
