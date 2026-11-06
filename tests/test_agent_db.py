"""`agent.duckdb` and its guard (plan 5, 7.3): tables only, no ground truth, no file access."""

import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pandas as pd
import pytest

from logtriage.agents.sql_guard import SqlRejected, agent_tables, check_query, run_guarded
from logtriage.data.store import (
    AGENT_HIDDEN_COLUMNS,
    build_agent_db,
    connect,
    connect_agent,
    write_lines,
)

TS = datetime(2022, 1, 24, 3, 0, tzinfo=UTC)
LABELS = "labels.parquet"
PHASES = "phases_x.csv"


def line(number: int) -> dict:
    return {
        "line_id": f"vpn|logs/openvpn.log|{number}",
        "testbed": "x",
        "host": "vpn",
        "log_type": "vpn",
        "file": "logs/openvpn.log",
        "line_no": number,
        "ts": TS,
        "raw": f"raw {number}",
        "message": "message",
        "template_id": 1,
        "template": "message",
        "is_unseen_template": False,
        "template_rarity": 1.0,
        "src_ip": "10.0.0.1",
        "user": "alice",
        "fields": "{}",
        "parse_ok": True,
    }


def build_directory(directory: Path) -> None:
    """Write a small testbed directory, with ground truth files next to the agent tables."""
    write_lines([line(1), line(2)], directory / "lines_vpn.parquet")
    key = {"testbed": ["x"], "host": ["vpn"], "log_type": ["vpn"], "window_start": [TS]}
    pd.DataFrame({**key, "n_lines": [2], "period": ["eval"]}).to_parquet(
        directory / "windows_vpn.parquet"
    )
    scores = {**key, "period": ["eval"], "score": [0.5], "incident_id": ["i1"]}
    pd.DataFrame(scores).to_parquet(directory / "scores.parquet")
    pd.DataFrame({"incident_id": ["i1"], "start": [TS]}).to_parquet(directory / "incidents.parquet")
    pd.DataFrame({"line_id": [line(1)["line_id"]], "phase": ["dirb"]}).to_parquet(
        directory / LABELS
    )
    (directory / PHASES).write_text("testbed,phase\nx,dirb\n", encoding="utf-8")
    build_agent_db(directory)


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    build_directory(tmp_path)
    return tmp_path


@pytest.fixture
def agent(directory: Path) -> Iterator[duckdb.DuckDBPyConnection]:
    with connect_agent(directory / "agent.duckdb") as connection:
        yield connection


def rejected(connection: duckdb.DuckDBPyConnection, query: str) -> bool:
    try:
        check_query(connection, query, agent_tables(connection))
    except SqlRejected:
        return True
    return False


def test_the_agent_database_holds_tables_and_no_views(agent: duckdb.DuckDBPyConnection) -> None:
    views = agent.execute("SELECT count(*) FROM duckdb_views() WHERE NOT internal").fetchone()
    assert views == (0,)
    assert agent_tables(agent) == {
        "lines",
        "lines_vpn",
        "windows",
        "windows_vpn",
        "scores",
        "incidents",
    }


def test_no_agent_table_has_a_hidden_column(agent: duckdb.DuckDBPyConnection) -> None:
    rows = agent.execute("SELECT column_name FROM duckdb_columns() WHERE NOT internal").fetchall()
    columns = {row[0] for row in rows}
    assert "line_id" in columns
    assert not columns & set(AGENT_HIDDEN_COLUMNS)
    assert not any("label" in name or "phase" in name or "attack" in name for name in columns)


def test_the_database_works_without_the_parquet_files(directory: Path, tmp_path_factory) -> None:
    moved = tmp_path_factory.mktemp("moved") / "agent.duckdb"
    shutil.copy(directory / "agent.duckdb", moved)
    for path in directory.glob("*.parquet"):
        path.unlink()
    with connect_agent(moved) as connection:
        assert connection.execute("SELECT count(*) FROM lines").fetchone() == (2,)


def test_the_connection_is_read_only_and_utc(agent: duckdb.DuckDBPyConnection) -> None:
    zone = agent.execute("SELECT current_setting('TimeZone')").fetchone()
    assert zone == ("UTC",)
    with pytest.raises(duckdb.Error):
        agent.execute("DELETE FROM lines")


@pytest.mark.parametrize(
    "statement",
    [
        "SET enable_external_access=true",
        "SET lock_configuration=false",
        "RESET lock_configuration",
        "SET threads=2",
        "SET TimeZone='Europe/Istanbul'",
    ],
)
def test_the_connection_alone_refuses_configuration(
    agent: duckdb.DuckDBPyConnection, statement: str
) -> None:
    with pytest.raises(duckdb.Error):
        agent.execute(statement)


@pytest.mark.parametrize(
    "template",
    [
        "SELECT * FROM read_parquet('{labels}')",
        "SELECT * FROM read_csv('{phases}')",
        "SELECT * FROM '{labels}'",
        "SELECT * FROM '{phases}'",
        "SELECT * FROM glob('{labels}')",
        "SELECT * FROM read_text('{phases}')",
        "ATTACH '{labels}' AS other",
        "COPY lines TO '{phases}.out'",
    ],
)
@pytest.mark.parametrize("absolute", [True, False])
def test_the_connection_alone_blocks_files_by_any_path(
    directory: Path,
    agent: duckdb.DuckDBPyConnection,
    monkeypatch: pytest.MonkeyPatch,
    template: str,
    absolute: bool,
) -> None:
    monkeypatch.chdir(directory)
    base = f"{directory}/" if absolute else ""
    with pytest.raises(duckdb.Error):
        agent.execute(template.format(labels=f"{base}{LABELS}", phases=f"{base}{PHASES}"))


@pytest.mark.parametrize(
    "query",
    [
        "INSERT INTO incidents SELECT * FROM incidents",
        "UPDATE lines SET raw = ''",
        "DELETE FROM lines",
        "DROP TABLE lines",
        "ALTER TABLE lines ADD COLUMN extra INT",
        "TRUNCATE lines",
        "CREATE TABLE extra (a INT)",
        "CREATE TEMP TABLE extra (a INT)",
        "CREATE VIEW extra AS SELECT 1",
        "CREATE MACRO extra() AS 1",
        "ATTACH 'other.duckdb' AS other",
        "ATTACH ':memory:' AS other",
        "DETACH agent",
        "USE memory",
        "COPY (SELECT 1) TO 'out.csv'",
        "COPY lines FROM 'in.csv'",
        "EXPORT DATABASE 'out'",
        "IMPORT DATABASE 'in'",
        "INSTALL httpfs",
        "INSTALL json",
        "LOAD httpfs",
        "LOAD json",
        "PRAGMA database_list",
        "PRAGMA show_tables",
        "PRAGMA threads=2",
        "CALL pragma_version()",
        "SET threads=2",
        "SET VARIABLE x=1",
        "RESET threads",
        "VACUUM",
        "CHECKPOINT",
        "EXPLAIN SELECT 1",
        "EXPLAIN ANALYZE SELECT 1",
        "DESCRIBE lines",
        "SHOW TABLES",
        "SUMMARIZE lines",
        "PIVOT lines ON host",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP TABLE lines",
        "WITH a AS (SELECT 1) INSERT INTO lines SELECT * FROM a",
        "",
        "   ",
        "-- only a comment",
        "not sql at all",
    ],
)
def test_the_guard_rejects_everything_but_one_select(
    agent: duckdb.DuckDBPyConnection, query: str
) -> None:
    assert rejected(agent, query)


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM read_parquet('x')",
        "SELECT * FROM ReAd_PaRqUeT('x')",
        "SELECT * FROM /* a */ read_parquet /* b */ ('x')",
        "SELECT * FROM read_csv('x')",
        "SELECT * FROM read_text('/etc/passwd')",
        "SELECT * FROM read_blob('/etc/hosts')",
        "SELECT * FROM glob('*')",
        "SELECT * FROM sniff_csv('x')",
        "SELECT * FROM parquet_metadata('x')",
        "SELECT * FROM query('SELECT 1')",
        "SELECT * FROM query_table('lines')",
        "SELECT * FROM duckdb_settings()",
        "SELECT * FROM duckdb_tables()",
        "SELECT * FROM pragma_database_list()",
        "SELECT * FROM generate_series(1, 3)",
        "SELECT * FROM lines JOIN read_parquet('x') USING (line_id)",
        "SELECT * FROM lines WHERE line_id IN (SELECT line_id FROM read_parquet('x'))",
        "SELECT (SELECT count(*) FROM read_parquet('x'))",
        "WITH a AS (SELECT * FROM read_parquet('x')) SELECT * FROM a",
        "SELECT * FROM (SELECT * FROM read_parquet('x'))",
        "SELECT 1 UNION ALL SELECT count(*) FROM read_parquet('x')",
        "SELECT * FROM 'labels.parquet'",
        'SELECT * FROM "labels.parquet"',
        "FROM 'data/phases.csv'",
        "SELECT * FROM (SELECT * FROM 'labels.parquet')",
        "SELECT * FROM lines, 'labels.parquet'",
        'WITH "labels.parquet" AS (SELECT 1) SELECT * FROM "labels.parquet"',
        'SELECT * FROM (WITH "a.parquet" AS (SELECT 1) SELECT 1), "a.parquet"',
        "SELECT * FROM unknown_table",
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM sqlite_master",
        "SELECT * FROM pg_catalog.pg_tables",
        "SELECT * FROM other.main.lines",
        "SELECT * FROM (DESCRIBE lines)",
        "SELECT * FROM (SHOW TABLES)",
        "SELECT * FROM (PIVOT lines ON host USING count(*))",
    ],
)
def test_the_guard_rejects_table_functions_paths_and_unknown_tables(
    agent: duckdb.DuckDBPyConnection, query: str
) -> None:
    assert rejected(agent, query)


@pytest.mark.parametrize(
    "query",
    [
        "SELECT count(*) FROM lines",
        "select raw from main.lines;",
        "SELECT 1 -- trailing comment",
        "SELECT s.host FROM scores s JOIN incidents i ON s.incident_id = i.incident_id",
        "WITH a AS (SELECT host FROM lines) SELECT * FROM a",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) "
        "SELECT * FROM r",
        "SELECT host FROM lines WHERE line_id IN (SELECT line_id FROM lines_vpn)",
        "SELECT fields->>'qname' FROM lines",
        "SELECT unnest([1, 2])",
        "SELECT 'labels.parquet' AS just_text",
    ],
)
def test_the_guard_accepts_reads_of_the_agent_tables(
    agent: duckdb.DuckDBPyConnection, query: str
) -> None:
    assert not run_guarded(agent, query, agent_tables(agent), 200, 10).empty


def test_results_are_limited_whatever_the_query_asks(agent: duckdb.DuckDBPyConnection) -> None:
    tables = agent_tables(agent)
    assert len(run_guarded(agent, "SELECT * FROM lines", tables, 1, 10)) == 1
    assert len(run_guarded(agent, "SELECT * FROM lines LIMIT 100", tables, 1, 10)) == 1


def test_a_slow_query_is_stopped_and_the_connection_survives(
    agent: duckdb.DuckDBPyConnection,
) -> None:
    tables = agent_tables(agent)
    endless = (
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r"
    )
    with pytest.raises(TimeoutError):
        run_guarded(agent, endless, tables, 200, 0.2)
    assert run_guarded(agent, "SELECT 1 AS a", tables, 200, 10).iloc[0, 0] == 1


def test_the_plain_connection_still_writes_for_the_build(tmp_path: Path) -> None:
    with connect(tmp_path / "other.duckdb") as connection:
        connection.execute("CREATE TABLE a (b INT)")
