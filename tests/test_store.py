"""DuckDB connections (plan 5.1): every session runs in UTC, on any machine."""

import ast
import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logtriage.data.store import connect, create_views

ROOT = Path(__file__).parents[1]
HELPER = ROOT / "src" / "logtriage" / "data" / "store.py"
# Module-level duckdb calls that open or reuse a connection without the session setting.
DIRECT = {"connect", "default_connection", "execute", "from_query", "query", "sql"}


@pytest.fixture
def machine_in_istanbul() -> Iterator[None]:
    """Run a test with the process zone away from UTC."""
    previous = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Istanbul"
    time.tzset()
    yield
    if previous is None:
        del os.environ["TZ"]
    else:
        os.environ["TZ"] = previous
    time.tzset()


def direct_uses(path: Path) -> list[str]:
    """Return `path:line` of every DuckDB connection opened without `connect`."""
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        is_call = (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "duckdb"
            and node.attr in DIRECT
        )
        is_import = (
            isinstance(node, ast.ImportFrom)
            and node.module == "duckdb"
            and any(alias.name in DIRECT for alias in node.names)
        )
        if is_call or is_import:
            found.append(f"{path}:{node.lineno}")
    return found


def test_connect_sets_utc_on_a_memory_connection(machine_in_istanbul: None) -> None:
    with connect() as con:
        assert con.execute("SELECT current_setting('TimeZone')").fetchone() == ("UTC",)


def test_connect_sets_utc_on_a_read_only_file(tmp_path: Path, machine_in_istanbul: None) -> None:
    path = tmp_path / "x.duckdb"
    create_views(path, {"one": "SELECT 1 AS a"})
    with connect(path, read_only=True) as con:
        assert con.execute("SELECT current_setting('TimeZone')").fetchone() == ("UTC",)
        assert con.execute("SELECT a FROM one").fetchone() == (1,)


def test_day_boundaries_are_utc_days(machine_in_istanbul: None) -> None:
    query = "SELECT strftime(TIMESTAMPTZ '2022-01-14 22:30:00+00', '%Y-%m-%d'), "
    query += "date_trunc('day', TIMESTAMPTZ '2022-01-14 22:30:00+00')"
    with connect() as con:
        day, start = con.execute(query).fetchone()
    assert day == "2022-01-14"
    assert start == datetime(2022, 1, 14, tzinfo=UTC)


def test_every_connection_goes_through_the_helper() -> None:
    files = [*(ROOT / "src").rglob("*.py"), *(ROOT / "tests").glob("*.py")]
    assert [item for path in files if path != HELPER for item in direct_uses(path)] == []


@pytest.mark.parametrize(
    "line",
    ["con = duckdb.connect()", "duckdb.sql('SELECT 1')", "from duckdb import connect"],
)
def test_the_scan_catches_a_direct_connection(tmp_path: Path, line: str) -> None:
    module = tmp_path / "module.py"
    module.write_text(f"{line}\n", encoding="utf-8")
    assert len(direct_uses(module)) == 1
