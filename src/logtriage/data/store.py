"""Parquet and DuckDB storage helpers (plan 5)."""

import hashlib
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

LINES_SCHEMA = pa.schema(
    [
        ("line_id", pa.string()),
        ("testbed", pa.string()),
        ("host", pa.string()),
        ("log_type", pa.string()),
        ("file", pa.string()),
        ("line_no", pa.int64()),
        ("ts", pa.timestamp("us", tz="UTC")),
        ("raw", pa.string()),
        ("message", pa.string()),
        ("template_id", pa.int64()),
        ("template", pa.string()),
        ("is_unseen_template", pa.bool_()),
        ("template_rarity", pa.float64()),
        ("src_ip", pa.string()),
        ("user", pa.string()),
        ("fields", pa.string()),
        ("parse_ok", pa.bool_()),
    ]
)


DETECTION_TABLES = ("scores", "incidents")
# `period` gives away the evaluation boundary, which sits a fixed time before the attack.
AGENT_HIDDEN_COLUMNS = ("period",)


def connect(path: Path | str = ":memory:", read_only: bool = False) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection whose session time zone is UTC (plan 5.1).

    The session zone decides how `TIMESTAMPTZ` values are bucketed, cast and returned, and it
    defaults to the machine's zone. Every connection in the project comes from here.

    Args:
        path: Database file, or `:memory:`.
        read_only: Open the file read-only.

    Returns:
        The open connection.
    """
    connection = duckdb.connect(str(path), read_only=read_only)
    connection.execute("SET TimeZone='UTC'")
    return connection


def connect_agent(path: Path | str) -> duckdb.DuckDBPyConnection:
    """Open `agent.duckdb` for an agent: read-only, no file access, configuration locked.

    Everything an agent may read is a table inside the file, so it needs no external access.
    Once the configuration is locked, a query can neither widen these settings nor reach a file.

    Args:
        path: The database file.

    Returns:
        The open connection, in UTC.
    """
    connection = duckdb.connect(
        str(path), read_only=True, config={"enable_external_access": "false"}
    )
    connection.execute("SET TimeZone='UTC'")
    connection.execute("SET lock_configuration=true")
    return connection


def write_lines(rows: list[dict[str, Any]], path: Path) -> None:
    """Write rows to a `lines_<log_type>.parquet` file (plan 5.1)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=LINES_SCHEMA), path)


def template_digest(rows: list[dict[str, Any]]) -> str:
    """Hash `(line_id, template_id)` of the rows, to compare template ids between runs."""
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["line_id"]):
        digest.update(f"{row['line_id']}\t{row.get('template_id')}\n".encode())
    return digest.hexdigest()


def _family_views(directory: Path, family: str) -> dict[str, str]:
    """Return a view per `<family>_*.parquet` file, and the view `<family>` over all of them."""
    views = {
        path.stem: f"SELECT * FROM read_parquet('{path}')"
        for path in sorted(directory.glob(f"{family}_*.parquet"))
    }
    if views:
        views[family] = " UNION ALL BY NAME ".join(
            f"SELECT * FROM {name}" for name in sorted(views)
        )
    return views


def data_views(directory: Path) -> dict[str, str]:
    """Return view name to SQL for the line, window and detection tables of a testbed."""
    views = {**_family_views(directory, "lines"), **_family_views(directory, "windows")}
    for name in DETECTION_TABLES:
        path = directory / f"{name}.parquet"
        if path.is_file():
            views[name] = f"SELECT * FROM read_parquet('{path}')"
    return views


def create_views(db_path: Path, views: dict[str, str]) -> None:
    """Recreate a DuckDB file holding the given views.

    View paths stay as given, so the files open from the directory they were built in.
    """
    db_path.unlink(missing_ok=True)
    with connect(db_path) as connection:
        for name, query in views.items():
            connection.execute(f'CREATE VIEW "{name}" AS {query}')


def create_tables(db_path: Path, sources: dict[str, str]) -> None:
    """Recreate a DuckDB file holding a table per source, without the hidden columns.

    The file keeps no reference to the Parquet files, so it opens from any directory and needs
    no file access at query time.

    Args:
        db_path: Database file to replace.
        sources: Table name to the SQL that fills it. A source may read an earlier table.
    """
    db_path.unlink(missing_ok=True)
    with connect(db_path) as connection:
        for name, query in sources.items():
            connection.execute(f'CREATE TABLE "{name}" AS {query}')
            columns = {row[0] for row in connection.execute(f'DESCRIBE "{name}"').fetchall()}
            for column in AGENT_HIDDEN_COLUMNS:
                if column in columns:
                    connection.execute(f'ALTER TABLE "{name}" DROP COLUMN "{column}"')


def build_agent_db(directory: Path) -> None:
    """Create `agent.duckdb`: tables only, and no ground truth (plan 5)."""
    create_tables(directory / "agent.duckdb", data_views(directory))
