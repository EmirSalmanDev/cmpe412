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


def lines_views(directory: Path) -> dict[str, str]:
    """Return view name to SQL for the `lines_*.parquet` files of a testbed."""
    views = {
        path.stem: f"SELECT * FROM read_parquet('{path}')"
        for path in sorted(directory.glob("lines_*.parquet"))
    }
    views["lines"] = " UNION ALL BY NAME ".join(f"SELECT * FROM {name}" for name in sorted(views))
    return views


def create_views(db_path: Path, views: dict[str, str]) -> None:
    """Recreate a DuckDB file holding the given views.

    View paths stay as given, so the files open from the directory they were built in.
    """
    db_path.unlink(missing_ok=True)
    with duckdb.connect(str(db_path)) as connection:
        for name, query in views.items():
            connection.execute(f'CREATE VIEW "{name}" AS {query}')


def build_agent_db(directory: Path) -> None:
    """Create `agent.duckdb`, which exposes the line tables only (plan 5)."""
    create_views(directory / "agent.duckdb", lines_views(directory))
