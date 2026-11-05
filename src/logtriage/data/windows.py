"""Time-window construction (plan 5.4).

A window holds the parsed lines of one `(testbed, host, log_type)` in one time bucket.
"""

from pathlib import Path

import duckdb

PARSED_VIEW = "parsed_lines"


def create_parsed_view(
    con: duckdb.DuckDBPyConnection, lines_path: Path, window_seconds: int
) -> None:
    """Create the view that windows and features read: parsed lines with their window.

    Lines with `parse_ok=False` stop here, so nothing downstream can count them (D14).

    Args:
        con: Connection from `store.connect`, so buckets follow UTC.
        lines_path: A `lines_<log_type>.parquet` file.
        window_seconds: Window length.
    """
    con.execute(
        f"""
        CREATE OR REPLACE TEMP VIEW {PARSED_VIEW} AS
        SELECT *, time_bucket(INTERVAL {int(window_seconds)} SECOND, ts) AS window_start
        FROM read_parquet('{lines_path}')
        WHERE parse_ok
        """
    )
