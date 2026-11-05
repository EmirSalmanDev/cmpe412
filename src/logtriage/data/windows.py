"""Time-window construction (plan 5.4).

A window holds the parsed lines of one `(testbed, host, log_type)` in one time bucket.
"""

from pathlib import Path

import duckdb

from logtriage.data.periods import Periods

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


def period_sql(window_seconds: int, periods: Periods) -> str:
    """SQL for the `period` of a window: the period in which the window ends.

    A window that crosses a boundary goes to the later period, so a `fit` window holds only
    fit lines and nothing fit on `fit` windows can see a later line.

    Args:
        window_seconds: Window length.
        periods: Boundaries of the testbed.

    Returns:
        A SQL expression over `window_start`.
    """
    end = f"window_start + INTERVAL {int(window_seconds)} SECOND"
    return (
        f"CASE WHEN {end} <= TIMESTAMPTZ '{periods.fit_end.isoformat()}' THEN 'fit' "
        f"WHEN {end} <= TIMESTAMPTZ '{periods.train_end.isoformat()}' THEN 'calib' "
        "ELSE 'eval' END"
    )
