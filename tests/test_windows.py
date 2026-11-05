"""Windows (plan 5.4): parsed lines only, in UTC buckets."""

from datetime import UTC, datetime
from pathlib import Path

from logtriage.data.store import connect, write_lines
from logtriage.data.windows import PARSED_VIEW, create_parsed_view


def line(number: int, ts: datetime, parse_ok: bool = True) -> dict:
    """Build a row of a lines table."""
    return {
        "line_id": f"h|f|{number}",
        "testbed": "tiny",
        "host": "h",
        "log_type": "vpn",
        "file": "f",
        "line_no": number,
        "ts": ts,
        "raw": "x",
        "message": "x",
        "fields": "{}",
        "parse_ok": parse_ok,
    }


def test_lines_that_did_not_parse_stay_out_of_the_view(tmp_path: Path) -> None:
    ts = datetime(2022, 1, 14, 0, 0, 5, tzinfo=UTC)
    path = tmp_path / "lines_vpn.parquet"
    write_lines([line(1, ts), line(2, ts, parse_ok=False), line(3, ts)], path)
    with connect() as con:
        create_parsed_view(con, path, 60)
        kept = con.execute(f"SELECT line_no FROM {PARSED_VIEW} ORDER BY 1").fetchall()
    assert kept == [(1,), (3,)]


def test_lines_fall_into_utc_minute_buckets(tmp_path: Path) -> None:
    moments = [
        datetime(2022, 1, 14, 0, 0, 0, tzinfo=UTC),
        datetime(2022, 1, 14, 0, 0, 59, 999999, tzinfo=UTC),
        datetime(2022, 1, 14, 0, 1, 0, tzinfo=UTC),
    ]
    path = tmp_path / "lines_vpn.parquet"
    write_lines([line(number, ts) for number, ts in enumerate(moments, 1)], path)
    with connect() as con:
        create_parsed_view(con, path, 60)
        rows = con.execute(f"SELECT window_start FROM {PARSED_VIEW} ORDER BY line_no").fetchall()
    assert [row[0] for row in rows] == [moments[0], moments[0], moments[2]]
