"""Shared types and timestamp helpers for the log parsers (plan 6.1)."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
HALF_YEAR = timedelta(days=183)


@dataclass(frozen=True)
class ParseContext:
    """What a parser needs to know beyond the line itself."""

    sim_start: datetime


@dataclass
class ParsedLine:
    """Result of parsing one line. `ok=False` means only the raw line is usable.

    `foreign` marks text in the file that is not a record of this log format, such as process
    stderr in an Apache error log. It does not count against the parse rate (plan 6.1).
    """

    ok: bool
    ts: datetime | None = None
    message: str = ""
    src_ip: str | None = None
    user: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    foreign: bool = False


FAILED = ParsedLine(ok=False)


def utc_from_parts(
    ctx: ParseContext, month: str, day: int, hour: int, minute: int, second: int
) -> datetime:
    """Build a UTC timestamp for a line without a year.

    The year comes from `sim_start`. A date more than half a year from `sim_start` belongs to
    the neighbouring year, which handles simulations that cross New Year.

    Raises:
        KeyError: If the month name is unknown.
        ValueError: If the date does not exist.
    """
    year = ctx.sim_start.year
    ts = datetime(year, MONTHS[month], day, hour, minute, second, tzinfo=UTC)
    if ts - ctx.sim_start > HALF_YEAR:
        return ts.replace(year=year - 1)
    if ctx.sim_start - ts > HALF_YEAR:
        return ts.replace(year=year + 1)
    return ts
