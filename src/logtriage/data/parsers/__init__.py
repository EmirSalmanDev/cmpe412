"""Per-log-family parsers and the file reader that assigns line numbers (plan 5.1, 6.1)."""

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from logtriage.config import LogSources
from logtriage.data.parsers import apache, audit, auth, dns, vpn
from logtriage.data.parsers.common import ParseContext, ParsedLine

PARSERS: dict[str, Callable[[str, ParseContext], ParsedLine]] = {
    "apache_access": apache.parse_access,
    "apache_error": apache.parse_error,
    "auth": auth.parse_line,
    "dns": dns.parse_line,
    "audit": audit.parse_line,
    "vpn": vpn.parse_line,
}
CHUNK_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class LogFile:
    """A log file of a testbed."""

    path: Path
    host: str
    file: str
    log_type: str


@dataclass
class FileStats:
    """Parse counts of one file. `lines` counts every line, including those out of range."""

    host: str
    file: str
    log_type: str
    lines: int = 0
    parsed: int = 0
    blank: int = 0
    foreign: int = 0
    kept: int = 0

    @property
    def parse_rate(self) -> float:
        """Share of the log records that parsed: blank and foreign lines are left out."""
        total = self.lines - self.blank - self.foreign
        return self.parsed / total if total else 1.0


def iter_raw_lines(path: Path, chunk_bytes: int = CHUNK_BYTES) -> Iterator[tuple[int, str]]:
    """Yield `(line_no, text)`, streaming binary chunks and splitting on `\\n` only.

    Line numbers are 1-based and count empty lines. A final newline does not start a line.
    """
    line_no = 0
    tail = b""
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_bytes):
            pieces = (tail + chunk).split(b"\n")
            tail = pieces.pop()
            for piece in pieces:
                line_no += 1
                yield line_no, piece.decode("utf-8", errors="replace")
    if tail:
        yield line_no + 1, tail.decode("utf-8", errors="replace")


def find_log_files(testbed_dir: Path, sources: LogSources) -> list[LogFile]:
    """Find the files of the log families under `gather/`, sorted by path."""
    files = []
    for path in sorted((testbed_dir / "gather").rglob("*")):
        relative = path.relative_to(testbed_dir).as_posix()
        log_type = sources.log_type(relative)
        if path.is_file() and log_type:
            _, host, file = relative.split("/", 2)
            files.append(LogFile(path, host, file, log_type))
    return files


def parse_file(
    log_file: LogFile, testbed: str, ctx: ParseContext, sim_end: datetime
) -> tuple[list[dict[str, Any]], FileStats]:
    """Parse a file into rows of `lines_<log_type>.parquet`, without the template columns.

    A line that does not parse keeps `raw` and takes the previous line's `ts`; at the start of
    a file it takes the next parsed `ts`. Lines outside `[sim_start, sim_end)` are dropped
    after numbering. A file with no parsed line yields no rows.

    Args:
        log_file: The file to parse.
        testbed: Testbed name.
        ctx: Parser context.
        sim_end: End of the simulation, exclusive.

    Returns:
        The kept rows and the parse counts.
    """
    parse = PARSERS[log_file.log_type]
    stats = FileStats(log_file.host, log_file.file, log_file.log_type)
    rows: list[dict[str, Any]] = []
    previous_ts: datetime | None = None
    for line_no, raw in iter_raw_lines(log_file.path):
        stats.lines += 1
        stats.blank += not raw.strip()
        parsed = parse(raw, ctx)
        stats.parsed += parsed.ok
        stats.foreign += parsed.foreign
        previous_ts = parsed.ts or previous_ts
        rows.append(
            {
                "line_id": f"{log_file.host}|{log_file.file}|{line_no}",
                "testbed": testbed,
                "host": log_file.host,
                "log_type": log_file.log_type,
                "file": log_file.file,
                "line_no": line_no,
                "ts": previous_ts,
                "raw": raw,
                "message": parsed.message,
                "src_ip": parsed.src_ip,
                "user": parsed.user,
                "fields": json.dumps(parsed.fields, sort_keys=True),
                "parse_ok": parsed.ok,
            }
        )
    next_ts = next((row["ts"] for row in rows if row["ts"] is not None), None)
    for row in rows:
        if row["ts"] is not None:
            break
        row["ts"] = next_ts
    kept = [row for row in rows if row["ts"] and ctx.sim_start <= row["ts"] < sim_end]
    stats.kept = len(kept)
    return kept, stats
