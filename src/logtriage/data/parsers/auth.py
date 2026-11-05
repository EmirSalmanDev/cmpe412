"""Syslog-format auth log parser (plan 6.1)."""

import re

from logtriage.data.parsers.common import FAILED, ParseContext, ParsedLine, utc_from_parts

LINE = re.compile(
    r"^(?P<month>\w{3}) +(?P<day>\d{1,2}) (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<hostname>\S+) (?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
SOURCE_IP = re.compile(r"(?:\bfrom |\brhost=)(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)")
USERS = (
    re.compile(r"\bfor (?:invalid user )?(?P<user>[\w.-]+) from\b"),
    re.compile(r"\bfor user (?P<user>[\w.-]+)"),
    re.compile(r"\buser=(?P<user>[\w.-]+)"),
    re.compile(r"^\s*(?P<user>[\w.-]+) : TTY="),
    re.compile(r"\bSuccessful su for (?P<user>[\w.-]+) by"),
)


def parse_line(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse an auth.log line."""
    match = LINE.match(raw)
    if match is None:
        return FAILED
    try:
        ts = utc_from_parts(
            ctx,
            match["month"],
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
        )
    except (KeyError, ValueError):
        return FAILED
    message = match["message"]
    source = SOURCE_IP.search(message)
    user = next((found["user"] for found in map(lambda p: p.search(message), USERS) if found), None)
    return ParsedLine(
        ok=True,
        ts=ts,
        message=message,
        src_ip=source.group(1) if source else None,
        user=user,
        fields={
            "hostname": match["hostname"],
            "process": match["process"],
            "pid": int(match["pid"]) if match["pid"] else None,
        },
    )
