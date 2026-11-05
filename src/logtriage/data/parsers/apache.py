"""Apache access and error log parsers (plan 6.1)."""

import re
from datetime import UTC, datetime

from logtriage.data.parsers.common import FAILED, MONTHS, ParseContext, ParsedLine


def _quoted(name: str) -> str:
    """Regex for a double-quoted field with backslash escapes."""
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


ACCESS = re.compile(
    r"^(?:(?P<vhost>\S+:\d+) )?(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) "
    r"\[(?P<time>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "
    rf"(?P<rest>{_quoted('request')} (?P<status>\d{{3}}) (?P<bytes>\d+|-)"
    rf"(?: {_quoted('referer')} {_quoted('user_agent')})?.*)$"
)
REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<protocol>HTTP/[\d.]+))?$")
ERROR = re.compile(
    r"^\[\w{3} (?P<month>\w{3}) (?P<day>\d{2}) (?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)? "
    r"(?P<year>\d{4})\] \[(?P<module>[^:\]]*):(?P<level>[^\]]+)\] \[pid (?P<pid>\d+)"
    r"(?::tid \d+)?\](?: \[client (?P<client>[^\]]+)\])? ?(?P<message>.*)$"
)


def parse_access(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse an Apache access line in combined or vhost_combined format."""
    match = ACCESS.match(raw)
    if match is None:
        return FAILED
    try:
        ts = _access_time(match["time"])
    except (ValueError, OverflowError):
        return FAILED
    request = match["request"]
    fields: dict[str, object] = {
        "status": int(match["status"]),
        "bytes": None if match["bytes"] == "-" else int(match["bytes"]),
        "referer": match["referer"],
        "user_agent": match["user_agent"],
        "request": request,
    }
    if match["vhost"]:
        fields["vhost"] = match["vhost"]
    if parsed := REQUEST.match(request):
        fields.update(parsed.groupdict())
    user = match["user"]
    return ParsedLine(
        ok=True,
        ts=ts,
        message=match["rest"],
        src_ip=match["ip"],
        user=None if user == "-" else user,
        fields=fields,
    )


def _access_time(text: str) -> datetime:
    """Parse `%d/%b/%Y:%H:%M:%S %z` into UTC."""
    return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)


def parse_error(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse an Apache error line. Lines not shaped like an Apache record are foreign."""
    match = ERROR.match(raw)
    if match is None:
        # Child processes write to the error log directly. Such text has no timestamp.
        is_foreign = raw.strip() and not raw.startswith("[")
        return ParsedLine(ok=False, foreign=True) if is_foreign else FAILED
    hour, minute, second = (int(part) for part in match["time"].split(":"))
    microsecond = int(float(match["frac"]) * 1_000_000) if match["frac"] else 0
    try:
        ts = datetime(
            int(match["year"]),
            MONTHS[match["month"]],
            int(match["day"]),
            hour,
            minute,
            second,
            microsecond,
            tzinfo=UTC,
        )
    except (KeyError, ValueError):
        return FAILED
    client = match["client"]
    return ParsedLine(
        ok=True,
        ts=ts,
        message=match["message"],
        src_ip=client.rsplit(":", 1)[0] if client else None,
        fields={"module": match["module"], "level": match["level"], "pid": int(match["pid"])},
    )
