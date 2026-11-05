"""auditd log parser (plan 6.1)."""

import re
from datetime import UTC, datetime

from logtriage.data.parsers.common import FAILED, ParseContext, ParsedLine

LINE = re.compile(
    r"^type=(?P<type>\S+) msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\): ?(?P<message>.*)$"
)
PAIR = re.compile(r"""([\w-]+)=("[^"]*"|'[^']*'|\S+)""")
KEPT = ("pid", "ppid", "uid", "auid", "euid", "ses", "exe", "comm", "res", "success", "op", "key")
NO_VALUE = {"?", "(none)", "(null)", ""}


def parse_line(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse an audit.log record."""
    match = LINE.match(raw)
    if match is None:
        return FAILED
    try:
        ts = datetime.fromtimestamp(float(match["epoch"]), tz=UTC)
    except (ValueError, OverflowError, OSError):
        return FAILED
    message = match["message"]
    pairs: dict[str, str] = {}
    for key, value in PAIR.findall(message):
        value = value.strip("\"'")
        pairs.setdefault(key, value)
        if key == "msg":  # USER_* records nest their key=value text in msg='...'
            for inner_key, inner_value in PAIR.findall(value):
                pairs.setdefault(inner_key, inner_value.strip("\"'"))
    fields: dict[str, object] = {"type": match["type"], "serial": int(match["serial"])}
    fields.update({key: pairs[key] for key in KEPT if key in pairs})
    address = pairs.get("addr")
    user = pairs.get("acct") or pairs.get("id")
    return ParsedLine(
        ok=True,
        ts=ts,
        message=f"{match['type']} {message}",
        src_ip=None if address in NO_VALUE else address,
        user=None if user in NO_VALUE else user,
        fields=fields,
    )
