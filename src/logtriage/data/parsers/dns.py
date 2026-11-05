"""dnsmasq log parser (plan 6.1)."""

import re

from logtriage.data.parsers.common import FAILED, ParseContext, ParsedLine, utc_from_parts

LINE = re.compile(
    r"^(?P<month>\w{3}) +(?P<day>\d{1,2}) (?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<process>[^\s:\[]+)\[(?P<pid>\d+)\]: (?P<message>.*)$"
)
QUERY = re.compile(r"^query\[(?P<qtype>[^\]]+)\] (?P<qname>\S+) from (?P<src>\S+)$")
FORWARDED = re.compile(r"^forwarded (?P<qname>\S+) to (?P<target>\S+)$")
ANSWER = re.compile(r"^(?P<action>reply|cached|config|/\S+) (?P<qname>\S+) is (?P<answer>.*)$")


def parse_line(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse a dnsmasq line."""
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
    fields: dict[str, object] = {"pid": int(match["pid"])}
    src_ip = None
    if query := QUERY.match(message):
        src_ip = query["src"]
        fields.update(action="query", qtype=query["qtype"], qname=query["qname"])
    elif forwarded := FORWARDED.match(message):
        fields.update(action="forwarded", qname=forwarded["qname"], target=forwarded["target"])
    elif answer := ANSWER.match(message):
        fields.update(action=answer["action"], qname=answer["qname"], answer=answer["answer"])
    else:
        fields["action"] = "other"
    return ParsedLine(ok=True, ts=ts, message=message, src_ip=src_ip, fields=fields)
