"""OpenVPN server log parser (plan 6.1)."""

import re
from datetime import UTC, datetime

from logtriage.data.parsers.common import FAILED, ParseContext, ParsedLine

LINE = re.compile(r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<message>.*)$")
PEER = re.compile(
    r"^(?:(?P<user>[^\s/]+)/)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d+))? (?P<rest>.*)$"
)
POOL = re.compile(r"\bIPv4=(?P<vpn_ip>\d{1,3}(?:\.\d{1,3}){3})")


def parse_line(raw: str, ctx: ParseContext) -> ParsedLine:
    """Parse an openvpn.log line. The server logs in UTC."""
    match = LINE.match(raw)
    if match is None:
        return FAILED
    ts = datetime.strptime(match["time"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    message = match["message"]
    fields: dict[str, object] = {}
    src_ip = user = None
    if peer := PEER.match(message):
        src_ip, user, message = peer["ip"], peer["user"], peer["rest"]
        if peer["port"]:
            fields["port"] = int(peer["port"])
    if pool := POOL.search(message):
        fields["vpn_ip"] = pool["vpn_ip"]
    return ParsedLine(ok=True, ts=ts, message=message, src_ip=src_ip, user=user, fields=fields)
