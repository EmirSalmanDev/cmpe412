"""Parser tests on hand-made fixtures: formats, years, empty lines and line numbering."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logtriage.config import load_sources
from logtriage.data.parsers import (
    LogFile,
    apache,
    audit,
    auth,
    dns,
    find_log_files,
    iter_raw_lines,
    parse_file,
    vpn,
)
from logtriage.data.parsers.common import ParseContext, utc_from_parts

LOGS = Path(__file__).parent / "fixtures" / "logs"
SOURCES = load_sources(Path(__file__).parents[1] / "configs" / "sources.yaml")
CTX = ParseContext(sim_start=datetime(2022, 1, 14, tzinfo=UTC))


def lines(name: str) -> list[str]:
    return [text for _, text in iter_raw_lines(LOGS / name)]


def test_apache_access_fields() -> None:
    parsed = apache.parse_access(lines("apache_access.log")[0], CTX)
    assert parsed.ok
    assert parsed.ts == datetime(2022, 1, 17, 6, 25, 38, tzinfo=UTC)
    assert parsed.src_ip == "172.21.128.119"
    assert parsed.user is None
    assert parsed.message.startswith('"POST /wp-admin/admin-ajax.php HTTP/1.1" 200 3598')
    assert parsed.fields["method"] == "POST"
    assert parsed.fields["path"] == "/wp-admin/admin-ajax.php"
    assert parsed.fields["protocol"] == "HTTP/1.1"
    assert parsed.fields["status"] == 200
    assert parsed.fields["bytes"] == 3598
    assert parsed.fields["referer"] == "https://intranet.example/wp-admin/upload.php"
    assert parsed.fields["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64)"


def test_apache_access_converts_offsets_to_utc_and_keeps_escaped_quotes() -> None:
    parsed = apache.parse_access(lines("apache_access.log")[1], CTX)
    assert parsed.ts == datetime(2022, 1, 17, 6, 25, 39, tzinfo=UTC)
    assert parsed.user == "alice"
    assert parsed.fields["bytes"] is None
    assert parsed.fields["user_agent"] == 'curl/7.58 \\"quoted\\"'


def test_apache_access_vhost_format() -> None:
    parsed = apache.parse_access(lines("apache_access.log")[2], CTX)
    assert parsed.fields["vhost"] == "intranet.example:443"
    assert parsed.src_ip == "10.0.0.6"


@pytest.mark.parametrize("index", [3, 4])
def test_apache_access_keeps_requests_that_are_not_http(index: int) -> None:
    parsed = apache.parse_access(lines("apache_access.log")[index], CTX)
    assert parsed.ok
    assert "method" not in parsed.fields


def test_apache_access_rejects_other_text() -> None:
    assert not apache.parse_access(lines("apache_access.log")[5], CTX).ok


def test_apache_error_fields() -> None:
    parsed = apache.parse_error(lines("apache_error.log")[0], CTX)
    assert parsed.ts == datetime(2022, 1, 17, 11, 22, 2, 607946, tzinfo=UTC)
    assert parsed.src_ip == "172.21.128.119"
    assert parsed.message.startswith("AH01630: client denied")
    assert parsed.fields == {"module": "authz_core", "level": "error", "pid": 20320}


def test_apache_error_without_client_or_fraction() -> None:
    no_client = apache.parse_error(lines("apache_error.log")[1], CTX)
    assert no_client.ok and no_client.src_ip is None
    no_fraction = apache.parse_error(lines("apache_error.log")[2], CTX)
    assert no_fraction.ts == datetime(2022, 1, 17, 11, 22, 3, tzinfo=UTC)


def test_apache_error_separates_foreign_text_from_broken_records() -> None:
    raw = lines("apache_error.log")
    stderr = apache.parse_error(raw[3], CTX)
    assert not stderr.ok and stderr.foreign
    blank = apache.parse_error(raw[4], CTX)
    assert not blank.ok and not blank.foreign
    broken = apache.parse_error(raw[5], CTX)
    assert not broken.ok and not broken.foreign


def test_auth_fields() -> None:
    raw = lines("auth.log")
    closed = auth.parse_line(raw[0], CTX)
    assert closed.ts == datetime(2022, 1, 16, 6, 25, 14, tzinfo=UTC)
    assert closed.user == "root"
    assert closed.fields == {"hostname": "intranet-server", "process": "CRON", "pid": 14139}
    accepted = auth.parse_line(raw[1], CTX)
    assert (accepted.src_ip, accepted.user) == ("10.0.0.9", "alice")
    failed = auth.parse_line(raw[2], CTX)
    assert failed.ts == datetime(2022, 1, 6, 6, 39, 3, tzinfo=UTC)
    assert (failed.src_ip, failed.user) == ("10.0.0.10", "bob")
    sudo = auth.parse_line(raw[3], CTX)
    assert sudo.user == "carol"
    assert sudo.fields["pid"] is None
    assert not auth.parse_line(raw[4], CTX).ok


def test_dns_fields() -> None:
    raw = lines("dnsmasq.log")
    assert dns.parse_line(raw[0], CTX).fields["action"] == "other"
    query = dns.parse_line(raw[1], CTX)
    assert query.ts == datetime(2022, 1, 14, 0, 0, 9, tzinfo=UTC)
    assert query.src_ip == "10.0.0.2"
    assert query.fields == {
        "pid": 14919,
        "action": "query",
        "qtype": "A",
        "qname": "a1-.b2.example.com",
    }
    assert dns.parse_line(raw[2], CTX).fields["target"] == "8.8.8.8"
    assert dns.parse_line(raw[3], CTX).fields["answer"] == "1.2.3.4"
    assert dns.parse_line(raw[4], CTX).fields["action"] == "cached"
    assert dns.parse_line(raw[5], CTX).fields["action"] == "/etc/hosts"
    assert not dns.parse_line("x", CTX).ok


def test_audit_fields() -> None:
    raw = lines("audit.log")
    acct = audit.parse_line(raw[0], CTX)
    assert acct.ts == datetime.fromtimestamp(1642118941.668, tz=UTC)
    assert acct.user == "root"
    assert acct.src_ip is None
    assert acct.message.startswith("USER_ACCT pid=9699")
    assert acct.fields["type"] == "USER_ACCT"
    assert acct.fields["serial"] == 306
    assert acct.fields["exe"] == "/usr/sbin/cron"
    assert acct.fields["res"] == "success"
    auth_record = audit.parse_line(raw[1], CTX)
    assert (auth_record.src_ip, auth_record.user) == ("10.0.0.9", "alice")
    syscall = audit.parse_line(raw[2], CTX)
    assert syscall.fields["comm"] == "sh"
    assert syscall.fields["success"] == "yes"
    assert not audit.parse_line(raw[3], CTX).ok


def test_vpn_fields() -> None:
    raw = lines("openvpn.log")
    peer = vpn.parse_line(raw[0], CTX)
    assert peer.ts == datetime(2022, 1, 14, 0, 49, 39, tzinfo=UTC)
    assert (peer.src_ip, peer.user) == ("10.229.3.112", "gmorgan")
    assert peer.fields == {"port": 54658}
    assert peer.message.startswith("TLS: soft reset")
    no_user = vpn.parse_line(raw[1], CTX)
    assert (no_user.src_ip, no_user.user) == ("10.229.3.113", None)
    assert vpn.parse_line(raw[2], CTX).fields["vpn_ip"] == "10.8.0.6"
    server = vpn.parse_line(raw[3], CTX)
    assert server.ok and server.src_ip is None
    assert not vpn.parse_line(raw[4], CTX).ok


@pytest.mark.parametrize(
    ("sim_start", "month", "expected_year"),
    [
        (datetime(2022, 1, 14, tzinfo=UTC), "Jan", 2022),
        (datetime(2022, 1, 1, tzinfo=UTC), "Dec", 2021),
        (datetime(2021, 12, 30, tzinfo=UTC), "Jan", 2022),
        (datetime(2021, 12, 30, tzinfo=UTC), "Dec", 2021),
    ],
)
def test_year_comes_from_sim_start_and_crosses_new_year(
    sim_start: datetime, month: str, expected_year: int
) -> None:
    ts = utc_from_parts(ParseContext(sim_start), month, 15, 1, 2, 3)
    assert ts.year == expected_year
    assert ts.tzinfo == UTC


def test_syslog_parsers_reject_impossible_dates() -> None:
    assert not dns.parse_line("Feb 30 00:00:00 dnsmasq[1]: x", CTX).ok
    assert not auth.parse_line("Foo 10 00:00:00 h p[1]: x", CTX).ok


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"", []),
        (b"a", [(1, "a")]),
        (b"a\n", [(1, "a")]),
        (b"a\n\nb\n", [(1, "a"), (2, ""), (3, "b")]),
        (b"\n\n", [(1, ""), (2, "")]),
        (b"a\rb\nc", [(1, "a\rb"), (2, "c")]),
        (b"\xff\n", [(1, "�")]),
    ],
)
@pytest.mark.parametrize("chunk_bytes", [1, 2, 1024])
def test_iter_raw_lines(
    tmp_path: Path, content: bytes, expected: list[tuple[int, str]], chunk_bytes: int
) -> None:
    path = tmp_path / "file"
    path.write_bytes(content)
    assert list(iter_raw_lines(path, chunk_bytes)) == expected


def write_log(tmp_path: Path, text: str, log_type: str = "dns") -> LogFile:
    path = tmp_path / "dnsmasq.log"
    path.write_text(text, encoding="utf-8")
    return LogFile(path, "inet-dns", "logs/dnsmasq.log", log_type)


END = datetime(2022, 1, 15, tzinfo=UTC)


def test_parse_file_numbers_lines_before_filtering(tmp_path: Path) -> None:
    log_file = write_log(
        tmp_path,
        "Jan 13 23:59:59 dnsmasq[1]: before\n"
        "\n"
        "Jan 14 00:00:00 dnsmasq[1]: first\n"
        "broken\n"
        "Jan 14 23:59:59 dnsmasq[1]: last\n"
        "Jan 15 00:00:00 dnsmasq[1]: after\n",
    )
    rows, stats = parse_file(log_file, "tiny", CTX, END)
    assert [row["line_no"] for row in rows] == [3, 4, 5]
    assert rows[0]["line_id"] == "inet-dns|logs/dnsmasq.log|3"
    assert (stats.lines, stats.parsed, stats.blank, stats.kept) == (6, 4, 1, 3)
    assert stats.parse_rate == pytest.approx(4 / 5)


def test_parse_file_gives_unparsed_lines_the_previous_time(tmp_path: Path) -> None:
    log_file = write_log(tmp_path, "Jan 14 00:00:01 dnsmasq[1]: a\nbroken\n")
    rows, _ = parse_file(log_file, "tiny", CTX, END)
    assert rows[1]["ts"] == rows[0]["ts"]
    assert rows[1]["parse_ok"] is False
    assert rows[1]["raw"] == "broken"
    assert rows[1]["message"] == ""


def test_parse_file_gives_leading_unparsed_lines_the_next_time(tmp_path: Path) -> None:
    log_file = write_log(tmp_path, "broken\nJan 14 00:00:01 dnsmasq[1]: a\n")
    rows, _ = parse_file(log_file, "tiny", CTX, END)
    assert rows[0]["ts"] == rows[1]["ts"]


def test_parse_file_without_any_time_keeps_no_rows(tmp_path: Path) -> None:
    rows, stats = parse_file(write_log(tmp_path, "broken\n"), "tiny", CTX, END)
    assert rows == []
    assert stats.lines == 1


def test_parse_rate_leaves_out_foreign_lines(tmp_path: Path) -> None:
    log_file = write_log(
        tmp_path,
        "[Fri Jan 14 11:22:03 2022] [core:notice] [pid 1] AH1: x\nstderr text\n[broken\n",
        "apache_error",
    )
    _, stats = parse_file(log_file, "tiny", CTX, END)
    assert (stats.parsed, stats.foreign) == (1, 1)
    assert stats.parse_rate == pytest.approx(1 / 2)


def test_parse_rate_of_an_empty_file(tmp_path: Path) -> None:
    _, stats = parse_file(write_log(tmp_path, ""), "tiny", CTX, END)
    assert stats.parse_rate == 1.0


def test_find_log_files(tmp_path: Path) -> None:
    for name in (
        "gather/vpn/logs/openvpn.log",
        "gather/vpn/logs/audit/audit.log",
        "gather/attacker_0/logs/attacks.log",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    assert [(f.host, f.file, f.log_type) for f in find_log_files(tmp_path, SOURCES)] == [
        ("vpn", "logs/audit/audit.log", "audit"),
        ("vpn", "logs/openvpn.log", "vpn"),
    ]


def test_ctx_year_boundary_margin() -> None:
    ctx = ParseContext(datetime(2022, 7, 1, tzinfo=UTC))
    assert utc_from_parts(ctx, "Jan", 2, 0, 0, 0).year == 2022
    assert ctx.sim_start - utc_from_parts(ctx, "Jan", 2, 0, 0, 0) < timedelta(days=183)


@pytest.mark.parametrize(
    ("parse", "raw"),
    [
        (apache.parse_access, '1.2.3.4 - - [99/Jan/2022:03:56:53 +0000] "GET / HTTP/1.1" 200 5'),
        (apache.parse_access, '1.2.3.4 - - [24/Foo/2022:03:56:53 +0000] "GET / HTTP/1.1" 200 5'),
        (apache.parse_access, '1.2.3.4 - - [01/Jan/0001:00:00:00 +1400] "GET / HTTP/1.1" 200 5'),
        (apache.parse_error, "[Mon Foo 24 03:57:26.1 2022] [core:error] [pid 1] text"),
        (apache.parse_error, "[Mon Jan 99 03:57:26.1 2022] [core:error] [pid 1] text"),
        (apache.parse_error, "[Mon Jan 24 99:57:26.1 2022] [core:error] [pid 1] text"),
        (vpn.parse_line, "2022-13-45 03:01:00 text"),
        (audit.parse_line, "type=X msg=audit(99999999999999999999.000:1): a=b"),
    ],
)
def test_an_impossible_timestamp_fails_the_line_instead_of_raising(parse, raw: str) -> None:
    parsed = parse(raw, CTX)
    assert not parsed.ok
    assert not parsed.foreign


def test_apache_error_keeps_the_exact_microseconds() -> None:
    # Real value from santos: float(".500624") * 1e6 truncates to 500623.
    raw = "[Sun Jan 16 06:25:14.500624 2022] [mpm_prefork:notice] [pid 1] text"
    assert apache.parse_error(raw, CTX).ts == datetime(2022, 1, 16, 6, 25, 14, 500624, tzinfo=UTC)
