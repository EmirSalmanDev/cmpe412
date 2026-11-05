"""Tests for line counting, the inventory, sources patterns and phase handling."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logtriage.config import glob_match, load_sources
from logtriage.data.inventory import (
    build_inventory,
    count_lines,
    render_report,
    unmapped_labeled_files,
)
from logtriage.data.labels import (
    Phase,
    cross_check_phases,
    read_attack_steps,
    read_exfil_interval,
    read_phase_intervals,
    summarize_label_file,
    write_phases_csv,
)

FIXTURES = Path(__file__).parent / "fixtures"
SOURCES = load_sources(Path(__file__).parents[1] / "configs" / "sources.yaml")


@pytest.mark.parametrize(
    ("content", "expected"),
    [(b"", 0), (b"a", 1), (b"a\n", 1), (b"a\nb", 2), (b"a\nb\n", 2), (b"\n\n", 2)],
)
def test_count_lines(tmp_path: Path, content: bytes, expected: int) -> None:
    path = tmp_path / "file"
    path.write_bytes(content)
    assert count_lines(path, chunk_bytes=1) == expected
    assert count_lines(path) == expected


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("gather/vpn/logs/auth.log", "gather/*/logs/auth.log*", True),
        ("gather/vpn/logs/auth.log.1", "gather/*/logs/auth.log*", True),
        ("gather/vpn/logs/sub/auth.log", "gather/*/logs/auth.log*", False),
        ("gather/a/logs/b/c.json", "gather/a/logs/**", True),
        ("gather/a/logs/b/c.pcap", "**.pcap", True),
        ("gather/a/logs/b.pcapng", "**.pcap", False),
        ("labels.csv", "labels/**", False),
    ],
)
def test_glob_match(path: str, pattern: str, expected: bool) -> None:
    assert glob_match(path, pattern) is expected


@pytest.mark.parametrize(
    ("path", "log_type"),
    [
        ("gather/webserver/logs/apache2/proxy-access.log.4", "apache_access"),
        ("gather/cloud_share/logs/apache2/other_vhosts_access.log.3", "apache_access"),
        ("gather/webserver/logs/apache2/mail.smith.santos.com-error.log", "apache_error"),
        ("gather/cloud_share/logs/apache2/error.log.1", "apache_error"),
        ("gather/vpn/logs/auth.log.1", "auth"),
        ("gather/inet-dns/logs/dnsmasq.log", "dns"),
        ("gather/mail/logs/audit/audit.log", "audit"),
        ("gather/vpn/logs/openvpn.log", "vpn"),
        ("gather/monitoring/logs/logstash/internal-share/2022-01-22-system.auth.log", None),
        ("gather/webserver/logs/horde/horde-access.log", None),
    ],
)
def test_log_type_mapping(path: str, log_type: str | None) -> None:
    assert SOURCES.log_type(path) == log_type


def make_testbed(root: Path) -> Path:
    """Create a tiny extracted testbed."""
    files = {
        "gather/vpn/logs/openvpn.log": "a\nb\nc\n",
        "gather/vpn/logs/auth.log": "a\n",
        "gather/monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log": "m\n",
    }
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    labels = {
        "labels/vpn/logs/openvpn.log": [
            {"line": 1, "labels": ["attacker_vpn", "foothold"], "rules": {}},
            {"line": 2, "labels": ["foothold"], "rules": {}},
        ],
        "labels/monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log": [
            {"line": 1, "labels": ["escalate"], "rules": {}},
        ],
    }
    for name, rows in labels.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return root


def test_summarize_label_file(tmp_path: Path) -> None:
    root = make_testbed(tmp_path)
    summary = summarize_label_file(root / "labels/vpn/logs/openvpn.log")
    assert summary.labeled_lines == 2
    assert summary.label_counts == {"attacker_vpn": 1, "foothold": 2}


def test_build_inventory_joins_labels_to_logs(tmp_path: Path) -> None:
    records = {r.path: r for r in build_inventory(make_testbed(tmp_path), SOURCES)}
    vpn = records["gather/vpn/logs/openvpn.log"]
    assert (vpn.host, vpn.lines, vpn.log_type) == ("vpn", 3, "vpn")
    assert (vpn.has_labels, vpn.labeled_lines) == (True, 2)
    assert not records["gather/vpn/logs/auth.log"].has_labels


def test_build_inventory_requires_the_labeled_log(tmp_path: Path) -> None:
    root = make_testbed(tmp_path)
    (root / "gather/vpn/logs/openvpn.log").unlink()
    with pytest.raises(FileNotFoundError, match="openvpn.log"):
        build_inventory(root, SOURCES)


def test_unmapped_labeled_files(tmp_path: Path) -> None:
    root = make_testbed(tmp_path)
    assert unmapped_labeled_files(build_inventory(root, SOURCES), SOURCES) == []

    (root / "gather/vpn/logs/new.log").write_text("x\n", encoding="utf-8")
    (root / "labels/vpn/logs/new.log").write_text('{"line": 1, "labels": []}\n', encoding="utf-8")
    assert unmapped_labeled_files(build_inventory(root, SOURCES), SOURCES) == [
        "gather/vpn/logs/new.log"
    ]


def test_render_report(tmp_path: Path) -> None:
    records = build_inventory(make_testbed(tmp_path), SOURCES)
    report = render_report("tiny", records, SOURCES, ["## Extra"])
    assert report.startswith("# Inventory: tiny\n")
    assert "| `gather/vpn/logs/openvpn.log` | vpn | 3 | 2 |" in report
    assert "| foothold | 2 |" in report
    assert "| `gather/vpn/logs/openvpn.log` | foothold | 2 |" in report
    assert "## Extra" in report


def test_read_phase_intervals_sorts_by_time_and_keeps_utc() -> None:
    phases = read_phase_intervals(FIXTURES / "ait_ads_labels.csv", "tiny", "labels.csv")
    assert [phase.phase for phase in phases] == ["dnsteal", "network_scans"]
    assert phases[1].end == datetime(2022, 1, 17, 9, 0, 30, 500000, tzinfo=UTC)
    assert phases[0].start.tzinfo == UTC


def test_read_phase_intervals_rejects_unknown_testbed() -> None:
    with pytest.raises(ValueError, match="nope"):
        read_phase_intervals(FIXTURES / "ait_ads_labels.csv", "nope", "labels.csv")


def test_read_attack_steps_keeps_the_first_time() -> None:
    steps = read_attack_steps(FIXTURES / "attacks.log")
    assert steps["vpn_connect"] == datetime(2022, 1, 17, 9, 0, tzinfo=UTC)
    assert steps["service_scan"] == datetime(2022, 1, 17, 9, 0, 10, 500000, tzinfo=UTC)


def test_cross_check_phases() -> None:
    phases = read_phase_intervals(FIXTURES / "ait_ads_labels.csv", "tiny", "labels.csv")
    steps = read_attack_steps(FIXTURES / "attacks.log")
    checks = cross_check_phases(
        phases, steps, {"network_scans": ["vpn_connect", "service_scan"], "dnsteal": ["not_logged"]}
    )
    assert [(c.phase, c.step, c.delta_seconds) for c in checks] == [
        ("dnsteal", "not_logged", None),
        ("network_scans", "vpn_connect", 0),
        ("network_scans", "service_scan", -10.5),
    ]


def test_read_exfil_interval(tmp_path: Path) -> None:
    path = tmp_path / "dnsteal.log"
    path.write_text(
        '{"event": "DNS server listening", "timestamp": 100.0}\n'
        '{"event": "Received data", "timestamp": 1642320000.0}\n'
        '{"data": "b\'abc\'", "timestamp": 1642320001.0}\n'
        "not json\n"
        '{"event": "Received data", "timestamp": 1642320060.0}\n'
        '{"event": "Saving unfinished files", "timestamp": 1642320090.0}\n',
        encoding="utf-8",
    )
    assert read_exfil_interval(path) == (
        datetime.fromtimestamp(1642320000, tz=UTC),
        datetime.fromtimestamp(1642320060, tz=UTC),
    )


def test_read_exfil_interval_needs_events(tmp_path: Path) -> None:
    path = tmp_path / "dnsteal.log"
    path.write_text('{"event": "DNS server listening", "timestamp": 100.0}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="no received data"):
        read_exfil_interval(path)


def test_write_phases_csv(tmp_path: Path) -> None:
    start = datetime(2022, 1, 17, 9, 0, tzinfo=UTC)
    end = datetime(2022, 1, 17, 9, 1, tzinfo=UTC)
    path = tmp_path / "meta" / "phases_tiny.csv"
    write_phases_csv([Phase("tiny", "dirb", start, end, "labels.csv")], path)
    assert path.read_text(encoding="utf-8") == (
        "testbed,phase,start_utc,end_utc,source\n"
        "tiny,dirb,2022-01-17T09:00:00+00:00,2022-01-17T09:01:00+00:00,labels.csv\n"
    )
