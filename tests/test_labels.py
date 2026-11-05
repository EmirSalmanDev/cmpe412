"""Tests for phase assignment and the label join (plan 5.2, 5.3)."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from logtriage.config import PhasesConfig, load_sources
from logtriage.data.labels import (
    Phase,
    assign_phase,
    build_eval_db,
    build_labels,
    phase_report,
    read_phases_csv,
    write_labels,
    write_phases_csv,
)
from logtriage.data.store import build_agent_db, connect, template_digest, write_lines

SOURCES = load_sources(Path(__file__).parents[1] / "configs" / "sources.yaml")
CONFIG = PhasesConfig()
T0 = datetime(2022, 1, 24, 3, 0, tzinfo=UTC)
PUBLISHED = "ait_ads:labels.csv"


def minutes(value: float) -> datetime:
    return T0 + timedelta(minutes=value)


PHASES = [
    Phase("tiny", "dnsteal_exfil", minutes(-600), minutes(600), "attacker_0:dnsteal.log"),
    Phase("tiny", "scan", minutes(0), minutes(10), PUBLISHED),
    Phase("tiny", "dirb", minutes(10), minutes(11), PUBLISHED),
    Phase("tiny", "service_stop", minutes(600.2), minutes(600.3), PUBLISHED),
    Phase("tiny", "dnsteal", minutes(700), minutes(760), PUBLISHED),
]


@pytest.mark.parametrize(
    ("ts", "labels", "expected"),
    [
        (minutes(5), ["network_scan"], "scan"),
        (minutes(10), ["dirb"], "dirb"),
        (minutes(10.5), ["dirb"], "dirb"),
        (minutes(-0.5), ["foothold"], "scan"),
        (minutes(11.5), ["foothold"], "dirb"),
        (minutes(-2), ["foothold"], "unassigned"),
        (minutes(100), ["foothold"], "unassigned"),
        (minutes(5), ["dnsteal", "attacker"], "dnsteal_exfil"),
        (minutes(100), ["dnsteal"], "dnsteal_exfil"),
        (minutes(600.1), ["dnsteal"], "dnsteal_exfil"),
        (minutes(600.25), ["dnsteal", "exfiltration-service"], "service_stop"),
        (minutes(705), ["dnsteal", "dnsteal-dropped"], "dnsteal"),
        (minutes(650), ["dnsteal"], "unassigned"),
        (minutes(599), ["foothold"], "unassigned"),
    ],
)
def test_assign_phase(ts: datetime, labels: list[str], expected: str) -> None:
    assert assign_phase(ts, labels, PHASES, CONFIG) == expected


def test_phases_csv_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "phases.csv"
    write_phases_csv(PHASES, path)
    assert read_phases_csv(path) == PHASES


def make_labels(root: Path) -> dict[str, datetime]:
    entries = {
        "labels/vpn/logs/openvpn.log": [
            {"line": 1, "labels": ["foothold"], "rules": {"foothold": ["r"]}},
            {"line": 3, "labels": ["foothold"], "rules": {}},
            {"line": 9, "labels": ["foothold"], "rules": {}},
        ],
        "labels/monitoring/logs/logstash/x/2022-01-24-system.cpu.log": [
            {"line": 1, "labels": ["escalate"], "rules": {}},
        ],
    }
    for name, rows in entries.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return {"vpn|logs/openvpn.log|1": minutes(5), "vpn|logs/openvpn.log|3": minutes(100)}


def test_build_labels_joins_on_host_file_and_line(tmp_path: Path) -> None:
    lines = make_labels(tmp_path)
    rows, report = build_labels(tmp_path, lines, PHASES, SOURCES, CONFIG)
    assert [(row["line_id"], row["phase"]) for row in rows] == [
        ("vpn|logs/openvpn.log|1", "scan"),
        ("vpn|logs/openvpn.log|3", "unassigned"),
    ]
    assert json.loads(rows[0]["rules"]) == {"foothold": ["r"]}
    assert (report["labeled"], report["resolved"], report["in_phase"]) == (3, 2, 1)
    assert report["in_phase_rate"] == 0.5
    assert report["skipped_files"] == ["monitoring/logs/logstash/x/2022-01-24-system.cpu.log"]


def test_phase_report_groups_by_log_type(tmp_path: Path) -> None:
    _, report = build_labels(tmp_path, make_labels(tmp_path), PHASES, SOURCES, CONFIG)
    assert phase_report(report) == [
        {"log_type": "vpn", "labeled": 3, "resolved": 2, "unassigned": 1, "in_phase": 1}
    ]


def line_row(line_no: int) -> dict:
    return {
        "line_id": f"vpn|logs/openvpn.log|{line_no}",
        "testbed": "tiny",
        "host": "vpn",
        "log_type": "vpn",
        "file": "logs/openvpn.log",
        "line_no": line_no,
        "ts": minutes(5),
        "raw": "raw",
        "message": "m",
        "template_id": 1,
        "template": "m",
        "is_unseen_template": False,
        "template_rarity": 1.0,
        "src_ip": None,
        "user": None,
        "fields": "{}",
        "parse_ok": True,
    }


def test_agent_db_has_no_label_tables_and_eval_db_has_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    out = Path("out")
    write_lines([line_row(1), line_row(2)], out / "lines_vpn.parquet")
    rows = [
        {"line_id": "vpn|logs/openvpn.log|1", "labels": ["x"], "rules": "{}", "phase": "scan"},
    ]
    write_labels(rows, {"labeled": 1}, out)
    write_phases_csv(PHASES, out / "phases.csv")
    build_agent_db(out)
    build_eval_db(out, out / "phases.csv")

    with connect(out / "agent.duckdb", read_only=True) as agent:
        names = {row[0] for row in agent.execute("SHOW TABLES").fetchall()}
        assert names == {"lines", "lines_vpn"}
        assert agent.execute("SELECT count(*) FROM lines").fetchone() == (2,)
    with connect(out / "eval.duckdb", read_only=True) as evaluation:
        names = {row[0] for row in evaluation.execute("SHOW TABLES").fetchall()}
        assert names == {"labels", "lines", "lines_vpn", "phases"}
        joined = evaluation.execute(
            "SELECT count(*) FROM labels JOIN lines USING (line_id)"
        ).fetchone()
        assert joined == (1,)

    assert pq.read_schema(out / "labels.parquet").names == ["line_id", "labels", "rules", "phase"]


def test_template_digest_depends_on_ids_not_order() -> None:
    first = [{"line_id": "a", "template_id": 1}, {"line_id": "b", "template_id": 2}]
    assert template_digest(first) == template_digest(first[::-1])
    assert template_digest(first) != template_digest(
        [{"line_id": "a", "template_id": 2}, {"line_id": "b", "template_id": 2}]
    )
