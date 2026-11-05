"""Tests for masking, the frozen and online miners, and their reproducibility."""

import math
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence

from logtriage.config import load_settings
from logtriage.data.drain import add_templates, make_miner
from logtriage.data.store import template_digest

CONFIG = load_settings(Path(__file__).parents[1] / "configs" / "default.yaml", env_file=None).drain
T0 = datetime(2022, 1, 14, tzinfo=UTC)
FIT_END = T0 + timedelta(hours=1)


def row(index: int, message: str, hours: float = 0, ok: bool = True) -> dict:
    return {
        "line_id": f"h|f|{index}",
        "ts": T0 + timedelta(hours=hours),
        "message": message,
        "parse_ok": ok,
    }


def sample_rows() -> list[dict]:
    return [
        row(1, "session opened for user alice", 0),
        row(2, "session opened for user bob", 0.1),
        row(3, "session opened for user carol", 0.2),
        row(4, "connection from 10.0.0.1 port 22", 0.3),
        row(5, "broken", 0.4, ok=False),
        row(6, "session opened for user dave", 2),
        row(7, "totally new message about something else entirely", 3),
    ]


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("from 10.1.2.3 port 22", "from <IP> port <NUM>"),
        ("addr fe80::1:2:3 up", "addr <IP6> up"),
        ("id 123e4567-e89b-12d3-a456-426614174000 done", "id <UUID> done"),
        ("value 0xdeadbeef", "value <HEX>"),
        ("sum deadbeef01 end", "sum <HEX> end"),
        ("query ScGCirxOxUUf11BDIVfdMkwtfLsy2ucy", "query <B64>"),
        ("3x6-.401-.ScGCirxO*xUUf11BDIVfdMkwtf.example", "3x6-.<NUM>-.<B64>.example"),
        ("open /var/www/wp-content/plugins/wpdiscuz/themes/x.php", None),
        ("host intranet.smith.santos.com up", None),
    ],
)
def test_masking(message: str, expected: str | None) -> None:
    assert make_miner(CONFIG).masker.mask(message) == (expected or message)


def test_add_templates_sets_the_columns(tmp_path: Path) -> None:
    rows = sample_rows()
    stats = add_templates(rows, FIT_END, CONFIG, tmp_path, "auth")
    assert (stats.lines, stats.fit_lines) == (6, 4)
    assert rows[0]["template_id"] == rows[5]["template_id"]
    assert rows[0]["template"] == "session opened for user <*>"
    assert "template_id" not in rows[4]
    assert rows[5]["is_unseen_template"] is False
    assert rows[6]["is_unseen_template"] is True
    assert stats.unseen_fit_lines == 0


def test_rarity_uses_fit_counts(tmp_path: Path) -> None:
    rows = sample_rows()
    add_templates(rows, FIT_END, CONFIG, tmp_path, "auth")
    n_fit, templates = 4, 2
    assert rows[0]["template_rarity"] == pytest.approx(-math.log(4 / (n_fit + templates)))
    assert rows[3]["template_rarity"] == pytest.approx(-math.log(2 / (n_fit + templates)))
    assert rows[6]["template_rarity"] == pytest.approx(-math.log(1 / (n_fit + templates)))


def test_template_ids_are_reproducible_even_with_old_state(tmp_path: Path) -> None:
    first, second = sample_rows(), sample_rows()
    add_templates(first, FIT_END, CONFIG, tmp_path, "auth")
    add_templates(second, FIT_END, CONFIG, tmp_path, "auth")
    assert template_digest(first) == template_digest(second)
    assert [row.get("template") for row in first] == [row.get("template") for row in second]


def test_frozen_state_is_saved_and_loadable(tmp_path: Path) -> None:
    add_templates(sample_rows(), FIT_END, CONFIG, tmp_path, "auth")
    assert (tmp_path / "auth.online.bin").is_file()
    miner = TemplateMiner(FilePersistence(str(tmp_path / "auth.frozen.bin")))
    assert miner.match("session opened for user zed") is not None
    assert miner.match("totally new message about something else entirely") is None


def test_no_fit_lines(tmp_path: Path) -> None:
    rows = [row(1, "only late line", 5)]
    stats = add_templates(rows, FIT_END, CONFIG, tmp_path, "vpn")
    assert stats.frozen_templates == 0
    assert rows[0]["is_unseen_template"] is True
