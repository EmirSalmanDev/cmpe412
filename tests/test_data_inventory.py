"""Acceptance checks for M1 on the real datasets."""

import csv
from pathlib import Path

import pytest

from logtriage.config import load_settings, load_sources
from logtriage.data.inventory import build_inventory, unmapped_labeled_files

ROOT = Path(__file__).parents[1]
TESTBEDS = ["russellmitchell", "santos"]
FAMILIES = {"apache_access", "apache_error", "auth", "dns", "audit"}

pytestmark = pytest.mark.data


@pytest.fixture(scope="module")
def settings():
    return load_settings(ROOT / "configs" / "default.yaml", env_file=None)


@pytest.fixture(scope="module")
def sources():
    return load_sources(ROOT / "configs" / "sources.yaml")


@pytest.mark.parametrize("testbed", TESTBEDS)
def test_sources_map_every_labeled_file(testbed: str, sources) -> None:
    records = build_inventory(ROOT / "data" / "raw" / testbed, sources)
    labeled = [record for record in records if record.has_labels]
    assert labeled
    assert unmapped_labeled_files(records, sources) == []
    assert FAMILIES <= {record.log_type for record in labeled}


@pytest.mark.parametrize("testbed", TESTBEDS)
def test_extraction_left_pcaps_out(testbed: str) -> None:
    assert not list((ROOT / "data" / "raw" / testbed).rglob("*.pcap*"))


@pytest.mark.parametrize("testbed", TESTBEDS)
def test_inventory_report_exists(testbed: str) -> None:
    assert (ROOT / "reports" / f"inventory_{testbed}.md").is_file()


@pytest.mark.parametrize("testbed", TESTBEDS)
def test_phases_keep_the_published_intervals(testbed: str) -> None:
    with (ROOT / "data_meta" / f"phases_{testbed}.csv").open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    with (ROOT / "data" / "raw" / "ait_ads" / "labels.csv").open(encoding="utf-8") as handle:
        published = [row for row in csv.DictReader(handle) if row["scenario"] == testbed]
    assert {row["phase"] for row in rows if row["source"] == "ait_ads:labels.csv"} == {
        row["attack"] for row in published
    }
    assert [row["phase"] for row in rows if row["source"] != "ait_ads:labels.csv"] == [
        "dnsteal_exfil"
    ]
    assert all(row["start_utc"] <= row["end_utc"] for row in rows)
