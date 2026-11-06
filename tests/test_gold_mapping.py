"""Gold ATT&CK mapping (plan 11): one entry per phase, and only real techniques."""

import csv
import json
import re
from pathlib import Path

import pytest

from logtriage.config import DEV_TESTBED, load_settings
from logtriage.eval.metrics import attack_techniques, load_gold_mapping, unusable_gold_ids

ROOT = Path(__file__).parents[1]
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
GOLD = load_gold_mapping(ROOT / "configs" / "gold_attack_mapping.yaml")


def phases_in_data() -> set[str]:
    found = set()
    for path in (ROOT / "data_meta").glob("phases_*.csv"):
        with path.open(encoding="utf-8", newline="") as handle:
            found |= {row["phase"] for row in csv.DictReader(handle)}
    return found


def test_there_are_phases_files_to_check() -> None:
    settings = load_settings(ROOT / "configs" / "default.yaml", env_file=None)
    expected = {f"phases_{name}.csv" for name in [DEV_TESTBED, *settings.test_testbeds]}
    assert {path.name for path in (ROOT / "data_meta").glob("phases_*.csv")} == expected


def test_every_phase_of_the_phases_files_has_a_gold_entry() -> None:
    assert sorted(phases_in_data() - set(GOLD)) == []


def test_gold_has_no_phase_the_data_does_not_have() -> None:
    assert sorted(set(GOLD) - phases_in_data()) == []


def test_every_gold_entry_lists_valid_unique_technique_ids() -> None:
    for phase, techniques in GOLD.items():
        assert techniques, phase
        assert len(techniques) == len(set(techniques)), phase
        assert all(TECHNIQUE.match(item) for item in techniques), phase


def test_exfil_phase_shares_the_gold_set_of_dnsteal() -> None:
    assert GOLD["dnsteal_exfil"] == GOLD["dnsteal"] == ["T1048.003", "T1048", "T1071.004"]


def test_unusable_ids_are_found_in_a_small_bundle(tmp_path: Path) -> None:
    def pattern(external_id: str, **extra: bool) -> dict:
        references = [{"source_name": "mitre-attack", "external_id": external_id}]
        return {"type": "attack-pattern", "external_references": references, **extra}

    bundle = {
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": "1.2"},
            pattern("T1000"),
            pattern("T1001", revoked=True),
            pattern("T1002", x_mitre_deprecated=True),
        ]
    }
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    techniques, version = attack_techniques(path)
    assert version == "1.2"
    gold = {"phase": ["T1000", "T1001", "T1002", "T9999"]}
    assert unusable_gold_ids(gold, techniques) == ["T1001", "T1002", "T9999"]


@pytest.mark.data
def test_every_gold_id_exists_in_the_pinned_attack_data() -> None:
    path = ROOT / load_settings(ROOT / "configs" / "default.yaml").paths.attack_stix_file
    if not path.is_file():
        pytest.skip(f"{path} is not available")
    techniques, _ = attack_techniques(path)
    assert unusable_gold_ids(GOLD, techniques) == []
