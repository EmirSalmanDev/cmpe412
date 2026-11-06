"""The real ATT&CK index and tools (plan 13, M7). Needs `data/` and the embedding model."""

import json
from pathlib import Path

import pytest
import yaml

from logtriage.agents.tools import AgentTools
from logtriage.config import load_settings
from logtriage.rag.attack_index import (
    AttackIndex,
    BgeEmbedder,
    cosine_collection,
    file_digest,
    load_techniques,
    open_client,
)

ROOT = Path(__file__).parents[1]
QUERY = "many DNS queries with long random subdomains to one domain"

pytestmark = pytest.mark.data


@pytest.fixture(scope="module")
def settings():
    return load_settings(ROOT / "configs" / "default.yaml", env_file=None)


@pytest.fixture(scope="module")
def index(settings) -> AttackIndex:
    client = open_client(ROOT / settings.paths.index_dir)
    collection = cosine_collection(client, settings.rag.attack_collection)
    return AttackIndex(collection, BgeEmbedder(settings.rag))


def gold_ids() -> set[str]:
    path = ROOT / "configs" / "gold_attack_mapping.yaml"
    gold = yaml.safe_load(path.read_text(encoding="utf-8"))["phases"]
    return {technique for group in gold.values() for technique in group}


def test_the_bundle_is_the_pinned_one(settings) -> None:
    assert file_digest(ROOT / settings.paths.attack_stix_file) == settings.rag.attack_sha256


def test_the_index_holds_every_usable_technique(settings, index: AttackIndex) -> None:
    techniques = load_techniques(ROOT / settings.paths.attack_stix_file)
    assert index.collection.count() == len(techniques) == 706


def test_gold_ids_exist_in_the_index_and_are_not_revoked(index: AttackIndex) -> None:
    ids = gold_ids()
    found = index.collection.get(ids=sorted(ids))["ids"]
    assert set(found) == ids


def test_revoked_and_deprecated_objects_are_not_indexed(settings, index: AttackIndex) -> None:
    bundle = json.loads((ROOT / settings.paths.attack_stix_file).read_text(encoding="utf-8"))
    gone = {
        reference["external_id"]
        for item in bundle["objects"]
        if item.get("type") == "attack-pattern"
        and (item.get("revoked") or item.get("x_mitre_deprecated"))
        for reference in item["external_references"]
        if reference.get("source_name") == "mitre-attack"
    }
    usable = {item.technique_id for item in load_techniques(ROOT / settings.paths.attack_stix_file)}
    only_old = sorted(gone - usable)
    assert only_old
    assert index.collection.get(ids=only_old)["ids"] == []


def test_retrieval_finds_dns_exfiltration_in_the_top_five(index: AttackIndex) -> None:
    ids = [hit["id"] for hit in index.search(QUERY, 5)]
    assert any(item.startswith("T1048") or item == "T1071.004" for item in ids), ids


@pytest.mark.parametrize("testbed", ["russellmitchell", "santos"])
def test_the_tools_work_on_the_real_data(settings, testbed: str) -> None:
    tools = AgentTools.open(testbed, settings)
    try:
        searched = tools.log_search(
            "inet-firewall", "2022-01-16T07:00:00", "2022-01-24T07:30:00", log_type="dns"
        )
        assert searched.line_ids
        assert len(searched.text) <= settings.tools.output_chars
        rows = tools.run_sql("SELECT line_id FROM lines_vpn WHERE fields->>'vpn_ip' IS NOT NULL")
        assert len(rows.line_ids) >= 1
        address = tools.run_sql("SELECT src_ip FROM lines_vpn WHERE src_ip IS NOT NULL LIMIT 1")
        profile = tools.ip_profile(address.text.splitlines()[2])
        assert "VPN: external" in profile.text
        for name in (f"data/processed/{testbed}/labels.parquet", f"data_meta/phases_{testbed}.csv"):
            for path in (name, str(ROOT / name)):
                assert tools.run_sql(f"SELECT * FROM '{path}'").text.startswith("rejected")
    finally:
        tools.close()
