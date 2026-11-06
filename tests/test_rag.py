"""ATT&CK index and incident memory (plan 8), with a fake embedder: no model, no network."""

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logtriage.config import Settings
from logtriage.rag.attack_index import (
    AttackIndex,
    build_index,
    clean_text,
    cosine_collection,
    file_digest,
    load_techniques,
    open_client,
    run_index_attack,
)
from logtriage.rag.incident_store import IncidentStore, report_document
from rag_fakes import BUNDLE, FakeEmbedder, report

START = datetime(2022, 1, 16, 7, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> IncidentStore:
    client = open_client(tmp_path)
    return IncidentStore(cosine_collection(client, "incidents"), FakeEmbedder())


def test_clean_text_removes_citations_links_and_tags() -> None:
    text = "Use <code>dig</code> [a tunnel](https://x.y/z).(Citation: Report 2020)\n\nDone."
    assert clean_text(text) == "Use dig a tunnel. Done."


def test_only_usable_techniques_are_loaded() -> None:
    ids = [item.technique_id for item in load_techniques(BUNDLE)]
    assert ids == ["T1048", "T1048.003", "T1110"]


def test_a_technique_keeps_its_tactics_and_sub_technique_mark() -> None:
    item = {entry.technique_id: entry for entry in load_techniques(BUNDLE)}["T1048.003"]
    assert item.tactics == ["exfiltration", "command-and-control"]
    assert item.is_subtechnique


def test_the_document_is_id_name_and_clean_description() -> None:
    item = load_techniques(BUNDLE)[0]
    assert item.document.startswith("T1048 Exfiltration Over Alternative Protocol. Adversaries")
    assert "Citation" not in item.document and "<code>" not in item.document


def test_search_returns_the_nearest_technique_with_metadata(tmp_path: Path) -> None:
    client = open_client(tmp_path)
    assert build_index(load_techniques(BUNDLE), client, FakeEmbedder(), "attack") == 3
    index = AttackIndex(cosine_collection(client, "attack"), FakeEmbedder())
    hits = index.search("guess passwords brute force", 2)
    assert hits[0]["id"] == "T1110"
    assert hits[0]["tactics"] == "credential-access"
    assert hits[0]["distance"] <= hits[1]["distance"]


def test_rebuilding_replaces_the_collection(tmp_path: Path) -> None:
    client = open_client(tmp_path)
    techniques = load_techniques(BUNDLE)
    build_index(techniques, client, FakeEmbedder(), "attack")
    assert build_index(techniques[:1], client, FakeEmbedder(), "attack") == 1


def settings_for(tmp_path: Path, digest: str) -> Settings:
    settings = Settings()
    settings.paths.attack_stix_file = tmp_path / "enterprise-attack.json"
    settings.paths.index_dir = tmp_path / "index"
    settings.rag.attack_sha256 = digest
    return settings


def test_the_index_is_built_from_the_pinned_bundle(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, file_digest(BUNDLE))
    shutil.copy(BUNDLE, settings.paths.attack_stix_file)
    assert run_index_attack(settings, FakeEmbedder()) == 3


def test_another_bundle_is_refused(tmp_path: Path) -> None:
    settings = settings_for(tmp_path, "0" * 64)
    shutil.copy(BUNDLE, settings.paths.attack_stix_file)
    with pytest.raises(ValueError, match="pinned"):
        run_index_attack(settings, FakeEmbedder())


def test_a_missing_bundle_is_refused_and_nothing_is_downloaded(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_index_attack(settings_for(tmp_path, "0" * 64), FakeEmbedder())


def test_a_report_document_holds_claims_techniques_and_verdict() -> None:
    text = report_document(report("i1", "Long DNS names."))
    assert "Long DNS names." in text and "T1048 Exfiltration" in text and "malicious" in text


def test_memory_never_looks_ahead(store: IncidentStore) -> None:
    store.add(report("early", "dns tunnel"), "santos", START)
    store.add(report("same", "dns tunnel"), "santos", START + timedelta(hours=1))
    store.add(report("late", "dns tunnel"), "santos", START + timedelta(hours=2))
    hits = store.search("dns tunnel", 3, "santos", before=START + timedelta(hours=1))
    assert [hit["incident_id"] for hit in hits] == ["early"]


def test_memory_without_a_time_limit_sees_all_of_the_testbed(store: IncidentStore) -> None:
    store.add(report("one", "dns tunnel"), "santos", START)
    store.add(report("other", "dns tunnel"), "russellmitchell", START)
    assert [hit["incident_id"] for hit in store.search("dns", 3, "santos")] == ["one"]


def test_runs_do_not_see_each_other(store: IncidentStore) -> None:
    store.add(report("one", "dns tunnel"), "santos", START, run="verifier_off")
    assert store.search("dns", 3, "santos", run="verifier_on") == []
    assert len(store.search("dns", 3, "santos", run="verifier_off")) == 1


def test_a_report_can_be_replaced(store: IncidentStore) -> None:
    store.add(report("one", "dns tunnel", "uncertain"), "santos", START)
    store.add(report("one", "dns tunnel", "benign"), "santos", START)
    hits = store.search("dns", 3, "santos")
    assert [hit["verdict"] for hit in hits] == ["benign"]


def test_an_empty_memory_returns_nothing(store: IncidentStore) -> None:
    assert store.search("dns", 3, "santos", before=START) == []
