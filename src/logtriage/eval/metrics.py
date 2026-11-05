"""Evaluation metrics and the gold ATT&CK mapping (plan 10.2, 11)."""

import json
from collections.abc import Iterable
from pathlib import Path

import yaml


def load_gold_mapping(path: Path) -> dict[str, list[str]]:
    """Read `configs/gold_attack_mapping.yaml` into phase to acceptable technique IDs."""
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)["phases"]


def required_detections(phases: int, share: float) -> int:
    """Return the fewest detected phases that reach `share` of `phases`, in whole phases."""
    return -int(-round(phases * share, 9) // 1)


def attack_techniques(stix_path: Path) -> tuple[dict[str, bool], str | None]:
    """Read the technique IDs of an ATT&CK STIX bundle.

    Args:
        stix_path: `enterprise-attack.json`.

    Returns:
        Technique ID to whether it is usable (not revoked or deprecated), and the ATT&CK
        version named by the bundle's collection object, if any.
    """
    objects = json.loads(stix_path.read_text(encoding="utf-8"))["objects"]
    techniques: dict[str, bool] = {}
    version = None
    for item in objects:
        if item.get("type") == "x-mitre-collection":
            version = item.get("x_mitre_version")
        if item.get("type") != "attack-pattern":
            continue
        for reference in item.get("external_references", []):
            if reference.get("source_name") == "mitre-attack":
                usable = not item.get("revoked") and not item.get("x_mitre_deprecated")
                techniques[reference["external_id"]] = usable
    return techniques, version


def unusable_gold_ids(gold: dict[str, list[str]], techniques: dict[str, bool]) -> list[str]:
    """Return the gold IDs that are missing from ATT&CK, revoked or deprecated."""
    ids: Iterable[str] = {item for group in gold.values() for item in group}
    return sorted(item for item in ids if not techniques.get(item, False))
