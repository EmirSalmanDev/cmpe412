"""Evaluation metrics and the gold ATT&CK mapping (plan 10.2, 11)."""

import json
from collections.abc import Iterable
from pathlib import Path

import duckdb
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import average_precision_score

AMBIGUOUS_LOG_TYPE = "dns"
AMBIGUOUS_HOST = "inet-dns"
EXFIL_PHASE = "dnsteal_exfil"


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


def window_truth(con: duckdb.DuckDBPyConnection, window_seconds: int) -> pd.DataFrame:
    """Return the phases of every attack window (plan 10.1).

    Args:
        con: Connection with the `lines` and `labels` views of `eval.duckdb`.
        window_seconds: Window length, the same as in the windows tables.

    Returns:
        One row per window with at least one labeled line: `host`, `log_type`, `window_start`,
        `phases` (sorted list).
    """
    return con.execute(
        f"""
        SELECT l.host, l.log_type,
               time_bucket(INTERVAL {int(window_seconds)} SECOND, l.ts) AS window_start,
               list_sort(list(DISTINCT b.phase)) AS phases
        FROM labels b JOIN lines l USING (line_id)
        WHERE l.parse_ok
        GROUP BY ALL
        """
    ).df()


def attach_truth(windows: pd.DataFrame, truth: pd.DataFrame) -> pd.DataFrame:
    """Return windows of any period with ground truth columns.

    Args:
        windows: Table with the window key.
        truth: Output of `window_truth`.

    Returns:
        The rows with `phases`, `is_attack` and `is_ambiguous` (D17).
    """
    table = windows.merge(truth, how="left", on=["host", "log_type", "window_start"])
    table["is_attack"] = table["phases"].notna()
    table["phases"] = table["phases"].map(
        lambda value: list(value) if isinstance(value, list | np.ndarray) else []
    )
    table["is_ambiguous"] = (table["log_type"] == AMBIGUOUS_LOG_TYPE) & (
        table["host"] == AMBIGUOUS_HOST
    )
    return table


def with_truth(scores: pd.DataFrame, truth: pd.DataFrame) -> pd.DataFrame:
    """Return the evaluation windows of a scores table, with ground truth columns.

    Args:
        scores: Scores with `period`, `score`, `is_anomalous` and `incident_id`.
        truth: Output of `window_truth`.

    Returns:
        The eval rows with `phases`, `is_attack` and `is_ambiguous` (D17).
    """
    return attach_truth(scores[scores["period"] == "eval"], truth)


def is_exfil_only(phases: pd.Series) -> pd.Series:
    """Return which windows have `dnsteal_exfil` as their only phase."""
    return phases.map(lambda value: list(value) == [EXFIL_PHASE])


def _window_row(name: str, table: pd.DataFrame) -> dict:
    """Compute the window metrics of one slice."""
    attack, flagged = table["is_attack"], table["is_anomalous"]
    hits = int((attack & flagged).sum())
    precision = hits / flagged.sum() if flagged.any() else float("nan")
    recall = hits / attack.sum() if attack.any() else float("nan")
    total = precision + recall
    has_both = attack.any() and not attack.all()
    return {
        "scope": name,
        "windows": len(table),
        "attack": int(attack.sum()),
        "anomalous": int(flagged.sum()),
        "true_positives": hits,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / total if total else float("nan"),
        "pr_auc": average_precision_score(attack, table["score"]) if has_both else float("nan"),
    }


def window_metrics(table: pd.DataFrame, include_ambiguous: bool = False) -> pd.DataFrame:
    """Return window P/R/F1/PR-AUC, pooled and per log type (plan 10.2).

    Args:
        table: Output of `with_truth`.
        include_ambiguous: Count label-ambiguous windows as normal: the secondary number (D17).

    Returns:
        One row for `pooled`, then one per log type.
    """
    kept = table if include_ambiguous else table[~table["is_ambiguous"]]
    rows = [_window_row("pooled", kept)]
    rows += [_window_row(name, part) for name, part in kept.groupby("log_type")]
    return pd.DataFrame(rows).set_index("scope")


def detected_phases(table: pd.DataFrame) -> pd.DataFrame:
    """Count, per phase and log type, the anomalous incident windows holding that phase.

    Args:
        table: Output of `with_truth`.

    Returns:
        A table with phases as rows and log types as columns. A phase is detected if its row
        has a non-zero count (plan 10.2).
    """
    hits = table[table["is_anomalous"] & table["incident_id"].notna() & table["is_attack"]]
    exploded = hits[["log_type", "phases"]].explode("phases")
    return exploded.pivot_table(
        index="phases", columns="log_type", aggfunc="size", fill_value=0
    ).rename_axis(index="phase", columns=None)


def phase_recall(detected: pd.DataFrame, counted: list[str]) -> dict:
    """Return phase recall over the counted phases (plan 10.2).

    Args:
        detected: Output of `detected_phases`.
        counted: Phases with traces.

    Returns:
        Counts, recall and the missed phases, for the primary denominator and the secondary
        one without the exfiltration phase.
    """
    found = set(detected.index) & set(counted)
    rest = [phase for phase in counted if phase != EXFIL_PHASE]
    return {
        "detected": len(found),
        "phases": len(counted),
        "recall": len(found) / len(counted),
        "missed": sorted(set(counted) - found),
        "detected_without_exfil": len(found - {EXFIL_PHASE}),
        "phases_without_exfil": len(rest),
        "recall_without_exfil": len(found - {EXFIL_PHASE}) / len(rest),
    }


def phase_credit(detected: pd.DataFrame, counted: list[str]) -> pd.DataFrame:
    """Show which log types earn each phase its detection, so DNS-only credit is visible.

    Args:
        detected: Output of `detected_phases`.
        counted: Phases with traces, in display order.

    Returns:
        One row per counted phase: window counts per log type, `detected`, and `dns_only`,
        which is True if no other log type detected the phase (D29).
    """
    table = detected.reindex(counted, fill_value=0)
    columns = list(table.columns)
    others = [name for name in columns if name != AMBIGUOUS_LOG_TYPE]
    table["detected"] = table[columns].sum(axis=1) > 0
    dns = table[AMBIGUOUS_LOG_TYPE] if AMBIGUOUS_LOG_TYPE in columns else 0
    table["dns_only"] = (dns > 0) & (table[others].sum(axis=1) == 0)
    return table


def incidents_per_day(incidents: int, days: float) -> float:
    """Return the incident rate over the evaluation period."""
    return incidents / days


def incident_phases(table: pd.DataFrame) -> dict[str, list[str]]:
    """Return the phases of every incident: the union of its window phases (plan 10.1).

    Args:
        table: Output of `with_truth`.

    Returns:
        Incident to sorted phases; an incident with no attack window has an empty list.
    """
    rows = table[table["incident_id"].notna()]
    return {
        incident: sorted({phase for phases in group["phases"] for phase in phases})
        for incident, group in rows.groupby("incident_id")
    }


def candidate_recall(
    reports: Iterable[dict], phases: dict[str, list[str]], gold: dict[str, list[str]]
) -> pd.DataFrame:
    """Tell, per incident, whether a gold technique was among the Mapper's candidates.

    This bounds the Mapper: it may only pick retrieved techniques (plan 7.4), so an incident with
    no gold technique among them cannot score a strict ATT&CK hit.

    Args:
        reports: Report dicts, with `meta.retrieved_techniques` in rank order.
        phases: Output of `incident_phases`.
        gold: Output of `load_gold_mapping`.

    Returns:
        One row per incident. `gold_in_top_k` is None for an incident with no gold set.
    """
    rows = []
    for report in reports:
        incident = report["incident_id"]
        meta = report["meta"]
        retrieved = meta["retrieved_techniques"]
        names = phases.get(incident, [])
        wanted = sorted({item for phase in names for item in gold.get(phase, [])})
        hits = [item for item in retrieved if item in wanted]
        rows.append(
            {
                "incident_id": incident,
                "phases": " ".join(names),
                "gold": " ".join(wanted),
                "retrieved": " ".join(retrieved),
                "gold_in_top_k": bool(hits) if wanted else None,
                "gold_retrieved": " ".join(hits),
                "best_rank": retrieved.index(hits[0]) + 1 if hits else None,
                "mapped": " ".join(meta["mapped_techniques"]),
                "behavior_summary": meta["behavior_summary"],
            }
        )
    return pd.DataFrame(rows).sort_values("incident_id", ignore_index=True)
