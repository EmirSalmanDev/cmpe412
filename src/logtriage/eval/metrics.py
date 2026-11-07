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
WITHOUT_DNS = "pooled_without_dns"
VERDICTS = ("malicious", "uncertain", "benign")
TOP_K = (1, 3)


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


def window_table(table: pd.DataFrame, include_ambiguous: bool = False) -> pd.DataFrame:
    """Return `window_metrics` with a row for the pool without `dns`, whose baseline is tainted.

    Args:
        table: Output of `with_truth`.
        include_ambiguous: Count label-ambiguous windows as normal: the secondary number (D17).

    Returns:
        The rows of `window_metrics`, then `pooled_without_dns`.
    """
    kept = table[table["log_type"] != AMBIGUOUS_LOG_TYPE]
    extra = pd.DataFrame([_window_row(WITHOUT_DNS, kept)]).set_index("scope")
    return pd.concat([window_metrics(table, include_ambiguous), extra])


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


def incident_truth(table: pd.DataFrame) -> pd.DataFrame:
    """Return the ground truth of every incident (plan 10.1, D17).

    Args:
        table: Output of `with_truth`.

    Returns:
        One row per incident, indexed by `incident_id`: `malicious`, `ambiguous` and `phases`. An
        incident with an attack window is malicious, whatever else it holds, so it is never
        ambiguous.
    """
    rows = table[table["incident_id"].notna()].groupby("incident_id")
    malicious = rows["is_attack"].any()
    return pd.DataFrame(
        {
            "malicious": malicious,
            "ambiguous": rows["is_ambiguous"].any() & ~malicious,
            "phases": pd.Series(incident_phases(table)),
        }
    )


def verdict_counts(
    truth: pd.DataFrame, verdicts: pd.Series, include_ambiguous: bool = False
) -> dict[str, int]:
    """Return the confusion matrix of plan 10.2: 3 predicted classes by 2 true ones.

    Args:
        truth: Output of `incident_truth`.
        verdicts: Verdict of each incident.
        include_ambiguous: Count label-ambiguous incidents as benign: the secondary number (D17).

    Returns:
        Counts named `<predicted>_true_<malicious or benign>`.
    """
    kept = truth if include_ambiguous else truth[~truth["ambiguous"]]
    predicted = verdicts.reindex(kept.index)
    if predicted.isna().any():
        raise ValueError(f"no verdict for {sorted(predicted.index[predicted.isna()])}")
    unknown = set(predicted) - set(VERDICTS)
    if unknown:
        raise ValueError(f"unknown verdicts: {sorted(unknown)}")
    counts = {}
    for verdict in VERDICTS:
        chosen = kept[predicted == verdict]
        counts[f"{verdict}_true_malicious"] = int(chosen["malicious"].sum())
        counts[f"{verdict}_true_benign"] = int((~chosen["malicious"]).sum())
    return counts


def verdict_scores(counts: dict[str, int]) -> dict[str, float]:
    """Return precision, recall and F1 of a confusion matrix, with `uncertain` as non-benign.

    Args:
        counts: Output of `verdict_counts`, or sums of it.

    Returns:
        `precision`, `recall` and `f1`; NaN where a denominator is 0.
    """
    hits = counts["malicious_true_malicious"] + counts["uncertain_true_malicious"]
    false_alarms = counts["malicious_true_benign"] + counts["uncertain_true_benign"]
    misses = counts["benign_true_malicious"]
    precision = hits / (hits + false_alarms) if hits + false_alarms else float("nan")
    recall = hits / (hits + misses) if hits + misses else float("nan")
    total = precision + recall
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / total if total else float("nan"),
    }


def parent_technique(technique: str) -> str:
    """Return the parent of an ATT&CK ID: `T1548` for `T1548.003`, and `T1548` for itself."""
    return technique.split(".")[0]


def attack_hit(predicted: list[str], wanted: set[str], k: int, lenient: bool = False) -> bool:
    """Tell whether a technique in the top `k` is acceptable (plan 10.2).

    Args:
        predicted: Techniques of a report, ranked.
        wanted: Union of the gold sets of the incident's phases.
        k: How many predictions count.
        lenient: Compare parent techniques, on both sides, not exact IDs.

    Returns:
        True on a hit. A report with no technique misses.
    """
    top = predicted[:k]
    if lenient:
        return bool({parent_technique(item) for item in top} & set(map(parent_technique, wanted)))
    return bool(set(top) & wanted)


def attack_incidents(
    truth: pd.DataFrame, reports: dict[str, dict], gold: dict[str, list[str]]
) -> pd.DataFrame:
    """Score every malicious incident against the gold mapping (plan 10.2, 11).

    Args:
        truth: Output of `incident_truth`.
        reports: Report dicts by incident.
        gold: Output of `load_gold_mapping`.

    Returns:
        One row per malicious incident, with a column per `top<k>_strict` and `top<k>_lenient`,
        and `gold_retrieved`, whether a gold technique was among the Mapper's candidates.
    """
    rows = []
    for incident, row in truth[truth["malicious"]].iterrows():
        report = reports[incident]
        predicted = [item["technique_id"] for item in report["techniques"]]
        wanted = {item for phase in row["phases"] for item in gold[phase]}
        entry = {
            "incident_id": incident,
            "phases": " ".join(row["phases"]),
            "gold": " ".join(sorted(wanted)),
            "predicted": " ".join(predicted),
            "verdict": report["verdict"],
            "gold_retrieved": bool(set(report["meta"]["retrieved_techniques"]) & wanted),
        }
        for k in TOP_K:
            entry[f"top{k}_strict"] = attack_hit(predicted, wanted, k)
            entry[f"top{k}_lenient"] = attack_hit(predicted, wanted, k, lenient=True)
        rows.append(entry)
    columns = ["incident_id", "phases", "gold", "predicted", "verdict", "gold_retrieved"]
    columns += [f"top{k}_{kind}" for k in TOP_K for kind in ("strict", "lenient")]
    return pd.DataFrame(rows, columns=columns)


def attack_summary(incidents: pd.DataFrame) -> dict[str, float]:
    """Return hit counts and shares of the rows of `attack_incidents`."""
    summary: dict[str, float] = {"malicious_incidents": len(incidents)}
    for k in TOP_K:
        for kind in ("strict", "lenient"):
            name = f"top{k}_{kind}"
            summary[f"{name}_hits"] = int(incidents[name].sum())
            summary[name] = incidents[name].mean() if len(incidents) else float("nan")
    return summary


def citation_summary(reports: Iterable[dict]) -> dict[str, float]:
    """Return the share of first-draft claims citing an eid that does not exist (plan 10.2)."""
    metas = [report["meta"] for report in reports]
    claims = sum(meta["draft_claims"] for meta in metas)
    unknown = sum(meta["draft_unknown_eid_claims"] for meta in metas)
    return {
        "reports": len(metas),
        "draft_claims": claims,
        "unknown_eid_claims": unknown,
        "hallucinated_share": unknown / claims if claims else float("nan"),
    }


def token_cost(meta: dict, rates: dict[str, float]) -> float:
    """Return the USD of a report's tokens at one rate set, per million tokens."""
    missed = meta["tokens_in"] - meta["tokens_cached"]
    total = (
        missed * rates["input"]
        + meta["tokens_cached"] * rates["cached_input"]
        + meta["tokens_out"] * rates["output"]
    )
    return total / 1_000_000


def priced_at(meta: dict, off_peak: dict[str, float], peak: dict[str, float]) -> str:
    """Name the rate set behind a report's logged cost: `off_peak`, `peak` or `mixed`."""
    for name, rates in (("off_peak", off_peak), ("peak", peak)):
        if abs(meta["cost_usd"] - token_cost(meta, rates)) <= 1e-9:
            return name
    return "mixed"


def cost_summary(
    reports: Iterable[dict], off_peak: dict[str, float], peak: dict[str, float]
) -> dict[str, float | str]:
    """Return cost, latency and tokens per incident (plan 10.2).

    Args:
        reports: Report dicts.
        off_peak: Off-peak rates, per million tokens.
        peak: Peak rates, per million tokens.

    Returns:
        Means and p90s as logged, and the cost of the same tokens at off-peak rates, which is the
        one comparable across runs: M8 ran at peak hours (D45).
    """
    metas = [report["meta"] for report in reports]
    cost = np.array([meta["cost_usd"] for meta in metas])
    latency = np.array([meta["latency_s"] for meta in metas])
    at_off_peak = np.array([token_cost(meta, off_peak) for meta in metas])
    return {
        "reports": len(metas),
        "priced_at": "/".join(sorted({priced_at(meta, off_peak, peak) for meta in metas})),
        "cost_total_usd": cost.sum(),
        "cost_mean_usd": cost.mean(),
        "cost_p90_usd": np.percentile(cost, 90),
        "off_peak_total_usd": at_off_peak.sum(),
        "off_peak_mean_usd": at_off_peak.mean(),
        "off_peak_p90_usd": np.percentile(at_off_peak, 90),
        "latency_mean_s": latency.mean(),
        "latency_p90_s": np.percentile(latency, 90),
        "tokens_in_mean": np.mean([meta["tokens_in"] for meta in metas]),
        "tokens_cached_mean": np.mean([meta["tokens_cached"] for meta in metas]),
        "tokens_out_mean": np.mean([meta["tokens_out"] for meta in metas]),
        "llm_calls_mean": np.mean([meta["llm_calls"] for meta in metas]),
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
