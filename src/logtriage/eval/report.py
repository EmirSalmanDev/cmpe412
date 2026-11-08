"""The `evaluate` command (plan 10.6): every derived table and `reports/results.md`, one command.

It reads saved outputs and the LLM cache only. Nothing here can pay: answers come through a
cache-only client with a refusing backend, so a missing answer raises, and the ledger is compared
before and after. It does not import `logtriage.ml` (D57).

Files of the stages that ran once (`supervised_*`, `tuning_dev.csv`, `test_runs.csv`) are inputs,
read as saved: writing them again would mean scoring again, which M11 forbids.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

from logtriage.agents.runner import REPORTS_DIR, default_table, write_run_table
from logtriage.config import DEV_TESTBED, M11_TESTBEDS, Settings
from logtriage.eval import ablations, faithfulness, llm_baseline
from logtriage.eval.detection import dev_candidate_recall
from logtriage.eval.metrics import (
    attack_incidents,
    attack_summary,
    incident_truth,
    load_gold_mapping,
    verdict_counts,
    verdict_scores,
)
from logtriage.eval.results_text import render
from logtriage.eval.tables import TestbedInputs, build_tables, load_inputs, write_tables

logger = logging.getLogger(__name__)

RESULTS_DIR = "results"
RESULTS_FILE = "results.md"
RECHECK_NAME = f"{ablations.BASE}_{ablations.RECHECK}"
PAID_CONDITIONS = tuple(name for name in ablations.CONDITIONS if name != ablations.BASE)
# Read as saved, never written here: each comes from a stage that ran once.
FROZEN_FILES = (
    "tuning_dev.csv",
    "test_runs.csv",
    "supervised_dev_oof.csv",
    "supervised_importance.csv",
)
FROZEN_PATTERNS = ("supervised_{}.csv", "supervised_{}_phases.csv", "supervised_{}_errors.csv")


class PaidCallError(RuntimeError):
    """The ledger moved during `evaluate`, which must never happen."""


@dataclass
class EvaluateSummary:
    """What a run of `evaluate` wrote."""

    tables: list[str]
    results: Path


def results_dir(settings: Settings) -> Path:
    """Return `reports/results`."""
    return settings.paths.reports_dir / RESULTS_DIR


def check_frozen_inputs(settings: Settings) -> None:
    """Refuse to run if a file of a once-only stage is missing.

    Raises:
        FileNotFoundError: Naming the missing files.
    """
    names = [*FROZEN_FILES]
    names += [p.format(t) for t in M11_TESTBEDS for p in FROZEN_PATTERNS]
    missing = [name for name in names if not (results_dir(settings) / name).is_file()]
    if missing:
        raise FileNotFoundError(f"inputs of once-only stages are missing: {missing}")


def run_tables(settings: Settings) -> None:
    """Write the run tables of the official reports and of the ablations again."""
    for testbed in [*M11_TESTBEDS, DEV_TESTBED]:
        directory = settings.paths.processed_dir / testbed / REPORTS_DIR
        write_run_table(directory, default_table(testbed, settings))
    for name in (ablations.BASE, RECHECK_NAME, *PAID_CONDITIONS):
        write_run_table(ablations.output_dir(settings, name), ablations.table_path(settings, name))


def ablation_row(
    condition: str, reports: dict[str, dict[str, Any]], item: TestbedInputs, gold: dict
) -> dict[str, Any]:
    """Return the metrics of one condition on santos (plan 10.4).

    Args:
        condition: Name of the condition.
        reports: Its reports by incident.
        item: The inputs of santos.
        gold: Gold mapping.

    Returns:
        Verdicts, ATT&CK hits, claims, Verifier work, tokens, cost and latency.
    """
    truth = incident_truth(item.result.table)
    verdicts = pd.Series({key: report["verdict"] for key, report in reports.items()})
    counts = verdict_counts(truth, verdicts)
    hits = attack_summary(attack_incidents(truth, reports, gold))
    metas = [report["meta"] for report in reports.values()]
    values = list(reports.values())
    return {
        "condition": condition,
        "run": metas[0]["run"],
        "reports": len(reports),
        **counts,
        **verdict_scores(counts),
        **hits,
        "claims": sum(
            len(report["summary"]) + len(report["timeline"]) + len(report["techniques"])
            for report in values
        ),
        "draft_claims": sum(meta["draft_claims"] for meta in metas),
        "unknown_eid_claims": sum(meta["draft_unknown_eid_claims"] for meta in metas),
        "rewrites": sum(report["verifier_rounds"] for report in values),
        "removed_claims": sum(len(report["unsupported_claims_removed"]) for report in values),
        "llm_calls": sum(meta["llm_calls"] for meta in metas),
        "cached_calls": sum(meta["cached_calls"] for meta in metas),
        "tokens_in": sum(meta["tokens_in"] for meta in metas),
        "tokens_out": sum(meta["tokens_out"] for meta in metas),
        "cost_usd": sum(meta["cost_usd"] for meta in metas),
        "spent_usd": sum(meta["spent_usd"] for meta in metas),
        "latency_mean_s": sum(meta["latency_s"] for meta in metas) / len(metas),
        "fingerprints": " ".join(
            sorted({print_ for meta in metas for print_ in meta["system_fingerprints"]})
        ),
    }


def ablation_tables(items: list[TestbedInputs], settings: Settings) -> dict[str, pd.DataFrame]:
    """Return the comparison of the conditions and the proof of the replays (D65, D69)."""
    item = next(entry for entry in items if entry.name == ablations.ABLATION_TESTBED)
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    rows = [
        ablation_row(name, ablations.condition_reports(settings, name), item, gold)
        for name in ablations.CONDITIONS
    ]
    proof = [ablations.replay_proof(settings, name=name) for name in (ablations.BASE, RECHECK_NAME)]
    return {
        "eval_ablations": pd.DataFrame(rows),
        "eval_ablation_replay": pd.concat(proof, ignore_index=True),
    }


def tool_table(items: list[TestbedInputs]) -> pd.DataFrame:
    """Return how often each tool was called in the official reports."""
    rows = [
        {"testbed": item.name, "tool": call["tool"]}
        for item in items
        for report in item.reports.values()
        for call in report["meta"]["tool_calls"]
    ]
    counts = pd.DataFrame(rows).groupby(["testbed", "tool"]).size().rename("calls").reset_index()
    tools = [*counts["tool"].unique(), "similar_incidents"]
    full = pd.MultiIndex.from_product(
        [[item.name for item in items], sorted(set(tools))], names=["testbed", "tool"]
    )
    indexed = counts.set_index(["testbed", "tool"]).reindex(full, fill_value=0)
    return indexed.reset_index()


def ai_tables(settings: Settings) -> dict[str, pd.DataFrame]:
    """Return every D67 reading, kappa, the disagreements and the reasons, from the saved labels.

    Both sheets are read (D71): `full_evidence`, the corrected one, and `raw_only`, the earlier
    one. Each row says which sheet it comes from.
    """
    testbeds = list(M11_TESTBEDS)
    parts: dict[str, list[pd.DataFrame]] = {}
    for name in faithfulness.SHEETS:
        directory = faithfulness.sheet_dir(settings, name)
        sheet = pd.read_csv(directory / faithfulness.SHEET_FILE, keep_default_na=False)
        key = pd.read_csv(faithfulness.key_path(settings, name), keep_default_na=False)
        paired = pd.read_csv(faithfulness.paired_path(settings, name), keep_default_na=False)
        labels = faithfulness.read_labels(directory, set(sheet["id"]))
        tables = {
            "eval_faithfulness_ai": faithfulness.readings_table(key, paired, labels, testbeds),
            "eval_faithfulness_kappa": faithfulness.agreement_table(key, labels, testbeds),
            "eval_faithfulness_disagreements": faithfulness.disagreements(sheet, key, labels),
            "eval_faithfulness_reasons": faithfulness.reason_table(key, labels),
        }
        for table_name, table in tables.items():
            parts.setdefault(table_name, []).append(table.assign(sheet=name))
    return {
        name: _sheet_first(pd.concat(frames, ignore_index=True)) for name, frames in parts.items()
    }


def _sheet_first(table: pd.DataFrame) -> pd.DataFrame:
    """Return a table with its `sheet` column first."""
    return table[["sheet", *[column for column in table.columns if column != "sheet"]]]


def run_evaluate(settings: Settings) -> EvaluateSummary:
    """Regenerate every derived table and `reports/results.md`. Run from the repo root.

    Args:
        settings: Loaded settings.

    Returns:
        What was written.

    Raises:
        CacheMissError: If an LLM answer is not saved, so a call would have to be paid.
        PaidCallError: If the ledger moved.
        FileNotFoundError: If an input is missing.
    """
    before = ablations.ledger_state(settings)
    check_frozen_inputs(settings)
    llm_baseline.replay_outputs(settings)
    run_tables(settings)
    items = []
    for testbed in [*M11_TESTBEDS, DEV_TESTBED]:
        logger.info("reading %s", testbed)
        items.append(load_inputs(testbed, settings))
    tables = build_tables(items, settings)
    tables |= ablation_tables(items, settings)
    tables |= llm_baseline.metric_tables(settings)
    tables["eval_faithfulness_auto"] = faithfulness.auto_table(settings)
    tables |= ai_tables(settings)
    tables["eval_tool_calls"] = tool_table(items)
    write_tables(tables, results_dir(settings))
    # Plain floats: the file was written so in M8, and only its values matter here.
    candidates = dev_candidate_recall(settings)
    candidates.to_csv(results_dir(settings) / "dev_candidate_recall.csv", index=False)
    path = settings.paths.reports_dir / RESULTS_FILE
    path.write_text(render(results_dir(settings)), encoding="utf-8")
    after = ablations.ledger_state(settings)
    if after != before:
        raise PaidCallError(f"the ledger moved during evaluate: {before} to {after}")
    return EvaluateSummary(sorted(tables), path)
