"""Faithfulness (plan 10.2, D67): the Verifier's saved judgments, and the blind claims sheet.

Auto faithfulness is self-assessment. It reads saved answers only: a Verifier answer is found by
rebuilding the key of its request from a Reporter answer and a report's evidence, so a match is
proof that the two belong together. No LLM call is made.

AI-annotated faithfulness is not the manual metric of plan 10.2, which is NOT MEASURED. The sheet
holds every claim with its cited raw lines and nothing else; the key stays under `data/`.
"""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from pydantic import ValidationError
from sklearn.metrics import cohen_kappa_score

from logtriage.agents.cache import LlmCache
from logtriage.agents.graph import verifier_request
from logtriage.agents.llm import request_key
from logtriage.agents.prompting import Prompt, load_prompts
from logtriage.agents.schemas import (
    Claim,
    Evidence,
    IncidentReport,
    ReportDraft,
    VerifierOutput,
    draft_claims,
)
from logtriage.config import DEV_TESTBED, Settings
from logtriage.eval.ablations import ABLATION_TESTBED, output_dir, report_files

ON = "verifier_on"
OFF = "verifier_off"
DRAFT_ONLY = "draft_only"
OFF_CONDITION = "verifier0"
SUPPORTED = "supported"
NOT_SUPPORTED = "not_supported"
POOLED = "pooled"
# Rewrites happen on these testbeds; santos has none, so a paired reading does not exist there.
SHEET_DIR = "faithfulness"
SHEET_FILE = "claims_sheet.csv"
KEY_FILE = "faithfulness_key.csv"
RATERS = ("a", "b")
LABEL_PATTERN = "labels_{}.csv"
# Testbed names and the organization names built on them (`status.md`, Recorded facts).
MASK = re.compile(r"santos|wardbeck|harrison|hurstwong|mannsmith|\bsmith\b", re.IGNORECASE)
MASKED = "<org>"


@dataclass
class Round:
    """One draft of a report and the Verifier's judgment of it."""

    position: int
    draft: ReportDraft
    judged: dict[str, str]


def reporter_answers(cache: LlmCache) -> list[tuple[int, ReportDraft]]:
    """Return every saved answer that is a report draft, oldest first.

    Args:
        cache: The LLM cache.

    Returns:
        Row number and draft. Answers of other roles do not parse, and are left out.
    """
    drafts = []
    rows = cache.connection.execute("SELECT rowid, answer FROM answers ORDER BY rowid")
    for rowid, text in rows.fetchall():
        content = json.loads(text).get("content") or ""
        if '"summary"' not in content:
            continue
        try:
            drafts.append((rowid, ReportDraft.model_validate_json(content)))
        except ValidationError:
            continue
    return drafts


def judgment_of(
    draft: ReportDraft,
    evidence: list[Evidence],
    prompt: Prompt,
    cache: LlmCache,
    settings: Settings,
    condition: dict[str, bool],
) -> dict[str, str] | None:
    """Return the Verifier's verdict per claim key, or None if it never judged this draft here.

    Args:
        draft: A draft.
        evidence: Evidence of a report.
        prompt: The Verifier's prompt.
        cache: The LLM cache.
        settings: Loaded settings.
        condition: Condition of the report.

    Returns:
        Claim key to `supported` or `unsupported`.
    """
    messages, to_judge, rejected = verifier_request(draft, evidence, prompt)
    if not to_judge:
        return None
    key = request_key(settings.llm, condition, messages, json_mode=True)
    answer = cache.get(key)
    if answer is None:
        return None
    output = VerifierOutput.model_validate_json(answer["content"])
    verdicts = {item.id: item.verdict for item in output.results}
    judged = {claim_key: verdicts[cid] for cid, (claim_key, _, _) in to_judge.items()}
    return judged | {item.key: "unsupported" for item in rejected}


def trace_report(
    report: IncidentReport,
    drafts: list[tuple[int, ReportDraft]],
    prompt: Prompt,
    cache: LlmCache,
    settings: Settings,
) -> list[Round]:
    """Return the rounds of a report, first draft first (D48).

    Args:
        report: A saved report with the Verifier on.
        drafts: Output of `reporter_answers`.
        prompt: The Verifier's prompt.
        cache: The LLM cache.
        settings: Loaded settings.

    Returns:
        One entry per draft the Verifier judged on this report's evidence.
    """
    condition = {key: report.meta[key] for key in ("verifier", "rag", "few_shot")}
    rounds = []
    for position, draft in drafts:
        judged = judgment_of(draft, report.evidence, prompt, cache, settings, condition)
        if judged is not None:
            rounds.append(Round(position, draft, judged))
    return rounds


def claim_text(item: ReportDraft | IncidentReport) -> dict[str, tuple[str, Claim]]:
    """Return the text to judge and the claim of every key of a draft or a report."""
    return {key: (text, claim) for key, claim, text in draft_claims(item)}


def check_trace(report: IncidentReport, rounds: list[Round]) -> None:
    """Refuse a trace that does not end in the saved report.

    Args:
        report: The report.
        rounds: Its rounds.

    Raises:
        ValueError: If a round is missing, or the last draft is not the report.
    """
    name = report.incident_id
    if len(rounds) != report.verifier_rounds + 1:
        raise ValueError(f"{name}: {len(rounds)} rounds for {report.verifier_rounds} rewrites")
    if len(claim_text(rounds[0].draft)) != report.meta["draft_claims"]:
        raise ValueError(f"{name}: the first draft is not the one the report counted")
    last = rounds[-1]
    kept = {
        (text, tuple(claim.evidence))
        for key, (text, claim) in claim_text(last.draft).items()
        if last.judged[key] == "supported" or report.verifier_rounds == 0
    }
    final = {(text, tuple(claim.evidence)) for text, claim in claim_text(report).values()}
    if not final <= kept | {
        (text, tuple(claim.evidence)) for text, claim in claim_text(last.draft).values()
    }:
        raise ValueError(f"{name}: the last draft does not hold the report's claims")


def load_official(testbed: str, settings: Settings) -> dict[str, IncidentReport]:
    """Return the official reports of a testbed by incident."""
    directory = settings.paths.processed_dir / testbed / "reports"
    paths = sorted(directory.glob(f"{testbed}-*.json"))
    return {
        path.stem: IncidentReport.model_validate_json(path.read_text(encoding="utf-8"))
        for path in paths
    }


def trace_testbeds(settings: Settings, testbeds: Iterable[str]) -> dict[str, dict[str, list[Round]]]:
    """Return the rounds of every official report, by testbed and incident."""
    prompt = load_prompts()["verifier"]
    cache = LlmCache(settings.paths.cache_dir / "llm.sqlite")
    try:
        drafts = reporter_answers(cache)
        traced: dict[str, dict[str, list[Round]]] = {}
        for testbed in testbeds:
            traced[testbed] = {}
            for name, report in load_official(testbed, settings).items():
                rounds = trace_report(report, drafts, prompt, cache, settings)
                check_trace(report, rounds)
                traced[testbed][name] = rounds
        return traced
    finally:
        cache.close()


def _auto_row(testbed: str, group: str, reports: list[list[Round]]) -> dict[str, Any]:
    """Return the shares of claims the Verifier itself called supported."""
    first = [verdict for rounds in reports for verdict in rounds[0].judged.values()]
    last = [verdict for rounds in reports for verdict in rounds[-1].judged.values()]
    return {
        "testbed": testbed,
        "group": group,
        "label": "self-assessment",
        "reports": len(reports),
        "reports_rewritten": sum(len(rounds) > 1 for rounds in reports),
        "first_draft_claims": len(first),
        "first_draft_supported": first.count("supported"),
        "first_draft_share": first.count("supported") / len(first),
        "last_round_claims": len(last),
        "last_round_supported": last.count("supported"),
        "last_round_share": last.count("supported") / len(last),
    }


def auto_table(settings: Settings) -> pd.DataFrame:
    """Return auto faithfulness per testbed and pooled (plan 10.2), from saved answers only."""
    testbeds = [*settings.test_testbeds, DEV_TESTBED]
    traced = trace_testbeds(settings, testbeds)
    rows = [
        _auto_row(name, "dev" if name == DEV_TESTBED else "test", list(traced[name].values()))
        for name in testbeds
    ]
    tests = [item for name in settings.test_testbeds for item in traced[name].values()]
    rows.append(_auto_row(POOLED, POOLED, tests))
    return pd.DataFrame(rows)


def mask(text: str) -> str:
    """Hide the testbed in a text."""
    return MASK.sub(MASKED, text)


def claim_rows(
    testbed: str, incident: str, arm: str, source: ReportDraft | IncidentReport, lines: dict
) -> list[dict[str, Any]]:
    """Return one row per claim, with the raw text of its cited lines.

    Args:
        testbed: Testbed name.
        incident: Incident id.
        arm: `verifier_on`, `verifier_off` or `draft_only`.
        source: Report or draft.
        lines: Eid to raw text.

    Returns:
        Rows with the key, the masked text and the masked lines. A cited eid that names no line
        has no raw text, so such a claim shows `(no such line)`.
    """
    rows = []
    for key, (text, claim) in claim_text(source).items():
        cited = [lines.get(eid, "(no such line)") for eid in dict.fromkeys(claim.evidence)]
        rows.append(
            {
                "testbed": testbed,
                "incident_id": incident,
                "arm": arm,
                "claim_key": key,
                "claim_type": key.split(":")[0],
                "text": mask(text),
                "lines": json.dumps([mask(line) for line in cited], ensure_ascii=False),
            }
        )
    return rows


def _identity(row: dict[str, Any]) -> tuple[str, str]:
    """Return what makes two claims the same: the text and the cited lines."""
    return row["text"], row["lines"]


def collect_claims(settings: Settings) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return every claim of D67, and the claims of the first drafts of the rewritten reports.

    Args:
        settings: Loaded settings.

    Returns:
        The rows to rate: the final claims of the test reports, the santos Verifier-off claims and
        the draft-only claims; and all first-draft claims of the reports the Verifier rewrote,
        which are the off side of the paired reading.
    """
    traced = trace_testbeds(settings, settings.test_testbeds)
    rows: list[dict[str, Any]] = []
    paired: list[dict[str, Any]] = []
    for testbed in settings.test_testbeds:
        for name, report in load_official(testbed, settings).items():
            lines = {item.eid: item.raw for item in report.evidence}
            final = claim_rows(testbed, name, ON, report, lines)
            rows += final
            rounds = traced[testbed][name]
            if len(rounds) == 1:
                continue
            first = claim_rows(testbed, name, DRAFT_ONLY, rounds[0].draft, lines)
            paired += first
            known = {_identity(row) for row in final}
            rows += [row for row in first if _identity(row) not in known]
    directory = output_dir(settings, OFF_CONDITION)
    for path in report_files(directory):
        report = IncidentReport.model_validate_json(path.read_text(encoding="utf-8"))
        lines = {item.eid: item.raw for item in report.evidence}
        rows += claim_rows(ABLATION_TESTBED, report.incident_id, OFF, report, lines)
    return pd.DataFrame(rows), pd.DataFrame(paired)


def build_sheet(claims: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return the blind sheet and its key (m11_design.md 3d).

    Args:
        claims: Rows of `collect_claims`.
        seed: The project seed.

    Returns:
        The sheet, one shuffled row per distinct claim: `id`, `claim`, `cited_lines`. And the key,
        one row per claim, with the `id` that holds it.
    """
    distinct = claims[["text", "lines"]].drop_duplicates().reset_index(drop=True)
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(distinct))
    ids = rng.choice(900_000, len(distinct), replace=False) + 100_000
    sheet = distinct.iloc[order].reset_index(drop=True)
    sheet.insert(0, "id", [f"c{number}" for number in ids])
    key = claims.merge(sheet, on=["text", "lines"], how="left")
    table = sheet.rename(columns={"text": "claim", "lines": "cited_lines"})
    return table, key.drop(columns=["text", "lines"])


def read_labels(directory: Path, ids: set[str]) -> pd.DataFrame:
    """Read the label file of each rater.

    Args:
        directory: `reports/faithfulness`.
        ids: The ids of the sheet.

    Returns:
        One row per id, with a column per rater and its reason.

    Raises:
        ValueError: If a file does not cover the sheet, or holds another label.
    """
    merged = pd.DataFrame({"id": sorted(ids)})
    for rater in RATERS:
        table = pd.read_csv(directory / LABEL_PATTERN.format(rater), keep_default_na=False)
        if set(table["id"]) != ids or table["id"].duplicated().any():
            raise ValueError(f"rater {rater}: the labels do not cover the sheet once each")
        unknown = set(table["label"]) - {SUPPORTED, NOT_SUPPORTED}
        if unknown:
            raise ValueError(f"rater {rater}: unknown labels {sorted(unknown)}")
        renamed = table.rename(columns={"label": f"label_{rater}", "reason": f"reason_{rater}"})
        merged = merged.merge(renamed[["id", f"label_{rater}", f"reason_{rater}"]], on="id")
    return merged


def _share(labels: pd.Series) -> float:
    """Return the share of claims a reader counts as supported."""
    return float(labels.mean()) if len(labels) else float("nan")


def reading_row(reading: str, testbed: str, part: pd.DataFrame) -> dict[str, Any]:
    """Return one row of the readings, with each rater and the reading of both.

    Args:
        reading: Name of the reading.
        testbed: Testbed or `pooled`.
        part: Claims joined with labels.

    Returns:
        The counts and shares. `both` counts a claim only if both raters call it supported, the
        reading fixed before any rating.
    """
    a = part["label_a"] == SUPPORTED
    b = part["label_b"] == SUPPORTED
    return {
        "reading": reading,
        "testbed": testbed,
        "claims": len(part),
        "supported_both": int((a & b).sum()),
        "share_both": _share(a & b),
        "share_a": _share(a),
        "share_b": _share(b),
    }


def readings_table(
    claims: pd.DataFrame, paired: pd.DataFrame, labels: pd.DataFrame, testbeds: list[str]
) -> pd.DataFrame:
    """Compute every D67 reading, per testbed and pooled.

    Args:
        claims: The key, one row per claim, with its `id`.
        paired: First-draft claims of the rewritten reports, with their `id`.
        labels: Output of `read_labels`.
        testbeds: The test testbeds.

    Returns:
        One row per reading and testbed.
    """
    joined = claims.merge(labels, on="id")
    drafts = paired.merge(labels, on="id")
    on = joined[joined["arm"] == ON]
    rewritten = set(paired["incident_id"])
    final = on[on["incident_id"].isin(rewritten)]
    first_keys = set(zip(paired["incident_id"], paired["id"], strict=True))
    final_keys = set(zip(final["incident_id"], final["id"], strict=True))
    only_final = final[
        [pair not in first_keys for pair in zip(final["incident_id"], final["id"], strict=True)]
    ]
    only_draft = drafts[
        [pair not in final_keys for pair in zip(drafts["incident_id"], drafts["id"], strict=True)]
    ]
    rows = []
    for testbed in [*testbeds, POOLED]:

        def of(table: pd.DataFrame, name: str = testbed) -> pd.DataFrame:
            return table if name == POOLED else table[table["testbed"] == name]

        rows.append(reading_row("verifier_on", testbed, of(on)))
        rows.append(reading_row("paired_first_draft", testbed, of(drafts)))
        rows.append(reading_row("paired_final", testbed, of(final)))
        rows.append(reading_row("paired_draft_only", testbed, of(only_draft)))
        rows.append(reading_row("paired_final_only", testbed, of(only_final)))
    rows.append(reading_row("verifier_off", ABLATION_TESTBED, joined[joined["arm"] == OFF]))
    return pd.DataFrame(rows)


def agreement_table(claims: pd.DataFrame, labels: pd.DataFrame, testbeds: list[str]) -> pd.DataFrame:
    """Return Cohen's kappa between the raters, on the rows of the sheet.

    Args:
        claims: The key.
        labels: Output of `read_labels`.
        testbeds: The test testbeds.

    Returns:
        One row per scope: all rows, then the rows that hold a claim of each testbed.
    """
    scopes = {"all": set(labels["id"])}
    for testbed in testbeds:
        scopes[testbed] = set(claims.loc[claims["testbed"] == testbed, "id"])
    rows = []
    for scope, ids in scopes.items():
        part = labels[labels["id"].isin(ids)]
        a, b = part["label_a"], part["label_b"]
        rows.append(
            {
                "scope": scope,
                "rows": len(part),
                "agree": int((a == b).sum()),
                "agreement": float((a == b).mean()),
                "kappa": float(cohen_kappa_score(a, b, labels=[SUPPORTED, NOT_SUPPORTED])),
            }
        )
    return pd.DataFrame(rows)
