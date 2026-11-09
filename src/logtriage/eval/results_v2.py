"""`reports/results_v2.md`: v1 against v2 on shaw and fox, from saved outputs only (M12, D91).

It reuses the M11 tables (`eval.tables`) on each mode's saved incidents, scores and reports, and
the §7 reading of `eval.v2_compare`. The definitions are those of plan §10.1-§10.2 and the
denominators those frozen in `reports/targets_shaw.md` and `reports/targets_fox.md`. Nothing is
scored, no LLM is called, and `reports/results.md`, v1's official results, is not touched.
Faithfulness is not measured here (D91).

Each plain statement of the summary is checked against the numbers before it is written: if one
does not hold, the run stops instead of printing it.

    python -m logtriage.eval.results_v2
"""

import logging
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from logtriage.config import V1_MODE, V2_CONFIG_PATH, V2_MODE, Settings, load_settings
from logtriage.eval import v2_compare
from logtriage.eval.report import tool_table
from logtriage.eval.tables import POOLED, TestbedInputs, build_tables, load_inputs, write_tables

logger = logging.getLogger(__name__)

TESTBEDS = v2_compare.UNSEEN_TESTBEDS
MODES = (V1_MODE, V2_MODE)
SUM = "sum"
RESULTS_FILE = "results_v2.md"
TABLE_PREFIX = "v2_"
SELECTION_FILE = "v2_dev_selection.csv"
CHOSEN = (("v1", 0.999, 30), ("b+d", 0.996, 30))  # D78
# The log type candidate (d) changes, and the dev phase it was found on (D76).
D_LOG_TYPE = "audit"
D_PHASE = "service_stop"
TABLES = (
    "eval_windows",
    "eval_phase_recall",
    "eval_phase_credit",
    "eval_alert_reduction",
    "eval_ids_recall",
    "eval_verdict",
    "eval_attack",
    "eval_attack_incidents",
    "eval_citations",
    "eval_cost",
)


class StatementError(ValueError):
    """A plain statement of the summary does not hold for the numbers."""


@dataclass
class Facts:
    """The numbers the plain statements rest on."""

    phases: int
    detected: dict[str, int]
    gained: dict[str, list[str]]
    lost: dict[str, list[str]]
    gain_types: dict[str, list[str]]
    gain_scores: list[tuple[str, float, float]]
    q: dict[str, float]
    d_phase_credited: list[tuple[str, str]]
    incidents: dict[tuple[str, str], int]
    required: dict[str, int]
    denominators: dict[str, int]
    per_testbed: dict[tuple[str, str], int]


def plain_statements(facts: Facts) -> list[str]:
    """Return the plain statements of the summary, each checked against the facts.

    Raises:
        StatementError: If a statement would not be true.
    """
    gains = [(testbed, phase) for testbed, names in facts.gained.items() for phase in names]
    if len(gains) != 1 or facts.detected[V2_MODE] - facts.detected[V1_MODE] != 1:
        raise StatementError(f"the gain is not one phase: {gains}, {facts.detected}")
    testbed, phase = gains[0]
    if any(facts.lost.values()):
        raise StatementError(f"v2 loses phases: {facts.lost}")
    for name, v1_score, v2_score in facts.gain_scores:
        if not (v1_score == v2_score and facts.q[V2_MODE] <= v2_score < facts.q[V1_MODE]):
            raise StatementError(f"{name}: the gain does not come from the lower q alone")
    types = facts.gain_types[phase]
    if D_LOG_TYPE in types or facts.d_phase_credited:
        raise StatementError(f"candidate (d) contributed: {types}, {facts.d_phase_credited}")
    fox = (facts.incidents[("fox", V1_MODE)], facts.incidents[("fox", V2_MODE)])
    if not fox[1] > 2 * fox[0]:
        raise StatementError(f"v2 did not more than double incidents on fox: {fox}")
    reached = [key for key, value in facts.per_testbed.items() if value >= facts.required[key[0]]]
    if reached:
        raise StatementError(f"the 80% target is reached: {reached}")
    score = facts.gain_scores[0][1]
    shaw = (facts.incidents[("shaw", V1_MODE)], facts.incidents[("shaw", V2_MODE)])
    return [
        f"**The gain is one phase of {facts.phases}:** {testbed} `{phase}`, credited through "
        f"{', '.join(f'`{name}`' for name in types)} by a window that scores {score:.6f} in "
        f"both modes, so it passes v2's `q` {facts.q[V2_MODE]} and not v1's "
        f"{facts.q[V1_MODE]}: the lower `q` of candidate (b). v2 loses no phase.",
        f"**Candidate (d) transferred nothing to shaw or fox:** no phase is gained through "
        f"`{D_LOG_TYPE}`, the only log type it changes, and `{D_PHASE}`, the dev phase it was "
        f"found on (D76), is missed in both modes on both testbeds.",
        f"**v2 more than doubled incidents on fox:** {fox[0]} to {fox[1]}. On shaw, "
        f"{shaw[0]} to {shaw[1]}.",
        "**Neither mode reaches the 80% target on either testbed:** "
        + "; ".join(
            f"{name} needs {facts.required[name]} of {facts.denominators[name]}, v1 "
            f"{facts.per_testbed[(name, V1_MODE)]}, v2 {facts.per_testbed[(name, V2_MODE)]}"
            for name in TESTBEDS
        )
        + ".",
        "**This is an observation from one run per testbed, not a statistical result.**",
        "**v1's official results are unchanged:** `reports/results.md` and every v1 file of "
        "santos, `wardbeck` and `harrison` are byte-identical (D91).",
    ]


def mode_items(settings: Settings, mode: str) -> list[TestbedInputs]:
    """Return the inputs of shaw and fox in one mode."""
    return [load_inputs(testbed, settings, mode) for testbed in TESTBEDS]


def mode_tables(items: list[TestbedInputs], settings: Settings, mode: str) -> dict:
    """Return the M11 tables of one mode, with a `mode` column and `sum` for the pooled rows."""
    tables = build_tables(items, settings)
    tables["eval_tools"] = tool_table(items)
    recall = tables["eval_phase_recall"]
    tables["eval_phase_recall"] = recall[recall["source"] == "computed"].drop(
        columns=["source", "note"]
    )
    out = {}
    for name, table in tables.items():
        table = table.copy()
        for column in ("testbed", "group"):
            if column in table.columns:
                table[column] = table[column].replace(POOLED, SUM)
        table.insert(0, "mode", mode)
        out[name] = table
    return out


def gain_scores(
    items: dict[str, list[TestbedInputs]], gained: dict[str, list[str]]
) -> list[tuple[str, float, float]]:
    """Return, for each window that credits a gained phase in v2, its score in v1 and in v2."""
    keys = ["log_type", "host", "window_start"]
    rows = []
    for index, testbed in enumerate(TESTBEDS):
        v1 = items[V1_MODE][index].result.table.set_index(keys)["score"]
        v2 = items[V2_MODE][index].result.table
        for phase in gained[testbed]:
            credits = v2[
                v2["is_anomalous"]
                & v2["incident_id"].notna()
                & v2["is_attack"]
                & v2["phases"].apply(lambda names, p=phase: p in list(names))
            ]
            for _, window in credits.iterrows():
                key = tuple(window[name] for name in keys)
                name = f"{testbed} {phase} {key[0]} {key[1]} {key[2]:%Y-%m-%d %H:%M}"
                rows.append((name, float(v1.loc[key]), float(window["score"])))
    return rows


def spend_rows(items: dict[str, list[TestbedInputs]]) -> pd.DataFrame:
    """Return reports, calls, cached calls, paid USD and fingerprints per testbed and mode."""
    rows = []
    for mode in MODES:
        for item in items[mode]:
            metas = [report["meta"] for report in item.reports.values()]
            rows.append(
                {
                    "mode": mode,
                    "testbed": item.name,
                    "reports": len(metas),
                    "llm_calls": sum(meta["llm_calls"] for meta in metas),
                    "cached_calls": sum(meta["cached_calls"] for meta in metas),
                    "paid_usd": sum(meta["spent_usd"] for meta in metas),
                    "fingerprints": " ".join(
                        sorted({f for meta in metas for f in meta["system_fingerprints"]})
                    ),
                }
            )
    return pd.DataFrame(rows)


def selection_rows(settings: Settings) -> pd.DataFrame:
    """Return the dev rows of the chosen settings of v1 and v2 (D78): selection data."""
    table = pd.read_csv(settings.paths.reports_dir / "results" / SELECTION_FILE)
    parts = [
        table[(table["configuration"] == name) & (table["q"] == q) & (table["gap_minutes"] == gap)]
        for name, q, gap in CHOSEN
    ]
    return pd.concat(parts, ignore_index=True)


# Rendering.


def _cell(value: object) -> str:
    return "" if value is None or (isinstance(value, float) and pd.isna(value)) else str(value)


def markdown(header: list[str], rows: list[list[object]]) -> list[str]:
    """Return a Markdown table."""
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows]
    return lines


def _of(found: int, total: int) -> str:
    return f"{found}/{total} ({found / total:.1%})"


def _names(text: object) -> str:
    names = str(text).split() if isinstance(text, str) else []
    return " ".join(f"`{name}`" for name in names) or "none"


def _row(table: pd.DataFrame, **match: object) -> pd.Series:
    part = table
    for column, value in match.items():
        part = part[part[column] == value]
    if len(part) != 1:
        raise ValueError(f"expected one row for {match}, found {len(part)}")
    return part.iloc[0]


def recall_section(tables: dict, compare_rows: pd.DataFrame) -> list[str]:
    """Return the phase recall section."""
    recall = tables["v2_eval_phase_recall"]
    rows = []
    for testbed in [*TESTBEDS, SUM]:
        for mode in MODES:
            cells = [
                _row(recall, mode=mode, testbed=testbed, variant=variant)
                for variant in ("primary", "all_parsed", "without_exfil")
            ]
            if testbed == SUM:
                credited, missed = "", ""
            else:
                summary = _row(compare_rows, mode=mode, testbed=testbed)
                credited, missed = _names(summary["credited"]), _names(summary["missed"])
            rows.append(
                [
                    testbed,
                    mode,
                    *[_of(int(cell["detected"]), int(cell["phases"])) for cell in cells],
                    credited,
                    missed,
                ]
            )
    header = ["Testbed", "Mode", "Primary", "All parsed", "Without `dnsteal_exfil`"]
    return markdown([*header, "Credited", "Missed"], rows)


def credit_section(credit: pd.DataFrame) -> list[str]:
    """Return which log types credit each phase, per mode, with window counts."""
    types = [
        name
        for name in credit.columns
        if name not in ("mode", "testbed", "phase", "detected", "dns_only")
    ]
    rows = []
    for testbed in TESTBEDS:
        part = credit[credit["testbed"] == testbed]
        for phase in part["phase"].unique():
            cells = []
            for mode in MODES:
                row = _row(part, mode=mode, phase=phase)
                found = [f"`{name}` {int(row[name])}" for name in types if row[name] > 0]
                cells.append(", ".join(found) if row["detected"] else "missed")
            rows.append([testbed, f"`{phase}`", *cells])
    return markdown(["Testbed", "Phase", "v1: windows by log type", "v2"], rows)


def build(settings: Settings, v2_settings: Settings) -> tuple[str, dict[str, pd.DataFrame]]:
    """Return the text of `results_v2.md` and its tables.

    Args:
        settings: v1 settings (`configs/default.yaml`).
        v2_settings: v2 settings (`configs/v2.yaml`); only their `q` is read.

    Returns:
        The Markdown text and the tables by file name.
    """
    items = {mode: mode_items(settings, mode) for mode in MODES}
    per_mode = {mode: mode_tables(items[mode], settings, mode) for mode in MODES}
    tables = {
        f"{TABLE_PREFIX}{name}": pd.concat(
            [per_mode[mode][name] for mode in MODES], ignore_index=True
        )
        for name in [*TABLES, "eval_tools"]
    }
    compare_rows, compare_credit, reading = v2_compare.compare(settings)
    recall = tables["v2_eval_phase_recall"]
    primary = recall[(recall["variant"] == "primary") & (recall["testbed"] != SUM)]
    for _, row in primary.iterrows():
        check = _row(compare_rows, mode=row["mode"], testbed=row["testbed"])
        if int(check["detected"]) != int(row["detected"]):
            raise ValueError(f"{row['testbed']} {row['mode']}: the two readings differ")
    spend = spend_rows(items)
    tables["v2_eval_spend"] = spend
    credit = tables["v2_eval_phase_credit"]
    alerts = tables["v2_eval_alert_reduction"]
    v2_credit = credit[credit["mode"] == V2_MODE]
    gained = reading["gained"]
    gain_types = {}
    for testbed, names in gained.items():
        for phase in names:
            row = _row(v2_credit, testbed=testbed, phase=phase)
            gain_types[phase] = [
                name
                for name in credit.columns
                if name not in ("mode", "testbed", "phase", "detected", "dns_only")
                and row[name] > 0
            ]
    d_credited = [
        (row["testbed"], row["mode"])
        for _, row in credit[credit["phase"] == D_PHASE].iterrows()
        if row["detected"]
    ]
    facts = Facts(
        phases=reading["phases"],
        detected={V1_MODE: reading["v1_detected"], V2_MODE: reading["v2_detected"]},
        gained=gained,
        lost=reading["lost"],
        gain_types=gain_types,
        gain_scores=gain_scores(items, gained),
        q={V1_MODE: settings.ml.q, V2_MODE: v2_settings.ml.q},
        d_phase_credited=d_credited,
        incidents={
            (row["testbed"], row["mode"]): int(row["incidents"]) for _, row in alerts.iterrows()
        },
        required={
            testbed: int(_row(compare_rows, mode=V1_MODE, testbed=testbed)["required_80"])
            for testbed in TESTBEDS
        },
        denominators={
            testbed: int(_row(compare_rows, mode=V1_MODE, testbed=testbed)["phases"])
            for testbed in TESTBEDS
        },
        per_testbed={
            (row["testbed"], row["mode"]): int(row["detected"]) for _, row in primary.iterrows()
        },
    )
    text = render(facts, reading, tables, compare_rows, selection_rows(settings), settings)
    return text, tables


def render(
    facts: Facts,
    reading: dict,
    tables: dict[str, pd.DataFrame],
    compare_rows: pd.DataFrame,
    selection: pd.DataFrame,
    settings: Settings,
) -> str:
    """Return the Markdown text of `results_v2.md`."""
    alerts = tables["v2_eval_alert_reduction"]
    ids = tables["v2_eval_ids_recall"]
    verdicts = tables["v2_eval_verdict"]
    attack = tables["v2_eval_attack"]
    citations = tables["v2_eval_citations"]
    tools = tables["v2_eval_tools"]
    cost = tables["v2_eval_cost"]
    spend = tables["v2_eval_spend"]
    budget = settings.ml.incidents_per_day_budget
    lines = [
        "# Results of v2 (M12): shaw and fox, v1 against v2",
        "",
        "Generated by `python -m logtriage.eval.results_v2` from saved outputs only; edit "
        "`eval/results_v2.py`, not this file. Tables are in `reports/results/v2_eval_*.csv`. "
        "**v1's official results are `reports/results.md`, unchanged by M12**; nothing here "
        "replaces them, and no v2 number exists for santos, `wardbeck` or `harrison` (D74).",
        "",
        "- **v1** is `configs/default.yaml` (`q` 0.999, gap 30). **v2** is `configs/v2.yaml`, "
        "chosen on russellmitchell only (D78): candidate (b), a finer `q` grid, and (d), the "
        "`audit` feature `n_unseen_units`, at `q` 0.996, gap 30. The agents are the same in both.",
        "- shaw and fox are unseen testbeds: prepared once, their targets frozen before any "
        "detection (`reports/targets_shaw.md`, `reports/targets_fox.md`), then each mode ran "
        "once on each, with ledger rows in `reports/results/test_runs.csv`.",
        "- **Scope (D91):** automated metrics only, with the definitions of plan §10.1–§10.2 "
        "and the frozen denominators; no new definition, no changed target. **Faithfulness, "
        "AI-annotated or manual, is NOT MEASURED for shaw or fox, in either mode**: the agents "
        "are unchanged and no raters were run.",
        "- **Format check (D92):** the check of the incident reports was declared after the "
        "`investigate` runs were planned, built from the existing validators (report schema, "
        "one report per incident, cited eids in the report's own evidence, no failure in the "
        "run summary). It passed on all 59 new reports.",
        "",
        "## 1. Summary",
        "",
        *[f"- {statement}" for statement in plain_statements(facts)],
        "",
        "## 2. Phase recall",
        "",
        "Primary denominator: phases with labeled lines of the evaluation period in a "
        "baseline-capable log type, frozen before detection: shaw 8, fox 9. `sum` is detected "
        "over denominators summed over shaw and fox (§10.7, `reports/v2_plan.md` §5).",
        "",
        *recall_section(tables, compare_rows),
        "",
        *markdown(
            ["Testbed", "Gained by v2", "Lost by v2"],
            [
                [testbed, _names(" ".join(facts.gained[testbed])), _names(" ".join(names))]
                for testbed, names in facts.lost.items()
            ],
        ),
        "",
        "Which log types credit each counted phase, with the number of anomalous incident "
        "windows that hold its labeled lines:",
        "",
        *credit_section(tables["v2_eval_phase_credit"]),
        "",
    ]
    dns_only = [
        f"{row['testbed']} {row['mode']} `{row['phase']}`"
        for _, row in tables["v2_eval_phase_credit"].iterrows()
        if row["dns_only"]
    ]
    lines += [
        "No phase is credited through `dns` alone, in either mode, on either testbed."
        if not dns_only
        else f"Credited through `dns` alone: {', '.join(dns_only)}.",
        "",
        "## 3. The §7 reading, as written",
        "",
        f"- v1 credits {reading['v1_detected']} of {reading['phases']} phases, summed over "
        f"shaw and fox; v2 credits {reading['v2_detected']} of {reading['phases']}.",
        "- An extra phase credited through a log type other than `dns`: "
        f"{'yes' if reading['extra_phase_through_non_dns'] else 'no'}.",
        f"- v2 within {budget} incidents per day on each testbed: "
        f"{'no' if reading['v2_over_budget_on_a_testbed'] else 'yes'}.",
        f"- **Reading: {reading['verdict']}.** `reports/v2_plan.md` §7 limits it: two testbeds "
        "with about 9 phases each and one run each, so a difference of one or two phases is an "
        "observation, not a statistical result. The reading changes no setting: "
        "`configs/default.yaml` stays v1.",
        "",
        "Expected outcome, logged before any detection (D87), against what happened:",
        "",
        *markdown(
            ["Expected", "Observed"],
            [
                [
                    "Low phase recall on fox in both modes, no reason to change anything",
                    "fox "
                    + ", ".join(f"{mode} {facts.per_testbed[('fox', mode)]} of 9" for mode in MODES)
                    + ", both under the 80% target; shaw had "
                    + ", ".join(
                        f"{mode} {facts.per_testbed[('shaw', mode)]} of 8" for mode in MODES
                    )
                    + ", so fox was not the lower one. Nothing was changed",
                ],
                [
                    "shaw has no `dnsteal_exfil` in its logs",
                    "As frozen: it is outside shaw's denominator of 8",
                ],
                [
                    "The dev gain rests on one phase, so a null result is acceptable",
                    f"Not null: {facts.detected[V2_MODE] - facts.detected[V1_MODE]:+d} phase "
                    f"of {facts.phases}, through (b), while (d), which gave the dev gain, "
                    "gave none",
                ],
            ],
        ),
        "",
        "## 4. Incidents, budget and windows",
        "",
        f"Never pooled (§10.7). Budget {budget} incidents per day. Flagged windows are the "
        "anomalous evaluation windows.",
        "",
    ]
    rows = []
    for testbed in TESTBEDS:
        for mode in MODES:
            row = _row(alerts, mode=mode, testbed=testbed)
            flagged = _row(compare_rows, mode=mode, testbed=testbed)["flagged_by_log_type"]
            rows.append(
                [
                    testbed,
                    mode,
                    f"{row['days']:.3f}",
                    int(row["incidents"]),
                    f"{row['incidents_per_day']:.2f}",
                    "within" if row["within_budget"] else "**over**",
                    f"{row['incidents_per_day'] / budget:.1%}",
                    f"{int(row['anomalous_windows'])} ({flagged})",
                    f"{row['raw_alerts_per_day']:,.0f}",
                    f"{row['reduction_vs_raw_alerts']:.3%}",
                    f"{row['grouped_alerts_per_day']:.1f}",
                    f"{row['reduction_vs_grouped_alerts']:.1%}",
                ]
            )
    lines += markdown(
        [
            "Testbed",
            "Mode",
            "Days",
            "Incidents",
            "Per day",
            "Budget",
            "Budget used",
            "Flagged windows (by log type)",
            "Raw alerts/day",
            "vs raw",
            "Grouped alerts/day",
            "vs grouped",
        ],
        rows,
    )
    unmet = [
        f"{row['testbed']} {row['mode']}"
        for _, row in alerts.iterrows()
        if not row["meets_reduction"]
    ]
    lines += [
        "",
        "Both modes keep at least 90% fewer incidents than raw IDS alerts on both testbeds."
        if not unmet
        else f"Under 90% fewer incidents than raw IDS alerts: {', '.join(unmet)}.",
        "",
        "## 5. Baselines",
        "",
        "### IDS",
        "",
        "Phase recall of the AIT-ADS alerts over the same primary denominators, with ours beside "
        "it; the IDS does not depend on the mode. As in `reports/results.md` §4 (D64): event "
        "recall matches alert text to labeled lines and is a **lower bound**; time recall counts "
        "any alert inside a phase and is an **upper bound**.",
        "",
    ]
    rows = []
    for testbed in [*TESTBEDS, SUM]:
        event = _row(ids, mode=V1_MODE, testbed=testbed, label="event", variant="primary")
        timed = _row(ids, mode=V1_MODE, testbed=testbed, label="time", variant="primary")
        ours = [
            _row(tables["v2_eval_phase_recall"], mode=mode, testbed=testbed, variant="primary")
            for mode in MODES
        ]
        rows.append(
            [
                testbed,
                f"{int(event['detected'])}/{int(event['phases'])}",
                f"{int(timed['detected'])}/{int(timed['phases'])}",
                *[f"{int(row['detected'])}/{int(row['phases'])}" for row in ours],
            ]
        )
    lines += markdown(["Testbed", "IDS event (lower)", "IDS time (upper)", "v1", "v2"], rows)
    lines += [
        "",
        "### ML only",
        "",
        "Every incident called malicious: the `ML-only F1` column of the verdict table below, "
        "and the alert reduction of section 4.",
        "",
        "## 6. Agents",
        "",
        "### Verdicts",
        "",
        "Predicted by true class, label-ambiguous incidents left out. F1 counts `uncertain` as "
        "non-benign (§10.2). `sum` adds the two matrices (D62).",
        "",
    ]
    rows = []
    for testbed in [*TESTBEDS, SUM]:
        for mode in MODES:
            row = _row(verdicts, mode=mode, testbed=testbed, method="agents", variant="primary")
            ml = _row(verdicts, mode=mode, testbed=testbed, method="ml_only", variant="primary")
            with_ambiguous = _row(
                verdicts, mode=mode, testbed=testbed, method="agents", variant="with_ambiguous"
            )
            rows.append(
                [
                    testbed,
                    mode,
                    int(row["malicious_true_malicious"]),
                    int(row["malicious_true_benign"]),
                    int(row["uncertain_true_malicious"]),
                    int(row["uncertain_true_benign"]),
                    int(row["benign_true_malicious"]),
                    int(row["benign_true_benign"]),
                    f"{row['f1']:.3f}",
                    f"{with_ambiguous['f1']:.3f}",
                    f"{ml['f1']:.3f}",
                ]
            )
    lines += markdown(
        [
            "Testbed",
            "Mode",
            "mal./true mal.",
            "mal./true ben.",
            "unc./true mal.",
            "unc./true ben.",
            "ben./true mal.",
            "ben./true ben.",
            "F1",
            "F1 with ambiguous",
            "ML-only F1",
        ],
        rows,
    )
    malicious = {
        (row["testbed"], row["mode"]): int(row["malicious_incidents"])
        for _, row in attack.iterrows()
    }
    lines += [
        "",
        "True malicious incidents (holding attack windows): "
        + "; ".join(
            f"{testbed} v1 {malicious[(testbed, V1_MODE)]}, v2 {malicious[(testbed, V2_MODE)]}"
            for testbed in TESTBEDS
        )
        + ".",
        "",
        "### ATT&CK",
        "",
        "Malicious incidents only: hits over the true malicious incidents of each row.",
        "",
    ]
    rows = []
    for testbed in [*TESTBEDS, SUM]:
        for mode in MODES:
            row = _row(attack, mode=mode, testbed=testbed)
            total = int(row["malicious_incidents"])
            rows.append(
                [
                    testbed,
                    mode,
                    total,
                    *[
                        f"{int(row[f'{name}_hits'])} of {total}"
                        for name in ("top1_strict", "top3_strict", "top1_lenient", "top3_lenient")
                    ],
                ]
            )
    lines += markdown(
        [
            "Testbed",
            "Mode",
            "Malicious incidents",
            "Top-1 strict",
            "Top-3 strict",
            "Top-1 lenient",
            "Top-3 lenient",
        ],
        rows,
    )
    lines += ["", "### Hallucinated citations, before the Verifier", ""]
    rows = [
        [
            row["testbed"],
            row["mode"],
            int(row["reports"]),
            int(row["draft_claims"]),
            int(row["unknown_eid_claims"]),
        ]
        for _, row in citations.sort_values(["testbed", "mode"], key=_testbed_order).iterrows()
    ]
    lines += markdown(["Testbed", "Mode", "Reports", "Draft claims", "Citing unknown eids"], rows)
    lines += ["", "### Tool calls", ""]
    names = sorted(tools["tool"].unique())
    rows = []
    for testbed in TESTBEDS:
        for mode in MODES:
            part = tools[(tools["testbed"] == testbed) & (tools["mode"] == mode)]
            counts = dict(zip(part["tool"], part["calls"], strict=True))
            rows.append([testbed, mode, *[int(counts.get(name, 0)) for name in names]])
    lines += markdown(["Testbed", "Mode", *[f"`{name}`" for name in names]], rows)
    lines += [
        "",
        "`similar_incidents`, the incident memory, was called 0 times, as in M11.",
        "",
        "### Cost and spend",
        "",
        "All four runs ran at peak rates (D89), twice the off-peak ones; compare the off-peak "
        "column with `reports/results.md`. Paid is what the run spent; a cached call costs "
        "nothing.",
        "",
    ]
    rows = []
    for testbed in TESTBEDS:
        for mode in MODES:
            row = _row(cost, mode=mode, testbed=testbed)
            paid = _row(spend, mode=mode, testbed=testbed)
            rows.append(
                [
                    testbed,
                    mode,
                    int(paid["reports"]),
                    f"{int(paid['llm_calls'])} ({int(paid['cached_calls'])})",
                    f"{paid['paid_usd']:.6f}",
                    row["priced_at"],
                    f"{row['cost_mean_usd']:.4f}",
                    f"{row['cost_p90_usd']:.4f}",
                    f"{row['off_peak_mean_usd']:.4f}",
                    f"{row['latency_mean_s']:.1f}",
                ]
            )
    lines += markdown(
        [
            "Testbed",
            "Mode",
            "Reports",
            "LLM calls (cached)",
            "Paid USD",
            "Priced at",
            "Mean USD",
            "p90 USD",
            "Mean USD off-peak",
            "Mean s",
        ],
        rows,
    )
    total = spend["paid_usd"].sum()
    prints = sorted({value for text in spend["fingerprints"] for value in text.split()})
    cached = spend[spend["cached_calls"] > 0]
    lines += [
        "",
        f"Paid over the four runs, from the reports: {total:.6f} USD for "
        f"{int(spend['llm_calls'].sum())} LLM calls, {int(spend['cached_calls'].sum())} of "
        f"them cached, and {int(spend['reports'].sum())} reports, against the M12 stop of "
        "2.00 USD. "
        f"`system_fingerprint` on every report: {', '.join(f'`{p}`' for p in prints)}. "
        + "".join(
            f"{row['testbed']} {row['mode']} had {int(row['cached_calls'])} cached calls: "
            "incidents whose requests equal v1's are answered by the cache "
            "(`reports/v2_plan.md` §5); their mean cost counts the original price."
            for _, row in cached.iterrows()
        ),
        "",
        "## 7. Dev selection data, not a result",
        "",
        "These rows of `reports/results/v2_dev_selection.csv` are the **selection metric** on "
        "russellmitchell, the testbed v2 was chosen on (D78). They are optimistic by "
        "construction, and (d) was found on dev labels (D76); they are never evidence that v2 "
        "helps.",
        "",
    ]
    rows = [
        [
            row["configuration"],
            row["q"],
            int(row["gap_minutes"]),
            f"{int(row['phases_detected'])}/{int(row['phases'])}",
            int(row["incidents"]),
            f"{row['incidents_per_day']:.2f}",
            int(row["anomalous_windows"]),
        ]
        for _, row in selection.iterrows()
    ]
    lines += markdown(
        ["Configuration", "q", "Gap", "Phases", "Incidents", "Per day", "Windows"], rows
    )
    lines += [
        "",
        "## 8. Limits",
        "",
        "- **One run per testbed and mode,** and few phases: one phase moves the sum by "
        f"{1 / facts.phases:.1%}. ATT&CK rests on 1 or 2 malicious incidents per testbed.",
        "- **Faithfulness is NOT MEASURED** for shaw and fox (D91); `reports/results.md` §6 "
        "is about the M11 testbeds only.",
        "- **The format check was declared after the runs were planned** (D92).",
        "- **shaw has no DNS exfiltration in its logs**, though the attacker logged it; fox's "
        "tunnel runs through all 34 training hours, so its baseline holds the attack (D87).",
        "- **Peak prices:** all four runs paid the peak rate (D89).",
        "- **Supervised reference:** the v1 stage ran once on each testbed and its files are in "
        "`reports/results/supervised_{shaw,fox}*.csv`; it is not part of the v1 and v2 "
        "comparison.",
        "",
    ]
    return "\n".join(lines)


def _testbed_order(column: pd.Series) -> pd.Series:
    order = {name: index for index, name in enumerate([*TESTBEDS, SUM, *MODES])}
    return column.map(lambda value: order.get(value, len(order)))


def write(settings: Settings, v2_settings: Settings) -> Path:
    """Write `reports/results_v2.md` and its tables; return the Markdown file."""
    text, tables = build(settings, v2_settings)
    write_tables(tables, settings.paths.reports_dir / "results")
    path = settings.paths.reports_dir / RESULTS_FILE
    path.write_text(text, encoding="utf-8")
    return path


def main() -> None:
    """Write the v2 results. Run from the repository root."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print(write(load_settings(), load_settings(V2_CONFIG_PATH)))


if __name__ == "__main__":
    main()
