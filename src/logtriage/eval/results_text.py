"""`reports/results.md` from the saved tables (plan 10.6). It computes no metric, it only reads.

The santos reading against `reports/targets.md` comes first, as plan 10.7 requires.
"""

from collections.abc import Sequence
from pathlib import Path

import pandas as pd

TEST_TESTBEDS = ("santos", "wardbeck", "harrison")
ALL_ROWS = (*TEST_TESTBEDS, "pooled", "russellmitchell")
THRESHOLD = 0.90
# Quoted from status.md: they come from saved scores, read once, and no table holds them (D28).
VPN_CEILINGS = (
    ("santos", 0.992063, 0.992063),
    ("wardbeck", 0.991031, 0.983558),
    ("harrison", 0.995318, 0.974719),
)


def pct(value: float, digits: int = 1) -> str:
    """Render a share as a percentage, or `n/a`."""
    return "n/a" if pd.isna(value) else f"{100 * value:.{digits}f}%"


def num(value: float, digits: int = 3) -> str:
    """Render a number, or `n/a`."""
    return "n/a" if pd.isna(value) else f"{value:.{digits}f}"


def table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    """Return a Markdown table."""
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(str(cell) for cell in row) + " |" for row in rows]
    return "\n".join(lines)


def one(frame: pd.DataFrame, **keys: object) -> pd.Series:
    """Return the only row with these values."""
    mask = pd.Series(True, index=frame.index)
    for name, value in keys.items():
        mask &= frame[name] == value
    found = frame[mask]
    if len(found) != 1:
        raise ValueError(f"{keys}: {len(found)} rows")
    return found.iloc[0]


class Saved:
    """The saved tables, by file name."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def __getattr__(self, name: str) -> pd.DataFrame:
        table_ = pd.read_csv(self.directory / f"{name}.csv", keep_default_na=False, na_values=[""])
        setattr(self, name, table_)
        return table_


def targets_section(s: Saved) -> str:
    """Return the santos reading against the frozen targets, then the pooled one."""
    recall = one(s.eval_phase_recall, testbed="santos", variant="primary")
    pooled = one(s.eval_phase_recall, testbed="pooled", variant="primary")
    reduction = one(s.eval_alert_reduction, testbed="santos")
    attack = one(s.eval_attack, testbed="santos")
    attack_pooled = one(s.eval_attack, testbed="pooled")
    per_day = [
        f"{name} {one(s.eval_alert_reduction, testbed=name)['incidents_per_day']:.2f}"
        for name in TEST_TESTBEDS
    ]
    cut = [
        f"{name} {pct(one(s.eval_alert_reduction, testbed=name)['reduction_vs_raw_alerts'], 3)}"
        for name in TEST_TESTBEDS
    ]
    rows = [
        (
            "Phase recall",
            "≥ 80% of phases with traces",
            f"{recall['detected']} of {recall['phases']} ({pct(recall['recall'])}), "
            + ("**met**" if recall["recall"] >= 0.8 else "**missed**"),
            f"{pooled['detected']} of {pooled['phases']} ({pct(pooled['recall'])})",
        ),
        (
            "Incidents per day",
            "≤ 25",
            f"{reduction['incidents_per_day']:.2f}, **met**",
            "not pooled: " + ", ".join(per_day),
        ),
        (
            "Fewer incidents than raw IDS alerts",
            "≥ 90%",
            f"{pct(reduction['reduction_vs_raw_alerts'], 3)}, **met**",
            "not pooled: " + ", ".join(cut),
        ),
        (
            "ATT&CK top-3, strict",
            "≥ 70% of malicious incidents",
            f"{attack['top3_strict_hits']} of {attack['malicious_incidents']} "
            f"({pct(attack['top3_strict'])}), **met, on 2 incidents**",
            f"{attack_pooled['top3_strict_hits']} of {attack_pooled['malicious_incidents']} "
            f"({pct(attack_pooled['top3_strict'])}), below 70%",
        ),
        (
            "Manual faithfulness",
            "≥ 90% with the Verifier, and higher than without",
            "**NOT MEASURED** (D67)",
            "**NOT MEASURED** (D67)",
        ),
    ]
    return (
        "## 1. Santos against the frozen targets\n\n"
        "This is the primary reading (§10.7). `reports/targets.md` names santos only, so the "
        "pooled column is additional and is not a target reading.\n\n"
        + table(("Target", "Value", "Santos", "Pooled test testbeds"), rows)
        + "\n\nManual faithfulness has no human annotators and is not reported as met or missed. "
        "The AI-annotated number in section 6 is a different measure and does not stand in for "
        "it. Human evaluation is **NOT PERFORMED** (D68).\n\n"
        "**Freeze reference.** The targets are the content of `reports/targets.md` at commit "
        "`3684424`, tag `targets-frozen`, not `m3-done`. Commit `0ae17bf` changed only line 3, "
        "the placeholder for the hash; no target number or definition changed.\n\n"
        "**Santos runs (D40).** Santos was scored three times by the frozen supervised models. "
        "The committed CSVs are run 1. The error file and the reading of the results were chosen "
        "after seeing santos numbers; no model, feature, threshold, config or definition was. "
        "The `dns` thresholds are uninformative.\n\n"
        "**How the santos reports came to exist (D47).** They come from an accidental run: a "
        "stub test in `tests/test_smoke.py` called `investigate` after it stopped being a stub, "
        "so `pytest` ran a real investigation at 08:59–09:01 UTC on 2026-11-06, with the frozen "
        "prompts and code, 4 s before the freeze commit. The reports were kept and santos was "
        "not run again, because a second run would be the real breach. No prompt, retrieval, "
        "config or code changed because of its output.\n"
    )


def phase_section(s: Saved) -> str:
    """Return phase recall per testbed, pooled, and the unclipped secondary."""
    rows = []
    for name in ALL_ROWS:
        cells = [name]
        for variant in ("primary", "all_parsed", "without_exfil"):
            row = one(s.eval_phase_recall, testbed=name, variant=variant)
            cells.append(f"{row['detected']}/{row['phases']} ({pct(row['recall'])})")
        missed = one(s.eval_phase_recall, testbed=name, variant="primary")["missed"]
        cells.append("" if pd.isna(missed) else str(missed))
        rows.append(cells)
    unclipped = s.eval_phase_recall[s.eval_phase_recall["variant"] == "unclipped_dns"]
    quoted = [
        (row["testbed"], f"{row['detected']}/{row['phases']}", row["note"])
        for _, row in unclipped.iterrows()
    ]
    return (
        "### Phase recall\n\n"
        + table(("Testbed", "Primary", "All parsed", "Without `dnsteal_exfil`", "Missed"), rows)
        + "\n\nNo phase is credited through `dns` on any testbed.\n\n"
        "Unclipped DNS secondary, quoted from M5 and not recomputed. It exists for "
        "russellmitchell and santos only, not for `wardbeck` and `harrison` (D61), because it "
        "needs a second scoring pass and each new testbed runs once:\n\n"
        + table(("Testbed", "Phases", "Note"), quoted)
        + "\n"
    )


def alerts_section(s: Saved) -> str:
    """Return incidents and alerts per day. Never pooled."""
    rows = []
    for _, row in s.eval_alert_reduction.iterrows():
        rows.append(
            (
                row["testbed"],
                f"{row['days']:.3f}",
                row["incidents"],
                f"{row['incidents_per_day']:.2f}",
                f"{row['anomalous_windows_per_day']:.2f}",
                f"{row['raw_alerts_per_day']:,.0f}",
                f"{row['grouped_alerts_per_day']:.1f}",
                pct(row["reduction_vs_raw_alerts"], 3),
                pct(row["reduction_vs_grouped_alerts"]),
                pct(row["reduction_vs_windows"]),
                pct(row["incidents_per_day"] / 25),
            )
        )
    return (
        "### Incidents and alert reduction\n\nNot pooled (§10.7).\n\n"
        + table(
            (
                "Testbed",
                "Days",
                "Incidents",
                "Per day",
                "Anomalous windows/day",
                "Raw alerts/day",
                "Grouped alerts/day",
                "vs raw",
                "vs grouped",
                "vs windows",
                "Budget used",
            ),
            rows,
        )  # fmt: skip
        + "\n\n**The incident budget is mostly unused.** `q` 0.999 is the only grid value inside "
        "the budget on dev, and the grid has nothing between 0.995 and 0.999. That is why phase "
        "recall misses its target while incidents per day are far under 25. The grid was not "
        "changed after santos was scored.\n"
    )


def verdict_section(s: Saved) -> str:
    """Return the confusion matrix and F1 of the agents and of ML-only."""
    rows = []
    for name in ALL_ROWS:
        row = one(s.eval_verdict, method="agents", variant="primary", testbed=name)
        ambiguous = one(s.eval_verdict, method="agents", variant="with_ambiguous", testbed=name)
        ml = one(s.eval_verdict, method="ml_only", variant="primary", testbed=name)
        rows.append(
            (
                name,
                row["malicious_true_malicious"],
                row["malicious_true_benign"],
                row["uncertain_true_malicious"],
                row["uncertain_true_benign"],
                row["benign_true_malicious"],
                row["benign_true_benign"],
                num(row["f1"]),
                num(ambiguous["f1"]),
                num(ml["f1"]),
            )
        )
    agents = s.eval_verdict[
        (s.eval_verdict["method"] == "agents")
        & (s.eval_verdict["variant"] == "with_ambiguous")
        & s.eval_verdict["testbed"].isin([*TEST_TESTBEDS, "russellmitchell"])
    ]
    told_benign = int(agents[["benign_true_malicious", "benign_true_benign"]].sum().sum())
    return (
        "### Verdicts\n\nPredicted by true class, label-ambiguous incidents left out. F1 counts "
        "`uncertain` as non-benign (§10.2). Pooled sums the three test testbeds (D62).\n\n"
        + table(
            (
                "Testbed",
                "mal./true mal.",
                "mal./true ben.",
                "unc./true mal.",
                "unc./true ben.",
                "ben./true mal.",
                "ben./true ben.",
                "F1",
                "F1 with ambiguous",
                "ML-only F1",
            ),
            rows,
        )  # fmt: skip
        + f"\n\n**{told_benign} of {len(agents) and int(agents['incidents'].sum())} reports say "
        "`benign`, so verdict F1 equals ML-only on every row.** F1 here says nothing about the "
        "agents: `uncertain` counts as non-benign, so the agents reject nothing. What they do "
        "add is that `malicious` is said only of true malicious incidents on all rows above, "
        "which F1 does not show.\n"
    )


def attack_section(s: Saved) -> str:
    """Return ATT&CK hits per testbed, pooled, and the misses."""
    rows = [
        (
            name,
            one(s.eval_attack, testbed=name)["malicious_incidents"],
            f"{one(s.eval_attack, testbed=name)['top1_strict_hits']}",
            f"{one(s.eval_attack, testbed=name)['top3_strict_hits']}",
            f"{one(s.eval_attack, testbed=name)['top1_lenient_hits']}",
            f"{one(s.eval_attack, testbed=name)['top3_lenient_hits']}",
            pct(one(s.eval_attack, testbed=name)["top3_strict"]),
        )
        for name in ALL_ROWS
    ]
    incidents = s.eval_attack_incidents
    tests = incidents[incidents["group"] == "test"]
    misses = tests[~tests["top3_strict"]]
    named = ", ".join(f"`{name}`" for name in misses["incident_id"])
    all_absent = not misses["gold_retrieved"].any()
    return (
        "### ATT&CK\n\nMalicious incidents only.\n\n"
        + table(
            (
                "Testbed",
                "Incidents",
                "Top-1 strict",
                "Top-3 strict",
                "Top-1 lenient",
                "Top-3 lenient",
                "Top-3 strict share",
            ),
            rows,
        )  # fmt: skip
        + f"\n\nThe {len(misses)} pooled top-3 misses are {named}. "
        + (
            "In both, no gold technique was among the Mapper's candidates, so the Mapper could "
            "not have hit. "
            if all_absent
            else ""
        )
        + "Retrieval is weak on exfiltration too: T1071.004 passes the M7 check at rank 2, but "
        "T1048 ranks 24 and T1048.003 ranks 55 (D43). Retrieval was not changed after santos.\n"
    )


def citation_cost_section(s: Saved) -> str:
    """Return hallucinated citations, cost and latency."""
    citations = [
        (
            name,
            one(s.eval_citations, testbed=name)["draft_claims"],
            one(s.eval_citations, testbed=name)["unknown_eid_claims"],
            pct(one(s.eval_citations, testbed=name)["hallucinated_share"]),
        )
        for name in ALL_ROWS
    ]
    cost = [
        (
            row["testbed"],
            row["priced_at"],
            f"{row['cost_mean_usd']:.4f}",
            f"{row['cost_p90_usd']:.4f}",
            f"{row['off_peak_mean_usd']:.4f}",
            f"{row['latency_mean_s']:.1f}",
            f"{row['latency_p90_s']:.1f}",
            f"{row['tokens_in_mean']:,.0f}",
            f"{row['tokens_out_mean']:,.0f}",
        )
        for _, row in s.eval_cost.iterrows()
    ]
    return (
        "### Hallucinated citations, before the Verifier\n\n"
        + table(("Testbed", "Draft claims", "Citing unknown eids", "Share"), citations)
        + "\n\n### Cost and latency per incident\n\n"
        + table(
            (
                "Testbed",
                "Priced at",
                "Mean USD",
                "p90 USD",
                "Mean USD off-peak",
                "Mean s",
                "p90 s",
                "Tokens in",
                "Tokens out",
            ),
            cost,
        )  # fmt: skip
        + "\n\n**Peak and off-peak.** The santos and russellmitchell reports ran on a weekday in "
        "the peak band, at twice the off-peak rate; `wardbeck` and `harrison` ran off-peak on a "
        "Saturday. Compare the off-peak column across testbeds, not the logged cost. The p90 of "
        "3 santos incidents is close to their maximum.\n"
    )


def windows_section(s: Saved) -> str:
    """Return window metrics. Never pooled over testbeds."""
    rows = []
    for name in (*TEST_TESTBEDS, "russellmitchell"):
        for scope in ("pooled", "pooled_without_dns", "dns"):
            row = one(s.eval_windows, testbed=name, variant="primary", scope=scope)
            rows.append(
                (
                    name,
                    scope,
                    row["windows"],
                    row["attack"],
                    row["anomalous"],
                    num(row["precision"]),
                    num(row["recall"]),
                    num(row["f1"]),
                    num(row["pr_auc"]),
                )
            )
    return (
        "### Windows\n\n**Window metrics are never pooled over testbeds (§10.7).** `pooled` below "
        "means the log types of one testbed. `dns` is shown apart because of the contaminated "
        "baseline (D16). The other log types and the rows with label-ambiguous windows are in "
        "`reports/results/eval_windows.csv`.\n\n"
        + table(
            ("Testbed", "Scope", "Windows", "Attack", "Flagged", "P", "R", "F1", "PR-AUC"), rows
        )
        + "\n"
    )


def baselines_section(s: Saved) -> str:
    """Return the IDS, ML-only, LLM-only and supervised baselines."""
    ids = [
        (
            name,
            f"{one(s.eval_ids_recall, testbed=name, label='event', variant='primary')['detected']}"
            f"/{one(s.eval_ids_recall, testbed=name, label='event', variant='primary')['phases']}",
            f"{one(s.eval_ids_recall, testbed=name, label='time', variant='primary')['detected']}"
            f"/{one(s.eval_ids_recall, testbed=name, label='time', variant='primary')['phases']}",
            f"{one(s.eval_phase_recall, testbed=name, variant='primary')['detected']}"
            f"/{one(s.eval_phase_recall, testbed=name, variant='primary')['phases']}",
        )
        for name in ALL_ROWS
    ]
    only = s.eval_llm_only.iloc[0]
    costs = s.llm_only_cost.set_index("band")
    matrix = [
        ("true attack", only["malicious_true_malicious"], only["uncertain_true_malicious"],
         only["benign_true_malicious"]),
        ("true normal", only["malicious_true_benign"], only["uncertain_true_benign"],
         only["benign_true_benign"]),
    ]  # fmt: skip
    supervised = []
    for name in TEST_TESTBEDS:
        frame = pd.read_csv(s.directory / f"supervised_{name}.csv")
        frame = frame[(frame["analysis"] == "primary") & (frame["scope"] == "dns")]
        for method in ("ensemble", "rf", "xgb"):
            row = one(frame, method=method)
            supervised.append(
                (name, method, row["windows"], row["n_pos"], num(row["pr_auc"]), num(row["f1"]))
            )
    return (
        "## 4. Baselines\n\n### IDS\n\nPhase recall, with our phase recall beside it. AIT-ADS has "
        "no per-alert label, so the event label is derived by matching alert text to labeled "
        "lines, host not compared (D64). Suricata alerts have no labeled source, so event recall "
        "is a **lower bound**. Alerts run all the time, so time-based recall is an **upper "
        "bound**. D64 was decided after these numbers were computed; it does not change our "
        "system's numbers, and the IDS beats our phase recall under both readings.\n\n"
        + table(("Testbed", "IDS event (lower)", "IDS time (upper)", "Ours"), ids)
        + "\n\nThe IDS gets there with tens of thousands of alerts per day, as section 2 shows.\n\n"
        "### ML only\n\nEvery incident called malicious: the `ML-only F1` column of the verdict "
        "table, and the alert reduction of section 2.\n\n"
        "### LLM only\n\nRaw lines of 40 santos windows (20 attack, 20 normal), `llm-only-1`, one "
        "call each, no agents (D66). The windows are stratified by phase and by log type, so "
        "these shares are not rates of the whole period, and a window is not an incident, so "
        "they do not compare with the incident metrics above.\n\n"
        + table(("Windows", "said malicious", "said uncertain", "said benign"), matrix)
        + f"\n\nPrecision {num(only['precision'])}, recall {num(only['recall'])}, F1 "
        f"{num(only['f1'])}. On the {only['attack_windows']} attack windows, ATT&CK top-1 strict "
        f"{only['top1_strict_hits']}, top-3 strict {only['top3_strict_hits']}, top-1 lenient "
        f"{only['top1_lenient_hits']}, top-3 lenient {only['top3_lenient_hits']}. Cost "
        f"{only['cost_usd']:.4f} USD off-peak, {only['tokens_in']:,} tokens in, "
        f"{only['tokens_out']:,} out, {only['latency_mean_s']:.2f} s per call.\n\n"
        "**Extrapolated to the whole santos evaluation period:** "
        f"{costs.loc['off_peak', 'calls']:,} calls over "
        f"{costs.loc['off_peak', 'windows']:,} windows and "
        f"{costs.loc['off_peak', 'lines']:,} lines: {costs.loc['off_peak', 'cost_usd']:.2f} USD "
        f"off-peak, {costs.loc['peak', 'cost_usd']:.2f} USD at peak, with no cached-input "
        "discount. Line rates come from a stratified sample and the fixed part is the smallest "
        "call, so this is a rough figure. The first estimator, a regression, gave 5.87 USD and "
        "was dropped because long exfiltration lines drove its `auth` rate below 0.\n\n"
        "### Supervised reference\n\nThe reference covers **1 of 5 log types**: `dns` is the only "
        "type with enough dev positives (D37). On `dns` it is a **tunnel-presence detector**: its "
        "negatives are only tunnel-absent windows, so these numbers are not attack detection. "
        "Without the exfiltration-only windows it falls to chance on santos (RF PR-AUC 0.027, "
        "XGB 0.0033), and to 0.258 and 0.085 on `wardbeck`, 0.876 and 0.859 on `harrison`. Read "
        "as saved; primary rows:\n\n"
        + table(("Testbed", "Method", "Windows", "Positives", "PR-AUC", "F1"), supervised)
        + "\n"
    )


def ablation_section(s: Saved) -> str:
    """Return the ablations and the proof of the replay."""
    rows = []
    for _, row in s.eval_ablations.iterrows():
        rows.append(
            (
                row["condition"],
                f"{row['malicious_true_malicious']}/{row['uncertain_true_benign']}",
                f"{row['top1_strict_hits']}/{row['malicious_incidents']}",
                f"{row['top3_strict_hits']}/{row['malicious_incidents']}",
                row["claims"],
                row["rewrites"],
                row["removed_claims"],
                row["llm_calls"],
                f"{row['spent_usd']:.4f}",
                f"{row['latency_mean_s']:.1f}",
            )
        )
    proof = s.eval_ablation_replay
    exact = bool(proof["identical"].all()) and bool((proof["spent_usd"] == 0).all())
    calls = int(proof[proof["replay"] == "base"]["llm_calls"].sum())
    return (
        "## 5. Ablations on santos\n\nOne run per condition (D65). **n = 3 incidents, so these "
        "are illustrative.** Each condition has its own cache keys, so each re-runs the "
        "Investigator, on a model that is not bit-exact, so a difference mixes the switch with "
        "run-to-run variation. Nothing here is an effect size. `base` is the official santos "
        "run, at the peak rate when it ran; the others ran off-peak.\n\n"
        + table(
            (
                "Condition",
                "Malicious on true mal. / uncertain on true ben.",
                "Top-1",
                "Top-3",
                "Claims",
                "Rewrites",
                "Removed",
                "Calls",
                "Paid USD",
                "Mean s",
            ),
            rows,
        )  # fmt: skip
        + f"\n\n`base` replayed from the cache: {calls} of {calls} calls hit, and again after "
        "the `llm.py` fix of D69, with no key and a backend that refuses. "
        + ("Both replays paid 0 USD and equal the saved reports." if exact else "NOT EXACT.")
        + " `verifier0` failed once, on an empty response from the endpoint, before any output, "
        "and was retried once under D69; its first answer came from the cache. Ablation reports "
        "and memory live apart from the official ones.\n"
    )


def faithfulness_section(s: Saved) -> str:
    """Return auto and AI-annotated faithfulness."""
    auto = [
        (
            row["testbed"],
            row["reports"],
            row["reports_rewritten"],
            f"{row['first_draft_supported']}/{row['first_draft_claims']}",
            pct(row["first_draft_share"]),
            f"{row['last_round_supported']}/{row['last_round_claims']}",
        )
        for _, row in s.eval_faithfulness_auto.iterrows()
    ]
    ai = s.eval_faithfulness_ai
    names = {
        "verifier_on": "Verifier on, final claims",
        "verifier_off": "Verifier off, santos run",
        "paired_first_draft": "Rewritten reports, first draft",
        "paired_final": "Rewritten reports, final",
        "paired_draft_only": "Claims only in the first draft",
        "paired_final_only": "Claims only in the final report",
    }
    rows = []
    for reading, label in names.items():
        for _, row in ai[ai["reading"] == reading].iterrows():
            if row["claims"]:
                rows.append(
                    (
                        label,
                        row["testbed"],
                        row["claims"],
                        pct(row["share_both"]),
                        pct(row["share_a"]),
                        pct(row["share_b"]),
                    )
                )
    on_pooled = one(ai, reading="verifier_on", testbed="pooled")
    on_santos = one(ai, reading="verifier_on", testbed="santos")
    off_santos = one(ai, reading="verifier_off", testbed="santos")
    first = one(ai, reading="paired_first_draft", testbed="pooled")
    final = one(ai, reading="paired_final", testbed="pooled")
    kappa = s.eval_faithfulness_kappa
    every = one(kappa, scope="all")
    kappas = [
        (row["scope"], row["rows"], row["agree"], pct(row["agreement"]), num(row["kappa"]))
        for _, row in kappa.iterrows()
    ]
    reasons = s.eval_faithfulness_reasons.pivot_table(
        index="reason_code", columns="rater", values="claims", aggfunc="sum", fill_value=0
    )
    reason_rows = [(name, row["a"], row["b"]) for name, row in reasons.iterrows()]

    def reached(value: float) -> str:
        return "reaches 90%" if value >= THRESHOLD else "is below 90%"

    def relation(left: float, right: float) -> str:
        return "higher than" if left > right else "equal to" if left == right else "lower than"

    return (
        "## 6. Faithfulness\n\n### Auto faithfulness, **self-assessment**\n\nThe Verifier's own "
        "saved judgments, found by rebuilding each request key, with no LLM call. All 34 reports "
        "traced to their drafts. It is the same model grading its own pipeline, and the last "
        "round is 100% by construction, because whatever it rejects is rewritten or removed.\n\n"
        + table(
            (
                "Testbed",
                "Reports",
                "Rewritten",
                "First draft supported",
                "Share",
                "Last round supported",
            ),
            auto,
        )  # fmt: skip
        + "\n\n### AI-annotated faithfulness\n\n**This is not manual faithfulness, which is NOT "
        "MEASURED (D67), and it is not a target reading.** There are no human annotators: "
        f"{every['rows']} distinct claims (every claim of the 27 test reports, the santos "
        "Verifier-off claims and the draft-only claims of the 8 rewritten reports) were rated "
        "by two independent AI subagents, each given only the sheet and the rubric, blind to "
        "testbed name and condition. Both are the same underlying model, so their agreement is "
        "not agreement between independent people. The readings were fixed before any rating: "
        "a claim counts as supported only if both raters say so.\n\n"
        + table(("Reading", "Testbed", "Claims", "Both raters", "Rater a", "Rater b"), rows)
        + f"\n\n- **≥ 90%, pooled Verifier-on:** {pct(on_pooled['share_both'])} "
        f"{reached(on_pooled['share_both'])}.\n"
        f"- **≥ 90%, santos Verifier-on:** {pct(on_santos['share_both'])} "
        f"{reached(on_santos['share_both'])}.\n"
        f"- **On and off on santos (primary, confounded):** {pct(on_santos['share_both'])} on, "
        f"{relation(on_santos['share_both'], off_santos['share_both'])} "
        f"{pct(off_santos['share_both'])} off. These are two different runs, and on santos the "
        "Verifier changed nothing in the official run (0 rewrites), so this gap cannot show a "
        "Verifier effect.\n"
        f"- **Paired drafts (secondary, same evidence):** on the 8 rewritten reports, "
        f"{pct(first['share_both'])} of first-draft claims and {pct(final['share_both'])} of "
        "final claims. This isolates the Verifier, but only where it acted, and the reports are "
        "the ones it flagged.\n\n"
        "Agreement between the raters, on rows of the sheet:\n\n"
        + table(("Scope", "Rows", "Agree", "Share", "Cohen's κ"), kappas)
        + "\n\nThe disagreements are in `reports/results/eval_faithfulness_disagreements.csv`.\n\n"
        "**Limit of the sheet.** Raters saw the raw text of the cited lines only, so not the "
        "host, file or parsed time that the Verifier saw. A claim that names a host a line does "
        "not show is `not_supported` under the rubric, so this reading is harsher than the "
        "Verifier's. Dates and address ranges can still hint at a testbed. Causes given for "
        "`not_supported`, counted over claims; this changes no reading:\n\n"
        + table(("Cause", "Rater a", "Rater b"), reason_rows)
        + "\n"
    )


def tools_line(s: Saved) -> str:
    """Return the sentence on the incident memory."""
    calls = int(s.eval_tool_calls["calls"].sum())
    similar = int(
        s.eval_tool_calls.loc[s.eval_tool_calls["tool"] == "similar_incidents", "calls"].sum()
    )
    reports = int(s.eval_cost["reports"].sum())
    return (
        f"- **Incident memory was never used.** `similar_incidents` was called {similar} times "
        f"in {calls} tool calls over the {reports} official reports, so that path has not run on "
        "the real model.\n"
    )


def limits_section(s: Saved) -> str:
    """Return everything a reader must keep in mind."""
    ceilings = [(name, f"{value:.6f}", best) for name, value, best in VPN_CEILINGS]
    return (
        "## 7. Limits of these numbers\n\n"
        "- **n is small everywhere.** Santos has 3 incidents, 2 of them malicious, so one miss "
        "moves ATT&CK top-3 by 50 points. Pooled ATT&CK rests on 6 incidents, pooled verdicts on "
        "25, ablations on 3, the LLM-only sample on 40 windows.\n"
        "- **DNS contamination of training.** The tunnel runs through every training hour: "
        "21.6% of `inet-firewall` DNS lines on russellmitchell, 26.0% on santos (D16). So "
        "`dnsteal_exfil` is the normal state of the baseline, and it is missed on every testbed; "
        "no DNS window earns phase credit.\n"
        "- **`harrison` `dns`.** All 42 flagged windows lie after the tunnel stopped, with no "
        "labeled line. They are quiet windows of 2 to 6 lines whose `mean_template_rarity` passes "
        "its calib maximum, the limit D29 named. They all score exactly 0.999298, the only score "
        "that passes `q` on 949 calib windows and 3 models. Not a bug; nothing changed.\n"
        "- **`harrison` is not comparable.** 59.36% of its parsed evaluation lines are attack "
        "lines, dominated by `dirb` (411,830 labeled lines), with 280,562 alerts per day. Seven "
        "of its 10 incidents hold `dns` windows only.\n"
        "- **`wardbeck` had the 6 h fallback gap (D58).** Only 6 h of its evaluation come before "
        "the first attack, against 24 h on the other testbeds.\n"
        "- **D28 `vpn` ceilings.** `vpn` has out-of-fold scores on the test testbeds, and its "
        "percentile ceiling sits below `q` 0.999, so `vpn` cannot flag anything there:\n\n"
        + table(("Testbed", "Ceiling", "Best eval score"), ceilings)
        + "\n\n- **Window metrics are never pooled** across testbeds; incidents per day and "
        "alert reduction neither.\n"
        "- **D53 limit.** The container refuses every test testbed through a marker file that "
        "user `app` cannot delete. Someone who rebuilds the image or starts it as root gets past "
        "it, so it is a guard against accidents, not a security boundary.\n"
        + tools_line(s)
        + "- **Chat answers are in no metric (D49).** Code checks that a cited line exists, not "
        "that it shows the claim, and there is no Verifier in the chat. Do not read chat text as "
        "checked evidence.\n"
        "- **D67.** Manual faithfulness and its target are NOT MEASURED, because there are no "
        "human annotators. `reports/targets.md` was not edited, and the AI-annotated number is "
        "named as what it is.\n"
        "- **D68.** Human evaluation is NOT PERFORMED, with no AI substitute, because usefulness "
        "and readability are questions about human readers.\n"
        "- **The model is a rolling alias (D44).** Every report and every paid call of M11 shows "
        "`system_fingerprint` `bc19ba97cbe016479903222bb1578db6`. It is not bit-exact at "
        "temperature 0, so only the cache makes reruns exact.\n"
    )


def render(directory: Path) -> str:
    """Return `reports/results.md` from the tables of a directory."""
    s = Saved(directory)
    return (
        "# Results\n\n"
        "Generated by `logtriage evaluate` from saved outputs and the LLM cache; edit "
        "`eval/results_text.py`, not this file. Tables are in `reports/results/`. "
        "russellmitchell is dev: it is shown apart and never pooled. Pooled means santos, "
        "`wardbeck` and `harrison` (§10.7). Weak results are reported as they are.\n\n"
        + targets_section(s)
        + "\n## 2. Per testbed and pooled\n\n"
        + phase_section(s)
        + "\n"
        + alerts_section(s)
        + "\n"
        + verdict_section(s)
        + "\n"
        + attack_section(s)
        + "\n"
        + citation_cost_section(s)
        + "\n## 3. Windows\n\n"
        + windows_section(s)
        + "\n"
        + baselines_section(s)
        + "\n"
        + ablation_section(s)
        + "\n"
        + faithfulness_section(s)
        + "\n"
        + limits_section(s)
    )
