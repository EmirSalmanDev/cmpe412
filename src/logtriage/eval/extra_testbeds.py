"""Preparation report of the extra test testbeds, `reports/targets_extra.md` (plan 10.7, M10b).

Reads labels, so it lives in `logtriage.eval` (plan 5.2). It scores nothing: the D28 exposure comes
from window counts alone, so it can say how far a reference tolerates high scores, not whether
such scores exist.
"""

import json
import math
from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from logtriage.config import DEV_TESTBED, TEST_TESTBED, MLConfig, Settings, load_settings
from logtriage.data.features import REPORT_FILE
from logtriage.data.periods import Periods
from logtriage.eval import baselines, eda
from logtriage.eval.metrics import (
    AMBIGUOUS_HOST,
    attack_techniques,
    load_gold_mapping,
    required_detections,
    unusable_gold_ids,
)

MODELS = 3
RECALL_SHARE = 0.8
REPORT_NAME = "targets_extra.md"
FIT, CALIB = "fit", "calib"
# The frozen denominators of `reports/targets.md`, which stay as they are.
SANTOS_PHASES = {"primary": 9, "all parsed": 9, "without exfil": 8}


def steps_allowed(reference: int, q: float) -> int:
    """Return the rank steps a window may lose in total and still reach `q`.

    One reference score above a window costs `1 / (MODELS * reference)` of ensemble score.
    """
    return math.floor(round((1 - q) * MODELS * reference, 9))


def ceiling_after(reference: int, lost: int) -> float:
    """Return the highest ensemble score once `lost` reference scores sit above the top."""
    return 1 - lost / (MODELS * reference)


def read_windows(testbed: str, settings: Settings) -> tuple[pd.DataFrame, list[str]]:
    """Return host, log type and period of the windows of baseline-capable types, and the others.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.

    Returns:
        The windows, and the log types without a baseline.
    """
    directory = settings.paths.processed_dir / testbed
    report = json.loads((directory / REPORT_FILE).read_text(encoding="utf-8"))
    parts, no_baseline = [], []
    for log_type, entry in report.items():
        if not entry["baseline_capable"]:
            no_baseline.append(log_type)
            continue
        columns = ["host", "log_type", "period"]
        parts.append(pd.read_parquet(directory / f"windows_{log_type}.parquet", columns=columns))
    return pd.concat(parts, ignore_index=True), no_baseline


def _with_steps(table: pd.DataFrame, q: float) -> pd.DataFrame:
    """Add what a reference of each size tolerates at `q`."""
    allowed = [steps_allowed(int(size), q) for size in table["reference"]]
    return table.assign(
        rank_step=[1 / (MODELS * int(size)) for size in table["reference"]],
        steps_allowed=allowed,
        q_means_one=[steps == 0 for steps in allowed],
        ceiling_past_allowed=[
            ceiling_after(int(size), steps + 1)
            for size, steps in zip(table["reference"], allowed, strict=True)
        ],
    )


def log_type_exposure(windows: pd.DataFrame, config: MLConfig, q: float) -> pd.DataFrame:
    """Give the log-type reference of each log type, as `detect` will build it (D28).

    Args:
        windows: Output of `read_windows`.
        config: Holds `min_calib_windows`.
        q: Threshold.

    Returns:
        One row per log type: `fit`, `calib`, `thin` (D28 adds out-of-fold scores), `oof`, the
        size of the `reference`, `oof_share` and the columns of the rank steps.
    """
    counts = windows.groupby(["log_type", "period"]).size().unstack(fill_value=0)
    table = pd.DataFrame(
        {
            FIT: counts[FIT] if FIT in counts else 0,
            CALIB: counts[CALIB] if CALIB in counts else 0,
        }
    )
    table["thin"] = table[CALIB] < config.min_calib_windows
    table["oof"] = table[FIT].where(table["thin"], 0)
    table["reference"] = table[CALIB] + table["oof"]
    table["oof_share"] = table["oof"] / table["reference"]
    return _with_steps(table, q).reset_index()


def stream_exposure(windows: pd.DataFrame, config: MLConfig, q: float) -> pd.DataFrame:
    """Give the reference of each stream `(host, log_type)`, as `calibrate` will pick it.

    Args:
        windows: Output of `read_windows`.
        config: Holds `min_calib_windows`.
        q: Threshold.

    Returns:
        One row per stream: its own `fit` and `calib` windows, `source` (`host`, `log_type` or
        `log_type+oof`), the `reference` size and the columns of the rank steps.
    """
    types = log_type_exposure(windows, config, q).set_index("log_type")
    counts = windows.groupby(["log_type", "host", "period"]).size().unstack(fill_value=0)
    table = pd.DataFrame(
        {
            FIT: counts[FIT] if FIT in counts else 0,
            CALIB: counts[CALIB] if CALIB in counts else 0,
        }
    ).reset_index()
    sources, sizes = [], []
    for row in table.itertuples():
        if row.calib >= config.min_calib_windows:
            sources.append("host")
            sizes.append(row.calib)
        else:
            entry = types.loc[row.log_type]
            sources.append("log_type+oof" if entry["thin"] else "log_type")
            sizes.append(int(entry["reference"]))
    return _with_steps(table.assign(source=sources, reference=sizes), q)


def calib_hours(periods: Periods) -> float:
    """Return the length of the calib slice in hours."""
    return (periods.train_end - periods.fit_end).total_seconds() / 3600


def exposure_verdict(row: pd.Series) -> str:
    """Say what counts alone show about reaching `q` for a stream or a log type."""
    if row["source"] != "log_type+oof":
        return "no OOF in the reference: D28 cannot cap it"
    if row["steps_allowed"] == 0:
        return "open: one OOF score above the top makes it unreachable"
    return f"open: {row['steps_allowed'] + 1} OOF scores above the top make it unreachable"


def parse_summary(directory: Path) -> pd.DataFrame:
    """Sum parse results per log type from `prepare_report.json`, with the lowest rate of a file.

    Args:
        directory: `data/processed/<testbed>/`.

    Returns:
        One row per log type: `files`, `lines`, `parsed`, `blank`, `foreign`, `kept` and
        `lowest_rate`.
    """
    report = json.loads((directory / "prepare_report.json").read_text(encoding="utf-8"))
    files = pd.DataFrame(report["files"])
    return (
        files.groupby("log_type")
        .agg(
            files=("file", "size"),
            lines=("lines", "sum"),
            parsed=("parsed", "sum"),
            blank=("blank", "sum"),
            foreign=("foreign", "sum"),
            kept=("kept", "sum"),
            lowest_rate=("parse_rate", "min"),
        )
        .reset_index()
    )


def low_parse_files(directory: Path, floor: float = 0.99) -> pd.DataFrame:
    """Return the files under the parse rate floor of plan 6.1."""
    report = json.loads((directory / "prepare_report.json").read_text(encoding="utf-8"))
    files = pd.DataFrame(report["files"])
    return files[files["parse_rate"] < floor]


def label_summary(directory: Path) -> pd.DataFrame:
    """Return labeled and resolved lines and the unassigned lines per labeled file."""
    report = json.loads((directory / "label_report.json").read_text(encoding="utf-8"))
    rows = [
        {
            "file": name,
            "labeled": entry["labeled"],
            "resolved": entry["resolved"],
            "unassigned": entry["phases"].get("unassigned", 0),
        }
        for name, entry in report["files"].items()
    ]
    return pd.DataFrame(rows)


def table(frame: pd.DataFrame, columns: Iterable[str] | None = None) -> list[str]:
    """Render a table in Markdown."""
    names = list(columns) if columns is not None else list(frame.columns)
    lines = ["| " + " | ".join(names) + " |", "|" + "---|" * len(names)]
    for row in frame[names].itertuples(index=False):
        lines.append("| " + " | ".join(_cell(value) for value in row) + " |")
    return lines


def _cell(value: object) -> str:
    """Format one table cell."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value)


def testbed_section(testbed: str, settings: Settings) -> tuple[list[str], dict[str, int]]:
    """Render the EDA of one new testbed.

    Args:
        testbed: Testbed name.
        settings: Loaded settings.

    Returns:
        The lines of the section, and the size of each recall denominator.
    """
    directory = settings.paths.processed_dir / testbed
    periods = eda.testbed_periods(testbed, settings)
    with eda.connect(testbed, settings) as con:
        baseline = eda.baseline_table(eda.period_lines(con, periods), settings.ml)
        capable = list(baseline.index[baseline["baseline_capable"]])
        traces = eda.phase_traces(con, periods)
        phases = eda.phase_denominators(con, traces, capable)
        summary = eda.denominator_summary(phases, RECALL_SHARE)
        domains = eda.exfil_domains(con)
        gap = eda.exfil_gap(con, domains)
        contamination = eda.contamination_summary(eda.dns_contamination(con, periods, domains))
        share = eda.attack_share(con, periods).set_index(["scope", "log_type"])
        ambiguous_labels = con.execute(
            "SELECT count(*) FROM labels b JOIN lines l USING (line_id) "
            "WHERE l.log_type = 'dns' AND l.host = ?",
            [AMBIGUOUS_HOST],
        ).fetchone()[0]
    alerts = baselines.load_ids_alerts(settings.paths.raw_dir / "ait_ads", testbed)
    rates = baselines.alert_rates(alerts, periods)
    budget = settings.ml.incidents_per_day_budget
    checks = baselines.budget_table(rates, budget)
    days = baselines.evaluation_days(periods)
    limit = math.floor(budget * days)
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    missing_gold = sorted(set(phases["phase"]) - set(gold))
    parsed, labeled = parse_summary(directory), label_summary(directory)
    low = low_parse_files(directory)
    counted = phases.assign(
        counted=[
            "yes" if row.primary else "no: no labeled lines in a baseline-capable log type"
            for row in phases.itertuples()
        ]
    )
    excluded = list(phases.loc[~phases["primary"], "phase"])
    sizes = {
        "primary": int(phases["primary"].sum()),
        "all parsed": int(phases["all_parsed"].sum()),
        "without exfil": int((phases["primary"] & (phases["phase"] != eda.EXFIL_PHASE)).sum()),
    }
    spans = eda.period_summary(periods)
    unassigned = int(labeled["unassigned"].sum())
    out = [
        f"## {testbed}",
        "",
        "### Periods",
        "",
        f"First attack {periods.first_attack.isoformat()}. Training "
        f"{periods.training_hours:.2f} h, gap {periods.gap_hours:g} h: "
        + (
            "at least 24 h, so §4.3 applies as written."
            if periods.gap_hours == settings.periods.gap_hours
            else "under 24 h, so the fallback gap of §4.3 applies."
        ),
        "",
        *table(spans),
        "",
        "### Parsing and labels",
        "",
        f"Files under 99%: {len(low)}. Labeled lines {int(labeled['labeled'].sum()):,}, resolved "
        f"{int(labeled['resolved'].sum()):,}, unassigned to a phase {unassigned:,}.",
        "",
        *table(parsed),
        "",
        "### Phases",
        "",
        "Labeled lines of the evaluation period, in time order; *labeled* adds training.",
        "",
        *table(
            counted,
            ["phase", "labeled_eval", "labeled", "log_types", "baseline_log_types", "counted"],
        ),
        "",
        *table(summary),
        "",
        f"**Excluded phases:** {', '.join(f'`{name}`' for name in excluded) or 'none'}.",
        "",
        "### Baseline-capable log types (D19)",
        "",
        *table(baseline.reset_index(), ["log_type", "fit", "calib", "eval", "baseline_capable"]),
        "",
        "### Label-ambiguous rule (D17)",
        "",
        f"`dns` lines of `{AMBIGUOUS_HOST}` with a label: {ambiguous_labels:,}. Exfiltration by "
        f"domain match ({', '.join(f'`{name}`' for name in domains)}):",
        "",
        *table(gap),
        "",
        "### DNS exfiltration in training (D16)",
        "",
        *table(contamination),
        "",
        "### Incidents per day and IDS alerts",
        "",
        f"Evaluation period {days:.3f} days, so at most {limit} incidents at {budget} per day. "
        f"Attack share of parsed lines in it: "
        f"{share.loc[('evaluation', 'all'), 'attack_share']:.2%}, without exfiltration "
        f"{share.loc[('evaluation', 'all without exfil'), 'attack_share']:.2%}.",
        "",
        *table(checks.round(4)),
        "",
        "### Gold mapping",
        "",
        f"Phases without a gold entry: {', '.join(missing_gold) or 'none'}.",
        "",
    ]
    return out, sizes


def exposure_section(testbed: str, settings: Settings) -> list[str]:
    """Render the D28 exposure of a testbed from its window counts."""
    windows, no_baseline = read_windows(testbed, settings)
    q = settings.ml.q
    periods = eda.testbed_periods(testbed, settings)
    types = log_type_exposure(windows, settings.ml, q)
    types["source"] = ["log_type+oof" if thin else "log_type" for thin in types["thin"]]
    types["reachable from counts"] = [exposure_verdict(row) for _, row in types.iterrows()]
    streams = stream_exposure(windows, settings.ml, q)
    streams["reachable from counts"] = [exposure_verdict(row) for _, row in streams.iterrows()]
    return [
        f"### {testbed}",
        "",
        f"Calib slice {calib_hours(periods):.2f} h, from {periods.fit_end.isoformat()} to "
        f"{periods.train_end.isoformat()}. No baseline: {', '.join(no_baseline) or 'none'}.",
        "",
        *table(
            types,
            [
                "log_type",
                "fit",
                "calib",
                "thin",
                "oof",
                "reference",
                "oof_share",
                "rank_step",
                "steps_allowed",
                "q_means_one",
                "ceiling_past_allowed",
                "reachable from counts",
            ],
        ),
        "",
        "Streams:",
        "",
        *table(
            streams,
            [
                "log_type",
                "host",
                "fit",
                "calib",
                "source",
                "reference",
                "steps_allowed",
                "q_means_one",
                "reachable from counts",
            ],
        ),
        "",
    ]


def gold_check(settings: Settings) -> str:
    """Check the gold IDs against the pinned ATT&CK bundle."""
    gold = load_gold_mapping(settings.paths.gold_mapping_file)
    techniques, version = attack_techniques(settings.paths.attack_stix_file)
    unusable = unusable_gold_ids(gold, techniques)
    return f"ATT&CK {version}: {len(gold)} phases, unusable gold IDs: {unusable or 'none'}."


def render_report(settings: Settings, intro: list[str], closing: list[str]) -> str:
    """Render `reports/targets_extra.md`.

    Args:
        settings: Loaded settings.
        intro: Fixed text before the testbed sections.
        closing: Fixed text after the D28 section.

    Returns:
        The report text.
    """
    new = [name for name in settings.test_testbeds if name != TEST_TESTBED]
    sections, sizes = [], {TEST_TESTBED: SANTOS_PHASES}
    for testbed in new:
        lines, sizes[testbed] = testbed_section(testbed, settings)
        sections += lines
    pooled = pd.DataFrame(
        [
            {
                "variant": variant,
                **{name: sizes[name][variant] for name in settings.test_testbeds},
                "pooled": sum(sizes[name][variant] for name in settings.test_testbeds),
                "80% of pooled": required_detections(
                    sum(sizes[name][variant] for name in settings.test_testbeds), RECALL_SHARE
                ),
            }
            for variant in SANTOS_PHASES
        ]
    )
    exposure: list[str] = []
    for testbed in [*new, TEST_TESTBED, DEV_TESTBED]:
        exposure += exposure_section(testbed, settings)
    return "\n".join(
        [
            *intro,
            *sections,
            "## Pooled denominators (§10.7)",
            "",
            *table(pooled),
            "",
            gold_check(settings),
            "",
            "## D28 exposure, from window counts only",
            "",
            *exposure,
            *closing,
            "",
        ]
    )


def main() -> None:
    """Write the report; the fixed text comes from `reports/targets_extra_text.json`, if any."""
    settings = load_settings()
    path = settings.paths.reports_dir / REPORT_NAME
    path.write_text(render_report(settings, [], []), encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
