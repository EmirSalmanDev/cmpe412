"""Read-only audit of the windows before the supervised reference is trained (plan 6.7, M6).

It fits nothing and scores nothing. Run it from the repository root with
`uv run python -m logtriage.eval.supervised_audit`.
"""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from logtriage.config import DEV_TESTBED, TEST_TESTBED, Settings, load_settings
from logtriage.data.features import REPORT_FILE
from logtriage.eval import eda
from logtriage.eval.metrics import attach_truth, is_exfil_only, window_truth

AUDIT_FILE = "audit_m6.md"
PERIODS = ["fit", "calib", "eval"]
DRIFT_FEATURES = re.compile(r"(?:n|ratio)_unseen_|_template_rarity$")


def labeled_windows(testbed: str, settings: Settings) -> dict[str, pd.DataFrame]:
    """Return the windows of each baseline-capable log type of a testbed, with ground truth."""
    directory = settings.paths.processed_dir / testbed
    with eda.connect(testbed, settings) as con:
        truth = window_truth(con, settings.features.window_seconds)
    tables = {}
    for log_type, entry in feature_report(testbed, settings).items():
        if entry["baseline_capable"]:
            windows = pd.read_parquet(directory / f"windows_{log_type}.parquet")
            tables[log_type] = attach_truth(windows, truth)
    return tables


def feature_report(testbed: str, settings: Settings) -> dict:
    """Read `features_report.json` of a testbed."""
    path = settings.paths.processed_dir / testbed / REPORT_FILE
    return json.loads(path.read_text(encoding="utf-8"))


def window_counts(tables: dict[str, pd.DataFrame], testbed: str) -> pd.DataFrame:
    """Count windows, attack, label-ambiguous and exfiltration-only windows per period."""
    rows = []
    for log_type, table in tables.items():
        for period in PERIODS:
            part = table[table["period"] == period]
            rows.append(
                {
                    "testbed": testbed,
                    "log_type": log_type,
                    "period": period,
                    "windows": len(part),
                    "attack": int(part["is_attack"].sum()),
                    "ambiguous": int(part["is_ambiguous"].sum()),
                    "exfil_only": int(is_exfil_only(part["phases"]).sum()),
                }
            )
    return pd.DataFrame(rows)


def phase_counts(tables: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Count eval attack windows per phase (rows) and log type (columns)."""
    parts = [
        table.loc[table["is_attack"] & (table["period"] == "eval"), ["log_type", "phases"]]
        for table in tables.values()
    ]
    exploded = pd.concat(parts).explode("phases")
    return exploded.pivot_table(
        index="phases", columns="log_type", aggfunc="size", fill_value=0
    ).rename_axis(index="phase", columns=None)


def feature_counts(dev: dict, test: dict, log_types: list[str]) -> pd.DataFrame:
    """Compare the kept feature columns of the two testbeds."""
    rows = []
    for log_type in log_types:
        first, second = set(dev[log_type]["features"]), set(test[log_type]["features"])
        rows.append(
            {
                "log_type": log_type,
                DEV_TESTBED: len(first),
                TEST_TESTBED: len(second),
                "intersection": len(first & second),
                "dropped": ", ".join(sorted(first ^ second)),
            }
        )
    return pd.DataFrame(rows)


def drift_means(tables: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Return the mean of each unseen and rarity feature per period. Reads no ground truth."""
    parts = []
    for log_type, table in tables.items():
        columns = [name for name in table.columns if DRIFT_FEATURES.search(name)]
        part = table.groupby("period")[columns].mean().reindex(PERIODS).T
        part.insert(0, "log_type", log_type)
        parts.append(part.rename_axis(index="feature", columns=None).reset_index())
    return pd.concat(parts, ignore_index=True)


def block_layout(tables: dict[str, pd.DataFrame], blocks: int) -> pd.DataFrame:
    """Show where each class falls in equal-count time blocks of the dev calib and eval windows.

    Args:
        tables: Dev windows with ground truth.
        blocks: Number of blocks.

    Returns:
        One row per log type: positives and negatives per block, as `a/b/c/d/e`.
    """
    rows = []
    for log_type, table in tables.items():
        kept = table[table["period"].isin(["calib", "eval"]) & ~table["is_ambiguous"]]
        ordered = kept.sort_values("window_start")["is_attack"].to_numpy()
        parts = np.array_split(ordered, blocks)
        rows.append(
            {
                "log_type": log_type,
                "windows": len(ordered),
                "positives": int(ordered.sum()),
                "negatives": int((~ordered).sum()),
                "positives_per_block": "/".join(str(int(part.sum())) for part in parts),
                "negatives_per_block": "/".join(str(int((~part).sum())) for part in parts),
            }
        )
    return pd.DataFrame(rows)


def markdown(table: pd.DataFrame) -> str:
    """Render a table as GitHub Markdown."""
    text = table.astype(object).where(table.notna(), "").astype(str)
    lines = [" | ".join(text.columns), " | ".join("---" for _ in text.columns)]
    lines += [" | ".join(row) for row in text.to_numpy()]
    return "\n".join(f"| {line} |" for line in lines)


def audit(settings: Settings) -> dict[str, pd.DataFrame]:
    """Compute every audit table.

    Args:
        settings: Loaded settings.

    Returns:
        Section title to table.
    """
    dev = labeled_windows(DEV_TESTBED, settings)
    test = labeled_windows(TEST_TESTBED, settings)
    log_types = [name for name in dev if name in test]
    reports = feature_report(DEV_TESTBED, settings), feature_report(TEST_TESTBED, settings)
    counts = pd.concat([window_counts(dev, DEV_TESTBED), window_counts(test, TEST_TESTBED)])
    return {
        "Windows per period": counts,
        f"Attack windows per phase, {DEV_TESTBED} eval": phase_counts(dev).reset_index(),
        "Kept feature columns": feature_counts(*reports, log_types),
        f"Unseen and rarity means, {DEV_TESTBED}, no labels": drift_means(dev).round(4),
        f"Classes in 5 equal-count time blocks, {DEV_TESTBED} calib and eval": block_layout(dev, 5),
    }


def write_audit(tables: dict[str, pd.DataFrame], path: Path) -> None:
    """Write the audit tables to a Markdown file."""
    sections = ["# M6 audit\n\nRead-only: no model was fit and santos was not scored.\n"]
    sections += [f"## {title}\n\n{markdown(table)}\n" for title, table in tables.items()]
    path.write_text("\n".join(sections), encoding="utf-8")


if __name__ == "__main__":
    loaded = load_settings()
    write_audit(audit(loaded), loaded.paths.reports_dir / AUDIT_FILE)
