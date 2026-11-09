"""`reports/results_v2.md` (M12, D91): checked statements, no scoring code, regenerated exactly."""

import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import load_settings
from logtriage.eval.results_v2 import RESULTS_FILE, Facts, StatementError, build, plain_statements

ROOT = Path(__file__).parents[1]


def facts(**changes: object) -> Facts:
    """The facts of session 3B, which the statements must accept."""
    base = Facts(
        phases=17,
        detected={"v1": 8, "v2": 9},
        gained={"shaw": [], "fox": ["cracking"]},
        lost={"shaw": [], "fox": []},
        gain_types={"cracking": ["apache_access"]},
        gain_scores=[("fox cracking", 0.998366, 0.998366)],
        q={"v1": 0.999, "v2": 0.996},
        d_phase_credited=[],
        incidents={("shaw", "v1"): 10, ("shaw", "v2"): 14, ("fox", "v1"): 11, ("fox", "v2"): 24},
        required={"shaw": 7, "fox": 8},
        denominators={"shaw": 8, "fox": 9},
        per_testbed={("shaw", "v1"): 3, ("shaw", "v2"): 3, ("fox", "v1"): 5, ("fox", "v2"): 6},
    )
    return replace(base, **changes)


def test_the_statements_of_the_brief_are_written_when_they_hold() -> None:
    text = "\n".join(plain_statements(facts()))
    assert "**The gain is one phase of 17:** fox `cracking`" in text
    assert "the lower `q` of candidate (b)" in text
    assert "**Candidate (d) transferred nothing to shaw or fox:**" in text
    assert "**v2 more than doubled incidents on fox:** 11 to 24" in text
    assert "**Neither mode reaches the 80% target on either testbed:**" in text
    assert "not a statistical result" in text
    assert "**v1's official results are unchanged:**" in text


@pytest.mark.parametrize(
    "changes",
    [
        {"detected": {"v1": 8, "v2": 10}, "gained": {"shaw": ["dirb"], "fox": ["cracking"]}},
        {"lost": {"shaw": ["dirb"], "fox": []}},
        {"gain_scores": [("fox cracking", 0.99, 0.998366)]},  # the score moved: not q alone
        {"gain_scores": [("fox cracking", 0.9995, 0.9995)]},  # passes v1's q as well
        {"gain_types": {"cracking": ["audit"]}},
        {"d_phase_credited": [("fox", "v2")]},
        {"incidents": {**facts().incidents, ("fox", "v1"): 12}},  # 24 is not more than double
        {"per_testbed": {**facts().per_testbed, ("shaw", "v2"): 7}},  # 7 of 8 reaches 80%
    ],
)
def test_a_statement_that_does_not_hold_stops_the_document(changes: dict) -> None:
    with pytest.raises(StatementError):
        plain_statements(facts(**changes))


def test_importing_the_v2_results_loads_no_scoring_module() -> None:
    code = (
        "import sys, logtriage.eval.results_v2; "
        "print([m for m in sys.modules if m.startswith('logtriage.ml')])"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    )
    assert result.stdout.strip() == "[]"


@pytest.mark.data
def test_the_committed_v2_results_come_from_the_saved_outputs() -> None:
    settings = load_settings(ROOT / "configs" / "default.yaml", env_file=None)
    v2 = load_settings(ROOT / "configs" / "v2.yaml", env_file=None)
    text, tables = build(settings, v2)
    assert text == (ROOT / "reports" / RESULTS_FILE).read_text(encoding="utf-8")
    for name, table in tables.items():
        saved = pd.read_csv(ROOT / "reports" / "results" / f"{name}.csv")
        written = ROOT / "reports" / "results" / f"{name}.csv"
        assert len(saved) == len(table), name
        assert written.read_text(encoding="utf-8") == table.to_csv(
            index=False, float_format="%.6f"
        ), name
