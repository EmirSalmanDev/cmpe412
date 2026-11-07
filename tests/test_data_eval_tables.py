"""The M11 tables on the real saved outputs agree with what earlier milestones recorded."""

import pandas as pd
import pytest

from logtriage.config import DEV_TESTBED, load_settings
from logtriage.eval import tables

pytestmark = pytest.mark.data

# Raw alerts in `reports/targets.md` and `targets_extra.md`, incidents and anomalous windows and
# phases detected in `status.md`, all written before these tables existed.
RECORDED = {
    "santos": (82_998, 3, 5, 5, 9),
    "wardbeck": (60_975, 14, 19, 5, 9),
    "harrison": (478_319, 10, 75, 3, 9),
    DEV_TESTBED: (29_435, 7, 24, 6, 10),
}


@pytest.fixture(scope="module")
def built() -> dict[str, pd.DataFrame]:
    settings = load_settings(env_file=None)
    items = [tables.load_inputs(name, settings) for name in RECORDED]
    return tables.build_tables(items, settings)


@pytest.mark.parametrize("testbed", RECORDED)
def test_counts_match_the_record(built: dict[str, pd.DataFrame], testbed: str) -> None:
    alerts, incidents, windows, detected, phases = RECORDED[testbed]
    reduction = built["eval_alert_reduction"].set_index("testbed").loc[testbed]
    assert reduction["raw_alerts"] == alerts
    assert reduction["incidents"] == incidents
    assert reduction["anomalous_windows"] == windows
    recall = built["eval_phase_recall"]
    row = recall[(recall["testbed"] == testbed) & (recall["variant"] == "primary")].iloc[0]
    assert (row["detected"], row["phases"]) == (detected, phases)


def test_pooled_denominators_match_the_freeze(built: dict[str, pd.DataFrame]) -> None:
    """`targets_extra.md`: 27, 27 and 24."""
    recall = built["eval_phase_recall"]
    pooled = recall[recall["testbed"] == "pooled"].set_index("variant")["phases"].to_dict()
    assert pooled == {"primary": 27, "all_parsed": 27, "without_exfil": 24}


def test_every_alert_has_a_host_and_dev_is_never_pooled(built: dict[str, pd.DataFrame]) -> None:
    assert (built["eval_alert_reduction"]["grouped_alerts"] > 0).all()
    pooled = built["eval_verdict"].query("testbed == 'pooled' and method == 'agents'")
    assert pooled["incidents"].tolist() == [25, 27]
