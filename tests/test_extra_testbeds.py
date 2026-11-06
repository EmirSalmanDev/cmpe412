"""The D28 exposure from window counts, against the numbers of the incident count audit."""

from pathlib import Path

import pandas as pd
import pytest

from logtriage.config import MLConfig, load_settings
from logtriage.eval.extra_testbeds import (
    ceiling_after,
    exposure_verdict,
    log_type_exposure,
    read_windows,
    steps_allowed,
    stream_exposure,
)

ROOT = Path(__file__).parents[1]
CONFIG = MLConfig(min_calib_windows=200)
Q = 0.999


def windows(*streams: tuple[str, str, int, int]) -> pd.DataFrame:
    """Build windows from `(log_type, host, fit, calib)`."""
    rows = []
    for log_type, host, fit, calib in streams:
        rows += [(host, log_type, "fit")] * fit + [(host, log_type, "calib")] * calib
        rows.append((host, log_type, "eval"))
    return pd.DataFrame(rows, columns=["host", "log_type", "period"])


@pytest.mark.parametrize(
    ("reference", "allowed"),
    [(84, 0), (272, 0), (333, 0), (334, 1), (375, 1), (613, 1), (868, 2), (1157, 3), (1264, 3)]
    + [(1915, 5)],
)
def test_steps_allowed_match_the_audit(reference: int, allowed: int) -> None:
    assert steps_allowed(reference, Q) == allowed


def test_the_ceiling_formula_gives_the_santos_ceilings_of_the_audit() -> None:
    assert ceiling_after(868, 3) == pytest.approx(0.998848, abs=1e-6)  # `auth`
    assert ceiling_after(84, 2) == pytest.approx(0.992063, abs=1e-6)  # `vpn`
    assert ceiling_after(84, 0) == 1.0


def test_a_thin_log_type_adds_all_its_fit_windows() -> None:
    table = log_type_exposure(windows(("vpn", "v", 77, 7)), CONFIG, Q).iloc[0]
    assert bool(table["thin"]) is True
    assert table["oof"] == 77 and table["reference"] == 84
    assert table["oof_share"] == pytest.approx(77 / 84)
    assert bool(table["q_means_one"]) is True


def test_a_log_type_at_the_limit_is_not_thin() -> None:
    table = log_type_exposure(windows(("audit", "a", 100, 200)), CONFIG, Q).iloc[0]
    assert bool(table["thin"]) is False
    assert table["oof"] == 0 and table["reference"] == 200


def test_a_full_stream_is_its_own_reference_and_a_small_one_uses_the_log_type() -> None:
    data = windows(("dns", "a", 10, 300), ("dns", "b", 10, 100))
    table = stream_exposure(data, CONFIG, Q).set_index("host")
    assert table.loc["a", "source"] == "host" and table.loc["a", "reference"] == 300
    assert table.loc["b", "source"] == "log_type" and table.loc["b", "reference"] == 400


def test_a_thin_log_type_puts_oof_in_the_reference_of_every_stream() -> None:
    data = windows(("auth", "a", 300, 90), ("auth", "b", 392, 86))
    table = stream_exposure(data, CONFIG, Q).set_index("host")
    assert set(table["source"]) == {"log_type+oof"}
    assert set(table["reference"]) == {868}


def test_the_verdict_never_claims_more_than_counts_show() -> None:
    assert exposure_verdict(pd.Series({"source": "host", "steps_allowed": 1})).endswith(
        "cannot cap it"
    )
    assert "one OOF score" in exposure_verdict(
        pd.Series({"source": "log_type+oof", "steps_allowed": 0})
    )
    assert "3 OOF scores" in exposure_verdict(
        pd.Series({"source": "log_type+oof", "steps_allowed": 2})
    )


@pytest.mark.data
def test_the_real_counts_reproduce_the_references_of_the_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT)
    settings = load_settings("configs/default.yaml", env_file=None)
    santos, _ = read_windows("santos", settings)
    table = log_type_exposure(santos, settings.ml, Q).set_index("log_type")
    assert table["reference"].to_dict() == {
        "apache_access": 1915, "audit": 1157, "auth": 868, "dns": 750, "vpn": 84,
    }  # fmt: skip
    streams = stream_exposure(santos, settings.ml, Q)
    assert set(streams.loc[streams["log_type"] == "dns", "reference"]) == {375}
    dev, _ = read_windows("russellmitchell", settings)
    table = stream_exposure(dev, settings.ml, Q)
    assert set(table.loc[table["log_type"] == "vpn", "reference"]) == {143}
    assert set(table.loc[table["log_type"] == "audit", "reference"]) == {209}
    assert set(table.loc[table["log_type"] == "auth", "reference"]) == {272}
