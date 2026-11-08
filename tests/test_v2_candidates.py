"""The v2 candidates of `reports/v2_plan.md` §3 and the selection of §4, on fixtures only.

(a) cross-fitted calibration of thin log types, (b) the finer `q` grid, (d) `n_unseen_units`.
Nothing here reads `data/`, and the v1 defaults must leave v1 unchanged.
"""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from logtriage.config import MLConfig, Settings, load_settings, read_config_values
from logtriage.data.features import OPTIONAL_FEATURES, fit_scaler, is_vocabulary_feature
from logtriage.data.parsers import LogFile, parse_file
from logtriage.data.parsers.common import ParseContext
from logtriage.eval.detection import DetectionResult
from logtriage.eval.tuning import (
    CONFIGURATIONS,
    V2_RESULTS_FILE,
    candidates_of,
    configuration_settings,
    phase_details,
    run_v2_selection,
    select_v2,
    v1_rows_match,
)
from logtriage.ml.detect import score_log_type
from logtriage.ml.ensemble import cross_fit_calibrate, empirical_cdf
from logtriage.ml.models import MODEL_NAMES, fit_fold_models, score_models
from test_detect import ML, make_windows
from test_features import SIM_END, SIM_START, build, read_vocabulary, read_windows, window

REPO = Path(__file__).parents[1]
V1_GRID = [0.95, 0.97, 0.98, 0.99, 0.995, 0.999]
V2_GRID = [0.95, 0.97, 0.98, 0.99, 0.995, 0.996, 0.997, 0.998, 0.999]


# Configuration -------------------------------------------------------------------------------


def test_a_base_config_is_read_first_and_overridden_key_by_key(tmp_path: Path) -> None:
    (tmp_path / "one.yaml").write_text("seed: 1\nml:\n  q: 0.9\n  gap_minutes: 5\n")
    (tmp_path / "two.yaml").write_text("base: one.yaml\nml:\n  q: 0.95\n")
    settings = load_settings(tmp_path / "two.yaml", env_file=None)
    assert (settings.seed, settings.ml.q, settings.ml.gap_minutes) == (1, 0.95, 5)
    assert "base" not in read_config_values(tmp_path / "two.yaml")


def test_a_loop_of_base_configs_is_refused(tmp_path: Path) -> None:
    (tmp_path / "one.yaml").write_text("base: two.yaml\n")
    (tmp_path / "two.yaml").write_text("base: one.yaml\n")
    with pytest.raises(ValueError, match="loops"):
        load_settings(tmp_path / "one.yaml", env_file=None)


def test_the_default_config_is_v1() -> None:
    settings = load_settings(REPO / "configs" / "default.yaml", env_file=None)
    assert settings.ml.thin_calibration == "oof_reference"
    assert settings.ml.optional_features == []
    assert settings.ml.q_grid == V1_GRID
    assert (settings.ml.q, settings.ml.gap_minutes) == (0.999, 30)


def test_v2_differs_from_v1_in_detection_settings_only() -> None:
    v1 = load_settings(REPO / "configs" / "default.yaml", env_file=None).model_dump()
    v2 = load_settings(REPO / "configs" / "v2.yaml", env_file=None).model_dump()
    assert [key for key in v1 if v1[key] != v2[key]] in ([], ["ml"])
    changed = {key for key in v1["ml"] if v1["ml"][key] != v2["ml"][key]}
    assert changed <= {"thin_calibration", "q_grid", "optional_features", "q", "gap_minutes"}


# (d) n_unseen_units --------------------------------------------------------------------------

SERVICE_TAIL = 'comm="systemd" exe="/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
# (minute, record, text of msg='...'): a fit unit, then eval units new and known.
SERVICE_LINES = [
    (2, "SERVICE_START", f"unit=logrotate {SERVICE_TAIL}"),
    (40, "SERVICE_START", f"unit=put {SERVICE_TAIL}"),
    (40, "SERVICE_STOP", f"unit=put {SERVICE_TAIL}"),
    (40, "SERVICE_START", f"unit=cron {SERVICE_TAIL}"),
    (40, "SERVICE_STOP", f"unit=fstrim {SERVICE_TAIL}"),
    (41, "SERVICE_STOP", f"unit=logrotate {SERVICE_TAIL}"),
    (41, "USER_START", 'op=PAM:session_open acct="unit=nope" exe="/usr/sbin/sshd" res=success'),
]
EPOCH = int(SIM_START.timestamp())


def with_service_lines(directory: Path):
    """An `edit` for `build` that adds systemd unit records to the audit fixture."""
    path = directory / "extra_audit.log"
    lines = [
        f"type={record} msg=audit({EPOCH + 60 * minute}.{serial:03d}:{serial}): pid=1 uid=0 "
        f"auid=0 ses=1 msg='{text}'"
        for serial, (minute, record, text) in enumerate(SERVICE_LINES, 11)
    ]
    path.write_text("\n".join(lines) + "\n")
    log_file = LogFile(path, "h", "logs/extra_audit.log", "audit")
    extra, _ = parse_file(log_file, "tiny", ParseContext(sim_start=SIM_START), SIM_END)

    def edit(rows: list[dict]) -> list[dict]:
        if not rows or rows[0]["log_type"] != "audit":
            return rows
        return sorted(rows + extra, key=lambda row: (row["ts"], row["file"], row["line_no"]))

    return edit


@pytest.fixture
def audit_windows(tmp_path: Path) -> pd.DataFrame:
    out = tmp_path / "out"
    build(out, edit=with_service_lines(tmp_path))
    return read_windows(out, "audit")


def test_the_unit_vocabulary_holds_fit_units_only(tmp_path: Path) -> None:
    out = tmp_path / "out"
    build(out, edit=with_service_lines(tmp_path))
    assert read_vocabulary(out, "audit", "units") == {"cron", "logrotate"}


def test_n_unseen_units_counts_distinct_units_outside_the_fit_vocabulary(
    audit_windows: pd.DataFrame,
) -> None:
    # put (start and stop) and fstrim are new; cron is known.
    assert window(audit_windows, 40)["n_unseen_units"] == 2
    # logrotate is known, and `unit=` outside a SERVICE record is no unit.
    assert window(audit_windows, 41)["n_unseen_units"] == 0
    assert (audit_windows.loc[audit_windows["period"] == "fit", "n_unseen_units"] == 0).all()


def test_n_unseen_units_is_gated_like_every_unseen_feature() -> None:
    assert is_vocabulary_feature("n_unseen_units")
    assert "n_unseen_units" in OPTIONAL_FEATURES


def test_dropping_a_column_from_the_scaler_leaves_the_others_unchanged() -> None:
    windows = make_windows(log_type="audit").assign(n_unseen_units=0.0)
    windows.loc[windows["period"] == "eval", "n_unseen_units"] = 3.0
    full = fit_scaler(windows)
    smaller = full.without(["n_unseen_units", "not_a_column"])
    assert "n_unseen_units" not in smaller.columns
    keep = [full.columns.index(name) for name in smaller.columns]
    assert np.array_equal(full.transform(windows)[:, keep], smaller.transform(windows))
    assert full.without([]) is full


def scored(windows: pd.DataFrame, settings: Settings) -> pd.DataFrame:
    table, _ = score_log_type(windows, fit_scaler(windows), settings)
    return table


def test_v1_scores_ignore_the_optional_feature() -> None:
    plain = make_windows(log_type="audit", n_calib=40)
    with_units = plain.assign(n_unseen_units=0.0)
    with_units.loc[with_units.index[-10:], "n_unseen_units"] = 2.0
    v1 = Settings(ml=ML.model_copy(update={"min_calib_windows": 30}))
    pd.testing.assert_frame_equal(scored(plain, v1), scored(with_units, v1))
    v2 = Settings(ml=v1.ml.model_copy(update={"optional_features": ["n_unseen_units"]}))
    assert not scored(with_units, v2)["score_pca"].equals(scored(with_units, v1)["score_pca"])


def test_an_optional_feature_must_be_known() -> None:
    windows = make_windows()
    settings = Settings(ml=ML.model_copy(update={"optional_features": ["n_lines"]}))
    with pytest.raises(ValueError, match="no optional feature"):
        score_log_type(windows, fit_scaler(windows), settings)


# (a) cross-fitted calibration ----------------------------------------------------------------


def test_fold_models_are_fit_without_their_block() -> None:
    matrix = np.random.default_rng(0).normal(size=(50, 3))
    folds = fit_fold_models(matrix, ML, 1)
    blocks = [positions for positions, _ in folds]
    assert np.array_equal(np.concatenate(blocks), np.arange(50))
    assert all(np.all(np.diff(block) == 1) for block in blocks)
    assert [models.pca.n_samples_ for _, models in folds] == [50 - len(b) for b in blocks]


def test_cross_fit_references_hold_each_fold_block_and_the_calib_windows() -> None:
    is_fit = np.array([True, True, True, True, False, False, False])
    is_calib = np.array([False, False, False, False, True, True, False])
    blocks = [np.array([0, 1]), np.array([2, 3])]
    first = np.array([1.0, 2.0, 50.0, 50.0, 3.0, 4.0, 3.5])
    second = np.array([50.0, 50.0, 10.0, 20.0, 30.0, 40.0, 100.0])
    fold_scores = [{name: first for name in MODEL_NAMES}, {name: second for name in MODEL_NAMES}]
    raw, percentiles = cross_fit_calibrate(fold_scores, blocks, is_fit, is_calib)
    # Fold 0's reference is {1, 2, 3, 4}, fold 1's is {10, 20, 30, 40}.
    assert raw["if"].tolist() == [1.0, 2.0, 10.0, 20.0, 16.5, 22.0, 51.75]
    assert percentiles["lof"][:4].tolist() == [0.25, 0.5, 0.25, 0.5]
    assert percentiles["pca"][4:].tolist() == [0.75, 1.0, (0.75 + 1.0) / 2]
    expected = np.mean([empirical_cdf(np.array([1, 2, 3, 4.0]), first[4:]), [0.75, 1.0, 1.0]], 0)
    assert np.allclose(percentiles["if"][4:], expected)


def thin_settings(mode: str) -> Settings:
    return Settings(ml=ML.model_copy(update={"thin_calibration": mode, "min_calib_windows": 50}))


def test_a_thin_type_under_cross_fit_is_scored_by_its_fold_models_alone() -> None:
    windows = make_windows(n_fit=60, n_calib=30, n_eval=40)
    scaler = fit_scaler(windows)
    table, report = score_log_type(windows, scaler, thin_settings("cross_fit"))
    assert report["reference_by_host"] == {"h": "log_type+cross_fit"}
    assert report["thin_calibration"] == "cross_fit"
    assert report["fold_reference_sizes"] == [20 + 30, 20 + 30, 20 + 30]
    matrix = scaler.transform(windows)  # one host, already in time order
    folds = fit_fold_models(matrix[:60], ML, Settings().seed)
    later = np.mean([score_models(models, matrix[60:])["lof"] for _, models in folds], axis=0)
    assert np.allclose(table["score_lof"].to_numpy()[60:], later)
    first = score_models(folds[0][1], matrix[:20])["if"]
    assert np.allclose(table["score_if"].to_numpy()[:20], first)
    assert table[["pct_if", "pct_lof", "pct_pca", "score"]].stack().between(0, 1).all()


def test_cross_fit_leaves_a_type_with_enough_calib_windows_unchanged() -> None:
    windows = make_windows(n_fit=60, n_calib=30, n_eval=40)
    settings = Settings(ml=ML.model_copy(update={"min_calib_windows": 20}))
    cross = Settings(ml=settings.ml.model_copy(update={"thin_calibration": "cross_fit"}))
    first, first_report = score_log_type(windows, fit_scaler(windows), settings)
    second, second_report = score_log_type(windows, fit_scaler(windows), cross)
    pd.testing.assert_frame_equal(first, second)
    assert first_report == second_report


def test_cross_fit_changes_a_thin_type() -> None:
    windows = make_windows(n_fit=60, n_calib=30, n_eval=40)
    d28, d28_report = score_log_type(windows, fit_scaler(windows), thin_settings("oof_reference"))
    cross, _ = score_log_type(windows, fit_scaler(windows), thin_settings("cross_fit"))
    assert d28_report["reference_by_host"] == {"h": "log_type+oof"}
    assert not np.allclose(d28["pct_lof"], cross["pct_lof"])


# (b) and the selection of §4 -----------------------------------------------------------------


def base_and_v2() -> tuple[Settings, Settings]:
    base = Settings(ml=MLConfig(q_grid=V1_GRID, q=0.999, gap_minutes=30))
    v2 = Settings(
        ml=MLConfig(
            q_grid=V2_GRID, thin_calibration="cross_fit", optional_features=["n_unseen_units"]
        )
    )
    return base, v2


def test_the_eight_configurations_of_section_4() -> None:
    assert CONFIGURATIONS == ("v1", "a", "b", "d", "a+b", "a+d", "b+d", "a+b+d")
    assert candidates_of("v1") == []
    assert candidates_of("a+b+d") == ["a", "b", "d"]
    with pytest.raises(ValueError):
        candidates_of("c")


def test_each_configuration_takes_only_its_candidates_from_v2() -> None:
    base, v2 = base_and_v2()
    assert configuration_settings(base, v2, "v1").ml == base.ml
    only_b = configuration_settings(base, v2, "b").ml
    assert (only_b.q_grid, only_b.thin_calibration, only_b.optional_features) == (
        V2_GRID,
        "oof_reference",
        [],
    )
    a_d = configuration_settings(base, v2, "a+d").ml
    assert (a_d.q_grid, a_d.thin_calibration, a_d.optional_features) == (
        V1_GRID,
        "cross_fit",
        ["n_unseen_units"],
    )
    assert (a_d.q, a_d.gap_minutes) == (0.999, 30)


def test_a_candidate_that_changes_nothing_is_refused() -> None:
    base, _ = base_and_v2()
    with pytest.raises(ValueError, match=r"candidate \(b\)"):
        configuration_settings(base, base, "b")


def row(configuration: str, q: float, gap: int, recall: float, incidents: int, per_day=5.0):
    return {
        "configuration": configuration,
        "n_candidates": len(candidates_of(configuration)),
        "q": q,
        "gap_minutes": gap,
        "incidents": incidents,
        "incidents_per_day": per_day,
        "phase_recall": recall,
    }


def test_the_rule_takes_recall_within_the_budget_then_fewer_incidents() -> None:
    grid = pd.DataFrame(
        [
            row("v1", 0.999, 30, 0.6, 7),
            row("b", 0.99, 30, 0.9, 60, per_day=30.0),
            row("a+d", 0.995, 30, 0.8, 12),
            row("d", 0.995, 30, 0.8, 9),
        ]
    )
    assert select_v2(grid, 25)["configuration"] == "d"


def test_ties_go_to_fewer_candidates_then_higher_q_smaller_gap_then_the_listed_order() -> None:
    tied = [row("a+d", 0.999, 30, 0.7, 7), row("a", 0.995, 30, 0.7, 7), row("v1", 0.95, 5, 0.6, 3)]
    assert select_v2(pd.DataFrame(tied), 25)["configuration"] == "a"
    tied += [row("v1", 0.95, 30, 0.7, 7)]
    assert select_v2(pd.DataFrame(tied), 25)["configuration"] == "v1"
    same = [row("d", 0.999, 30, 0.7, 7), row("a", 0.999, 30, 0.7, 7), row("b", 0.998, 5, 0.7, 7)]
    assert select_v2(pd.DataFrame(same), 25)["configuration"] == "a"
    gaps = [row("d", 0.999, 30, 0.7, 7), row("d", 0.999, 10, 0.7, 7)]
    assert select_v2(pd.DataFrame(gaps), 25)["gap_minutes"] == 10


def test_no_row_within_the_budget_is_an_error() -> None:
    with pytest.raises(ValueError):
        select_v2(pd.DataFrame([row("v1", 0.95, 5, 1.0, 99, per_day=50.0)]), 25)


def test_the_v1_rows_must_equal_the_saved_tuning_file_as_written(tmp_path: Path) -> None:
    saved = pd.DataFrame({"q": [0.99, 0.999], "gap_minutes": [30, 30], "missed": ["x, y", ""]})
    path = tmp_path / "tuning_dev.csv"
    saved.to_csv(path, index=False)
    grid = pd.concat(
        [
            saved.assign(configuration="v1", n_candidates=0, credit="c"),
            saved.assign(configuration="a", n_candidates=1, credit="c", q=0.5),
        ]
    )
    assert v1_rows_match(grid, path)
    changed = grid.copy()
    changed.loc[changed["configuration"] == "v1", "gap_minutes"] = 15
    assert not v1_rows_match(changed, path)
    assert not v1_rows_match(grid[grid["configuration"] == "a"], path)


def test_the_selection_runs_once(tmp_path: Path) -> None:
    (tmp_path / V2_RESULTS_FILE).write_text("done\n")
    base, v2 = base_and_v2()
    with pytest.raises(FileExistsError):
        run_v2_selection(base, v2, tmp_path)


def test_phase_details_name_the_crediting_types_and_dns_only_phases() -> None:
    credit = pd.DataFrame(
        {
            "apache_access": [2, 0, 0],
            "dns": [1, 3, 0],
            "detected": [True, True, False],
            "dns_only": [False, True, False],
        },
        index=pd.Index(["dirb", "network_scans", "service_stop"], name="phase"),
    )
    table = pd.DataFrame(
        {"log_type": ["apache_access", "dns", "dns", "audit"], "is_anomalous": [1, 1, 1, 0]}
    ).astype({"is_anomalous": bool})
    result = DetectionResult(table, None, None, credit, {}, 1, 1.0)
    assert phase_details(result) == {
        "dns_only": "network_scans",
        "credit": "dirb: apache_access dns; network_scans: dns",
        "anomalous_by_type": "apache_access 1; dns 2",
    }
