"""Window feature extraction (plan 5.4, 6.3).

Windows hold raw feature values, which stay readable for analysts and agent tools. Models read
them through the `FeatureScaler` of the log type.
"""

import json
import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler

from logtriage.config import FeaturesConfig, MLConfig, Settings
from logtriage.data.periods import Periods, is_baseline_capable
from logtriage.data.store import connect
from logtriage.data.windows import PARSED_VIEW, create_parsed_view, period_sql

logger = logging.getLogger(__name__)

TEMPLATE_VOCABULARY_FEATURES = frozenset(
    {
        "n_unseen_templates",
        "ratio_unseen_templates",
        "mean_template_rarity",
        "max_template_rarity",
    }
)


# Built into the windows like any feature, but used by the models only when listed in
# `ml.optional_features`, so v1 scores ignore them (reports/v2_plan.md §3 (d), D76).
OPTIONAL_FEATURES = frozenset({"n_unseen_units"})


DERIVED_TABLE = "derived_lines"
VOCABULARY_TABLE = "vocabulary"
FEATURE_TABLE = "window_features"
KEY = ("testbed", "host", "log_type", "window_start")
NOT_FEATURES = frozenset({*KEY, "src_ips", "users", "period"})
ALWAYS_KEPT = frozenset({"n_lines"})
SCALER_DIR = "scalers"
VOCABULARY_DIR = "vocabularies"
REPORT_FILE = "features_report.json"


@dataclass(frozen=True)
class FeatureSet:
    """SQL definition of the features of a log type.

    `derived` adds per-line columns; later entries may use earlier ones. `vocabularies` maps a
    vocabulary name to the column it is built from, and each one adds a boolean column
    `unseen_<name>` for the aggregates to use. `aggregates` maps a feature to its SQL.
    """

    aggregates: dict[str, str]
    derived: dict[str, str] = field(default_factory=dict)
    vocabularies: dict[str, str] = field(default_factory=dict)


def _field(name: str) -> str:
    """SQL for a key of the `fields` JSON."""
    return f"json_extract_string(fields, '$.{name}')"


def _ratio(numerator: str, denominator: str) -> str:
    """SQL for a ratio that is 0 when the denominator is 0."""
    return f"COALESCE({numerator} / NULLIF({denominator}, 0), 0)"


# Only `query` lines count: dnsmasq repeats the name in its forwarded, reply and cached lines.
DNS = FeatureSet(
    derived={
        "qname": f"CASE WHEN {_field('action')} = 'query' THEN {_field('qname')} END",
        "qname_key": "lower(rtrim(qname, '.'))",
        "domain": "registered_domain(qname)",
        "parts": "name_parts(qname)",
        "part_lengths": "list_transform(parts, lambda part: length(part))",
        "part_entropies": "list_transform(parts, lambda part: shannon_entropy(part))",
    },
    vocabularies={"domains": "domain"},
    aggregates={
        "n_queries": "count(qname)",
        "mean_qname_len": "COALESCE(avg(length(qname)), 0)",
        "max_label_len": "COALESCE(max(list_max(part_lengths)), 0)",
        "mean_label_entropy": _ratio("sum(list_sum(part_entropies))", "sum(len(part_entropies))"),
        "max_label_entropy": "COALESCE(max(list_max(part_entropies)), 0)",
        "ratio_unique_qnames": _ratio("count(DISTINCT qname_key)", "count(qname)"),
        "top_domain_share": _ratio("list_max(map_values(histogram(domain)))", "count(domain)"),
        "n_unique_clients": "count(DISTINCT src_ip)",
        "n_unseen_domains": "count(DISTINCT domain) FILTER (unseen_domains)",
    },
)
APACHE_ACCESS = FeatureSet(
    derived={
        "status": f"TRY_CAST({_field('status')} AS INTEGER)",
        "method": _field("method"),
        "target": _field("path"),
        "path": "split_part(target, '?', 1)",
        "user_agent": _field("user_agent"),
    },
    vocabularies={"paths": "path", "ua": "user_agent", "src_ip": "src_ip"},
    aggregates={
        "n_req": "count(*)",
        "ratio_4xx": "count(*) FILTER (status BETWEEN 400 AND 499) / count(*)",
        "ratio_404": "count(*) FILTER (status = 404) / count(*)",
        "ratio_5xx": "count(*) FILTER (status BETWEEN 500 AND 599) / count(*)",
        "ratio_post": "count(*) FILTER (method = 'POST') / count(*)",
        "n_unique_paths": "count(DISTINCT path)",
        "ratio_unseen_paths": "count(*) FILTER (unseen_paths) / count(*)",
        "mean_path_len": "COALESCE(avg(length(target)), 0)",
        "max_path_len": "COALESCE(max(length(target)), 0)",
        "n_unique_ua": "count(DISTINCT user_agent)",
        "ratio_unseen_ua": "count(*) FILTER (unseen_ua) / count(*)",
        "n_unique_src_ip": "count(DISTINCT src_ip)",
        "n_unseen_src_ip": "count(DISTINCT src_ip) FILTER (unseen_src_ip)",
    },
)
APACHE_ERROR = FeatureSet(
    derived={"level": _field("level")},
    aggregates={
        "n_errors": "count(*) FILTER (level IN ('error', 'crit', 'alert', 'emerg'))",
        "n_unique_clients": "count(DISTINCT src_ip)",
    },
)
AUTH = FeatureSet(
    derived={"process": _field("process")},
    vocabularies={"users": '"user"'},
    aggregates={
        "n_failed_login": "count(*) FILTER (regexp_matches(message, "
        "'authentication failure|Failed password|Invalid user|FAILED LOGIN'))",
        "n_success_login": "count(*) FILTER (starts_with(message, 'Accepted '))",
        "n_session_open": "count(*) FILTER (contains(message, 'session opened'))",
        "n_sudo": "count(*) FILTER (process = 'sudo')",
        "n_su": "count(*) FILTER (process = 'su')",
        "n_unique_users": 'count(DISTINCT "user")',
        "n_unseen_users": 'count(DISTINCT "user") FILTER (unseen_users)',
        "n_events_by_web_user": r"count(*) FILTER (regexp_matches(message, "
        r"'www-data|\be?uid=33\b'))",
    },
)
# An execve shows as a SYSCALL record, which carries the uid and exe that EXECVE records lack.
# systemd names the unit of a SERVICE_START or SERVICE_STOP record only inside its `msg='...'`
# text, as `unit=<name>`, and the template masks it, so `unit` is read from the message.
AUDIT = FeatureSet(
    derived={
        "record": _field("type"),
        "exe": _field("exe"),
        "uid": _field("uid"),
        "is_execve": "record = 'SYSCALL' AND regexp_matches(message, '\\bsyscall=59\\b')",
        "unit": "CASE WHEN record IN ('SERVICE_START', 'SERVICE_STOP') "
        "THEN NULLIF(regexp_extract(message, '\\bunit=([^ '']+)', 1), '') END",
    },
    vocabularies={"exe": "exe", "units": "unit"},
    aggregates={
        "n_execve": "count(*) FILTER (is_execve)",
        "n_execve_web_user": "count(*) FILTER (is_execve AND uid = '33')",
        "n_unique_exe": "count(DISTINCT exe)",
        "n_unseen_exe": "count(DISTINCT exe) FILTER (unseen_exe)",
        "n_user_auth_events": "count(*) FILTER "
        "(record IN ('USER_AUTH', 'USER_START', 'CRED_ACQ', 'USER_CMD'))",
        "n_root_execve": "count(*) FILTER (is_execve AND uid = '0')",
        "n_unseen_units": "count(DISTINCT unit) FILTER (unseen_units)",
    },
)
# OpenVPN writes UNDEF before a peer has authenticated: a placeholder, not a user.
VPN = FeatureSet(
    derived={"vpn_user": """NULLIF("user", 'UNDEF')"""},
    vocabularies={"src_ip": "src_ip", "users": "vpn_user"},
    aggregates={
        "n_auth_success": "count(*) FILTER (contains(message, 'Peer Connection Initiated'))",
        "n_auth_fail": "count(*) FILTER (regexp_matches(message, "
        "'AUTH_FAILED|VERIFY ERROR|TLS Auth Error|TLS handshake failed'))",
        "n_new_sessions": "count(*) FILTER (contains(message, 'MULTI_sva: pool returned'))",
        "n_unique_src_ip": "count(DISTINCT src_ip)",
        "n_unseen_src_ip": "count(DISTINCT src_ip) FILTER (unseen_src_ip)",
        "n_unseen_users": "count(DISTINCT vpn_user) FILTER (unseen_users)",
    },
)
FEATURE_SETS: dict[str, FeatureSet] = {
    "apache_access": APACHE_ACCESS,
    "apache_error": APACHE_ERROR,
    "auth": AUTH,
    "dns": DNS,
    "audit": AUDIT,
    "vpn": VPN,
}
COMMON_AGGREGATES = {
    "n_lines": "count(*)",
    "n_unseen_templates": "count(*) FILTER (is_unseen_template)",
    "ratio_unseen_templates": "count(*) FILTER (is_unseen_template) / count(*)",
    "mean_template_rarity": "avg(template_rarity)",
    "max_template_rarity": "max(template_rarity)",
    "n_unique_templates": "count(DISTINCT template_id)",
}


def stamp(value: datetime) -> str:
    """Render a timestamp as a SQL literal."""
    return f"TIMESTAMPTZ '{value.isoformat()}'"


def count_parsed_lines(con: duckdb.DuckDBPyConnection, start: datetime, end: datetime) -> int:
    """Count the lines of the parsed view with `start <= ts < end`."""
    query = f"SELECT count(*) FROM {PARSED_VIEW} WHERE ts >= {stamp(start)} AND ts < {stamp(end)}"
    return con.execute(query).fetchone()[0]


def is_vocabulary_feature(name: str) -> bool:
    """Return True if a feature depends on a fit-period vocabulary or template counts."""
    return name in TEMPLATE_VOCABULARY_FEATURES or "_unseen_" in name


def has_vocabulary(fit_lines: int, config: MLConfig) -> bool:
    """Return True if a log type has enough parsed fit lines for vocabularies (D15)."""
    return fit_lines >= config.min_fit_lines


def usable_features(names: Iterable[str], fit_lines: int, config: MLConfig) -> list[str]:
    """Drop vocabulary, rarity and "unseen" features of a log type with too few fit lines.

    A vocabulary from almost no lines marks nearly everything unseen, and an empty frozen
    miner gives an infinite rarity (D15).

    Args:
        names: Feature names of the log type.
        fit_lines: Parsed lines of the log type in the fit period.
        config: Holds `min_fit_lines`.

    Returns:
        The names that stay, in the given order.
    """
    if has_vocabulary(fit_lines, config):
        return list(names)
    return [name for name in names if not is_vocabulary_feature(name)]


def create_macros(con: duckdb.DuckDBPyConnection, second_level_suffixes: list[str]) -> None:
    """Create the SQL macros of the DNS features.

    A DNS name splits into parts at its dots. `suffix_size` is the number of parts that form
    the public suffix: one, or two under a two-letter TLD such as `co.uk`. The registered
    domain adds one part to the suffix, and a name without a dot is its own domain.
    `name_parts` drops the suffix, which is the same for most names and says nothing about
    the name. Case stays, because mixed case is part of the entropy of an encoded name.

    Args:
        con: Connection to create the macros on.
        second_level_suffixes: Second-level names that are suffixes under a two-letter TLD.
    """
    suffixes = ", ".join(f"'{name}'" for name in second_level_suffixes)
    con.execute(
        f"""
        CREATE OR REPLACE TEMP MACRO shannon_entropy(text) AS
            COALESCE(list_aggregate(string_split(text, ''), 'entropy'), 0);
        CREATE OR REPLACE TEMP MACRO qname_parts(qname) AS
            list_filter(string_split(rtrim(qname, '.'), '.'), lambda part: part <> '');
        CREATE OR REPLACE TEMP MACRO suffix_size(parts) AS
            CASE WHEN len(parts) >= 3 AND length(parts[-1]) = 2
                      AND lower(parts[-2]) IN ({suffixes})
                 THEN 2 ELSE 1 END;
        CREATE OR REPLACE TEMP MACRO registered_domain(qname) AS
            lower(array_to_string(
                list_slice(
                    qname_parts(qname),
                    greatest(len(qname_parts(qname)) - suffix_size(qname_parts(qname)), 1),
                    len(qname_parts(qname))
                ),
                '.'
            ));
        CREATE OR REPLACE TEMP MACRO name_parts(qname) AS
            CASE WHEN len(qname_parts(qname)) <= suffix_size(qname_parts(qname))
                 THEN list_slice(qname_parts(qname), 1, 1)
                 ELSE list_slice(
                     qname_parts(qname),
                     1,
                     len(qname_parts(qname)) - suffix_size(qname_parts(qname))
                 )
            END;
        """
    )


def create_derived_table(con: duckdb.DuckDBPyConnection, features: FeatureSet) -> None:
    """Materialize the parsed lines with the derived columns of a log type."""
    columns = "".join(f", {sql} AS {name}" for name, sql in features.derived.items())
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE {DERIVED_TABLE} AS SELECT *{columns} FROM {PARSED_VIEW}"
    )


def build_vocabularies(
    con: duckdb.DuckDBPyConnection, features: FeatureSet, fit_end: datetime
) -> None:
    """Build the vocabularies from fit-period lines, and flag every line against them.

    Args:
        con: Connection holding the derived table.
        features: Feature set of the log type.
        fit_end: End of the fit period. Only lines before it enter a vocabulary.
    """
    selects = [
        f"SELECT '{name}' AS vocabulary, {column}::VARCHAR AS value, count(*) AS n_fit_lines "
        f"FROM {DERIVED_TABLE} WHERE ts < {stamp(fit_end)} AND {column} IS NOT NULL GROUP BY 2"
        for name, column in features.vocabularies.items()
    ]
    empty = (
        "SELECT ''::VARCHAR AS vocabulary, ''::VARCHAR AS value, 0::BIGINT AS n_fit_lines "
        "WHERE false"
    )
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE {VOCABULARY_TABLE} AS "
        + " UNION ALL ".join([empty, *selects])
    )
    for name, column in features.vocabularies.items():
        con.execute(
            f"""
            ALTER TABLE {DERIVED_TABLE} ADD COLUMN unseen_{name} BOOLEAN;
            UPDATE {DERIVED_TABLE} SET unseen_{name} = {column} IS NOT NULL AND {column}::VARCHAR
                NOT IN (SELECT value FROM {VOCABULARY_TABLE} WHERE vocabulary = '{name}');
            """
        )


def aggregate_windows(con: duckdb.DuckDBPyConnection, aggregates: dict[str, str]) -> None:
    """Compute the given features per window key, into the feature table."""
    key = ", ".join(KEY)
    columns = ", ".join(f"{sql} AS {name}" for name, sql in aggregates.items())
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE {FEATURE_TABLE} AS "
        f"SELECT {key}, {columns} FROM {DERIVED_TABLE} GROUP BY {key}"
    )


def _top_values_sql(column: str, top: int) -> str:
    """SQL for the most frequent values of a column per window, ties in value order."""
    key = ", ".join(KEY)
    return f"""
        SELECT {key}, list(value ORDER BY n DESC, value)[1:{int(top)}] AS top_values
        FROM (
            SELECT {key}, {column} AS value, count(*) AS n
            FROM {DERIVED_TABLE} WHERE {column} IS NOT NULL GROUP BY ALL
        )
        GROUP BY {key}
    """


def constant_features(con: duckdb.DuckDBPyConnection, names: Iterable[str]) -> list[str]:
    """Return the features with a single value over all windows of the log type (plan 6.3).

    All periods count: an "unseen" feature is 0 on every fit window by construction, and its
    signal only appears later, so a check on the fit period would drop all of them.
    """
    names = [name for name in names if name not in ALWAYS_KEPT]
    if not names:
        return []
    counts = ", ".join(f"count(DISTINCT {name})" for name in names)
    values = con.execute(f"SELECT {counts} FROM {FEATURE_TABLE}").fetchone()
    return [name for name, count in zip(names, values, strict=True) if count <= 1]


def write_windows(
    con: duckdb.DuckDBPyConnection,
    names: list[str],
    path: Path,
    periods: Periods,
    config: FeaturesConfig,
) -> None:
    """Write `windows_<log_type>.parquet` (plan 5.4) from the feature table."""
    key = ", ".join(KEY)
    columns = ", ".join(f"f.{name}" for name in (*KEY, *names))
    period = period_sql(config.window_seconds, periods)
    path.parent.mkdir(parents=True, exist_ok=True)
    con.execute(
        f"""
        COPY (
            SELECT {columns},
                COALESCE(ips.top_values, []::VARCHAR[]) AS src_ips,
                COALESCE(accounts.top_values, []::VARCHAR[]) AS users,
                {period} AS period
            FROM {FEATURE_TABLE} AS f
            LEFT JOIN ({_top_values_sql("src_ip", config.top_entities)}) AS ips USING ({key})
            LEFT JOIN ({_top_values_sql('"user"', config.top_entities)}) AS accounts USING ({key})
            ORDER BY f.host, f.window_start
        ) TO '{path}' (FORMAT parquet)
        """
    )


@dataclass(frozen=True)
class FeatureScaler:
    """`log1p` on counts, the center and scale of a `RobustScaler`, one-sided clip (plan 6.3)."""

    columns: list[str]
    count_columns: list[str]
    center: list[float]
    scale: list[float]
    one_sided: list[str] = field(default_factory=list)

    def transform(self, windows: pd.DataFrame, clip: bool = True) -> np.ndarray:
        """Return the scaled feature matrix of the given windows.

        Args:
            windows: Windows with the feature columns.
            clip: Clip the negative values of the one-sided features at 0 (D29). False gives
                the unclipped secondary variant.

        Returns:
            One row per window, one column per entry of `columns`.
        """
        matrix = log_counts(windows, self.columns, self.count_columns)
        scaled = (matrix - np.array(self.center)) / np.array(self.scale)
        if clip:
            positions = [self.columns.index(name) for name in self.one_sided]
            scaled[:, positions] = np.maximum(scaled[:, positions], 0.0)
        return scaled

    def without(self, names: Iterable[str]) -> "FeatureScaler":
        """Return the scaler of the other columns, in the same order.

        Every column is scaled on its own, so the columns that stay are transformed exactly
        as before. v1 scoring uses it to leave out `OPTIONAL_FEATURES`.

        Args:
            names: Columns to leave out. Names the scaler lacks are ignored.

        Returns:
            This scaler if no column is left out, otherwise a smaller one.
        """
        dropped = set(names) & set(self.columns)
        if not dropped:
            return self
        positions = [index for index, name in enumerate(self.columns) if name not in dropped]
        return FeatureScaler(
            [self.columns[index] for index in positions],
            [name for name in self.count_columns if name not in dropped],
            [self.center[index] for index in positions],
            [self.scale[index] for index in positions],
            [name for name in self.one_sided if name not in dropped],
        )

    def save(self, path: Path) -> None:
        """Write the scaler as JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "FeatureScaler":
        """Read a scaler written by `save`."""
        return cls(**json.loads(path.read_text(encoding="utf-8")))


def log_counts(windows: pd.DataFrame, columns: list[str], counts: list[str]) -> np.ndarray:
    """Return `columns` as a float matrix, with `log1p` applied to the `counts` columns."""
    matrix = windows[columns].to_numpy(dtype=float, copy=True)
    positions = [columns.index(name) for name in counts]
    matrix[:, positions] = np.log1p(matrix[:, positions])
    return matrix


def feature_columns(windows: pd.DataFrame) -> list[str]:
    """Return the feature columns of a windows table, including `n_lines`."""
    return [name for name in windows.columns if name not in NOT_FEATURES]


def fit_scaler(windows: pd.DataFrame, one_sided: Iterable[str] = ()) -> FeatureScaler:
    """Fit a scaler on the `fit` windows of a log type.

    Args:
        windows: Windows of every period. Rows of other periods are ignored.
        one_sided: Features to clip at 0 after scaling. Names the table lacks are ignored.

    Returns:
        The fitted scaler.

    Raises:
        ValueError: If there is no `fit` window.
    """
    fit = windows[windows["period"] == "fit"]
    if fit.empty:
        raise ValueError("no fit windows to scale from")
    columns = feature_columns(windows)
    counts = [name for name in columns if name.startswith("n_")]
    robust = RobustScaler().fit(log_counts(fit, columns, counts))
    clipped = [name for name in columns if name in set(one_sided)]
    return FeatureScaler(columns, counts, robust.center_.tolist(), robust.scale_.tolist(), clipped)


def build_log_type(
    con: duckdb.DuckDBPyConnection,
    log_type: str,
    directory: Path,
    periods: Periods,
    settings: Settings,
) -> dict[str, Any]:
    """Build the windows, vocabularies and scaler of one log type.

    Args:
        con: Connection for the temporary tables.
        log_type: Log type.
        directory: `data/processed/<testbed>/`.
        periods: Boundaries of the testbed.
        settings: Loaded settings.

    Returns:
        The report entry of the log type.
    """
    config = settings.features
    features = FEATURE_SETS[log_type]
    create_parsed_view(con, directory / f"lines_{log_type}.parquet", config.window_seconds)
    fit_lines = count_parsed_lines(con, periods.train_start, periods.fit_end)
    calib_lines = count_parsed_lines(con, periods.fit_end, periods.train_end)
    aggregates = {**COMMON_AGGREGATES, **features.aggregates}
    kept = usable_features(aggregates, fit_lines, settings.ml)
    create_derived_table(con, features)
    vocabulary_sizes: dict[str, int] = {}
    if has_vocabulary(fit_lines, settings.ml):
        build_vocabularies(con, features, periods.fit_end)
        path = directory / VOCABULARY_DIR / f"{log_type}.parquet"
        path.parent.mkdir(parents=True, exist_ok=True)
        con.execute(
            f"COPY (SELECT * FROM {VOCABULARY_TABLE} ORDER BY vocabulary, value) "
            f"TO '{path}' (FORMAT parquet)"
        )
        query = f"SELECT vocabulary, count(*) FROM {VOCABULARY_TABLE} GROUP BY 1"
        vocabulary_sizes = dict(con.execute(query).fetchall())
    aggregate_windows(con, {name: aggregates[name] for name in kept})
    constant = constant_features(con, kept)
    names = [name for name in kept if name not in constant]
    windows_path = directory / f"windows_{log_type}.parquet"
    write_windows(con, names, windows_path, periods, config)

    windows = pd.read_parquet(windows_path)
    capable = is_baseline_capable(fit_lines, calib_lines, settings.ml)
    if capable:
        scaler = fit_scaler(windows, config.one_sided_features)
        scaler.save(directory / SCALER_DIR / f"{log_type}.json")
    return {
        "fit_lines": fit_lines,
        "calib_lines": calib_lines,
        "baseline_capable": capable,
        "windows": {
            period: int((windows["period"] == period).sum()) for period in ("fit", "calib", "eval")
        },
        "features": names,
        "dropped_vocabulary": [name for name in aggregates if name not in kept],
        "dropped_constant": constant,
        "vocabulary_sizes": vocabulary_sizes,
    }


def build_windows(directory: Path, periods: Periods, settings: Settings) -> dict[str, Any]:
    """Build the windows of every log type and write `features_report.json`.

    Earlier scalers and vocabularies are removed first, so a type that lost its baseline
    cannot keep a stale one.

    Args:
        directory: `data/processed/<testbed>/`, holding the `lines_*.parquet` files.
        periods: Boundaries of the testbed.
        settings: Loaded settings.

    Returns:
        The report, by log type.
    """
    for subdirectory, suffix in ((SCALER_DIR, "json"), (VOCABULARY_DIR, "parquet")):
        for path in (directory / subdirectory).glob(f"*.{suffix}"):
            path.unlink()
    report: dict[str, Any] = {}
    with connect() as con:
        create_macros(con, settings.features.second_level_suffixes)
        for log_type in FEATURE_SETS:
            report[log_type] = build_log_type(con, log_type, directory, periods, settings)
            logger.info("%s %s: %s", periods.testbed, log_type, report[log_type]["windows"])
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (directory / REPORT_FILE).write_text(text, encoding="utf-8")
    return report


def feature_summary(windows: pd.DataFrame) -> pd.DataFrame:
    """Summarize the features of a log type: one row per feature, in raw units.

    Args:
        windows: A windows table.

    Returns:
        The mean per period, the overall maximum and the share of non-zero windows.
    """
    columns = feature_columns(windows)
    means = windows.groupby("period")[columns].mean().T
    summary = means.reindex(columns=["fit", "calib", "eval"]).add_prefix("mean_")
    summary["max"] = windows[columns].max()
    summary["share_nonzero"] = (windows[columns] != 0).mean()
    return summary.round(3)
