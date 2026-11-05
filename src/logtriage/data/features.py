"""Window feature extraction (plan 6.3)."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

import duckdb

from logtriage.config import MLConfig
from logtriage.data.windows import PARSED_VIEW

TEMPLATE_VOCABULARY_FEATURES = frozenset(
    {
        "n_unseen_templates",
        "ratio_unseen_templates",
        "mean_template_rarity",
        "max_template_rarity",
    }
)


DERIVED_TABLE = "derived_lines"
VOCABULARY_TABLE = "vocabulary"
FEATURE_TABLE = "window_features"
KEY = ("testbed", "host", "log_type", "window_start")


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
FEATURE_SETS: dict[str, FeatureSet] = {"dns": DNS}


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
