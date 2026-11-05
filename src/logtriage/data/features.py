"""Window feature extraction (plan 6.3)."""

from collections.abc import Iterable
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
