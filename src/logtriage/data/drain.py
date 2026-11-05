"""Drain3 templating: a frozen fit-period miner and an online miner (plan 6.2)."""

import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from logtriage.config import DrainConfig

logging.getLogger("drain3").setLevel(logging.WARNING)


@dataclass
class DrainStats:
    """Results and throughput of one log type."""

    lines: int
    fit_lines: int
    frozen_templates: int
    online_templates: int
    unseen_lines: int
    unseen_fit_lines: int
    seconds: float

    @property
    def lines_per_second(self) -> float:
        """Lines through both miners, divided by the wall time."""
        return self.lines / self.seconds if self.seconds else 0.0


def make_miner(config: DrainConfig) -> TemplateMiner:
    """Create a miner without persistence, so no earlier state can leak into a run."""
    miner_config = TemplateMinerConfig()
    miner_config.drain_sim_th = config.sim_th
    miner_config.drain_depth = config.depth
    miner_config.drain_max_children = config.max_children
    miner_config.masking_instructions = [
        MaskingInstruction(rule.pattern, rule.mask_with) for rule in config.masking
    ]
    return TemplateMiner(None, miner_config)


def save_miner(miner: TemplateMiner, path: Path) -> None:
    """Save a miner's state to `path`, replacing any earlier file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    miner.persistence_handler = FilePersistence(str(path))
    miner.save_state("final")
    miner.persistence_handler = None


def add_templates(
    rows: list[dict[str, Any]],
    fit_end: datetime,
    config: DrainConfig,
    state_dir: Path,
    log_type: str,
) -> DrainStats:
    """Add the template columns to rows in place (plan 5.1, 6.2).

    Lines with `parse_ok=False` have no message, so their template columns stay None.

    Args:
        rows: Rows of one log type, in chronological order.
        fit_end: End of the fit period. Fit lines are the rows before it.
        config: Drain3 settings.
        state_dir: Directory for `<log_type>.frozen.bin` and `<log_type>.online.bin`.
        log_type: Log type of the rows.

    Returns:
        Counts and timing.
    """
    started = time.perf_counter()
    parsed = [row for row in rows if row["parse_ok"]]
    fit = [row for row in parsed if row["ts"] < fit_end]

    frozen = make_miner(config)
    for row in fit:
        frozen.add_log_message(row["message"])
    save_miner(frozen, state_dir / f"{log_type}.frozen.bin")
    sizes = {cluster.cluster_id: cluster.size for cluster in frozen.drain.clusters}
    denominator = sum(sizes.values()) + len(sizes)

    online = make_miner(config)
    online_ids = [online.add_log_message(row["message"])["cluster_id"] for row in parsed]
    save_miner(online, state_dir / f"{log_type}.online.bin")
    templates = {cluster.cluster_id: cluster.get_template() for cluster in online.drain.clusters}

    matches: dict[str, int | None] = {}
    unseen_lines = unseen_fit_lines = 0
    for row, online_id in zip(parsed, online_ids, strict=True):
        message = row["message"]
        if message not in matches:
            cluster = frozen.match(message, full_search_strategy="fallback")
            matches[message] = cluster.cluster_id if cluster else None
        frozen_id = matches[message]
        count = sizes.get(frozen_id, 0) if frozen_id is not None else 0
        row["template_id"] = online_id
        row["template"] = templates[online_id]
        row["is_unseen_template"] = frozen_id is None
        row["template_rarity"] = -math.log((count + 1) / denominator) if denominator else math.inf
        unseen_lines += frozen_id is None
        unseen_fit_lines += frozen_id is None and row["ts"] < fit_end
    return DrainStats(
        lines=len(parsed),
        fit_lines=len(fit),
        frozen_templates=len(sizes),
        online_templates=len(templates),
        unseen_lines=unseen_lines,
        unseen_fit_lines=unseen_fit_lines,
        seconds=time.perf_counter() - started,
    )
