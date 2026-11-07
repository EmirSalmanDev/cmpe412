"""Agent tools (plan 7.3). They read only `agent.duckdb`, through `store.connect_agent`.

Each tool returns compact text and the line_ids shown in it. The graph of M8 registers those
line_ids as eids. Every text respects `tools.output_chars`, and a line_id is returned only if its
line made it into the text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import pandas as pd

from logtriage.agents.sql_guard import SqlRejected, agent_tables, run_guarded
from logtriage.config import Settings, ToolsConfig
from logtriage.data.store import connect_agent
from logtriage.rag.attack_index import AttackIndex, BgeEmbedder, cosine_collection, open_client
from logtriage.rag.incident_store import DEFAULT_RUN, IncidentStore

MORE = "... {count} more not shown"
NO_USER = "UNDEF"


@dataclass
class ToolResult:
    """Output of a tool."""

    text: str
    line_ids: list[str] = field(default_factory=list)


def clip(text: str, chars: int) -> str:
    """Shorten one line of text, on one row."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= chars else f"{flat[: chars - 3]}..."


def fit_blocks(
    header: str, blocks: list[tuple[str, str | None]], chars: int
) -> tuple[str, list[str]]:
    """Join a header and as many text blocks as fit in the limit.

    Args:
        header: First line, always kept.
        blocks: Text of each block, with the line_id it shows, if any.
        chars: Most characters of the result.

    Returns:
        The text, and the line_ids of the blocks that fit.
    """
    lines = [header[:chars]]
    shown: list[str] = []
    used = len(lines[0])
    for index, (text, line_id) in enumerate(blocks):
        reserve = len(MORE.format(count=len(blocks))) + 1
        if used + len(text) + 1 + reserve > chars:
            lines.append(MORE.format(count=len(blocks) - index))
            break
        lines.append(text)
        used += len(text) + 1
        if line_id is not None:
            shown.append(line_id)
    return "\n".join(lines)[:chars], shown


def parse_time(value: str | datetime) -> datetime:
    """Read a time as tz-aware UTC. A time without a zone is taken as UTC."""
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _stamp(moment: pd.Timestamp) -> str:
    """Render a timestamp for a tool output."""
    return moment.tz_convert("UTC").strftime("%Y-%m-%d %H:%M:%S")


class AgentTools:
    """The five tools of plan 7.3, bound to one testbed."""

    def __init__(
        self,
        connection: duckdb.DuckDBPyConnection,
        config: ToolsConfig,
        testbed: str,
        attack: AttackIndex | None = None,
        incidents: IncidentStore | None = None,
    ) -> None:
        self.connection = connection
        self.config = config
        self.testbed = testbed
        self.attack = attack
        self.incidents = incidents
        self.tables = agent_tables(connection)
        # Start of the incident under investigation: `similar_incidents` sees only earlier ones.
        self.before: datetime | None = None
        # The run of the agent graph: `similar_incidents` sees only reports of the same run.
        self.run = DEFAULT_RUN

    @classmethod
    def open(
        cls,
        testbed: str,
        settings: Settings,
        connection: duckdb.DuckDBPyConnection | None = None,
        memory_dir: Path | None = None,
    ) -> AgentTools:
        """Open the tools of a testbed.

        Args:
            testbed: Testbed name.
            settings: Loaded settings.
            connection: An open locked connection. A process can hold only one per file, because
                the lock covers the whole database; opened here if None.
            memory_dir: A Chroma store of its own for the incident memory, so that an ablation
                never writes to the official one (D65). The ATT&CK index stays shared.

        Returns:
            The tools, on a locked connection and the persistent Chroma store.
        """
        connection = connection or connect_agent(
            settings.paths.processed_dir / testbed / "agent.duckdb"
        )
        client = open_client(settings.paths.index_dir)
        embedder = BgeEmbedder(settings.rag)
        rag = settings.rag
        return cls(
            connection,
            settings.tools,
            testbed,
            AttackIndex(cosine_collection(client, rag.attack_collection), embedder, rag),
            IncidentStore(
                cosine_collection(
                    open_client(memory_dir) if memory_dir else client, rag.incidents_collection
                ),
                embedder,
            ),
        )

    def close(self) -> None:
        """Close the database connection."""
        self.connection.close()

    def log_search(
        self,
        host: str,
        start: str | datetime,
        end: str | datetime,
        log_type: str | None = None,
        contains: str | None = None,
        limit: int = 50,
    ) -> ToolResult:
        """Search raw log lines of a host in a time range, one example per template.

        Unseen templates come first, then rarer ones. Lines whose timestamp is unreliable are left
        out and counted.

        Args:
            host: Host name.
            start: Range start, ISO 8601, UTC if no zone is given.
            end: Range end, inclusive.
            log_type: Only this log type.
            contains: Only lines holding this text, in any case.
            limit: Most templates shown.

        Returns:
            One row per template: count, unseen mark, time, line_id and an example line.
        """
        try:
            first, last = parse_time(start), parse_time(end)
        except ValueError as error:
            return ToolResult(f"error: bad time: {error}")
        where = "host = ? AND ts >= ? AND ts <= ?"
        values: list[object] = [host, first, last]
        if log_type is not None:
            where += " AND log_type = ?"
            values.append(log_type)
        if contains is not None:
            where += " AND contains(lower(raw), lower(?))"
            values.append(contains)
        shown = max(1, min(limit, self.config.log_search_limit))
        table = self.connection.execute(
            f"""
            SELECT log_type, template_id, count(*) AS n, min(ts) AS ts,
                   bool_or(is_unseen_template) AS unseen, max(template_rarity) AS rarity,
                   arg_min(line_id, (ts, line_no)) AS line_id, arg_min(raw, (ts, line_no)) AS raw
            FROM lines WHERE parse_ok AND {where}
            GROUP BY log_type, template_id
            ORDER BY unseen DESC, rarity DESC, n DESC, log_type, template_id
            """,
            values,
        ).df()
        left_out = self.connection.execute(
            f"SELECT count(*) FROM lines WHERE NOT parse_ok AND {where}", values
        ).fetchone()[0]
        header = (
            f"{int(table['n'].sum())} lines, {len(table)} templates on {host}; "
            f"{left_out} lines with an unreliable time left out"
        )
        blocks = [
            (
                f"{row.n}x{' UNSEEN' if row.unseen else ''} {_stamp(row.ts)} {row.log_type} "
                f"[{row.line_id}] {clip(row.raw, self.config.line_chars)}",
                row.line_id,
            )
            for row in table.head(shown).itertuples()
        ]
        if len(table) > shown:
            header += f"; showing {shown} templates"
        return ToolResult(*fit_blocks(header, blocks, self.config.output_chars))

    def run_sql(self, query: str) -> ToolResult:
        """Run one read-only SELECT or WITH query on the agent tables.

        One statement only, at most 200 rows and 10 seconds. No table functions and no files.

        Tables:
        - `lines`, and one `lines_<log_type>` per type (`apache_access`, `apache_error`, `audit`,
          `auth`, `dns`, `vpn`): `line_id`, `testbed`, `host`, `log_type`, `file`, `line_no`,
          `ts` (UTC), `raw`, `message`, `template_id`, `template`, `is_unseen_template`,
          `template_rarity`, `src_ip`, `user`, `fields` (JSON text, read with `fields->>'key'`),
          `parse_ok` (false: the timestamp is unreliable).
        - `windows`, and one `windows_<log_type>` per type: one-minute windows with `host`,
          `log_type`, `window_start`, `n_lines`, feature columns, `src_ips`, `users`.
        - `scores`: `host`, `log_type`, `window_start`, `score_if`, `score_lof`, `score_pca`,
          `pct_if`, `pct_lof`, `pct_pca`, `score`, `is_anomalous`, `incident_id`.
        - `incidents`: `incident_id`, `start`, `end`, `hosts`, `log_types`, `src_ips`, `users`,
          `n_windows`, `max_score`, `mean_score`, `priority`, `window_keys`.

        Args:
            query: The SQL text.

        Returns:
            The rows as CSV, or the reason the query did not run.
        """
        try:
            table = run_guarded(
                self.connection,
                query,
                self.tables,
                self.config.sql_rows,
                self.config.sql_timeout_seconds,
            )
        except SqlRejected as error:
            return ToolResult(clip(f"rejected: {error}", self.config.output_chars))
        except TimeoutError as error:
            return ToolResult(f"error: {error}")
        except duckdb.Error as error:
            return ToolResult(clip(f"error: {error}", self.config.output_chars))
        ids = table["line_id"].tolist() if "line_id" in table.columns else [None] * len(table)
        cells = (
            table.astype(object)
            .where(table.notna(), "")
            .map(lambda value: clip(value, self.config.line_chars))
        )
        rows = [",".join(row) for row in cells.to_numpy().tolist()]
        header = f"{len(table)} rows\n" + ",".join(map(str, table.columns))
        return ToolResult(
            *fit_blocks(header, list(zip(rows, ids, strict=True)), self.config.output_chars)
        )

    def ip_profile(self, ip: str) -> ToolResult:
        """Describe an IP address: where it appears, and its VPN identity.

        Args:
            ip: IPv4 address, external or VPN-internal.

        Returns:
            Per log type and host: first and last seen, count, top templates, and the first line.
            VPN sessions of the address follow: external IP, VPN IP and user, with their times.
        """
        vpn = self.connection.execute(
            f"""
            SELECT src_ip, nullif("user", '{NO_USER}') AS vpn_user, fields->>'vpn_ip' AS vpn_ip,
                   min(ts) AS first_seen, max(ts) AS last_seen, count(*) AS n,
                   arg_min(line_id, (ts, line_no)) AS line_id
            FROM lines
            WHERE parse_ok AND log_type = 'vpn' AND fields->>'vpn_ip' IS NOT NULL
              AND (src_ip = ? OR fields->>'vpn_ip' = ?)
            GROUP BY ALL ORDER BY first_seen
            """,
            [ip, ip],
        ).df()
        seen = self.connection.execute(
            """
            WITH hits AS (SELECT * FROM lines WHERE parse_ok AND src_ip = ?),
            counted AS (
                SELECT log_type, host, template, count(*) AS n FROM hits GROUP BY ALL
            ),
            ranked AS (
                SELECT *, row_number() OVER (
                    PARTITION BY log_type, host ORDER BY n DESC, template
                ) AS position FROM counted
            ),
            top AS (
                SELECT log_type, host, string_agg(template, ' | ' ORDER BY position) AS templates
                FROM ranked WHERE position <= ? GROUP BY ALL
            )
            SELECT h.log_type, h.host, min(h.ts) AS first_seen, max(h.ts) AS last_seen,
                   count(*) AS n, arg_min(h.line_id, (h.ts, h.line_no)) AS line_id,
                   any_value(t.templates) AS templates
            FROM hits h JOIN top t USING (log_type, host)
            GROUP BY h.log_type, h.host ORDER BY n DESC, h.log_type, h.host
            """,
            [ip, self.config.top_templates],
        ).df()
        session_blocks = [
            (
                f"VPN: external {row.src_ip}, vpn {row.vpn_ip}, user {row.vpn_user or 'unknown'}, "
                f"{_stamp(row.first_seen)} to {_stamp(row.last_seen)}, {row.n} assignments "
                f"[{row.line_id}]",
                row.line_id,
            )
            for row in vpn.itertuples()
        ]
        seen_blocks = [
            (
                f"{row.log_type} on {row.host}: {row.n} lines, {_stamp(row.first_seen)} to "
                f"{_stamp(row.last_seen)} [{row.line_id}] top: "
                f"{clip(row.templates, self.config.line_chars)}",
                row.line_id,
            )
            for row in seen.itertuples()
        ]
        header = f"{ip}: {int(seen['n'].sum())} lines, {len(vpn)} VPN session records"
        blocks = session_blocks + seen_blocks
        return ToolResult(*fit_blocks(header, blocks, self.config.output_chars))

    def attack_search(self, text: str, k: int = 5) -> ToolResult:
        """Search the ATT&CK index by meaning.

        Args:
            text: What was observed, in plain words.
            k: Number of results.

        Returns:
            One row per technique: ID, name, tactics and the start of its description.
        """
        if self.attack is None:
            return ToolResult("error: the ATT&CK index is not available")
        count = max(1, min(k, self.config.attack_k))
        rows = [
            (
                f"{hit['id']} {hit['name']} [{hit['tactics']}] "
                f"{clip(hit['document'], self.config.line_chars)}",
                None,
            )
            for hit in self.attack.search(text, count)
        ]
        return ToolResult(fit_blocks(f"{len(rows)} techniques", rows, self.config.output_chars)[0])

    def similar_incidents(self, text: str, k: int = 3) -> ToolResult:
        """Search finalized reports of incidents that started before the current one.

        Args:
            text: What was observed, in plain words.
            k: Number of results.

        Returns:
            One row per report: incident, verdict and the indexed text.
        """
        if self.incidents is None:
            return ToolResult("error: the incident memory is not available")
        count = max(1, min(k, self.config.incidents_k))
        hits = self.incidents.search(text, count, self.testbed, self.before, self.run)
        rows = [
            (
                f"{hit['incident_id']} [{hit['verdict']}] "
                f"{clip(hit['document'], self.config.line_chars)}",
                None,
            )
            for hit in hits
        ]
        return ToolResult(fit_blocks(f"{len(rows)} incidents", rows, self.config.output_chars)[0])
