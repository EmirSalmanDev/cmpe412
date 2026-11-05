"""Exploratory analysis behind `01_eda.ipynb` and `reports/targets.md` (plan 13 M3).

Reads labels, so it lives in `logtriage.eval` (plan 5.2). Every function takes a DuckDB
connection holding the `lines`, `labels` and `phases` views of `eval.duckdb`.
"""

import re
from datetime import datetime
from pathlib import Path

import duckdb
import pandas as pd

from logtriage.config import MLConfig, Settings
from logtriage.data.periods import Periods, is_baseline_capable, load_periods
from logtriage.eval.metrics import required_detections

PUBLISHED_SOURCE = "ait_ads:labels.csv"
EXFIL_PHASE = "dnsteal_exfil"
EXFIL_LABEL = "dnsteal"
PHASE_TOLERANCE_SECONDS = 60
# Roles of the attacker addresses, by the raw label of the lines that carry them.
ATTACKER_ROLES = {"attacker_http": "tunnel", "attacker_vpn": "external"}
# Apache error log text that is not attacker output: the only other stderr in the testbeds.
STDERR_NOISE = "mkdir failed on directory /var/run/samba"
MIN_DOMAIN_SHARE = 0.01
QNAME = "json_extract_string(fields, '$.qname')"
DOMAIN = rf"regexp_extract({QNAME}, '([^.]+\.[^.]+)$', 1)"


def connect(testbed: str, settings: Settings) -> duckdb.DuckDBPyConnection:
    """Open `eval.duckdb` read-only, with UTC as the session time zone.

    Views use paths relative to the repository root, so run from there.
    """
    path = Path(settings.paths.processed_dir) / testbed / "eval.duckdb"
    connection = duckdb.connect(str(path), read_only=True)
    connection.execute("SET TimeZone='UTC'")
    return connection


def testbed_periods(testbed: str, settings: Settings) -> Periods:
    """Read the `periods.json` of a testbed."""
    return load_periods(Path(settings.paths.processed_dir) / testbed / "periods.json")


def _stamp(value: datetime) -> str:
    """Render a timestamp as a SQL literal."""
    return f"TIMESTAMPTZ '{value.isoformat()}'"


def line_counts(con: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Count lines per log type and host (rows) and UTC day (columns), with a total."""
    table = con.execute(
        "SELECT log_type, host, strftime(ts, '%Y-%m-%d') AS day, count(*) AS n "
        "FROM lines GROUP BY ALL"
    ).df()
    wide = table.pivot_table(
        index=["log_type", "host"], columns="day", values="n", aggfunc="sum", fill_value=0
    )
    wide["total"] = wide.sum(axis=1)
    return wide


def hourly_lines(con: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Count parsed lines per log type and UTC hour."""
    return con.execute(
        "SELECT log_type, date_trunc('hour', ts) AS hour, count(*) AS lines "
        "FROM lines WHERE parse_ok GROUP BY ALL ORDER BY 1, 2"
    ).df()


def period_lines(con: duckdb.DuckDBPyConnection, periods: Periods) -> pd.DataFrame:
    """Count parsed lines per log type (rows) and period (`fit`, `calib`, `eval`)."""
    table = con.execute(
        f"""
        SELECT log_type,
               count(*) FILTER (ts < {_stamp(periods.fit_end)}) AS fit,
               count(*) FILTER (ts >= {_stamp(periods.fit_end)}
                                AND ts < {_stamp(periods.train_end)}) AS calib,
               count(*) FILTER (ts >= {_stamp(periods.eval_start)}) AS eval
        FROM lines WHERE parse_ok GROUP BY log_type ORDER BY log_type
        """
    ).df()
    return table.set_index("log_type")


def baseline_table(lines_per_period: pd.DataFrame, config: MLConfig) -> pd.DataFrame:
    """Add `baseline_capable` to the output of `period_lines` (plan 6.4)."""
    table = lines_per_period.copy()
    table["baseline_capable"] = [
        is_baseline_capable(int(row.fit), int(row.calib), config) for row in table.itertuples()
    ]
    return table


def attack_share(con: duckdb.DuckDBPyConnection, periods: Periods) -> pd.DataFrame:
    """Measure class imbalance in parsed lines, over the simulation and the evaluation period.

    Returns:
        One row per scope and log type, plus `all` and `all without exfil` (labeled exfil
        lines removed from both sides): `lines`, `attack_lines`, `attack_share` and
        `normal_per_attack`.
    """
    counts = con.execute(
        f"""
        SELECT l.log_type, l.ts >= {_stamp(periods.eval_start)} AS in_eval, b.phase,
               count(*) AS n
        FROM lines l LEFT JOIN labels b USING (line_id)
        WHERE l.parse_ok GROUP BY ALL
        """
    ).df()
    rows = []
    for scope, part in (("simulation", counts), ("evaluation", counts[counts["in_eval"]])):
        groups = [(name, group) for name, group in part.groupby("log_type")]
        groups.append(("all", part))
        groups.append(("all without exfil", part[part["phase"] != EXFIL_PHASE]))
        for name, group in groups:
            lines = int(group["n"].sum())
            attack = int(group.loc[group["phase"].notna(), "n"].sum())
            rows.append(
                {
                    "scope": scope,
                    "log_type": name,
                    "lines": lines,
                    "attack_lines": attack,
                    "attack_share": attack / lines if lines else 0.0,
                    "normal_per_attack": (lines - attack) / attack if attack else float("inf"),
                }
            )
    return pd.DataFrame(rows)


def phase_traces(con: duckdb.DuckDBPyConnection, periods: Periods) -> pd.DataFrame:
    """Count labeled lines per phase and log type, overall and in the evaluation period."""
    return con.execute(
        f"""
        SELECT b.phase, l.log_type, count(*) AS labeled,
               count(*) FILTER (l.ts >= {_stamp(periods.eval_start)}) AS labeled_eval
        FROM labels b JOIN lines l USING (line_id) GROUP BY ALL ORDER BY 1, 2
        """
    ).df()


def phase_denominators(
    con: duckdb.DuckDBPyConnection, traces: pd.DataFrame, capable_log_types: list[str]
) -> pd.DataFrame:
    """Decide which phases count as "phases with traces" (plan 10.1).

    A phase counts if the evaluation period holds at least one of its labeled lines: in a
    baseline-capable log type for the primary denominator, in any parsed log type for the
    secondary one.

    Args:
        con: Connection with the `phases` view.
        traces: Output of `phase_traces`.
        capable_log_types: Baseline-capable log types of the testbed.

    Returns:
        One row per phase of the phases file, in time order.
    """
    names = [
        row[0] for row in con.execute("SELECT phase FROM phases ORDER BY start_utc").fetchall()
    ]
    rows = []
    for phase in names:
        part = traces[(traces["phase"] == phase) & (traces["labeled_eval"] > 0)]
        all_types = sorted(part["log_type"])
        capable = [name for name in all_types if name in capable_log_types]
        rows.append(
            {
                "phase": phase,
                "labeled": int(traces.loc[traces["phase"] == phase, "labeled"].sum()),
                "labeled_eval": int(part["labeled_eval"].sum()),
                "log_types": ", ".join(all_types),
                "baseline_log_types": ", ".join(capable),
                "primary": bool(capable),
                "all_parsed": bool(all_types),
            }
        )
    return pd.DataFrame(rows)


def denominator_summary(table: pd.DataFrame, share: float = 0.8) -> pd.DataFrame:
    """Give the size and the required detections of each recall denominator variant."""
    variants = {
        "primary (baseline-capable log types)": table["primary"],
        "secondary (all parsed log types)": table["all_parsed"],
        f"secondary (primary without {EXFIL_PHASE})": table["primary"]
        & (table["phase"] != EXFIL_PHASE),
    }
    rows = [
        {
            "variant": name,
            "phases": int(mask.sum()),
            "required": required_detections(int(mask.sum()), share),
        }
        for name, mask in variants.items()
    ]
    return pd.DataFrame(rows)


def attacker_ips(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    """Return attacker addresses to role, taken from lines labeled as attacker traffic.

    `external` is the attacker's own host, seen by the VPN server. `tunnel` is its VPN address.
    Pool addresses go back to other VPN users later, so a tunnel match is only a candidate.
    Sources of exfiltration are compromised hosts, not the attacker, and stay out.
    """
    found: dict[str, str] = {}
    for label, role in ATTACKER_ROLES.items():
        rows = con.execute(
            "SELECT DISTINCT l.src_ip FROM lines l JOIN labels b USING (line_id) "
            "WHERE l.src_ip IS NOT NULL AND list_contains(b.labels, ?) ORDER BY 1",
            [label],
        ).fetchall()
        found.update({row[0]: role for row in rows})
    return found


def exfil_domains(con: duckdb.DuckDBPyConnection) -> list[str]:
    """Return the registered domains that carry the labeled exfiltration."""
    rows = con.execute(
        f"""
        SELECT {DOMAIN} AS domain, count(*) AS n
        FROM lines l JOIN labels b USING (line_id)
        WHERE l.log_type = 'dns' AND list_contains(b.labels, ?) AND {QNAME} IS NOT NULL
        GROUP BY 1 ORDER BY 2 DESC, 1
        """,
        [EXFIL_LABEL],
    ).fetchall()
    total = sum(row[1] for row in rows)
    return [row[0] for row in rows if row[1] / total >= MIN_DOMAIN_SHARE]


def exfil_gap(con: duckdb.DuckDBPyConnection, domains: list[str]) -> pd.DataFrame:
    """Count exfiltration lines per DNS host, by domain match, against the labels.

    The match can be trusted where labels exist: `labeled_exfil_outside` counts labeled
    exfiltration lines it misses, and `unlabeled` on the labeled host counts its false matches.

    Returns:
        One row per DNS host: `dns_lines`, `exfil_lines`, `exfil_queries`, `labeled`,
        `unlabeled`, `labeled_exfil_outside` and `exfil_share`.
    """
    table = con.execute(
        f"""
        SELECT l.host,
               count(*) AS dns_lines,
               count(*) FILTER (hit) AS exfil_lines,
               count(*) FILTER (hit AND action = 'query') AS exfil_queries,
               count(*) FILTER (hit AND exfil_label) AS labeled,
               count(*) FILTER (hit AND NOT exfil_label) AS unlabeled,
               count(*) FILTER (NOT hit AND exfil_label) AS labeled_exfil_outside
        FROM (
            SELECT l.host, coalesce({DOMAIN} IN (SELECT unnest(?)), false) AS hit,
                   json_extract_string(l.fields, '$.action') AS action,
                   coalesce(list_contains(b.labels, ?), false) AS exfil_label
            FROM lines l LEFT JOIN labels b USING (line_id)
            WHERE l.log_type = 'dns'
        ) l GROUP BY l.host ORDER BY l.host
        """,
        [domains, EXFIL_LABEL],
    ).df()
    table["exfil_share"] = table["exfil_lines"] / table["dns_lines"]
    return table


def _address_pattern(addresses: list[str]) -> str:
    """Regex for whole IPv4 addresses, so `10.1.1.1` does not match inside `110.1.1.11`."""
    alternatives = "|".join(re.escape(address) for address in addresses)
    return f"(^|[^0-9.])({alternatives})([^0-9]|$)"


def attacker_ip_lines(
    con: duckdb.DuckDBPyConnection, ips: dict[str, str], domains: list[str]
) -> pd.DataFrame:
    """Count parsed lines naming an attacker address, labeled or not, in and out of phases.

    Exfiltration lines are left out: `inet-dns` forwards them to the attacker's name server,
    so they name its address, but `exfil_gap` already counts them. A line naming both
    addresses takes the `external` role. A phase window is a published phase ±60 s; as in
    plan 5.3, a line takes the phase holding its `ts`, else the nearest one.

    Returns:
        One row per role, log type, host and phase (null outside the windows), with `lines`
        and `labeled`.
    """
    any_address = _address_pattern(list(ips))
    external = _address_pattern([ip for ip, role in ips.items() if role == "external"])
    margin = f"INTERVAL {PHASE_TOLERANCE_SECONDS} SECOND"
    return con.execute(
        f"""
        WITH hits AS (
            SELECT l.line_id, l.log_type, l.host, l.ts, l.raw
            FROM lines l
            WHERE l.parse_ok AND regexp_matches(l.raw, ?)
              AND NOT coalesce(l.log_type = 'dns' AND {DOMAIN} IN (SELECT unnest(?)), false)
        ), windows AS (
            SELECT h.line_id,
                   arg_min(p.phase, greatest(p.start_utc - h.ts, h.ts - p.end_utc)) AS phase
            FROM hits h JOIN phases p
              ON p.source = ? AND h.ts >= p.start_utc - {margin} AND h.ts <= p.end_utc + {margin}
            GROUP BY h.line_id
        )
        SELECT CASE WHEN regexp_matches(h.raw, ?) THEN 'external' ELSE 'tunnel' END AS role,
               h.log_type, h.host, w.phase, count(*) AS lines, count(b.line_id) AS labeled
        FROM hits h
        LEFT JOIN windows w USING (line_id)
        LEFT JOIN labels b USING (line_id)
        GROUP BY ALL ORDER BY 1, 2, 3, 4
        """,
        [any_address, domains, PUBLISHED_SOURCE, external],
    ).df()


def attacker_gap_summary(lines: pd.DataFrame) -> pd.DataFrame:
    """Summarize `attacker_ip_lines` per role inside the phase windows, with both totals.

    `external` is the low estimate of the gap and `all roles` the upper bound, because tunnel
    addresses also serve ordinary VPN users.
    """
    inside = lines[lines["phase"].notna()]
    rows = []
    for name, part in [*inside.groupby("role"), ("all roles", inside)]:
        total = int(part["lines"].sum())
        labeled = int(part["labeled"].sum())
        rows.append(
            {
                "role": name,
                "lines_in_windows": total,
                "labeled": labeled,
                "unlabeled": total - labeled,
                "gap_share": (total - labeled) / total if total else 0.0,
            }
        )
    table = pd.DataFrame(rows)
    outside = lines[lines["phase"].isna()]
    table["unlabeled_outside_windows"] = [
        int((outside["lines"] - outside["labeled"]).sum())
        if name == "all roles"
        else int(
            (
                outside.loc[outside["role"] == name, "lines"]
                - outside.loc[outside["role"] == name, "labeled"]
            ).sum()
        )
        for name in table["role"]
    ]
    return table


def labeled_timeline(con: duckdb.DuckDBPyConnection, seconds: int = 30) -> pd.DataFrame:
    """Count labeled lines per phase, log type and time bin, for the timeline figure."""
    return con.execute(
        f"""
        SELECT b.phase, l.log_type, time_bucket(INTERVAL {seconds} SECOND, l.ts) AS bin,
               count(*) AS lines
        FROM labels b JOIN lines l USING (line_id) GROUP BY ALL ORDER BY 3
        """
    ).df()


def phase_intervals(con: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Return the rows of the phases file in time order."""
    return con.execute(
        "SELECT phase, start_utc AS start, end_utc AS end, source FROM phases ORDER BY start_utc"
    ).df()


def stderr_gap(con: duckdb.DuckDBPyConnection) -> pd.DataFrame:
    """Split the stderr text of Apache error logs into attacker output and other noise.

    Returns:
        One row per host, file and kind: `lines`, `labeled`, the `ts` those lines inherited,
        and the first and last time written inside their text, if any.
    """
    return con.execute(
        r"""
        SELECT l.host, l.file,
               CASE WHEN contains(l.raw, ?) THEN 'noise' ELSE 'attacker output' END AS kind,
               count(*) AS lines, count(b.line_id) AS labeled,
               strftime(min(l.ts), '%Y-%m-%d %H:%M:%S') AS inherited_ts,
               min(nullif(regexp_extract(l.raw, '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'), ''))
                   AS first_written,
               max(nullif(regexp_extract(l.raw, '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'), ''))
                   AS last_written
        FROM lines l LEFT JOIN labels b USING (line_id)
        WHERE l.log_type = 'apache_error' AND NOT l.parse_ok AND trim(l.raw) <> ''
        GROUP BY ALL ORDER BY 1, 2, 3
        """,
        [STDERR_NOISE],
    ).df()


def dns_contamination(
    con: duckdb.DuckDBPyConnection, periods: Periods, domains: list[str]
) -> pd.DataFrame:
    """Measure the exfiltration share of DNS lines per hour of the training period (D16).

    Returns:
        One row per UTC hour: `period`, then `labeled_host_*` for `inet-firewall` (labeled
        lines) and `all_hosts_*` for both DNS hosts (domain match).
    """
    table = con.execute(
        f"""
        SELECT hour,
               sum((host = 'inet-firewall')::INT) AS labeled_host_lines,
               sum((host = 'inet-firewall' AND labeled)::INT) AS labeled_host_exfil,
               count(*) AS all_hosts_lines,
               sum(hit::INT) AS all_hosts_exfil
        FROM (
            SELECT date_trunc('hour', l.ts) AS hour, l.host,
                   coalesce(list_contains(b.labels, ?), false) AS labeled,
                   coalesce({DOMAIN} IN (SELECT unnest(?)), false) AS hit
            FROM lines l LEFT JOIN labels b USING (line_id)
            WHERE l.log_type = 'dns' AND l.parse_ok
              AND l.ts >= {_stamp(periods.train_start)} AND l.ts < {_stamp(periods.train_end)}
        ) GROUP BY hour ORDER BY hour
        """,
        [EXFIL_LABEL, domains],
    ).df()
    table["labeled_host_share"] = table["labeled_host_exfil"] / table["labeled_host_lines"]
    table["all_hosts_share"] = table["all_hosts_exfil"] / table["all_hosts_lines"]
    table["period"] = ["fit" if hour < periods.fit_end else "calib" for hour in table["hour"]]
    return table


def contamination_summary(table: pd.DataFrame) -> pd.DataFrame:
    """Summarize `dns_contamination` per period and over the whole training period."""
    rows = []
    for name, part in [*table.groupby("period", sort=False), ("training", table)]:
        rows.append(
            {
                "period": name,
                "hours": len(part),
                "hours_with_exfil": int((part["labeled_host_exfil"] > 0).sum()),
                "labeled_host_share": part["labeled_host_exfil"].sum()
                / part["labeled_host_lines"].sum(),
                "hourly_min": part["labeled_host_share"].min(),
                "hourly_median": part["labeled_host_share"].median(),
                "hourly_max": part["labeled_host_share"].max(),
                "all_hosts_share": part["all_hosts_exfil"].sum() / part["all_hosts_lines"].sum(),
            }
        )
    return pd.DataFrame(rows)


def period_summary(periods: Periods) -> pd.DataFrame:
    """List the boundaries of a testbed with the length of each period."""
    spans = {
        "fit": (periods.train_start, periods.fit_end),
        "calib": (periods.fit_end, periods.train_end),
        "training": (periods.train_start, periods.train_end),
        "evaluation": (periods.eval_start, periods.eval_end),
        "evaluation before first attack": (periods.eval_start, periods.first_attack),
    }
    return pd.DataFrame(
        [
            {
                "period": name,
                "start": start.strftime("%Y-%m-%d %H:%M:%S"),
                "end": end.strftime("%Y-%m-%d %H:%M:%S"),
                "hours": round((end - start).total_seconds() / 3600, 2),
            }
            for name, (start, end) in spans.items()
        ]
    )


def training_labels(con: duckdb.DuckDBPyConnection, periods: Periods) -> pd.DataFrame:
    """Count labeled lines inside the training period per log type and phase."""
    return con.execute(
        f"""
        SELECT l.log_type, b.phase, count(*) AS labeled
        FROM labels b JOIN lines l USING (line_id)
        WHERE l.ts < {_stamp(periods.train_end)} GROUP BY ALL ORDER BY 1, 2
        """
    ).df()
