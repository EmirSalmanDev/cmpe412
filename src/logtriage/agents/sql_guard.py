"""SQL guard of the `run_sql` tool (plan 7.3).

It works on DuckDB's own parse tree, not on the text, and it fails closed: a statement is accepted
only if every table reference is of a kind it knows and names a table of `agent.duckdb`. The
connection from `store.connect_agent` is the second layer, which blocks file access by itself.
"""

import json
import re
import threading
from typing import Any

import duckdb
import pandas as pd

ALLOWED_REFERENCES = {"BASE_TABLE", "EMPTY", "EXPRESSION_LIST", "JOIN", "SUBQUERY"}
ALLOWED_SCHEMAS = {"", "main"}
PLAIN_NAME = re.compile(r"\w+\Z")


class SqlRejected(ValueError):
    """The query is not a single read of the agent tables."""


def agent_tables(connection: duckdb.DuckDBPyConnection) -> set[str]:
    """Return the names of the tables an agent may read."""
    rows = connection.execute("SELECT table_name FROM duckdb_tables() WHERE NOT internal")
    return {row[0] for row in rows.fetchall()}


def _single_select(connection: duckdb.DuckDBPyConnection, query: str) -> str:
    """Return the text of the one SELECT statement in `query`."""
    try:
        statements = connection.extract_statements(query)
    except duckdb.Error as error:
        raise SqlRejected(f"not valid SQL: {error}") from error
    if len(statements) != 1:
        raise SqlRejected("exactly one statement is allowed")
    if statements[0].type != duckdb.StatementType.SELECT:
        raise SqlRejected("only SELECT and WITH are allowed")
    return statements[0].query.strip().rstrip(";")


def _parse_tree(connection: duckdb.DuckDBPyConnection, statement: str) -> dict[str, Any]:
    """Return DuckDB's parse tree of a statement."""
    row = connection.execute("SELECT json_serialize_sql(?)", [statement]).fetchone()
    tree = json.loads(row[0])
    if tree.get("error"):
        raise SqlRejected("only SELECT and WITH are allowed")
    return tree


def _nodes(tree: Any) -> list[dict[str, Any]]:
    """Return every object of a parse tree."""
    found, pending = [], [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            found.append(node)
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    return found


def _common_table_names(nodes: list[dict[str, Any]]) -> set[str]:
    """Return the WITH names of a query, which must be plain names."""
    names = set()
    for node in nodes:
        for entry in node.get("cte_map", {}).get("map", []):
            if not PLAIN_NAME.match(entry["key"]):
                raise SqlRejected(f"bad WITH name: {entry['key']}")
            names.add(entry["key"].lower())
    return names


def _check_reference(reference: dict[str, Any], allowed: set[str]) -> None:
    """Check one FROM item, going through the sides of a join."""
    kind = reference.get("type")
    if kind not in ALLOWED_REFERENCES:
        raise SqlRejected(f"not allowed in FROM: {kind}")
    if kind == "JOIN":
        _check_reference(reference["left"], allowed)
        _check_reference(reference["right"], allowed)
    if kind == "BASE_TABLE":
        name = reference["table_name"]
        in_place = reference.get("schema_name", "") in ALLOWED_SCHEMAS
        if not in_place or reference.get("catalog_name") or name.lower() not in allowed:
            raise SqlRejected(f"unknown table: {name}")


def check_query(connection: duckdb.DuckDBPyConnection, query: str, tables: set[str]) -> str:
    """Accept one read of the agent tables, or raise.

    Args:
        connection: Connection from `store.connect_agent`.
        query: SQL text.
        tables: Output of `agent_tables`.

    Returns:
        The statement, without its final semicolon.

    Raises:
        SqlRejected: If it is anything else.
    """
    statement = _single_select(connection, query)
    nodes = _nodes(_parse_tree(connection, statement))
    allowed = {name.lower() for name in tables} | _common_table_names(nodes)
    for node in nodes:
        if node.get("type") == "TABLE_FUNCTION":
            raise SqlRejected("table functions are not allowed")
        if "from_table" in node:
            _check_reference(node["from_table"], allowed)
    return statement


def run_guarded(
    connection: duckdb.DuckDBPyConnection,
    query: str,
    tables: set[str],
    limit: int,
    timeout_seconds: float,
) -> pd.DataFrame:
    """Run a checked query with a row limit and a time limit.

    Args:
        connection: Connection from `store.connect_agent`.
        query: SQL text.
        tables: Output of `agent_tables`.
        limit: Most rows returned, whatever the query asks for.
        timeout_seconds: The query is interrupted after this long.

    Returns:
        The rows.

    Raises:
        SqlRejected: If the guard refuses the query.
        TimeoutError: If the query runs out of time.
    """
    statement = check_query(connection, query, tables)
    timer = threading.Timer(timeout_seconds, connection.interrupt)
    timer.start()
    try:
        return connection.execute(
            f"SELECT * FROM (\n{statement}\n) AS guarded LIMIT {int(limit)}"
        ).df()
    except duckdb.InterruptException as error:
        raise TimeoutError(f"query stopped after {timeout_seconds} s") from error
    finally:
        timer.cancel()
