"""SQLite cache of LLM answers and ledger of real spending (plan 7.1)."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS answers (key TEXT PRIMARY KEY, answer TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS spend (
    at TEXT NOT NULL, model TEXT NOT NULL, role TEXT NOT NULL, usd REAL NOT NULL
);
"""


def cache_key(
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    params: dict[str, Any],
    condition: dict[str, bool],
) -> str:
    """Return the key of a request: `sha256(model, messages, tools, params)` and the condition.

    Args:
        model: Model string.
        messages: The messages, as plain data.
        tools: Tool schemas, if any.
        params: Request parameters.
        condition: Ablation switches, so that conditions never share an answer (plan 10.4).

    Returns:
        The hex digest.
    """
    request = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "params": params,
        "condition": condition,
    }
    text = json.dumps(request, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class LlmCache:
    """Answers by request key, and every paid call."""

    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # Streamlit runs each rerun on a new thread; its calls are serialized by the chat lock.
        self.connection = sqlite3.connect(str(path), check_same_thread=False)
        self.connection.executescript(SCHEMA)

    def get(self, key: str) -> dict[str, Any] | None:
        """Return a stored answer, or None."""
        row = self.connection.execute("SELECT answer FROM answers WHERE key = ?", [key]).fetchone()
        return None if row is None else json.loads(row[0])

    def put(self, key: str, answer: dict[str, Any]) -> None:
        """Store or replace an answer."""
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO answers VALUES (?, ?)", [key, json.dumps(answer)]
            )

    def record_spend(self, model: str, role: str, usd: float) -> None:
        """Add one paid call to the ledger."""
        with self.connection:
            self.connection.execute(
                "INSERT INTO spend VALUES (?, ?, ?, ?)",
                [datetime.now(UTC).isoformat(), model, role, usd],
            )

    def total_spend(self) -> float:
        """Return the USD paid over all runs."""
        return self.connection.execute("SELECT coalesce(sum(usd), 0) FROM spend").fetchone()[0]

    def role_spend(self, role: str) -> float:
        """Return the USD paid for one agent role over all runs."""
        return self.connection.execute(
            "SELECT coalesce(sum(usd), 0) FROM spend WHERE role = ?", [role]
        ).fetchone()[0]

    def close(self) -> None:
        """Close the file."""
        self.connection.close()
