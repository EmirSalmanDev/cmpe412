"""Incident memory (plan 8.2): finalized reports, searched by embedding, with no look-ahead."""

from datetime import datetime
from typing import Any

from chromadb.api.models.Collection import Collection

from logtriage.rag.attack_index import Embedder

DEFAULT_RUN = "default"


def report_document(report: dict[str, Any]) -> str:
    """Return the indexed text of a report: summary claims, techniques and verdict (plan 5.7)."""
    claims = " ".join(claim["text"] for claim in report["summary"])
    techniques = ", ".join(
        f"{item['technique_id']} {item['name']}" for item in report["techniques"]
    )
    return f"{claims} Techniques: {techniques}. Verdict: {report['verdict']}."


class IncidentStore:
    """Finalized reports of a testbed."""

    def __init__(self, collection: Collection, embedder: Embedder) -> None:
        self.collection = collection
        self.embedder = embedder

    def add(
        self, report: dict[str, Any], testbed: str, start: datetime, run: str = DEFAULT_RUN
    ) -> None:
        """Store or replace a finalized report.

        Args:
            report: `IncidentReport` as a dict.
            testbed: Testbed name.
            start: Start of the incident, tz-aware.
            run: Evaluation run, so that runs do not see each other.
        """
        document = report_document(report)
        self.collection.upsert(
            ids=[f"{run}:{testbed}:{report['incident_id']}"],
            documents=[document],
            embeddings=self.embedder.documents([document]),
            metadatas=[
                {
                    "testbed": testbed,
                    "incident_id": report["incident_id"],
                    "start": start.timestamp(),
                    "verdict": report["verdict"],
                    "run": run,
                }
            ],
        )

    def search(
        self,
        text: str,
        k: int,
        testbed: str,
        before: datetime | None = None,
        run: str = DEFAULT_RUN,
    ) -> list[dict[str, Any]]:
        """Return the nearest reports of the same testbed and run.

        Args:
            text: Free text.
            k: Number of results.
            testbed: Testbed name.
            before: Only incidents that started earlier than this, tz-aware.
            run: Evaluation run.

        Returns:
            Metadata of each report, with its `document` and cosine `distance`, best first.
        """
        filters: list[dict[str, Any]] = [{"testbed": testbed}, {"run": run}]
        if before is not None:
            filters.append({"start": {"$lt": before.timestamp()}})
        found = self.collection.query(
            query_embeddings=[self.embedder.query(text)],
            n_results=k,
            where={"$and": filters},
        )
        rows = zip(found["metadatas"][0], found["documents"][0], found["distances"][0], strict=True)
        return [
            {**metadata, "document": document, "distance": distance}
            for metadata, document, distance in rows
        ]
