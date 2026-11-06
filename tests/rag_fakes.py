"""Test helpers for the RAG code: a fake embedder and a report, so no model is needed."""

import hashlib
from pathlib import Path

import numpy as np

BUNDLE = Path(__file__).parent / "fixtures" / "attack_mini.json"


class FakeEmbedder:
    """Bag of hashed words, normalized: texts sharing words are close."""

    def _vector(self, text: str) -> list[float]:
        vector = np.zeros(64)
        for word in text.lower().replace(".", " ").split():
            vector[hashlib.sha256(word.encode()).digest()[0] % 64] += 1
        return (vector / max(np.linalg.norm(vector), 1e-9)).tolist()

    def documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def query(self, text: str) -> list[float]:
        return self._vector(text)


def report(incident_id: str, text: str, verdict: str = "malicious") -> dict:
    """Return the parts of a finalized report that the incident memory reads."""
    return {
        "incident_id": incident_id,
        "summary": [{"text": text, "evidence": ["E1"]}],
        "techniques": [{"technique_id": "T1048", "name": "Exfiltration"}],
        "verdict": verdict,
    }
