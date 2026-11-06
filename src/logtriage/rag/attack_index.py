"""ATT&CK index (plan 8.1): one document per technique, searched by embedding and by keyword."""

import hashlib
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import chromadb
import numpy as np
from chromadb.api.models.Collection import Collection

from logtriage.config import RagConfig, Settings

logger = logging.getLogger(__name__)

CHROMA_DIR = "chroma"
BATCH = 500
CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
MARKUP = re.compile(r"</?[a-zA-Z][^>]*>")
SPACE = re.compile(r"\s+")
TOKEN = re.compile(r"[a-z0-9]+")


class Embedder(Protocol):
    """Turns text into vectors. Documents and queries may be embedded differently."""

    def documents(self, texts: list[str]) -> list[list[float]]:
        """Embed documents."""
        ...

    def query(self, text: str) -> list[float]:
        """Embed a search query."""
        ...


class BgeEmbedder:
    """The sentence-transformers model of plan 8.1, loaded on first use."""

    def __init__(self, config: RagConfig) -> None:
        self.config = config
        self._model: Any = None

    @property
    def model(self) -> Any:
        """Load the model, which is slow and may download it once."""
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self.config.embedding_model)
        return self._model

    def documents(self, texts: list[str]) -> list[list[float]]:
        """Embed documents, normalized."""
        return self.model.encode(texts, normalize_embeddings=True).tolist()

    def query(self, text: str) -> list[float]:
        """Embed a query with the instruction prefix of the model, normalized."""
        prompt = self.config.query_prefix + text
        return self.model.encode([prompt], normalize_embeddings=True)[0].tolist()


@dataclass
class Technique:
    """One technique or sub-technique."""

    technique_id: str
    name: str
    description: str
    tactics: list[str]
    is_subtechnique: bool

    @property
    def document(self) -> str:
        """Return the indexed text."""
        return f"{self.technique_id} {self.name}. {self.description}"


def clean_text(text: str) -> str:
    """Remove citations, Markdown links and HTML tags from a description."""
    text = LINK.sub(r"\1", CITATION.sub("", text))
    return SPACE.sub(" ", MARKUP.sub("", text)).strip()


def _technique_id(item: dict[str, Any]) -> str | None:
    """Return the ATT&CK ID of a STIX object."""
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def load_techniques(path: Path) -> list[Technique]:
    """Read the usable techniques of a STIX bundle.

    Args:
        path: `enterprise-attack.json`.

    Returns:
        Techniques and sub-techniques, without revoked or deprecated objects, sorted by ID.
    """
    objects = json.loads(path.read_text(encoding="utf-8"))["objects"]
    techniques = []
    for item in objects:
        usable = not item.get("revoked") and not item.get("x_mitre_deprecated")
        technique_id = _technique_id(item)
        if item.get("type") != "attack-pattern" or not usable or technique_id is None:
            continue
        techniques.append(
            Technique(
                technique_id=technique_id,
                name=item["name"],
                description=clean_text(item.get("description", "")),
                tactics=[step["phase_name"] for step in item.get("kill_chain_phases", [])],
                is_subtechnique=bool(item.get("x_mitre_is_subtechnique")),
            )
        )
    return sorted(techniques, key=lambda technique: technique.technique_id)


def file_digest(path: Path) -> str:
    """Return the SHA-256 of a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def open_client(index_dir: Path) -> chromadb.api.ClientAPI:
    """Open the persistent Chroma store, with telemetry off."""
    return chromadb.PersistentClient(
        path=str(index_dir / CHROMA_DIR),
        settings=chromadb.Settings(anonymized_telemetry=False),
    )


def cosine_collection(client: chromadb.api.ClientAPI, name: str) -> Collection:
    """Return a collection that compares by cosine distance. Vectors always come from us."""
    return client.get_or_create_collection(
        name, embedding_function=None, configuration={"hnsw": {"space": "cosine"}}
    )


def build_index(
    techniques: list[Technique],
    client: chromadb.api.ClientAPI,
    embedder: Embedder,
    name: str,
) -> int:
    """Replace the collection with the given techniques.

    Args:
        techniques: Output of `load_techniques`.
        client: Chroma client.
        embedder: Embedding model.
        name: Collection name.

    Returns:
        The number of indexed techniques.
    """
    if name in [item.name for item in client.list_collections()]:
        client.delete_collection(name)
    collection = cosine_collection(client, name)
    for start in range(0, len(techniques), BATCH):
        part = techniques[start : start + BATCH]
        texts = [technique.document for technique in part]
        collection.add(
            ids=[technique.technique_id for technique in part],
            documents=texts,
            embeddings=embedder.documents(texts),
            metadatas=[
                {
                    "id": technique.technique_id,
                    "name": technique.name,
                    "tactics": ", ".join(technique.tactics),
                    "is_subtechnique": technique.is_subtechnique,
                }
                for technique in part
            ],
        )
    return collection.count()


def tokenize(text: str) -> list[str]:
    """Split text into lowercase alphanumeric tokens."""
    return TOKEN.findall(text.lower())


def bm25_scores(documents: list[list[str]], query: list[str], k1: float, b: float) -> np.ndarray:
    """Return the Okapi BM25 score of each tokenized document for a tokenized query.

    Args:
        documents: Tokens of each document.
        query: Tokens of the query.
        k1: Term frequency saturation.
        b: Length normalization.

    Returns:
        One score per document.
    """
    lengths = np.array([len(document) for document in documents], dtype=float)
    counts = [Counter(document) for document in documents]
    scores = np.zeros(len(documents))
    for term in set(query):
        frequency = np.array([count[term] for count in counts], dtype=float)
        holding = int((frequency > 0).sum())
        rarity = np.log(1 + (len(documents) - holding + 0.5) / (holding + 0.5))
        norm = k1 * (1 - b + b * lengths / lengths.mean())
        scores += rarity * frequency * (k1 + 1) / (frequency + norm)
    return scores


def fuse_ranks(rankings: list[list[str]], k: int) -> dict[str, float]:
    """Combine rankings by Reciprocal Rank Fusion, with equal weights.

    Args:
        rankings: IDs of each ranking, best first.
        k: Damping constant.

    Returns:
        ID to fused score.
    """
    fused: dict[str, float] = {}
    for ranking in rankings:
        for position, item in enumerate(ranking, 1):
            fused[item] = fused.get(item, 0.0) + 1 / (k + position)
    return fused


class AttackIndex:
    """Hybrid search over the ATT&CK collection (D43)."""

    def __init__(self, collection: Collection, embedder: Embedder, config: RagConfig) -> None:
        self.collection = collection
        self.embedder = embedder
        self.config = config
        self._entries: dict[str, dict[str, Any]] | None = None
        self._tokens: list[list[str]] = []

    @property
    def entries(self) -> dict[str, dict[str, Any]]:
        """Read the metadata and tokens of every technique once."""
        if self._entries is None:
            found = self.collection.get(include=["metadatas", "documents"])
            rows = zip(found["ids"], found["metadatas"], found["documents"], strict=True)
            self._entries = {
                item: {**metadata, "document": document} for item, metadata, document in rows
            }
            self._tokens = [tokenize(entry["document"]) for entry in self._entries.values()]
        return self._entries

    def search(self, text: str, k: int) -> list[dict[str, Any]]:
        """Return the `k` best techniques by fused dense and keyword rank.

        Args:
            text: Free text.
            k: Number of results.

        Returns:
            Metadata of each technique, with its `document` and fused `score`, best first.
        """
        entries = self.entries
        if not entries:
            return []
        found = self.collection.query(
            query_embeddings=[self.embedder.query(text)],
            n_results=len(entries),
            include=[],
        )
        scores = bm25_scores(self._tokens, tokenize(text), self.config.bm25_k1, self.config.bm25_b)
        ids = list(entries)
        keyword = [ids[position] for position in np.argsort(-scores, kind="stable")]
        fused = fuse_ranks([found["ids"][0], keyword], self.config.rrf_k)
        best = sorted(fused, key=lambda item: (-fused[item], item))[:k]
        return [{**entries[item], "score": fused[item]} for item in best]


def run_index_attack(settings: Settings, embedder: Embedder | None = None) -> int:
    """Build the ATT&CK index from the pinned local bundle. It downloads no bundle.

    Args:
        settings: Loaded settings.
        embedder: Embedding model; the configured one if None.

    Returns:
        The number of indexed techniques.

    Raises:
        FileNotFoundError: If the bundle is missing.
        ValueError: If the bundle is not the pinned one.
    """
    path = settings.paths.attack_stix_file
    if not path.is_file():
        raise FileNotFoundError(f"{path} is missing")
    digest = file_digest(path)
    if digest != settings.rag.attack_sha256:
        raise ValueError(f"{path}: sha256 {digest} is not the pinned bundle")
    client = open_client(settings.paths.index_dir)
    model = embedder or BgeEmbedder(settings.rag)
    count = build_index(load_techniques(path), client, model, settings.rag.attack_collection)
    logger.info("indexed %d techniques", count)
    return count
