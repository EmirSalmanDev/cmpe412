"""ATT&CK index (plan 8.1): one document per technique, searched by embedding."""

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import chromadb
from chromadb.api.models.Collection import Collection

from logtriage.config import RagConfig, Settings

logger = logging.getLogger(__name__)

CHROMA_DIR = "chroma"
BATCH = 500
CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
MARKUP = re.compile(r"</?[a-zA-Z][^>]*>")
SPACE = re.compile(r"\s+")


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


class AttackIndex:
    """Search over the ATT&CK collection."""

    def __init__(self, collection: Collection, embedder: Embedder) -> None:
        self.collection = collection
        self.embedder = embedder

    def search(self, text: str, k: int) -> list[dict[str, Any]]:
        """Return the `k` nearest techniques, best first.

        Args:
            text: Free text.
            k: Number of results.

        Returns:
            Metadata of each technique, with its `document` and cosine `distance`.
        """
        found = self.collection.query(query_embeddings=[self.embedder.query(text)], n_results=k)
        rows = zip(found["metadatas"][0], found["documents"][0], found["distances"][0], strict=True)
        return [
            {**metadata, "document": document, "distance": distance}
            for metadata, document, distance in rows
        ]


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
