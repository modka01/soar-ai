"""Pluggable embedding providers.

The default ``hashing`` provider is a deterministic, dependency-free
TF-IDF-style projection into a fixed-dimension vector. It requires no external
service, which keeps the platform fully functional in air-gapped SOC
deployments; swap ``SOAR_EMBEDDING_PROVIDER`` to ``voyage`` or ``openai`` for
semantic quality when egress is permitted.
"""

from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod

import httpx

from app.core.config import settings
from app.core.errors import IntegrationError
from app.core.logging import get_logger

logger = get_logger(__name__)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-_.]*")

# Words that carry no discriminative signal in security prose.
_STOPWORDS = frozenset(
    [
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "if",
        "then",
        "than",
        "that",
        "this",
        "these",
        "those",
        "for",
        "with",
        "without",
        "within",
        "from",
        "into",
        "onto",
        "over",
        "under",
        "via",
        "using",
        "use",
        "used",
        "uses",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "to",
        "of",
        "in",
        "on",
        "at",
        "by",
        "as",
        "it",
        "its",
        "it's",
        "not",
        "no",
        "yes",
        "can",
        "could",
        "should",
        "would",
        "may",
        "might",
        "must",
        "will",
        "shall",
        "do",
        "does",
        "did",
        "have",
        "has",
        "had",
        "we",
        "you",
        "they",
        "he",
        "she",
        "them",
        "their",
        "our",
        "your",
        "his",
        "her",
    ]
)


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens, stopwords and 1-2 char noise removed."""
    return [
        token
        for token in _TOKEN_RE.findall(text.lower())
        if len(token) > 2 and token not in _STOPWORDS
    ]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


class EmbeddingProvider(ABC):
    """Contract every embedding backend implements."""

    name: str = "base"

    def __init__(self, dimensions: int) -> None:
        self.dimensions = dimensions

    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Embed a batch of documents."""

    async def embed_query(self, text: str) -> list[float]:
        """Embed a single query. Some providers use a distinct query prompt."""
        vectors = await self.embed([text])
        return vectors[0]


class HashingEmbeddingProvider(EmbeddingProvider):
    """Deterministic hashed bag-of-words with sublinear term weighting.

    Each token is hashed into ``dimensions`` buckets with a signed
    contribution, weighted by ``1 + log(tf)``. The result is L2-normalised so
    cosine similarity is a plain dot product. Deterministic across processes,
    which means embeddings survive restarts without re-indexing.
    """

    name = "hashing"

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(text) for text in texts]

    def _embed_one(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        counts: dict[str, int] = {}
        for token in tokenize(text):
            counts[token] = counts.get(token, 0) + 1
        if not counts:
            return vector

        for token, count in counts.items():
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign * (1.0 + math.log(count))

        norm = math.sqrt(sum(value * value for value in vector))
        if norm > 0:
            vector = [value / norm for value in vector]
        return vector


class VoyageEmbeddingProvider(EmbeddingProvider):
    """Voyage AI embeddings — Anthropic's recommended embedding partner."""

    name = "voyage"
    ENDPOINT = "https://api.voyageai.com/v1/embeddings"

    def __init__(self, dimensions: int, api_key: str | None, model: str) -> None:
        super().__init__(dimensions)
        self.api_key = api_key
        self.model = model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return await self._call(texts, input_type="document")

    async def embed_query(self, text: str) -> list[float]:
        vectors = await self._call([text], input_type="query")
        return vectors[0]

    async def _call(self, texts: list[str], *, input_type: str) -> list[list[float]]:
        if not self.api_key:
            raise IntegrationError(
                "Voyage embeddings selected but SOAR_VOYAGE_API_KEY is not set.",
                details={"integration": "voyage"},
            )
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                self.ENDPOINT,
                headers={"authorization": f"Bearer {self.api_key}"},
                json={"input": texts, "model": self.model, "input_type": input_type},
            )
        if response.status_code >= 400:
            raise IntegrationError(
                f"Voyage embeddings failed (HTTP {response.status_code}).",
                details={"integration": "voyage", "body": response.text[:300]},
            )
        payload = response.json()
        return [item["embedding"] for item in sorted(payload["data"], key=lambda d: d["index"])]


class OpenAIEmbeddingProvider(EmbeddingProvider):
    """OpenAI embeddings, for deployments already standardised on them."""

    name = "openai"
    ENDPOINT = "https://api.openai.com/v1/embeddings"

    def __init__(self, dimensions: int, api_key: str | None, model: str) -> None:
        super().__init__(dimensions)
        self.api_key = api_key
        self.model = model or "text-embedding-3-small"

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if not self.api_key:
            raise IntegrationError(
                "OpenAI embeddings selected but SOAR_OPENAI_API_KEY is not set.",
                details={"integration": "openai"},
            )
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                self.ENDPOINT,
                headers={"authorization": f"Bearer {self.api_key}"},
                json={"input": texts, "model": self.model, "dimensions": self.dimensions},
            )
        if response.status_code >= 400:
            raise IntegrationError(
                f"OpenAI embeddings failed (HTTP {response.status_code}).",
                details={"integration": "openai", "body": response.text[:300]},
            )
        payload = response.json()
        return [item["embedding"] for item in sorted(payload["data"], key=lambda d: d["index"])]


_provider: EmbeddingProvider | None = None


def get_embedding_provider() -> EmbeddingProvider:
    """Build the configured provider once per process."""
    global _provider
    if _provider is not None:
        return _provider

    dimensions = settings.embedding_dimensions
    match settings.embedding_provider:
        case "voyage":
            _provider = VoyageEmbeddingProvider(
                dimensions, settings.voyage_api_key, settings.embedding_model
            )
        case "openai":
            _provider = OpenAIEmbeddingProvider(
                dimensions, settings.openai_api_key, settings.embedding_model
            )
        case _:
            _provider = HashingEmbeddingProvider(dimensions)

    logger.info("embedding_provider_selected", provider=_provider.name, dimensions=dimensions)
    return _provider


def reset_embedding_provider() -> None:
    """Test hook — clears the cached provider."""
    global _provider
    _provider = None
