"""Retrieval-augmented generation over the security knowledge base.

Indexing splits a document into overlapping chunks, embeds each one, and
persists it. Retrieval embeds the query and ranks chunks by cosine similarity,
with a lexical overlap bonus so exact identifiers (``CVE-2024-3400``,
``T1021.002``) reliably surface even under a weak embedding provider.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.db.models import KnowledgeChunk, KnowledgeDocument
from app.services.embeddings import cosine_similarity, get_embedding_provider, tokenize

logger = get_logger(__name__)

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n{2,}")
#: Identifiers that must match exactly to be useful: CVEs, MITRE techniques, hashes.
_IDENTIFIER = re.compile(r"\b(?:cve-\d{4}-\d{4,7}|t\d{4}(?:\.\d{3})?|[a-f0-9]{32,64})\b", re.I)


@dataclass(slots=True)
class RetrievalResult:
    chunk_id: str
    title: str
    source: str
    category: str
    text: str
    score: float
    external_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "external_id": self.external_id,
            "title": self.title,
            "source": self.source,
            "category": self.category,
            "text": self.text,
            "score": round(self.score, 4),
        }


def chunk_text(text: str, *, size: int | None = None, overlap: int | None = None) -> list[str]:
    """Split prose into ~``size``-token chunks with ``overlap`` tokens of context.

    Splitting happens on sentence boundaries so a detection description is never
    cut mid-sentence, which would strand the indicator from its meaning.
    """
    size = size or settings.rag_chunk_size
    overlap = overlap or settings.rag_chunk_overlap
    if overlap >= size:
        overlap = size // 4

    sentences = [s.strip() for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    if not sentences:
        return []

    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for sentence in sentences:
        sentence_len = len(sentence.split())
        if current_len + sentence_len > size and current:
            chunks.append(" ".join(current))
            # Carry the tail of the previous chunk forward as overlap.
            carry: list[str] = []
            carry_len = 0
            for prev in reversed(current):
                prev_len = len(prev.split())
                if carry_len + prev_len > overlap:
                    break
                carry.insert(0, prev)
                carry_len += prev_len
            current = carry
            current_len = carry_len
        current.append(sentence)
        current_len += sentence_len

    if current:
        chunks.append(" ".join(current))
    return chunks


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class RAGService:
    """Indexes and retrieves knowledge chunks."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.embedder = get_embedding_provider()

    # ── indexing ─────────────────────────────────────────────────────

    async def index_document(
        self,
        *,
        title: str,
        source: str,
        category: str,
        content: str,
        url: str | None = None,
        meta: dict[str, Any] | None = None,
        external_id: str | None = None,
    ) -> KnowledgeDocument:
        """Create or refresh a document and (re)build its chunks.

        Re-indexing an unchanged document is a no-op — the content hash guards
        against burning embedding quota on every sync.
        """
        digest = content_hash(content)
        existing = await self.db.scalar(
            select(KnowledgeDocument).where(
                KnowledgeDocument.title == title, KnowledgeDocument.source == source
            )
        )

        if existing and existing.content_hash == digest:
            logger.debug("rag_document_unchanged", title=title, source=source)
            return existing

        document = existing or KnowledgeDocument(
            title=title, source=source, category=category, content=content, content_hash=digest
        )
        document.title = title
        document.source = source
        document.category = category
        document.content = content
        document.content_hash = digest
        document.url = url
        document.meta = meta or {}

        if existing:
            await self.db.execute(
                delete(KnowledgeChunk).where(KnowledgeChunk.document_id == existing.id)
            )
        else:
            self.db.add(document)
            await self.db.flush()

        pieces = chunk_text(content) or [content]
        vectors = await self.embedder.embed(pieces)

        for position, (piece, vector) in enumerate(zip(pieces, vectors, strict=True)):
            self.db.add(
                KnowledgeChunk(
                    document_id=document.id,
                    external_id=(
                        f"{external_id}-{position}"
                        if external_id and len(pieces) > 1
                        else external_id
                    ),
                    title=title if len(pieces) == 1 else f"{title} ({position + 1}/{len(pieces)})",
                    source=source,
                    category=category,
                    text=piece,
                    token_count=len(piece.split()),
                    embedding=vector,
                    embedding_model=self.embedder.name,
                    meta={"position": position, **(meta or {})},
                )
            )

        document.chunk_count = len(pieces)
        await self.db.flush()
        logger.info("rag_document_indexed", title=title, source=source, chunks=len(pieces))
        return document

    async def delete_document(self, document_id: str) -> None:
        document = await self.db.get(KnowledgeDocument, document_id)
        if document is None:
            raise NotFoundError(f"Knowledge document {document_id} does not exist.")
        await self.db.delete(document)

    # ── retrieval ────────────────────────────────────────────────────

    async def retrieve(
        self,
        query: str,
        *,
        top_k: int | None = None,
        categories: list[str] | None = None,
        sources: list[str] | None = None,
        min_score: float | None = None,
    ) -> list[RetrievalResult]:
        """Rank chunks against ``query``. Returns at most ``top_k`` results."""
        top_k = top_k or settings.rag_top_k
        min_score = settings.rag_min_score if min_score is None else min_score

        statement = select(KnowledgeChunk)
        if categories:
            statement = statement.where(KnowledgeChunk.category.in_(categories))
        if sources:
            statement = statement.where(KnowledgeChunk.source.in_(sources))

        chunks = list((await self.db.scalars(statement)).all())
        if not chunks:
            return []

        query_vector = await self.embedder.embed_query(query)
        query_tokens = set(tokenize(query))
        query_identifiers = {m.lower() for m in _IDENTIFIER.findall(query)}

        scored: list[RetrievalResult] = []
        for chunk in chunks:
            embedding = chunk.embedding or []
            score = cosine_similarity(query_vector, embedding) if embedding else 0.0
            score += self._lexical_bonus(chunk, query_tokens, query_identifiers)
            if score >= min_score:
                scored.append(
                    RetrievalResult(
                        chunk_id=chunk.id,
                        external_id=chunk.external_id,
                        title=chunk.title,
                        source=chunk.source,
                        category=chunk.category,
                        text=chunk.text,
                        score=score,
                    )
                )

        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]

    @staticmethod
    def _lexical_bonus(
        chunk: KnowledgeChunk, query_tokens: set[str], query_identifiers: set[str]
    ) -> float:
        """Reward exact-identifier and keyword overlap on top of vector similarity."""
        bonus = 0.0
        haystack = f"{chunk.title} {chunk.text}".lower()

        for identifier in query_identifiers:
            if identifier in haystack:
                # An exact CVE/technique match is near-conclusive evidence of relevance.
                bonus += 0.35

        if query_tokens:
            chunk_tokens = set(tokenize(f"{chunk.title} {chunk.text}"))
            overlap = len(query_tokens & chunk_tokens) / len(query_tokens)
            bonus += 0.15 * overlap

        return bonus

    @staticmethod
    def build_context(results: list[RetrievalResult], *, max_chars: int = 6000) -> str:
        """Render retrieved chunks as a prompt block, truncated to a token budget."""
        if not results:
            return ""
        blocks: list[str] = []
        used = 0
        for result in results:
            block = f"[{result.source} | {result.title}]\n{result.text}"
            if used + len(block) > max_chars:
                break
            blocks.append(block)
            used += len(block)
        return "\n\n---\n\n".join(blocks)

    # ── browse / stats ───────────────────────────────────────────────

    async def list_chunks(
        self,
        *,
        search: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[KnowledgeChunk], int]:
        statement = select(KnowledgeChunk)
        count_statement = select(func.count()).select_from(KnowledgeChunk)

        if search:
            pattern = f"%{search.lower()}%"
            condition = func.lower(KnowledgeChunk.title).like(pattern) | func.lower(
                KnowledgeChunk.text
            ).like(pattern)
            statement = statement.where(condition)
            count_statement = count_statement.where(condition)
        if category:
            statement = statement.where(KnowledgeChunk.category == category)
            count_statement = count_statement.where(KnowledgeChunk.category == category)

        total = int(await self.db.scalar(count_statement) or 0)
        rows = list(
            (
                await self.db.scalars(
                    statement.order_by(KnowledgeChunk.source, KnowledgeChunk.title)
                    .limit(limit)
                    .offset(offset)
                )
            ).all()
        )
        return rows, total

    async def stats(self) -> dict[str, Any]:
        """Counts powering the RAG module's Sources / Embedding Stats panels."""
        total_chunks = int(
            await self.db.scalar(select(func.count()).select_from(KnowledgeChunk)) or 0
        )
        total_docs = int(
            await self.db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0
        )
        avg_tokens = float(await self.db.scalar(select(func.avg(KnowledgeChunk.token_count))) or 0)

        by_source = [
            {"source": source, "count": count}
            for source, count in (
                await self.db.execute(
                    select(KnowledgeChunk.source, func.count())
                    .group_by(KnowledgeChunk.source)
                    .order_by(func.count().desc())
                )
            ).all()
        ]
        by_category = [
            {"category": category, "count": count}
            for category, count in (
                await self.db.execute(
                    select(KnowledgeChunk.category, func.count())
                    .group_by(KnowledgeChunk.category)
                    .order_by(func.count().desc())
                )
            ).all()
        ]

        return {
            "total_chunks": total_chunks,
            "total_documents": total_docs,
            "avg_tokens_per_chunk": round(avg_tokens, 1),
            "embedding_model": self.embedder.name,
            "dimensions": self.embedder.dimensions,
            "chunk_size": settings.rag_chunk_size,
            "chunk_overlap": settings.rag_chunk_overlap,
            "top_k": settings.rag_top_k,
            "by_source": by_source,
            "by_category": by_category,
        }
