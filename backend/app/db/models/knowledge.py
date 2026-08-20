"""RAG knowledge base: source documents and their embedded chunks."""

from __future__ import annotations

from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, JSONBType, TimestampMixin, UUIDPrimaryKeyMixin


class KnowledgeDocument(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An ingested source: MITRE page, CVE record, IR playbook, vendor doc."""

    __tablename__ = "knowledge_documents"

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    url: Mapped[str | None] = mapped_column(String(1000))
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)

    chunks: Mapped[list[KnowledgeChunk]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class KnowledgeChunk(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A retrievable slice of a document plus its embedding.

    The embedding is stored as a float array in JSON so the schema works on
    stock PostgreSQL. When the ``vector`` extension is available the
    ``embedding_vector`` column is populated by migration and used for ANN
    search; otherwise retrieval falls back to in-process cosine similarity.
    """

    __tablename__ = "knowledge_chunks"
    __table_args__ = (Index("ix_knowledge_chunks_source_category", "source", "category"),)

    document_id: Mapped[str | None] = mapped_column(
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"), index=True
    )
    external_id: Mapped[str | None] = mapped_column(String(120), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    source: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    token_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    embedding: Mapped[list[Any]] = mapped_column(JSONBType, default=list, nullable=False)
    embedding_model: Mapped[str] = mapped_column(String(80), nullable=False, default="hashing")
    meta: Mapped[dict[str, Any]] = mapped_column(JSONBType, default=dict, nullable=False)

    document: Mapped[KnowledgeDocument | None] = relationship(back_populates="chunks")
