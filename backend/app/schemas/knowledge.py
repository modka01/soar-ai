"""RAG knowledge base schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class DocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    source: str = Field(min_length=1, max_length=120)
    category: str = Field(min_length=1, max_length=80)
    content: str = Field(min_length=10)
    url: str | None = Field(default=None, max_length=1000)
    meta: dict[str, Any] = Field(default_factory=dict)


class DocumentOut(ORMModel):
    id: str
    title: str
    source: str
    category: str
    url: str | None
    chunk_count: int
    created_at: datetime


class ChunkOut(ORMModel):
    id: str
    document_id: str | None
    external_id: str | None
    title: str
    source: str
    category: str
    text: str
    token_count: int
    embedding_model: str


class RetrievalRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    top_k: int = Field(default=4, ge=1, le=20)
    categories: list[str] | None = None
    sources: list[str] | None = None


class RetrievalHit(BaseModel):
    chunk_id: str
    external_id: str | None = None
    title: str
    source: str
    category: str
    text: str
    score: float


class RAGStats(BaseModel):
    total_chunks: int
    total_documents: int
    avg_tokens_per_chunk: float
    embedding_model: str
    dimensions: int
    chunk_size: int
    chunk_overlap: int
    top_k: int
    by_source: list[dict[str, Any]]
    by_category: list[dict[str, Any]]
