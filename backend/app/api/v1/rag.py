"""RAG knowledge base: browse, search, index and retrieve."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select

from app.api.deps import CurrentPrincipal, DbSession, PaginationDep, Principal, require_permission
from app.db.models import KnowledgeDocument
from app.schemas.common import Message, Page
from app.schemas.knowledge import (
    ChunkOut,
    DocumentCreate,
    DocumentOut,
    RAGStats,
    RetrievalHit,
    RetrievalRequest,
)
from app.services.audit import AuditService
from app.services.rag import RAGService
from app.services.seed import seed_knowledge_base

router = APIRouter(prefix="/rag", tags=["rag"])


@router.get("/chunks", response_model=Page[ChunkOut], summary="Browse knowledge chunks")
async def list_chunks(
    db: DbSession,
    page: PaginationDep,
    principal: CurrentPrincipal,
    search: Annotated[str | None, Query()] = None,
    category: Annotated[str | None, Query()] = None,
) -> Page[ChunkOut]:
    rows, total = await RAGService(db).list_chunks(
        search=search, category=category, limit=page.limit, offset=page.offset
    )
    return Page(
        items=[ChunkOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post("/retrieve", response_model=list[RetrievalHit], summary="Retrieve relevant context")
async def retrieve(
    payload: RetrievalRequest, db: DbSession, principal: CurrentPrincipal
) -> list[RetrievalHit]:
    results = await RAGService(db).retrieve(
        payload.query,
        top_k=payload.top_k,
        categories=payload.categories,
        sources=payload.sources,
    )
    return [RetrievalHit(**result.to_dict()) for result in results]


@router.get("/stats", response_model=RAGStats, summary="Knowledge base statistics")
async def stats(db: DbSession, principal: CurrentPrincipal) -> RAGStats:
    return RAGStats(**await RAGService(db).stats())


@router.get("/documents", response_model=Page[DocumentOut], summary="List source documents")
async def list_documents(
    db: DbSession, page: PaginationDep, principal: CurrentPrincipal
) -> Page[DocumentOut]:
    total = int(await db.scalar(select(func.count()).select_from(KnowledgeDocument)) or 0)
    rows = list(
        (
            await db.scalars(
                select(KnowledgeDocument)
                .order_by(KnowledgeDocument.created_at.desc())
                .limit(page.limit)
                .offset(page.offset)
            )
        ).all()
    )
    return Page(
        items=[DocumentOut.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.post(
    "/documents",
    response_model=DocumentOut,
    status_code=status.HTTP_201_CREATED,
    summary="Index a document",
)
async def create_document(
    payload: DocumentCreate,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("rag:write"))],
) -> KnowledgeDocument:
    document = await RAGService(db).index_document(
        title=payload.title,
        source=payload.source,
        category=payload.category,
        content=payload.content,
        url=payload.url,
        meta={**payload.meta, "added_by": principal.display_name},
    )
    await AuditService(db).record(
        actor=principal.display_name,
        action="knowledge_index",
        resource_type="document",
        resource_id=document.id,
        detail={"title": payload.title, "chunks": document.chunk_count},
    )
    return document


@router.delete("/documents/{document_id}", response_model=Message, summary="Remove a document")
async def delete_document(
    document_id: str,
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("rag:write"))],
) -> Message:
    await RAGService(db).delete_document(document_id)
    await AuditService(db).record(
        actor=principal.display_name,
        action="knowledge_delete",
        resource_type="document",
        resource_id=document_id,
    )
    return Message(message="Document and its chunks removed.")


@router.post("/seed", response_model=Message, summary="Re-index the baseline knowledge base")
async def reseed(
    db: DbSession,
    principal: Annotated[Principal, Depends(require_permission("settings:write"))],
) -> Message:
    count = await seed_knowledge_base(db)
    return Message(message=f"Baseline knowledge re-indexed ({count} documents).")
