"""Chunking, embedding and retrieval."""

from __future__ import annotations

import pytest
from app.services.embeddings import (
    HashingEmbeddingProvider,
    cosine_similarity,
    tokenize,
)
from app.services.rag import RAGService, chunk_text


def test_tokenize_drops_stopwords_and_short_tokens():
    tokens = tokenize("The adversary is using DNS tunneling to a C2 server")
    assert "adversary" in tokens
    assert "tunneling" in tokens
    assert "the" not in tokens
    assert "is" not in tokens


def test_chunking_respects_size_and_overlaps():
    text = ". ".join(f"Sentence number {i} about lateral movement detection" for i in range(40))
    chunks = chunk_text(text, size=50, overlap=10)
    assert len(chunks) > 1
    assert all(len(chunk.split()) <= 70 for chunk in chunks)


def test_chunking_short_text_yields_one_chunk():
    assert len(chunk_text("A single short sentence.", size=256, overlap=50)) == 1


async def test_hashing_embeddings_are_deterministic():
    provider = HashingEmbeddingProvider(dimensions=128)
    first, second = await provider.embed(["PsExec lateral movement"] * 2)
    assert first == second
    assert len(first) == 128


async def test_hashing_embeddings_are_normalised():
    provider = HashingEmbeddingProvider(dimensions=128)
    [vector] = await provider.embed(["Kerberoasting detection via event 4769"])
    magnitude = sum(value * value for value in vector) ** 0.5
    assert magnitude == pytest.approx(1.0, abs=1e-6)


async def test_similar_text_scores_higher_than_unrelated():
    provider = HashingEmbeddingProvider(dimensions=512)
    query, related, unrelated = await provider.embed(
        [
            "lateral movement psexec smb admin shares",
            "psexec creates a service over smb admin shares for lateral movement",
            "quarterly financial reporting and budget reconciliation",
        ]
    )
    assert cosine_similarity(query, related) > cosine_similarity(query, unrelated)


def test_cosine_similarity_edge_cases():
    assert cosine_similarity([], []) == 0.0
    assert cosine_similarity([0.0, 0.0], [1.0, 1.0]) == 0.0
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


async def test_index_and_retrieve(db):
    rag = RAGService(db)
    await rag.index_document(
        title="T1021.002 SMB PsExec",
        source="MITRE ATT&CK",
        category="Lateral Movement",
        content=(
            "PsExec creates a PSEXESVC service on the remote host over the ADMIN$ share. "
            "Monitor Windows Event ID 7045 for service creation with this name."
        ),
    )
    await rag.index_document(
        title="Expense Policy",
        source="Internal",
        category="Admin",
        content="Employees submit expense claims within thirty days of the transaction date.",
    )

    results = await rag.retrieve("psexec service creation event 7045", top_k=2)
    assert results
    assert results[0].source == "MITRE ATT&CK"


async def test_exact_identifier_match_is_prioritised(db):
    rag = RAGService(db)
    await rag.index_document(
        title="Palo Alto advisory",
        source="CVE Database",
        category="Vulnerability",
        content="CVE-2024-3400 is an unauthenticated command injection in PAN-OS GlobalProtect.",
    )
    await rag.index_document(
        title="General patching guidance",
        source="Internal",
        category="Process",
        content="Apply vendor patches to internet-facing appliances within seven days.",
    )

    results = await rag.retrieve("What do we know about CVE-2024-3400?", top_k=2)
    assert results[0].source == "CVE Database"


async def test_reindexing_identical_content_does_not_duplicate_chunks(db):
    rag = RAGService(db)
    payload = {
        "title": "Ransomware playbook",
        "source": "IR Playbook",
        "category": "Response",
        "content": "Isolate the endpoint, then snapshot before any recovery attempt is made.",
    }
    await rag.index_document(**payload)
    first = (await rag.stats())["total_chunks"]
    await rag.index_document(**payload)
    assert (await rag.stats())["total_chunks"] == first


def test_build_context_respects_the_character_budget():
    from app.services.rag import RetrievalResult

    results = [
        RetrievalResult(
            chunk_id=str(i),
            title=f"Doc {i}",
            source="Test",
            category="Test",
            text="x" * 3000,
            score=1.0,
        )
        for i in range(5)
    ]
    assert len(RAGService.build_context(results, max_chars=6000)) <= 6200
