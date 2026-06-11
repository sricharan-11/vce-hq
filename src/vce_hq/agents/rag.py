"""Shared RAG retrieval utility.

Provides a single, reusable function for the RAG pattern used by
all agents: embed query → search LTM → format context string.

This module is the bridge between the embedding service and the
long-term memory store. Agents call ``retrieve_context()`` and
receive a formatted string ready for LLM prompt injection.
"""

import sqlite3

from vce_hq.db.long_term import LongTermMemory
from vce_hq.db.models import VectorSearchResult
from vce_hq.embeddings.service import EmbeddingService


async def retrieve_context(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    query: str,
    *,
    top_k: int = 5,
    category: str | None = None,
    include_resolutions: bool = True,
) -> tuple[str, list[VectorSearchResult]]:
    """Retrieve relevant context from long-term memory via semantic search.

    Performs the full RAG retrieval cycle:
        1. Embed the query using ``RETRIEVAL_QUERY`` task type
        2. Search knowledge chunks in sqlite-vec
        3. Optionally search past incident resolutions
        4. Format results into a context string for LLM consumption

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: The embedding service for query vectorization.
        query: The natural language query to search for.
        top_k: Number of results per source (knowledge + resolutions).
        category: If provided, filter knowledge chunks to this category.
        include_resolutions: Whether to also search past incident resolutions.

    Returns:
        A tuple of (formatted context string, raw search results).
    """
    ltm = LongTermMemory(conn)

    # Step 1: Embed the query
    query_embedding = await embedding_service.embed_query(query)

    # Step 2: Search knowledge chunks
    knowledge_results = ltm.search_knowledge(
        query_embedding, top_k=top_k, category=category
    )

    # Step 3: Optionally search incident resolutions
    resolution_results: list[VectorSearchResult] = []
    if include_resolutions:
        resolution_results = ltm.search_resolutions(
            query_embedding, top_k=top_k
        )

    # Step 4: Format into a context string
    all_results = knowledge_results + resolution_results
    context = _format_results(knowledge_results, resolution_results)

    return context, all_results


def _format_results(
    knowledge: list[VectorSearchResult],
    resolutions: list[VectorSearchResult],
) -> str:
    """Format search results into a structured context string.

    Args:
        knowledge: Results from knowledge chunk search.
        resolutions: Results from incident resolution search.

    Returns:
        A formatted string suitable for LLM prompt injection.
        Returns a "no relevant context" message if both lists are empty.
    """
    if not knowledge and not resolutions:
        return "No relevant historical context found in long-term memory."

    sections: list[str] = []

    if knowledge:
        sections.append("=== RELEVANT KNOWLEDGE (ADRs, Runbooks, Infra Inventory) ===")
        for i, result in enumerate(knowledge, 1):
            sections.append(
                f"\n--- [{i}] Source: {result.source_document} "
                f"(Category: {result.category}, Relevance: {1 - result.distance:.2%}) ---\n"
                f"{result.content}"
            )

    if resolutions:
        sections.append("\n\n=== PAST INCIDENT RESOLUTIONS ===")
        for i, result in enumerate(resolutions, 1):
            sections.append(
                f"\n--- [{i}] Session: {result.source_document} "
                f"(Relevance: {1 - result.distance:.2%}) ---\n"
                f"{result.content}"
            )

    return "\n".join(sections)
