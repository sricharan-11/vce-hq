"""Knowledge ingestion pipeline.

Orchestrates the full flow: document → chunk → embed → store.

This pipeline is designed to run asynchronously and independently of
the main request path. It can be triggered via the API when a tenant
uploads new knowledge documents.

Usage:
    pipeline = IngestionPipeline(conn, embedding_service)
    stats = await pipeline.ingest(
        tenant_id="tenant-123",
        document_name="vpc-migration-adr.md",
        content="...",
        category=KnowledgeCategory.ADR,
    )
"""

import asyncio
import logging
import sqlite3
from dataclasses import dataclass

from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from vce_hq.config import settings
from vce_hq.db.long_term import LongTermMemory
from vce_hq.db.models import KnowledgeCategory, KnowledgeChunk
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.ingestion.chunker import TextChunker

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionStats:
    """Summary statistics from a single ingestion run."""
    document_name: str
    chunks_created: int
    chunks_replaced: int


class IngestionPipeline:
    """Orchestrates knowledge document ingestion.

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: The embedding service for vector generation.
        chunk_size: Maximum characters per chunk.
        chunk_overlap: Overlap characters between chunks.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        embedding_service: EmbeddingService,
        *,
        chunk_size: int = 1000,
        chunk_overlap: int = 200,
    ) -> None:
        self._ltm = LongTermMemory(conn)
        self._embeddings = embedding_service
        self._chunker = TextChunker(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        
        # Instantiate LLM for Contextual Retrieval summarization
        self._llm = ChatGoogleGenerativeAI(
            model=settings.llm_model,
            google_api_key=settings.google_api_key,
            temperature=0.0,
        )

    async def _generate_context(self, full_doc: str, chunk: str) -> str:
        """Generate Anthropic-style contextual retrieval text for a chunk."""
        prompt = f"""<document>
{full_doc}
</document>

Here is the chunk we want to situate within the whole document:
<chunk>
{chunk}
</chunk>

Please give a short, succinct context to situate this chunk within the overall document for the purposes of improving search retrieval of the chunk. Answer ONLY with the succinct context and nothing else. Do not use conversational filler.
"""
        try:
            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            return response.content.strip()
        except Exception as e:
            logger.error("Context generation failed for chunk: %s", e)
            return ""

    async def ingest(
        self,
        *,
        tenant_id: str,
        document_name: str,
        content: str,
        category: KnowledgeCategory,
        metadata: dict | None = None,
    ) -> IngestionStats:
        """Ingest a knowledge document into the vector store.

        If the document already exists (by name), its old chunks are
        deleted before re-ingestion. This makes ingestion idempotent.

        Args:
            tenant_id: The tenant this document belongs to.
            document_name: Human-readable document identifier.
            content: The full text of the document.
            category: The knowledge category (ADR, runbook, etc.).
            metadata: Optional metadata dict attached to each chunk.

        Returns:
            Statistics about the ingestion operation.
        """
        metadata = metadata or {}

        # Step 1: Delete existing chunks for this document (idempotent re-ingestion)
        replaced = self._ltm.delete_knowledge_by_document(document_name)
        if replaced > 0:
            logger.info(
                "Replaced %d existing chunks for document '%s'",
                replaced, document_name,
            )

        # Step 2: Chunk the document
        chunk_texts = self._chunker.chunk(content)
        if not chunk_texts:
            logger.warning("Document '%s' produced zero chunks after splitting", document_name)
            return IngestionStats(
                document_name=document_name,
                chunks_created=0,
                chunks_replaced=replaced,
            )

        logger.info(
            "Chunked document '%s' into %d chunks (category: %s)",
            document_name, len(chunk_texts), category.value,
        )

        # Step 2.5: Contextual Retrieval (Anthropic's Method)
        # We use the LLM to generate a situational context for every chunk simultaneously.
        logger.info("Generating Contextual Retrieval summaries for %d chunks...", len(chunk_texts))
        context_tasks = [self._generate_context(content, chunk) for chunk in chunk_texts]
        contexts = await asyncio.gather(*context_tasks)

        contextualized_chunks = []
        for ctx, chunk in zip(contexts, chunk_texts, strict=True):
            if ctx:
                contextualized_chunks.append(f"CONTEXT: {ctx}\n\n{chunk}")
            else:
                contextualized_chunks.append(chunk)

        # Step 3: Embed all contextualized chunks in batch
        embeddings = await self._embeddings.embed_batch(contextualized_chunks)

        # Step 4: Store each chunk with its embedding
        for contextual_chunk, embedding in zip(contextualized_chunks, embeddings, strict=True):
            chunk_obj = KnowledgeChunk(
                tenant_id=tenant_id,
                category=category,
                source_document=document_name,
                content=contextual_chunk,
                metadata=metadata,
            )
            self._ltm.store_knowledge_chunk(chunk_obj, embedding)

        logger.info(
            "Ingested %d chunks for document '%s' (tenant: %s)",
            len(chunk_texts), document_name, tenant_id,
        )

        return IngestionStats(
            document_name=document_name,
            chunks_created=len(chunk_texts),
            chunks_replaced=replaced,
        )
