"""Knowledge ingestion API endpoint.

Allows tenants to upload ADRs, runbooks, post-mortems, and
infrastructure inventory documents for embedding and indexing
in their tenant-scoped vector store.
"""

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vce_hq.api.dependencies import (
    get_db_connection,
    get_embedding_service,
    get_tenant_id,
)
from vce_hq.db.long_term import LongTermMemory
from vce_hq.db.models import KnowledgeCategory
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.ingestion.pipeline import IngestionPipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


class IngestRequest(BaseModel):
    """Request body for knowledge document ingestion."""
    document_name: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Unique name/identifier for this document",
        examples=["vpc-migration-adr-2024.md"],
    )
    content: str = Field(
        ...,
        min_length=10,
        description="Full text content of the document",
    )
    category: KnowledgeCategory = Field(
        ...,
        description="Document category for filtering during retrieval",
    )
    metadata: dict | None = Field(
        default=None,
        description="Optional metadata to attach to each chunk",
    )


class IngestResponse(BaseModel):
    """Response from a knowledge ingestion operation."""
    document_name: str
    chunks_created: int
    chunks_replaced: int
    message: str


@router.post(
    "/ingest",
    response_model=IngestResponse,
    summary="Ingest a knowledge document",
    status_code=status.HTTP_201_CREATED,
)
async def ingest_document(
    request: IngestRequest,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
) -> IngestResponse:
    """Ingest a knowledge document into the tenant's vector store.

    The document is chunked, embedded, and indexed for semantic retrieval
    by the agent swarm. Re-uploading a document with the same name
    replaces the previous version (idempotent).
    """
    pipeline = IngestionPipeline(conn, embedding_service)

    stats = await pipeline.ingest(
        tenant_id=tenant_id,
        document_name=request.document_name,
        content=request.content,
        category=request.category,
        metadata=request.metadata,
    )

    action = "replaced" if stats.chunks_replaced > 0 else "created"
    message = (
        f"Successfully {action} document '{stats.document_name}': "
        f"{stats.chunks_created} chunks indexed"
    )

    logger.info(
        "Knowledge ingestion: tenant=%s doc=%s chunks=%d replaced=%d",
        tenant_id, stats.document_name, stats.chunks_created, stats.chunks_replaced,
    )

    return IngestResponse(
        document_name=stats.document_name,
        chunks_created=stats.chunks_created,
        chunks_replaced=stats.chunks_replaced,
        message=message,
    )


@router.get(
    "",
    summary="List ingested documents",
)
async def list_documents(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> list[dict]:
    """Retrieve a list of all documents currently indexed in the LTM."""
    ltm = LongTermMemory(conn)
    return ltm.list_knowledge_documents()


@router.delete(
    "/{document_name}",
    summary="Delete an ingested document",
)
async def delete_document(
    document_name: str,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> dict:
    """Delete a document and all its chunks from the LTM."""
    ltm = LongTermMemory(conn)
    deleted_chunks = ltm.delete_knowledge_by_document(document_name)
    if deleted_chunks == 0:
        raise HTTPException(status_code=404, detail=f"Document '{document_name}' not found.")
    
    logger.info("Deleted document '%s' (%d chunks) for tenant '%s'", document_name, deleted_chunks, tenant_id)
    return {"message": f"Deleted document '{document_name}' ({deleted_chunks} chunks removed)."}
