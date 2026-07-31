"""Knowledge ingestion API endpoint.

Allows tenants to upload ADRs, runbooks, post-mortems, and
infrastructure inventory documents for embedding and indexing
in their tenant-scoped vector store.
"""

import hashlib
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vce_hq.api.dependencies import (
    get_db_connection,
    get_embedding_service,
    get_tenant_id,
)
from vce_hq.auth.dependencies import User, get_current_admin_user
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
    current_admin: Annotated[User, Depends(get_current_admin_user)],
) -> IngestResponse:
    """Ingest a knowledge document into the tenant's vector store.

    The document is chunked, embedded, and indexed for semantic retrieval
    by the agent swarm. Re-uploading a document with the same name
    replaces the previous version (idempotent).

    Restricted to admin users so an unprivileged account cannot poison the
    RAG corpus. Every chunk is stamped with the uploader's identity and a
    SHA-256 of the source content so a later integrity check can detect
    tampering or unauthorised modification.
    """
    pipeline = IngestionPipeline(conn, embedding_service)

    content_hash = hashlib.sha256(request.content.encode("utf-8")).hexdigest()
    uploader_metadata = {
        "uploader_id": current_admin.id,
        "uploader_username": current_admin.username,
        "uploader_role": current_admin.role,
        "content_sha256": content_hash,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }

    stats = await pipeline.ingest(
        tenant_id=tenant_id,
        document_name=request.document_name,
        content=request.content,
        category=request.category,
        metadata=request.metadata,
        uploader=uploader_metadata,
    )

    action = "replaced" if stats.chunks_replaced > 0 else "created"
    message = (
        f"Successfully {action} document '{stats.document_name}': "
        f"{stats.chunks_created} chunks indexed"
    )

    logger.info(
        "Knowledge ingestion: tenant=%s doc=%s chunks=%d replaced=%d uploader=%s sha256=%s",
        tenant_id,
        stats.document_name,
        stats.chunks_created,
        stats.chunks_replaced,
        current_admin.username,
        content_hash,
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
    current_admin: Annotated[User, Depends(get_current_admin_user)],
) -> dict:
    """Delete a document and all its chunks from the LTM."""
    ltm = LongTermMemory(conn)
    deleted_chunks = ltm.delete_knowledge_by_document(document_name)
    if deleted_chunks == 0:
        raise HTTPException(status_code=404, detail=f"Document '{document_name}' not found.")

    logger.info(
        "Deleted document '%s' (%d chunks) for tenant '%s' by admin '%s'",
        document_name, deleted_chunks, tenant_id, current_admin.username,
    )
    return {"message": f"Deleted document '{document_name}' ({deleted_chunks} chunks removed)."}
