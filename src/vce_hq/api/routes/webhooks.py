"""Webhook ingestion endpoints (The Eyes).

Accepts alert payloads from Datadog, CloudWatch, and custom sources.
Each payload is normalized into the common NormalizedEvent schema
and then run through the full agent graph for analysis.
"""

import logging
import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vce_hq.agents.graph import build_agent_graph
from vce_hq.api.dependencies import (
    get_credential_manager,
    get_db_connection,
    get_embedding_service,
    get_tenant_id,
)
from vce_hq.db.models import NormalizedEvent, Session
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.manager import CredentialManager
from vce_hq.webhooks.normalizer import (
    normalize_cloudwatch,
    normalize_custom,
    normalize_datadog,
)
from vce_hq.webhooks.schemas import (
    CloudWatchWebhookPayload,
    CustomWebhookPayload,
    DatadogWebhookPayload,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookResponse(BaseModel):
    """Response returned after processing a webhook."""
    session_id: str
    status: str
    analysis: str = ""
    security_flags: list[str] = Field(default_factory=list)


@router.post(
    "/datadog",
    response_model=WebhookResponse,
    summary="Receive Datadog alert webhook",
    status_code=status.HTTP_200_OK,
)
async def receive_datadog_webhook(
    payload: DatadogWebhookPayload,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
    credential_manager: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> WebhookResponse:
    """Receive and process a Datadog alert webhook."""
    event = normalize_datadog(tenant_id, payload)
    return await _process_event(event, conn, embedding_service, credential_manager)


@router.post(
    "/cloudwatch",
    response_model=WebhookResponse,
    summary="Receive CloudWatch/SNS webhook",
    status_code=status.HTTP_200_OK,
)
async def receive_cloudwatch_webhook(
    payload: CloudWatchWebhookPayload,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
    credential_manager: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> WebhookResponse:
    """Receive and process a CloudWatch alarm notification via SNS."""
    event = normalize_cloudwatch(tenant_id, payload)
    return await _process_event(event, conn, embedding_service, credential_manager)


@router.post(
    "/custom",
    response_model=WebhookResponse,
    summary="Receive custom JSON webhook",
    status_code=status.HTTP_200_OK,
)
async def receive_custom_webhook(
    payload: CustomWebhookPayload,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
    credential_manager: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> WebhookResponse:
    """Receive and process a custom/generic JSON webhook."""
    event = normalize_custom(tenant_id, payload)
    return await _process_event(event, conn, embedding_service, credential_manager)


async def _process_event(
    event: NormalizedEvent,
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    credential_manager: CredentialManager,
) -> WebhookResponse:
    """Process a normalized event through the agent graph.

    This is the shared processing path for all webhook sources:
        1. Create a session in STM
        2. Build and run the agent graph
        3. Return the analysis result

    Args:
        event: The normalized event to analyze.
        conn: Tenant-scoped database connection.
        embedding_service: For agent RAG operations.
        credential_manager: For cloud CLI credential injection.

    Returns:
        The analysis result with session ID and security flags.
    """
    stm = ShortTermMemory(conn)

    # Create a session for this event
    session = Session(tenant_id=event.tenant_id, event=event)
    stm.create_session(session)
    stm.update_session_status(session.session_id, session.status.ANALYZING)

    logger.info(
        "Processing event '%s' for tenant '%s' (session: %s)",
        event.title, event.tenant_id, session.session_id,
    )

    try:
        # Build and invoke the agent graph
        graph = build_agent_graph(conn, embedding_service, credential_manager)
        result = await graph.ainvoke({
            "tenant_id": event.tenant_id,
            "session_id": session.session_id,
            "event": event.model_dump(),
        })

        # Update session status
        final_status = session.status.FAILED if result.get("error") else session.status.COMPLETED
        stm.update_session_status(session.session_id, final_status)

        return WebhookResponse(
            session_id=session.session_id,
            status=final_status.value,
            analysis=result.get("final_output", ""),
            security_flags=result.get("security_flags", []),
        )

    except Exception as e:
        logger.error("Agent graph failed for session %s: %s", session.session_id, e)
        stm.update_session_status(session.session_id, session.status.FAILED)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline failed: {e}",
        )
