"""User query analysis endpoint.

Allows tenants to submit free-text queries (not webhook-triggered)
for analysis by the agent swarm. Useful for proactive investigation
and ad-hoc infrastructure questions.
"""

import asyncio
import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from vce_hq.agents.graph import build_agent_graph
from vce_hq.api.dependencies import (
    get_credential_manager,
    get_db_connection,
    get_embedding_service,
    get_tenant_id,
)
from vce_hq.db.models import AgentType, ConversationTurn, Session
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.discovery.probe import get_environment_profile
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analyze", tags=["analysis"])


class AnalyzeRequest(BaseModel):
    """Request body for a user-initiated analysis query."""
    query: str = Field(
        ...,
        max_length=5000,
        description="The infrastructure question or investigation query",
        examples=["Why is the API response time spiking on the production cluster?"],
    )
    session_id: str | None = Field(
        default=None,
        description="Optional session ID to continue a previous conversation",
    )


class ApproveRequest(BaseModel):
    """Request body to approve or reject a HITL command."""
    approved: bool = Field(
        ...,
        description="Whether to approve or reject the command execution",
    )
    reason: str | None = Field(
        default=None,
        description="Optional reason for rejection",
    )


class AnalyzeResponse(BaseModel):
    """Response from a user-initiated analysis."""
    session_id: str
    status: str
    route: str = ""
    route_reasoning: str = ""
    analysis: str = ""
    security_flags: list[str] = Field(default_factory=list)
    hitl_command: str | None = None
    hitl_reason: str | None = None


@router.post(
    "/",
    response_model=AnalyzeResponse,
    summary="Submit a query for analysis",
    status_code=status.HTTP_200_OK,
)
async def analyze_query(
    request: AnalyzeRequest,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
    credential_manager: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> AnalyzeResponse:
    """Submit a free-text query for analysis by the agent swarm.

    The query is routed through the same pipeline as webhook alerts:
    Router → Specialist Agent(s) → Security Review.
    """
    stm = ShortTermMemory(conn)

    # Use existing session or create a new one
    if request.session_id:
        session = stm.get_session(request.session_id)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{request.session_id}' not found",
            )
    else:
        session = Session(tenant_id=tenant_id)
        stm.create_session(session)

    stm.update_session_status(session.session_id, session.status.ANALYZING)

    # Persist user query as a conversation turn
    turn = ConversationTurn(
        session_id=session.session_id,
        agent=AgentType.ROUTER,  # User input enters via the router
        content=f"[USER QUERY]: {request.query}",
    )
    stm.add_turn(turn)
    
    # Asynchronously embed the query for Semantic STM
    await stm.embed_and_save_turn(turn, embedding_service)

    logger.info(
        "Analyzing query for tenant '%s' (session: %s): %.100s...",
        tenant_id, session.session_id, request.query,
    )

    try:
        # Probe the environment (cached with 1-hour TTL)
        env_profile = await get_environment_profile()
        logger.info(
            "Environment probe: ssh_method=%s iap=%s vms=%d",
            env_profile.ssh_method, env_profile.iap_available,
            len(env_profile.running_vms),
        )

        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
        from vce_hq.config import get_settings
        app_settings = get_settings()
        db_path = str(app_settings.tenant_db_path(tenant_id))

        async with AsyncSqliteSaver.from_conn_string(db_path) as checkpointer:
            graph = build_agent_graph(conn, embedding_service, credential_manager, env_profile=env_profile, checkpointer=checkpointer)
            result = await graph.ainvoke(
                {
                    "tenant_id": tenant_id,
                    "session_id": session.session_id,
                    "user_query": request.query,
                },
                config={"configurable": {"thread_id": session.session_id}}
            )

        if result.get("hitl_pending"):
            final_status = "requires_approval"
            stm.update_session_status(session.session_id, session.status.ANALYZING)
        else:
            final_status = session.status.FAILED.value if result.get("error") else session.status.COMPLETED.value
            stm.update_session_status(session.session_id, session.status.FAILED if result.get("error") else session.status.COMPLETED)

            final_output = result.get("final_output", "")

            # Persist the final validated output as a conversation turn
            if final_output:
                final_turn = ConversationTurn(
                    session_id=session.session_id,
                    agent=AgentType.SECURITY_REVIEW,
                    content=final_output,
                )
                stm.add_turn(final_turn)
                # Ensure the final output is embedded too so it can be retrieved later
                await stm.embed_and_save_turn(final_turn, embedding_service)

        return AnalyzeResponse(
            session_id=session.session_id,
            status=final_status,
            route=result.get("route", ""),
            route_reasoning=result.get("route_reasoning", ""),
            analysis=result.get("final_output", ""),
            security_flags=result.get("security_flags", []),
            hitl_command=result.get("hitl_command"),
            hitl_reason=result.get("hitl_reason"),
        )

    except Exception as e:
        logger.error("Analysis failed for session %s: %s", session.session_id, e)
        stm.update_session_status(session.session_id, session.status.FAILED)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline failed: {e}",
        )

@router.post(
    "/{session_id}/approve",
    response_model=AnalyzeResponse,
    summary="Approve or reject a pending HITL command",
)
async def approve_hitl(
    session_id: str,
    request: ApproveRequest,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    embedding_service: Annotated[EmbeddingService, Depends(get_embedding_service)],
    credential_manager: Annotated[CredentialManager, Depends(get_credential_manager)],
) -> AnalyzeResponse:
    """Resume a paused agent graph with human approval."""
    stm = ShortTermMemory(conn)
    session = stm.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        env_profile = await get_environment_profile()
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
        from vce_hq.config import get_settings
        app_settings = get_settings()
        db_path = str(app_settings.tenant_db_path(tenant_id))

        async with AsyncSqliteSaver.from_conn_string(db_path) as checkpointer:
            graph = build_agent_graph(conn, embedding_service, credential_manager, env_profile=env_profile, checkpointer=checkpointer)
            
            # We need to get the current state and inject the approval.
            config = {"configurable": {"thread_id": session_id}}
            
            if request.approved:
                # Tell the agent that the command was approved.
                # In a full implementation, we might execute the command here or let the agent execute it.
                # For simplicity, we just resume the graph which will go to the router.
                pass
                
            result = await graph.ainvoke(None, config=config)
        
        if result.get("hitl_pending"):
            final_status = "requires_approval"
            stm.update_session_status(session.session_id, session.status.ANALYZING)
        else:
            final_status = session.status.FAILED.value if result.get("error") else session.status.COMPLETED.value
            stm.update_session_status(session.session_id, session.status.FAILED if result.get("error") else session.status.COMPLETED)

            final_output = result.get("final_output", "")
            if final_output:
                final_turn = ConversationTurn(
                    session_id=session.session_id,
                    agent=AgentType.SECURITY_REVIEW,
                    content=final_output,
                )
                stm.add_turn(final_turn)
                await stm.embed_and_save_turn(final_turn, embedding_service)

        return AnalyzeResponse(
            session_id=session.session_id,
            status=final_status,
            route=result.get("route", ""),
            route_reasoning=result.get("route_reasoning", ""),
            analysis=result.get("final_output", ""),
            security_flags=result.get("security_flags", []),
            hitl_command=result.get("hitl_command"),
            hitl_reason=result.get("hitl_reason"),
        )
    except Exception as e:
        logger.error("Resume failed for session %s: %s", session_id, e)
        raise HTTPException(status_code=500, detail=str(e))

@router.get(
    "/sessions",
    summary="List recent analysis sessions",
)
async def list_sessions(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> list[dict]:
    """List recent sessions for the current tenant."""
    stm = ShortTermMemory(conn)
    sessions = stm.list_sessions(limit=20)
    return [
        {
            "session_id": s.session_id,
            "status": s.status.value,
            "created_at": s.created_at if isinstance(s.created_at, str) else s.created_at.isoformat(),
        }
        for s in sessions
    ]


@router.get(
    "/sessions/{session_id}/history",
    summary="Get conversation history for a session",
)
async def get_session_history(
    session_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> list[dict]:
    """Retrieve all conversation turns for a given session."""
    stm = ShortTermMemory(conn)
    session = stm.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    turns = stm.get_conversation(session_id)
    return [
        {
            "agent": t.agent if isinstance(t.agent, str) else t.agent.value,
            "content": t.content,
            "created_at": t.created_at if isinstance(t.created_at, str) else t.created_at.isoformat(),
        }
        for t in turns
    ]


@router.get(
    "/reports/automated",
    summary="Get automated reports (like FinOps hourly runs)",
)
async def get_automated_reports(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> list[dict]:
    """Fetch automated background reports to display as UI notifications."""
    stm = ShortTermMemory(conn)
    sessions = stm.list_sessions(limit=50)
    
    automated_reports = []
    for s in sessions:
        # Check if it was an automated session
        turns = stm.get_conversation(s.session_id)
        if not turns:
            continue
            
        first_turn = turns[0]
        if "[SYSTEM SCHEDULED FINOPS" in first_turn.content and "EVENT]" in first_turn.content:
            # Extract job type (HOURLY, DAILY, MONTHLY)
            job_type = "UNKNOWN"
            if "HOURLY" in first_turn.content:
                job_type = "hourly"
            elif "DAILY" in first_turn.content:
                job_type = "daily"
            elif "MONTHLY" in first_turn.content:
                job_type = "monthly"

            # Find the final security review output
            final_output = next(
                (t.content for t in reversed(turns) if (isinstance(t.agent, str) and t.agent == "security_review") or (hasattr(t.agent, "value") and t.agent.value == "security_review")), 
                "Analysis in progress..."
            )
            
            automated_reports.append({
                "session_id": s.session_id,
                "type": f"finops_{job_type}",
                "status": s.status.value if hasattr(s.status, "value") else s.status,
                "created_at": s.created_at if isinstance(s.created_at, str) else s.created_at.isoformat(),
                "summary": final_output[:500] + "..." if len(final_output) > 500 else final_output,
            })
            
    return automated_reports
