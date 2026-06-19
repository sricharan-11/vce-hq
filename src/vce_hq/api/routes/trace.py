"""API routes for Decision Traceability (Chain of Decisions)."""

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from vce_hq.api.dependencies import get_db_connection, get_tenant_id

router = APIRouter(prefix="/api/trace", tags=["trace"])


@router.get(
    "/requests",
    summary="List recent request IDs",
)
def list_requests(
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
    limit: int = 50,
) -> dict[str, Any]:
    """Retrieve the most recent distinct request IDs."""
    
    # We query from conversation_turns as it usually holds the entry point user queries
    rows = conn.execute(
        """
        SELECT request_id, MAX(created_at) as last_activity
        FROM conversation_turns
        WHERE request_id IS NOT NULL
        GROUP BY request_id
        ORDER BY last_activity DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()
    
    requests = [{"request_id": row["request_id"], "last_activity": row["last_activity"]} for row in rows]
    return {"requests": requests}


@router.get(
    "/{request_id}",
    summary="Get complete decision trace for a request",
)
def get_trace(
    request_id: str,
    tenant_id: Annotated[str, Depends(get_tenant_id)],
    conn: Annotated[sqlite3.Connection, Depends(get_db_connection)],
) -> dict[str, Any]:
    """Retrieve the chronologically sorted Chain of Decisions for a given request."""
    
    # 1. Fetch conversation turns
    turns = conn.execute(
        "SELECT 'turn' as type, turn_id as id, agent, content, created_at FROM conversation_turns WHERE request_id = ? ORDER BY created_at ASC",
        (request_id,)
    ).fetchall()
    
    # 2. Fetch command executions
    commands = conn.execute(
        "SELECT 'command' as type, command_id as id, agent, command, reasoning, exit_code, stdout, stderr, validated_by, created_at FROM command_executions WHERE request_id = ? ORDER BY created_at ASC",
        (request_id,)
    ).fetchall()
    
    # 3. Fetch token usages
    tokens = conn.execute(
        "SELECT 'token_usage' as type, usage_id as id, agent, prompt_tokens, completion_tokens, total_tokens, model_name, created_at FROM token_usage WHERE request_id = ? ORDER BY created_at ASC",
        (request_id,)
    ).fetchall()
    
    # Combine and sort chronologically
    timeline = []
    
    for row in turns:
        timeline.append({
            "type": row["type"],
            "id": row["id"],
            "agent": row["agent"],
            "content": row["content"],
            "created_at": row["created_at"]
        })
        
    for row in commands:
        timeline.append({
            "type": row["type"],
            "id": row["id"],
            "agent": row["agent"],
            "command": row["command"],
            "reasoning": row["reasoning"],
            "exit_code": row["exit_code"],
            "stdout": row["stdout"],
            "stderr": row["stderr"],
            "validated_by": row["validated_by"],
            "created_at": row["created_at"]
        })
        
    for row in tokens:
        timeline.append({
            "type": row["type"],
            "id": row["id"],
            "agent": row["agent"],
            "prompt_tokens": row["prompt_tokens"],
            "completion_tokens": row["completion_tokens"],
            "total_tokens": row["total_tokens"],
            "model_name": row["model_name"],
            "created_at": row["created_at"]
        })
        
    # Sort timeline by created_at string
    timeline.sort(key=lambda x: x["created_at"])
    
    return {"request_id": request_id, "timeline": timeline}
