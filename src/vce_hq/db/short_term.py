"""Short-Term Memory (STM) data access layer.

Manages sessions and conversation turns — the ephemeral state of an
active incident analysis. All operations are scoped to a single tenant's
database connection.
"""

import json
import sqlite3
from typing import Any

from vce_hq.db.models import (
    CommandExecution,
    ConversationTurn,
    IncidentStatus,
    NormalizedEvent,
    Session,
    TokenUsageRecord,
)


class ShortTermMemory:
    """CRUD operations for session and conversation state.

    Args:
        conn: An open SQLite connection for a specific tenant.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ── Sessions ──────────────────────────────────────────────

    def create_session(self, session: Session) -> Session:
        """Insert a new analysis session.

        Args:
            session: The session to persist.

        Returns:
            The same session object (now persisted).
        """
        event_json = session.event.model_dump_json() if session.event else None
        self._conn.execute(
            """
            INSERT INTO sessions (session_id, tenant_id, status, event_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session.session_id,
                session.tenant_id,
                session.status.value,
                event_json,
                session.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        return session

    def get_session(self, session_id: str) -> Session | None:
        """Retrieve a session by ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            The session if found, otherwise ``None``.
        """
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        if row is None:
            return None

        event = None
        if row["event_json"]:
            event = NormalizedEvent.model_validate_json(row["event_json"])

        return Session(
            session_id=row["session_id"],
            tenant_id=row["tenant_id"],
            status=IncidentStatus(row["status"]),
            event=event,
            created_at=row["created_at"],
        )

    def update_session_status(self, session_id: str, status: IncidentStatus) -> None:
        """Update the status of an existing session.

        Args:
            session_id: The session to update.
            status: The new status value.
        """
        self._conn.execute(
            "UPDATE sessions SET status = ? WHERE session_id = ?",
            (status.value, session_id),
        )
        self._conn.commit()

    def list_sessions(
        self, *, status: IncidentStatus | None = None, limit: int = 50
    ) -> list[Session]:
        """List sessions, optionally filtered by status.

        Args:
            status: If provided, filter to sessions with this status.
            limit: Maximum number of sessions to return.

        Returns:
            List of sessions ordered by creation time (newest first).
        """
        if status:
            rows = self._conn.execute(
                "SELECT * FROM sessions WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        sessions = []
        for row in rows:
            event = None
            if row["event_json"]:
                event = NormalizedEvent.model_validate_json(row["event_json"])
            sessions.append(
                Session(
                    session_id=row["session_id"],
                    tenant_id=row["tenant_id"],
                    status=IncidentStatus(row["status"]),
                    event=event,
                    created_at=row["created_at"],
                )
            )
        return sessions

    # ── Conversation Turns ────────────────────────────────────

    def add_turn(self, turn: ConversationTurn) -> ConversationTurn:
        """Append a conversation turn to a session.

        Args:
            turn: The turn to persist.

        Returns:
            The same turn object (now persisted).
        """
        self._conn.execute(
            """
            INSERT INTO conversation_turns (turn_id, session_id, request_id, agent, content, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                turn.turn_id,
                turn.session_id,
                turn.request_id,
                turn.agent.value,
                turn.content,
                turn.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        return turn

    async def embed_and_save_turn(self, turn: ConversationTurn, embedding_service: Any) -> None:
        """Asynchronously embed a turn and store it in the vector index.

        Args:
            turn: The ConversationTurn that was already saved via add_turn.
            embedding_service: An instance of EmbeddingService.
        """
        # Embed the turn content
        embedding = await embedding_service.embed(f"[{turn.agent.value.upper()}]: {turn.content}")
        
        # Insert into conversation_vectors
        self._conn.execute(
            """
            INSERT INTO conversation_vectors(turn_id, embedding)
            VALUES (?, ?)
            """,
            (turn.turn_id, json.dumps(embedding)),
        )
        self._conn.commit()

    def get_conversation(self, session_id: str) -> list[ConversationTurn]:
        """Retrieve all conversation turns for a session, in chronological order.

        Args:
            session_id: The session whose conversation to retrieve.

        Returns:
            Ordered list of conversation turns.
        """
        rows = self._conn.execute(
            "SELECT * FROM conversation_turns WHERE session_id = ? ORDER BY created_at ASC",
            (session_id,),
        ).fetchall()

        return [
            ConversationTurn(
                turn_id=row["turn_id"],
                session_id=row["session_id"],
                agent=row["agent"],
                content=row["content"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def get_conversation_text(self, session_id: str) -> str:
        """Get the full conversation as a formatted text string.

        Useful for passing conversation context to LLM prompts.

        Args:
            session_id: The session whose conversation to format.

        Returns:
            A newline-separated string of ``[AGENT]: content`` entries.
        """
        turns = self.get_conversation(session_id)
        return "\n".join(
            f"[{turn.agent.value.upper()}]: {turn.content}" for turn in turns
        )

    def get_recent_conversation_text(self, session_id: str, *, limit: int = 3) -> str:
        """Get the most recent N conversation turns as a formatted text string.

        Returns the last ``limit`` turns in chronological order. Used by the
        Intent Analyzer for lightweight context (full history is too large).

        Args:
            session_id: The session whose conversation to format.
            limit: Maximum number of most-recent turns to include.

        Returns:
            A newline-separated string of ``[AGENT]: content`` entries.
        """
        rows = self._conn.execute(
            """
            SELECT * FROM conversation_turns
            WHERE session_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (session_id, limit),
        ).fetchall()

        # Reverse to chronological order
        rows = list(reversed(rows))

        turns = [
            ConversationTurn(
                turn_id=row["turn_id"],
                session_id=row["session_id"],
                agent=row["agent"],
                content=row["content"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
        return "\n".join(
            f"[{turn.agent.value.upper()}]: {turn.content}" for turn in turns
        )

    def get_semantic_conversation_context(
        self, session_id: str, query_embedding: list[float], limit: int = 3
    ) -> str:
        """Get semantically relevant past conversation turns using vector search.
        
        Retrieves the top-K most relevant turns, plus the 1 most recent turn 
        (if not already included) to maintain immediate context flow.

        Args:
            session_id: The session whose conversation to search.
            query_embedding: The vector embedding of the user's current query.
            limit: Number of semantic turns to retrieve.

        Returns:
            A formatted string of conversation turns ordered chronologically.
        """
        # Fetch top K semantically similar turns
        semantic_rows = self._conn.execute(
            """
            SELECT ct.*
            FROM conversation_turns ct
            JOIN conversation_vectors cv ON ct.turn_id = cv.turn_id
            WHERE ct.session_id = ?
            ORDER BY vec_distance_L2(cv.embedding, ?) ASC
            LIMIT ?
            """,
            (session_id, json.dumps(query_embedding), limit),
        ).fetchall()

        # Fetch the absolute latest turn to ensure immediate context
        latest_row = self._conn.execute(
            """
            SELECT * FROM conversation_turns 
            WHERE session_id = ? 
            ORDER BY created_at DESC LIMIT 1
            """,
            (session_id,),
        ).fetchone()

        # Combine, avoiding duplicates, and sort chronologically
        turn_dict = {}
        if latest_row:
            turn_dict[latest_row["turn_id"]] = latest_row
            
        for row in semantic_rows:
            turn_dict[row["turn_id"]] = row
            
        # Sort by created_at ascending
        sorted_rows = sorted(turn_dict.values(), key=lambda r: r["created_at"])
        
        turns = [
            ConversationTurn(
                turn_id=row["turn_id"],
                session_id=row["session_id"],
                agent=row["agent"],
                content=row["content"],
                created_at=row["created_at"],
            )
            for row in sorted_rows
        ]
        
        return "\n".join(
            f"[{turn.agent.value.upper()}]: {turn.content}" for turn in turns
        )

    # ── Command Executions ──────────────────────────────────

    def log_command(self, execution: CommandExecution) -> CommandExecution:
        """Persist a command execution record.

        Called after every command execution (successful or not)
        to maintain the full audit trail for Security Review.

        Args:
            execution: The command execution record to persist.

        Returns:
            The same execution object (now persisted).
        """
        self._conn.execute(
            """
            INSERT INTO command_executions (
                command_id, session_id, request_id, agent, command, reasoning,
                exit_code, stdout, stderr, duration_ms,
                validated_by, risk_signal, gate_invoked, gate_decision,
                truncated, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                execution.command_id,
                execution.session_id,
                execution.request_id,
                execution.agent.value,
                execution.command,
                execution.reasoning,
                execution.exit_code,
                execution.stdout,
                execution.stderr,
                execution.duration_ms,
                execution.validated_by,
                execution.risk_signal,
                int(execution.gate_invoked),
                execution.gate_decision,
                int(execution.truncated),
                execution.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        return execution

    def get_command_log(self, session_id: str) -> list[CommandExecution]:
        """Retrieve all command executions for a session, in chronological order.

        Args:
            session_id: The session whose command log to retrieve.

        Returns:
            Ordered list of command execution records.
        """
        rows = self._conn.execute(
            "SELECT * FROM command_executions WHERE session_id = ? ORDER BY created_at ASC",
            (session_id,),
        ).fetchall()

        return [
            CommandExecution(
                command_id=row["command_id"],
                session_id=row["session_id"],
                request_id=row["request_id"],
                agent=AgentType(row["agent"]),
                command=row["command"],
                reasoning=row["reasoning"],
                exit_code=row["exit_code"],
                stdout=row["stdout"] or "",
                stderr=row["stderr"] or "",
                duration_ms=row["duration_ms"],
                validated_by=row["validated_by"],
                risk_signal=row["risk_signal"] if "risk_signal" in row.keys() else "none",
                gate_invoked=bool(row["gate_invoked"]) if "gate_invoked" in row.keys() else False,
                gate_decision=row["gate_decision"] if "gate_decision" in row.keys() else "",
                truncated=bool(row["truncated"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def get_command_count(self, session_id: str) -> int:
        """Get the total number of commands executed in a session.

        Used to enforce the max-commands-per-session limit.

        Args:
            session_id: The session to count commands for.

        Returns:
            The total number of command executions.
        """
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM command_executions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        return row["cnt"] if row else 0

    # ── Token Usage ─────────────────────────────────────────

    def log_token_usage(self, record: TokenUsageRecord) -> TokenUsageRecord:
        """Persist a token usage record for billing analysis.

        Args:
            record: The token usage record to persist.

        Returns:
            The same record object (now persisted).
        """
        self._conn.execute(
            """
            INSERT INTO token_usage
                (usage_id, session_id, tenant_id, agent, prompt_tokens,
                 completion_tokens, total_tokens, reasoning_tokens, cache_read_tokens, cache_creation_tokens, model_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.usage_id,
                record.session_id,
                record.tenant_id,
                record.agent.value,
                record.prompt_tokens,
                record.completion_tokens,
                record.total_tokens,
                record.reasoning_tokens,
                record.cache_read_tokens,
                record.cache_creation_tokens,
                record.model_name,
                record.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        return record

    def get_token_usage_summary(self, tenant_id: str) -> dict:
        """Get token usage aggregated by period (day, week, month, overall).
        
        Args:
            tenant_id: The tenant to get usage for.
            
        Returns:
            A dictionary with the aggregated token usage per period,
            including a breakdown by agent.
        """
        cursor = self._conn.cursor()
        cursor.execute(
            """
            SELECT 
                agent,
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN prompt_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN completion_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN total_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN reasoning_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN cache_read_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-1 day') THEN cache_creation_tokens ELSE 0 END),

                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN prompt_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN completion_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN total_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN reasoning_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN cache_read_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN cache_creation_tokens ELSE 0 END),

                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN prompt_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN completion_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN total_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN reasoning_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN cache_read_tokens ELSE 0 END),
                SUM(CASE WHEN created_at >= datetime('now', '-30 days') THEN cache_creation_tokens ELSE 0 END),

                SUM(prompt_tokens),
                SUM(completion_tokens),
                SUM(total_tokens),
                SUM(reasoning_tokens),
                SUM(cache_read_tokens),
                SUM(cache_creation_tokens)
            FROM token_usage
            WHERE tenant_id = ?
            GROUP BY agent
            """,
            (tenant_id,)
        )
        
        rows = cursor.fetchall()
        
        periods = ["day", "week", "month", "overall"]
        metrics = ["prompt", "completion", "total", "reasoning", "cache_read", "cache_creation"]
        
        summary = {
            period: {metric + "_tokens": 0 for metric in metrics}
            for period in periods
        }
        
        for period in periods:
            summary[period]["by_agent"] = {}
            
        for row in rows:
            agent = row[0]
            idx = 1
            for period in periods:
                agent_data = {}
                for metric in metrics:
                    val = row[idx] or 0
                    summary[period][metric + "_tokens"] += val
                    agent_data[metric + "_tokens"] = val
                    idx += 1
                summary[period]["by_agent"][agent] = agent_data
                
        return summary

