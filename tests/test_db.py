"""Tests for the database layer."""

import json
import sqlite3

import pytest

from vce_hq.db.models import (
    AgentType,
    ConversationTurn,
    EventSeverity,
    IncidentResolution,
    IncidentStatus,
    KnowledgeCategory,
    KnowledgeChunk,
    NormalizedEvent,
    Session,
)
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.db.long_term import LongTermMemory


# ── Short-Term Memory Tests ──────────────────────────────────

class TestShortTermMemory:
    """Tests for session and conversation management."""

    def test_create_and_get_session(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        session = Session(tenant_id="tenant-1")
        stm.create_session(session)

        retrieved = stm.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == session.session_id
        assert retrieved.tenant_id == "tenant-1"
        assert retrieved.status == IncidentStatus.PENDING

    def test_get_nonexistent_session(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        assert stm.get_session("nonexistent") is None

    def test_update_session_status(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        session = Session(tenant_id="tenant-1")
        stm.create_session(session)

        stm.update_session_status(session.session_id, IncidentStatus.ANALYZING)
        retrieved = stm.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.status == IncidentStatus.ANALYZING

    def test_session_with_event(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        event = NormalizedEvent(
            tenant_id="tenant-1",
            source="datadog",
            severity="critical",
            title="High CPU",
            body="CPU usage above 95%",
        )
        session = Session(tenant_id="tenant-1", event=event)
        stm.create_session(session)

        retrieved = stm.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.event is not None
        assert retrieved.event.title == "High CPU"

    def test_add_and_get_conversation(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        session = Session(tenant_id="tenant-1")
        stm.create_session(session)

        turn1 = ConversationTurn(
            session_id=session.session_id,
            agent=AgentType.ROUTER,
            content="Classified as OS-level issue",
        )
        turn2 = ConversationTurn(
            session_id=session.session_id,
            agent=AgentType.OS_ENGINEER,
            content="Root cause: disk full on /var",
        )
        stm.add_turn(turn1)
        stm.add_turn(turn2)

        turns = stm.get_conversation(session.session_id)
        assert len(turns) == 2
        assert turns[0].agent == AgentType.ROUTER
        assert turns[1].agent == AgentType.OS_ENGINEER

    def test_conversation_text_format(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        session = Session(tenant_id="tenant-1")
        stm.create_session(session)

        stm.add_turn(ConversationTurn(
            session_id=session.session_id,
            agent=AgentType.ROUTER,
            content="OS-level",
        ))
        text = stm.get_conversation_text(session.session_id)
        assert "[ROUTER]: OS-level" in text

    def test_list_sessions(self, db_connection: sqlite3.Connection) -> None:
        stm = ShortTermMemory(db_connection)
        for i in range(3):
            stm.create_session(Session(tenant_id="tenant-1"))

        sessions = stm.list_sessions()
        assert len(sessions) == 3


# ── Long-Term Memory Tests ───────────────────────────────────

class TestLongTermMemory:
    """Tests for vector-indexed knowledge and resolution storage."""

    def _fake_embedding(self, seed: float = 0.0) -> list[float]:
        """Generate a deterministic fake 768-dim embedding."""
        from vce_hq.config import settings
        return [seed + (i * 0.001) for i in range(settings.embedding_dimensions)]

    def test_store_and_search_knowledge(self, db_connection: sqlite3.Connection) -> None:
        ltm = LongTermMemory(db_connection)

        chunk = KnowledgeChunk(
            tenant_id="tenant-1",
            category=KnowledgeCategory.ADR,
            source_document="vpc-migration.md",
            content="We decided to use VPC peering instead of Transit Gateway",
        )
        embedding = self._fake_embedding(0.1)
        ltm.store_knowledge_chunk(chunk, embedding)

        # Search with a similar vector
        results = ltm.search_knowledge(self._fake_embedding(0.1), top_k=1)
        assert len(results) == 1
        assert results[0].chunk_id == chunk.chunk_id
        assert "VPC peering" in results[0].content

    def test_store_and_search_resolution(self, db_connection: sqlite3.Connection) -> None:
        ltm = LongTermMemory(db_connection)

        resolution = IncidentResolution(
            tenant_id="tenant-1",
            session_id="session-1",
            title="OOM Killer on API Server",
            root_cause="Memory leak in connection pool",
            remediation="Restart the service and increase memory limits",
            agent_used=AgentType.OS_ENGINEER,
            severity=EventSeverity.CRITICAL,
        )
        embedding = self._fake_embedding(0.2)
        ltm.store_resolution(resolution, embedding)

        results = ltm.search_resolutions(self._fake_embedding(0.2), top_k=1)
        assert len(results) == 1
        assert "OOM Killer" in results[0].content

    def test_delete_knowledge_by_document(self, db_connection: sqlite3.Connection) -> None:
        ltm = LongTermMemory(db_connection)

        for i in range(3):
            chunk = KnowledgeChunk(
                tenant_id="tenant-1",
                category=KnowledgeCategory.RUNBOOK,
                source_document="restart-guide.md",
                content=f"Step {i}: Do something",
            )
            ltm.store_knowledge_chunk(chunk, self._fake_embedding(i * 0.1))

        deleted = ltm.delete_knowledge_by_document("restart-guide.md")
        assert deleted == 3

    def test_search_empty_store(self, db_connection: sqlite3.Connection) -> None:
        ltm = LongTermMemory(db_connection)
        results = ltm.search_knowledge(self._fake_embedding(), top_k=5)
        assert results == []
