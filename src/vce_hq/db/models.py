"""Pydantic models for database records.

These models serve as the contract between the database layer and the
rest of the application. All data entering or leaving the DB passes
through these models for validation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────

class EventSeverity(StrEnum):
    """Severity levels for normalized events."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class EventSource(StrEnum):
    """Supported webhook sources."""
    DATADOG = "datadog"
    CLOUDWATCH = "cloudwatch"
    CUSTOM = "custom"


class KnowledgeCategory(StrEnum):
    """Categories for ingested knowledge documents."""
    ADR = "adr"
    RUNBOOK = "runbook"
    POST_MORTEM = "post_mortem"
    INFRA_INVENTORY = "infra_inventory"
    DIAGNOSTIC_PATTERN = "diagnostic_pattern"


class AgentType(StrEnum):
    """Agent identifiers within the swarm."""
    ROUTER = "router"
    OS_ENGINEER = "os_engineer"
    CLOUD_ENGINEER = "cloud_engineer"
    FINOPS_AGENT = "finops_agent"
    SECURITY_REVIEW = "security_review"


class IncidentStatus(StrEnum):
    """Lifecycle status of an incident analysis."""
    PENDING = "pending"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


# ──────────────────────────────────────────────────────────────
# Normalized Event (The Eyes → The Brain)
# ──────────────────────────────────────────────────────────────

class NormalizedEvent(BaseModel):
    """A webhook payload normalized into VCE-HQ's common schema.

    This is the single format that all webhook sources are translated
    into before being passed to the Router agent.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    source: EventSource
    severity: EventSeverity
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    title: str
    body: str
    tags: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


# ──────────────────────────────────────────────────────────────
# Short-Term Memory (STM)
# ──────────────────────────────────────────────────────────────

class Session(BaseModel):
    """An active analysis session (one per incident or user query)."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: IncidentStatus = IncidentStatus.PENDING
    event: NormalizedEvent | None = None


class ConversationTurn(BaseModel):
    """A single turn in the analysis conversation.

    Tracks the agent that produced the output and the content it generated.
    """
    turn_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    request_id: str | None = None
    agent: AgentType
    content: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CommandExecution(BaseModel):
    """A single command executed by a specialist agent.

    Stored in STM for session-scoped audit trail. Passed to the
    Security Review agent for validation and included in the
    final output for full transparency.
    """
    command_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    request_id: str | None = None
    agent: AgentType
    command: str
    reasoning: str  # Why the agent chose to run this command
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    validated_by: str = "blocklist_v1"
    truncated: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TokenUsageRecord(BaseModel):
    """LLM token usage tracking per agent request.
    
    Provides the underlying data for FinOps Agent billing analysis.
    """
    usage_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    request_id: str | None = None
    tenant_id: str
    agent: AgentType
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    reasoning_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    model_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────────────────────────────────────
# Long-Term Memory (LTM) — Vector-Indexed
# ──────────────────────────────────────────────────────────────

class KnowledgeChunk(BaseModel):
    """A chunk of knowledge document, ready for embedding and storage.

    Represents a single text segment from an ADR, runbook, post-mortem,
    or infrastructure inventory document after chunking.
    """
    chunk_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    category: KnowledgeCategory
    source_document: str  # Original document name/path
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentResolution(BaseModel):
    """A completed incident analysis stored in long-term memory.

    After the full pipeline (Router → Agent → Security Review) completes,
    the resolution is embedded and stored for future semantic retrieval.
    """
    resolution_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    session_id: str
    title: str
    root_cause: str
    remediation: str
    agent_used: AgentType
    severity: EventSeverity
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ──────────────────────────────────────────────────────────────
# Credential (The Vault)
# ──────────────────────────────────────────────────────────────

class StoredCredential(BaseModel):
    """A hashed credential stored per-tenant.

    In v1-v2, credentials are hashed (not encrypted) — the original
    value is used at call time and never persisted in plaintext.
    """
    credential_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    name: str  # Human-readable label (e.g., "AWS Production Read-Only")
    provider: str  # e.g., "aws", "gcp", "azure"
    credential_hash: str  # SHA-256 hash of the credential value
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_rotated: datetime | None = None


# ──────────────────────────────────────────────────────────────
# Search Results
# ──────────────────────────────────────────────────────────────

class VectorSearchResult(BaseModel):
    """A single result from a sqlite-vec similarity search."""
    chunk_id: str
    content: str
    category: str
    source_document: str
    distance: float
    metadata: dict[str, Any] = Field(default_factory=dict)
