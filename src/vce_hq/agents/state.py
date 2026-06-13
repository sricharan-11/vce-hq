"""Shared agent state schema for LangGraph.

This module defines the typed state that flows through the LangGraph
graph. Every node reads from and writes to this state, making the
data flow explicit and traceable.

Design rationale:
    Using TypedDict instead of Pydantic here because LangGraph's
    state management works natively with TypedDict and handles
    reducer functions on dict keys.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


class AgentState(TypedDict, total=False):
    """Shared state flowing through the LangGraph agent graph.

    Attributes:
        tenant_id: The tenant this analysis belongs to.
        session_id: Unique session identifier for STM tracking.

        event: The normalized event being analyzed.
        user_query: Free-text query from the user (alternative to event).

        route: The Router's classification result.
        route_sequence: For multi-signal incidents, the ordered list of
            agent types to execute sequentially.

        conversation_history: Formatted conversation context from STM.
        retrieved_context: RAG-retrieved context from LTM (per agent).

        os_analysis: Output from the OS Engineer Agent.
        cloud_analysis: Output from the Cloud Engineer Agent.
        finops_analysis: Output from the FinOps Agent.

        command_log: List of command execution result dicts (audit trail).
        command_count: Total commands executed across all agents this session.

        security_review: Output from the mandatory Security Review.
        security_flags: Any contradictions or concerns flagged by Security.

        final_output: The complete, validated analysis + remediation playbook.

        error: Error message if any step fails.
        current_agent: Tracks which agent is currently executing.
        hitl_pending: True if the system is waiting for user approval.
        hitl_command: The command waiting for approval.
        hitl_reason: The reason given by the security gate.
    """

    # Identity
    tenant_id: str
    session_id: str

    # Input (one of these will be populated)
    event: dict[str, Any]
    user_query: str

    # Supervisor output
    router_theory: str
    router_instruction: str
    delegate_to: Literal["os_engineer", "cloud_engineer", "finops_agent", "security_review"]

    # Context
    conversation_history: str
    retrieved_context: str

    # Agent outputs
    os_analysis: str
    cloud_analysis: str
    finops_analysis: str

    # Command execution (The Hands)
    command_log: list[dict[str, Any]]
    command_count: int

    # Security Review
    security_review: str
    security_flags: list[str]

    # Final
    final_output: str

    # Control
    error: str
    current_agent: str
    router_iterations: int
    hitl_pending: bool
    hitl_command: str
    hitl_reason: str

