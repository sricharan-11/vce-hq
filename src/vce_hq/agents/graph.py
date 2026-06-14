"""LangGraph graph definition — the full agent pipeline.

Defines the directed graph that orchestrates the agent swarm:
    Event → Router → [OS Agent | Cloud Agent] → Security Review → Output

The graph uses conditional edges based on the Router's classification
to determine which specialist agents to invoke and in what order.

This is the central orchestration module — it wires together all
agents into a single executable graph.
"""

import logging
import sqlite3

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph

from vce_hq.agents.cloud_engineer import create_cloud_engineer_node
from vce_hq.agents.finops_agent import create_finops_agent_node
from vce_hq.agents.os_engineer import create_os_engineer_node
from vce_hq.agents.router import create_router_node
from vce_hq.agents.security_review import create_security_review_node
from vce_hq.agents.intent_analyzer import create_intent_analyzer_node
from vce_hq.agents.state import AgentState
from vce_hq.discovery.probe import EnvironmentProfile
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.vault.manager import CredentialManager

logger = logging.getLogger(__name__)


def build_agent_graph(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    credential_manager: CredentialManager,
    env_profile: EnvironmentProfile | None = None,
    checkpointer=None,
) -> StateGraph:
    """Build and compile the full agent graph.

    The graph topology:
        router → (conditional) → os_engineer and/or cloud_engineer → security_review → END

    Routing logic (determined by Router node):
        - "os"    → os_engineer → security_review
        - "cloud" → cloud_engineer → security_review
        - "finops" → finops_agent → security_review
        - "multi" → first agent in sequence → second agent → security_review

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: Shared embedding service for RAG.
        credential_manager: Vault credential manager for injecting cloud
            CLI credentials into the Cloud Engineer agent.
        env_profile: Auto-discovered environment profile. Passed to all
            agents so they have runtime infrastructure awareness.

    Returns:
        A compiled LangGraph ``StateGraph`` ready for invocation.
    """
    # Create node functions
    intent_analyzer_node = create_intent_analyzer_node(conn, embedding_service, env_profile=env_profile)
    router_node = create_router_node(conn, env_profile=env_profile)
    os_node = create_os_engineer_node(conn, embedding_service, credential_manager, env_profile=env_profile)
    cloud_node = create_cloud_engineer_node(conn, embedding_service, credential_manager, env_profile=env_profile)
    finops_node = create_finops_agent_node(conn, embedding_service, credential_manager, env_profile=env_profile)
    security_node = create_security_review_node(conn, embedding_service)

    # Build the graph
    graph = StateGraph(AgentState)

    # Add nodes
    graph.add_node("intent_analyzer", intent_analyzer_node)
    graph.add_node("router", router_node)
    graph.add_node("os_engineer", os_node)
    graph.add_node("cloud_engineer", cloud_node)
    graph.add_node("finops_agent", finops_node)
    graph.add_node("security_review", security_node)
    
    async def human_approval_node(state: AgentState) -> AgentState:
        # This node just acts as a breakpoint.
        # Once approved and resumed, it clears the hitl_pending flag.
        return {"hitl_pending": False}

    graph.add_node("human_approval", human_approval_node)

    # Set entry point
    graph.set_entry_point("intent_analyzer")

    def _route_after_intent(state: AgentState) -> str:
        if state.get("intent_status") == "IRRELEVANT":
            return "security_review"
        return "router"

    graph.add_conditional_edges(
        "intent_analyzer",
        _route_after_intent,
        {
            "security_review": "security_review",
            "router": "router"
        }
    )

    # Conditional routing after the Router node
    graph.add_conditional_edges(
        "router",
        _route_after_router,
        {
            "os_engineer": "os_engineer",
            "cloud_engineer": "cloud_engineer",
            "finops_agent": "finops_agent",
            "security_review": "security_review",
            "error": END,
        },
    )

    def _route_after_agent(state: AgentState) -> str:
        if state.get("hitl_pending"):
            return "human_approval"
        return "router"

    # After Agents: check if HITL pending, otherwise back to router
    graph.add_conditional_edges("os_engineer", _route_after_agent, {"human_approval": "human_approval", "router": "router"})
    graph.add_conditional_edges("cloud_engineer", _route_after_agent, {"human_approval": "human_approval", "router": "router"})
    graph.add_conditional_edges("finops_agent", _route_after_agent, {"human_approval": "human_approval", "router": "router"})

    # After Human Approval: go back to the router so it can orchestrate next step
    graph.add_edge("human_approval", "router")

    # After Security Review: end
    graph.add_edge("security_review", END)

    if checkpointer is None:
        checkpointer = SqliteSaver(conn)

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["human_approval"]
    )


def _route_after_router(state: AgentState) -> str:
    """Determine which agent to invoke next based on Router's delegation.

    Args:
        state: Current graph state after Router execution.

    Returns:
        The name of the next node to invoke.
    """
    if state.get("error"):
        return "error"

    iterations = state.get("router_iterations", 0)
    from vce_hq.config import settings
    max_iterations = settings.router_max_iterations

    if iterations >= max_iterations:
        logger.warning("Router: max iterations (%d) reached, forcing security_review", max_iterations)
        return "security_review"

    target = state.get("delegate_to", "security_review")
    
    if target in ["os_engineer", "cloud_engineer", "finops_agent", "security_review"]:
        return target
    
    return "security_review"
