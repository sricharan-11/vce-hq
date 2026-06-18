"""Intent Analyzer node for pre-processing user queries.

This node acts as the entry point to the swarm. It evaluates the user's query against
the recent conversation history to determine the intent:
- CONTINUATION: The query is related to the ongoing context.
- NEW_TOPIC: The query is valid but starts a new infrastructure topic.
- IRRELEVANT: The query is completely outside the scope of infrastructure operations.

Based on the intent, it optimizes the context window using semantic RAG or 
gracefully redirects the user with a clarifying question.
"""

import json
import logging
import sqlite3
from typing import Any, Callable

from langchain_google_genai import ChatGoogleGenerativeAI

from vce_hq.agents.state import AgentState
from vce_hq.config import settings
from vce_hq.db.models import AgentType, TokenUsageRecord
from vce_hq.db.short_term import ShortTermMemory

logger = logging.getLogger(__name__)

_INTENT_SYSTEM_PROMPT = """\
You are the Intent Analyzer for VCE-HQ, an AI-powered infrastructure operations orchestrator.
Your job is to read the user's query and the recent conversation history to determine the intent.

You MUST classify the query into exactly one of these three categories:
1. "CONTINUATION": The user is asking a follow-up question, referencing previous results, \
or diving deeper into the current ongoing infrastructure investigation.
2. "NEW_TOPIC": The user is asking a valid infrastructure or operations question, but it \
is completely unrelated to the previous conversation. The previous context should be cleared.
3. "IRRELEVANT": The user is asking something completely outside the scope of cloud \
infrastructure, DevOps, FinOps, or server operations.

If you choose "IRRELEVANT", you MUST also provide a `clarifying_question`. \
Do not just reject them. Use your reasoning to guess a closely matching B2B infrastructure topic \
and ask a clarifying question. (e.g., User: "How do I make a cake?" -> Agent: "I specialize in \
infrastructure operations. Did you mean to ask about 'baking' new AMI images or setting up a \
deployment pipeline?"). If the query is just a generic greeting ("hi", "hello"), you can ask \
"Hello! How can I help you with your cloud infrastructure today?"

Respond with valid JSON only:
{
  "intent": "CONTINUATION" | "NEW_TOPIC" | "IRRELEVANT",
  "reasoning": "Brief explanation of why you classified it this way",
  "clarifying_question": "Required only if intent is IRRELEVANT. A polite question redirecting to infra."
}
"""

def create_intent_analyzer_node(conn: sqlite3.Connection, embedding_service: Any, env_profile: Any = None) -> Callable:
    """Create the Intent Analyzer node function.

    Args:
        conn: Tenant-scoped SQLite connection for STM access.
        embedding_service: Service for vectorizing queries.
        env_profile: Optional environment profile.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    llm = ChatGoogleGenerativeAI(
        model=settings.llm_model,
        google_api_key=settings.google_api_key,
        temperature=0.0,
    )
    stm = ShortTermMemory(conn)

    async def intent_analyzer_node(state: AgentState) -> AgentState:
        """Analyze intent and manage conversation context."""
        logger.info("Intent Analyzer: evaluating query for session %s", state.get("session_id"))

        if not state.get("user_query"):
            # If it's an alert/event and not a user query, skip intent detection
            return {
                **state,
                "intent_status": "NEW_TOPIC",
                "conversation_history": "",
                "current_agent": "intent_analyzer"
            }

        user_query = state["user_query"]
        session_id = state.get("session_id", "")
        
        # Pull chronological recent history (last 2-3 turns) just for intent detection
        recent_conversation = stm.get_recent_conversation_text(session_id, limit=3) if session_id else ""

        messages = [("system", _INTENT_SYSTEM_PROMPT)]
        if recent_conversation:
            messages.append(("system", f"Recent conversation history:\n{recent_conversation}"))
        messages.append(("human", f"USER QUERY: {user_query}"))

        try:
            response = await llm.ainvoke(messages)
            
            usage = response.usage_metadata or {}
            if usage:
                input_details = usage.get("input_token_details") or {}
                output_details = usage.get("output_token_details") or {}
                stm.log_token_usage(TokenUsageRecord(
                    session_id=session_id,
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.ROUTER, # Log under router for simplicity
                    prompt_tokens=usage.get("input_tokens", 0),
                    completion_tokens=usage.get("output_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    reasoning_tokens=output_details.get("reasoning", 0),
                    cache_read_tokens=input_details.get("cache_read", 0),
                    cache_creation_tokens=input_details.get("cache_creation", 0),
                    model_name=llm.model,
                ))

            content = response.content
            if isinstance(content, list):
                text_parts: list[str] = []
                for block in content:
                    if isinstance(block, dict) and "text" in block:
                        text_parts.append(block["text"])
                    elif isinstance(block, str):
                        text_parts.append(block)
                content = "".join(text_parts)
            elif not isinstance(content, str):
                content = str(content)

            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            result = json.loads(content)
            intent = result.get("intent", "NEW_TOPIC")
            reasoning = result.get("reasoning", "No reasoning provided")
            clarifying_question = result.get("clarifying_question", "")
            
            logger.info("Intent Analyzer classified query as %s: %s", intent, reasoning)

            conversation_history = ""
            if intent == "CONTINUATION":
                # Smart Context: Use RAG to fetch semantically relevant older turns
                try:
                    query_embedding = await embedding_service.embed_query(user_query)
                    conversation_history = stm.get_semantic_conversation_context(
                        session_id=session_id, 
                        query_embedding=query_embedding, 
                        limit=3
                    )
                except Exception as e:
                    logger.warning("Failed to fetch semantic context, falling back to chronological: %s", e)
                    conversation_history = recent_conversation
            elif intent == "NEW_TOPIC":
                # Clear context to avoid confusing the router with old issues
                conversation_history = ""
                # CRITICAL FIX: Clear old agent outputs from state
                state["os_analysis"] = ""
                state["cloud_analysis"] = ""
                state["finops_analysis"] = ""
                state["security_review"] = ""
                state["final_output"] = ""
                state["command_log"] = []
                state["command_count"] = 0
            elif intent == "IRRELEVANT":
                # Do not execute agents. Security review will output the clarifying question.
                conversation_history = ""
                if not clarifying_question:
                    clarifying_question = "I specialize in cloud and OS infrastructure. Could you clarify how your question relates to your environment?"
            else:
                intent = "NEW_TOPIC"
                conversation_history = ""
                state["os_analysis"] = ""
                state["cloud_analysis"] = ""
                state["finops_analysis"] = ""
                state["security_review"] = ""
                state["final_output"] = ""
                state["command_log"] = []
                state["command_count"] = 0

            return {
                **state,
                "intent_status": intent,
                "clarifying_question": clarifying_question,
                "conversation_history": conversation_history,
                "current_agent": "intent_analyzer"
            }

        except Exception as e:
            logger.error("Intent Analyzer failed: %s", e)
            # Fail open: treat as new topic
            return {
                **state,
                "intent_status": "NEW_TOPIC",
                "conversation_history": "",
                "current_agent": "intent_analyzer"
            }

    return intent_analyzer_node
