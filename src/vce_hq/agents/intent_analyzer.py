"""Intent Analyzer node — two-stage entry point to the swarm.

Stage 1 — Intent Classification (4 categories) + entity resolution.
    CONTINUATION  → Stage 2 (standard param-mapping gate)
    NEW_TOPIC     → Stage 2 (standard param-mapping gate)
    AMBIGUOUS     → Stage 2 (dual-mode hypothesis, advisory only) → short-circuit
    IRRELEVANT    → short-circuit (polite redirect, no Stage 2)

Stage 2 — Dynamic Parameter Mapping (No-Hallucination Gate).
    Standard mode (CONT/NEW_TOPIC):
        All required params resolved → pass through to Supervisor Router.
        Any required param missing   → short-circuit (MISSING_PARAMS).
    Dual-mode (AMBIGUOUS):
        Speculatively resolves a continuation hypothesis from STM + describes
        what a new-topic hypothesis would need, then bundles both into ONE
        composite clarifying question. Result is advisory; the Router never runs.

Short-circuit branches (IRRELEVANT / AMBIGUOUS / MISSING_PARAMS) bypass the
swarm and the Blocklist-First Security Pipeline entirely — there is nothing
to gate because no command is being formulated.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Callable

from vce_hq.llm_factory import get_llm

from vce_hq.agents.state import AgentState
from vce_hq.cache_manager import cache_manager
from vce_hq.config import settings
from vce_hq.db.models import AgentType, TokenUsageRecord, ConversationTurn
from vce_hq.db.short_term import ShortTermMemory

logger = logging.getLogger(__name__)


# ── Stage 1: Intent Classification + Entity Resolution ─────────────────

_INTENT_SYSTEM_PROMPT = """\
You are the Intent Analyzer for VCE-HQ, an AI-powered infrastructure operations orchestrator.
Your job is to read the user's query and the recent conversation history and classify the
query into EXACTLY ONE of four categories.

## CATEGORIES (pick exactly one)

1. "CONTINUATION" — The user is asking a follow-up that depends on the active investigation
   (e.g. "now check the cloud side", "what about the previous host?", "show me the next 1h"). \
The current context must be retained.
2. "NEW_TOPIC" — A valid infrastructure / DevOps / FinOps question that is unrelated to the
   prior conversation. The prior context should be cleared.
3. "AMBIGUOUS" — A plausible-sounding infra query that lacks the resource/system anchor
   needed to disambiguate. Examples: "is my database slow?" with no project specified;
   "restart the service" when multiple services are in play. Do NOT auto-resolve to
   CONTINUATION — only the user can break ambiguity.
4. "IRRELEVANT" — A query completely outside the scope of cloud / OS / DevOps / FinOps
   operations (e.g. "how do I bake a cake?", greetings, jokes).

## CLARIFYING QUESTION

- If "IRRELEVANT": produce a polite redirect that maps the off-topic query to the closest
  plausible infra concept (e.g. "How do I make a cake?" → "I specialize in infrastructure
  operations. Did you mean baking new AMI images or setting up a deployment pipeline?").
  Generic greetings → "Hello! How can I help you with your cloud infrastructure today?".
- If "AMBIGUOUS": leave clarifying_question empty — a richer dual-mode clarification is
  produced in a downstream stage.
- If "CONTINUATION" or "NEW_TOPIC": leave clarifying_question empty.

## ENTITY RESOLUTION (always)

Users often use shorthand (e.g. "cart" for "lowerground_cart_app", "abc" for
"abc-dev-002-mumbai"). Cross-reference the query against the provided Environment Profile
and expand every shorthand into its canonical name in `resolved_query`. If nothing needs
expansion, return the original query unchanged. NEVER invent a name that isn't in the
Environment Profile.

## OUTPUT

Respond with valid JSON only:
{
  "intent": "CONTINUATION" | "NEW_TOPIC" | "AMBIGUOUS" | "IRRELEVANT",
  "reasoning": "Brief explanation of why you classified it this way",
  "clarifying_question": "Required only for IRRELEVANT; empty string otherwise",
  "resolved_query": "User query with all shorthand expanded to canonical names"
}
"""


# ── Stage 2: Dynamic Parameter Mapping (No-Hallucination Gate) ─────────

_PARAM_EXTRACTION_SYSTEM_PROMPT = """\
You are the Parameter Extractor for VCE-HQ. The Intent Analyzer has already classified
the user's query as actionable (CONTINUATION or NEW_TOPIC). Your job is to ensure the
downstream specialist agents have every concrete parameter they need to execute the
task safely, with ZERO hallucinated values.

Do the following, in order:

1. INFER the underlying task the user wants performed. Examples (for reference only —
   you must interpret the actual query and figure out what task it implies):
     - "restart a systemd service"
     - "fetch CPU metrics for a VM"
     - "scale a GKE deployment"
     - "diagnose 5xx spike"
     - "investigate billing anomaly"
   State the inferred task in one sentence → `task_summary`.

2. DYNAMICALLY DETERMINE the parameters required to execute that task. The required set
   is per-task — there is no static schema. The minimum set varies by task:
     - a restart needs: target host/service identifier
     - a metric query needs: target resource, time window (if no sensible default exists)
     - a scale op needs: target deployment + replica count
     - a cost analysis needs: project/account + time range
     - a log fetch needs: log source + filter or time range
   Only ask for parameters that are required to act safely. Optional context may be
   requested when the task genuinely needs it, but do not pad with nice-to-haves.

3. RESOLVE each required parameter from these sources, in this priority order:
     (a) the resolved user query,
     (b) the conversation history (CONTINUATION queries usually carry params from
         earlier turns — this is why Stage 2 runs AFTER Stage 1),
     (c) the EnvironmentProfile, for canonical resource names.
   If a value is genuinely available, mark `present: true`, record the value and its
   `source`. If it is not available from any of (a)-(c), mark `present: false` and add
   the param name to `missing_parameters`.
   NEVER fabricate, guess, or default a parameter value. Missing means missing.

4. CLARIFYING QUESTION
   - If `missing_parameters` is non-empty, craft a SINGLE concise clarifying question
     that asks ONLY for the missing pieces. Bundle every missing item into ONE ask.
     Do not re-ask for anything already resolved.
   - If everything is resolved, return an empty clarifying_question.

## OUTPUT

Respond with valid JSON only:
{
  "task_summary": "one-sentence description of the action to perform",
  "required_parameters": [
    {
      "name": "param_key",
      "description": "what this parameter represents",
      "present": true,
      "value": "resolved value or null if missing",
      "source": "user_query" | "conversation" | "env_profile" | "missing"
    }
  ],
  "missing_parameters": ["param_key", ...],
  "clarifying_question": "single concise question bundling all missing items, or empty string"
}
"""


# ── Stage 2 (AMBIGUOUS dual-mode): hypothesis + composite clarification ─

_AMBIGUOUS_DUAL_MODE_SYSTEM_PROMPT = """\
You are the Parameter Extractor for VCE-HQ operating in DUAL-MODE because the Intent
Analyzer flagged the query as AMBIGUOUS. The user gave a plausible infra query that
lacks the resource/system anchor needed to act on it.

Your job is to produce ONE composite clarifying question that lets the user disambiguate
in a single turn — minimizing friction.

Do the following:

1. CONTINUATION HYPOTHESIS — speculatively assume the query is a follow-up to the most
   recent investigation in the conversation history.
     - Identify which active investigation the query most plausibly continues
       (resource name, time window, last action taken).
     - Identify what parameters that continuation would need and whether they can be
       inherited from the conversation history.
     - If a coherent continuation interpretation exists, capture it as a single short
       sentence the user can confirm with one word (e.g. "Continue investigating
       `lowerground_cart_app` in `prod-1`?").

2. NEW-TOPIC HYPOTHESIS — identify what a fresh interpretation would minimally require
   (target system/project, time window, etc.). List ONLY the parameters that would be
   needed if the user is starting a new topic.

3. COMPOSITE CLARIFICATION — combine both into ONE question the user can answer with
   either a one-word confirmation (continuation) OR a brief reply that picks the
   new-topic path and supplies the missing details:

     "Did you mean to continue <continuation_hypothesis>? Or are you starting a new
      topic — if so, please tell me <comma-separated missing new-topic params>."

   Keep it under ~30 words. If no plausible continuation exists, fall back to a
   pure new-topic clarifying question.

NEVER auto-resolve the ambiguity. The user must pick. NEVER fabricate continuation
context that isn't actually in the conversation history.

## OUTPUT

Respond with valid JSON only:
{
  "continuation_hypothesis": "short sentence describing the inferred continuation, or empty string if none",
  "continuation_required_parameters": [
    {"name": "...", "description": "...", "present": true|false, "value": "...", "source": "conversation|env_profile|missing"}
  ],
  "new_topic_required_parameters": [
    {"name": "...", "description": "..."}
  ],
  "clarifying_question": "single composite question for the user"
}
"""


def _strip_code_fences(content: Any) -> str:
    """Normalize an LLM response into a JSON-parseable string."""
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
        content = "".join(parts)
    elif not isinstance(content, str):
        content = str(content)
    content = content.strip()
    if content.startswith("```json"):
        content = content[7:]
    elif content.startswith("```"):
        content = content[3:]
    if content.endswith("```"):
        content = content[:-3]
    return content.strip()


def create_intent_analyzer_node(
    conn: sqlite3.Connection, embedding_service: Any, env_profile: Any = None
) -> Callable:
    """Create the Intent Analyzer node function.

    Args:
        conn: Tenant-scoped SQLite connection for STM access.
        embedding_service: Service for vectorizing queries (used by §3.3 RAG).
        env_profile: Optional auto-discovered EnvironmentProfile.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    env_context = env_profile.to_prompt_context() if env_profile else ""

    # Stage 1 cached system prompt
    intent_cache_name = cache_manager.get_or_create_cache(
        model_name=settings.llm_model,
        system_prompt=_INTENT_SYSTEM_PROMPT,
        env_context=env_context,
    )
    # Stage 2 standard cached system prompt
    param_cache_name = cache_manager.get_or_create_cache(
        model_name=settings.llm_model,
        system_prompt=_PARAM_EXTRACTION_SYSTEM_PROMPT,
        env_context=env_context,
    )
    # Stage 2 AMBIGUOUS dual-mode cached system prompt
    dual_mode_cache_name = cache_manager.get_or_create_cache(
        model_name=settings.llm_model,
        system_prompt=_AMBIGUOUS_DUAL_MODE_SYSTEM_PROMPT,
        env_context=env_context,
    )

    def _build_llm(cache_name: str | None):
        kwargs: dict[str, Any] = {
            "model": settings.llm_model,
            "google_api_key": settings.google_api_key,
            "temperature": 0.0,
        }
        if cache_name:
            kwargs["cached_content"] = cache_name
        return get_llm(
            provider=settings.intent_analyzer_llm_provider,
            model_name=settings.intent_analyzer_llm_model,
            **kwargs
        )

    intent_llm = _build_llm(intent_cache_name)
    param_llm = _build_llm(param_cache_name)
    dual_mode_llm = _build_llm(dual_mode_cache_name)
    stm = ShortTermMemory(conn)

    def _log_usage(response: Any, state: AgentState) -> None:
        usage = getattr(response, "usage_metadata", None) or {}
        if not usage:
            return
        input_details = usage.get("input_token_details") or {}
        output_details = usage.get("output_token_details") or {}
        try:
            stm.log_token_usage(TokenUsageRecord(
                session_id=state.get("session_id", ""),
                request_id=state.get("request_id"),
                tenant_id=state.get("tenant_id", ""),
                agent=AgentType.ROUTER,  # logged under router bucket for FinOps simplicity
                prompt_tokens=usage.get("input_tokens", 0),
                completion_tokens=usage.get("output_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                reasoning_tokens=output_details.get("reasoning", 0),
                cache_read_tokens=input_details.get("cache_read", 0),
                cache_creation_tokens=input_details.get("cache_creation", 0),
                model_name=getattr(intent_llm, "model", settings.llm_model),
            ))
        except Exception as e:  # never let token bookkeeping break the swarm
            logger.warning("token usage log failed: %s", e)

    def _clear_transient_state(state: AgentState) -> None:
        """Wipe per-turn output state so a previous turn cannot bleed into this one."""
        state["os_analysis"] = ""
        state["cloud_analysis"] = ""
        state["finops_analysis"] = ""
        state["security_review"] = ""
        state["final_output"] = ""
        state["security_flags"] = []
        state["router_iterations"] = 0
        state["command_log"] = []
        state["command_count"] = 0
        state["hitl_pending"] = False
        state["router_execution_plan"] = []
        state["router_current_step"] = 1
        state["task_summary"] = ""
        state["required_parameters"] = []
        state["missing_parameters"] = []

    async def _classify_intent(state: AgentState, recent_conversation: str) -> dict:
        """Stage 1 — classify intent + resolve entities."""
        messages: list = []
        if not intent_cache_name:
            messages.append(("system", _INTENT_SYSTEM_PROMPT))
            if env_profile:
                messages.append(("system", env_profile.to_prompt_context()))
        if recent_conversation:
            messages.append(("human", f"Recent conversation history:\n{recent_conversation}"))
        messages.append(("human", f"USER QUERY: {state['user_query']}"))

        response = await intent_llm.ainvoke(messages)
        _log_usage(response, state)
        return json.loads(_strip_code_fences(response.content))

    async def _extract_params_standard(
        state: AgentState, conversation_history: str, intent: str
    ) -> dict:
        """Stage 2 (standard) — for CONTINUATION / NEW_TOPIC."""
        messages: list = []
        if not param_cache_name:
            messages.append(("system", _PARAM_EXTRACTION_SYSTEM_PROMPT))
            if env_profile:
                messages.append(("system", env_profile.to_prompt_context()))
        if conversation_history:
            messages.append((
                "human",
                f"CONVERSATION HISTORY (for param resolution):\n{conversation_history}",
            ))
        messages.append(("human", f"RESOLVED USER QUERY: {state['user_query']}"))
        messages.append(("human", f"INTENT CLASSIFICATION: {intent}"))

        response = await param_llm.ainvoke(messages)
        _log_usage(response, state)
        return json.loads(_strip_code_fences(response.content))

    async def _extract_params_dual_mode(
        state: AgentState, conversation_history: str
    ) -> dict:
        """Stage 2 (dual-mode) — for AMBIGUOUS. Output is advisory only."""
        messages: list = []
        if not dual_mode_cache_name:
            messages.append(("system", _AMBIGUOUS_DUAL_MODE_SYSTEM_PROMPT))
            if env_profile:
                messages.append(("system", env_profile.to_prompt_context()))
        if conversation_history:
            messages.append((
                "human",
                f"CONVERSATION HISTORY (for continuation hypothesis):\n{conversation_history}",
            ))
        messages.append(("human", f"AMBIGUOUS USER QUERY (resolved): {state['user_query']}"))

        response = await dual_mode_llm.ainvoke(messages)
        _log_usage(response, state)
        return json.loads(_strip_code_fences(response.content))

    async def intent_analyzer_node(state: AgentState) -> AgentState:
        """Two-stage entry point: classify, then (serial) dynamic param mapping."""
        session_id = state.get("session_id", "")
        logger.info("Intent Analyzer: evaluating query for session %s", session_id)

        # Webhook / event path skips intent detection entirely.
        if not state.get("user_query"):
            return {
                **state,
                "intent_status": "NEW_TOPIC",
                "conversation_history": "",
                "current_agent": "intent_analyzer",
            }

        user_query = state["user_query"]
        recent_conversation = (
            stm.get_recent_conversation_text(session_id, limit=3) if session_id else ""
        )

        # ── STAGE 1: Intent Classification + Entity Resolution ────────
        try:
            classify_result = await _classify_intent(state, recent_conversation)
        except Exception as e:
            logger.error("Intent Analyzer Stage 1 failed: %s — failing open as NEW_TOPIC", e)
            _clear_transient_state(state)
            return {
                **state,
                "intent_status": "NEW_TOPIC",
                "conversation_history": "",
                "current_agent": "intent_analyzer",
            }

        intent = classify_result.get("intent", "NEW_TOPIC")
        reasoning = classify_result.get("reasoning", "")
        stage1_clarifying = classify_result.get("clarifying_question", "") or ""
        resolved_query = classify_result.get("resolved_query") or user_query

        # Apply entity resolution so every downstream stage sees the canonical query.
        if resolved_query and resolved_query != user_query:
            logger.info("Entity Resolution: '%s' -> '%s'", user_query, resolved_query)
            state["user_query"] = resolved_query

        logger.info("Intent: %s. Reasoning: %s", intent, reasoning)
        stm.add_turn(ConversationTurn(
            session_id=session_id,
            request_id=state.get("request_id"),
            agent=AgentType.INTENT_ANALYZER,
            content=f"[INTENT CLASSIFICATION]: {intent}\n[REASONING]: {reasoning}"
        ))

        _clear_transient_state(state)

        # ── IRRELEVANT short-circuit (no Stage 2) ─────────────────────
        if intent == "IRRELEVANT":
            clarifying = stage1_clarifying or (
                "I specialize in cloud and OS infrastructure. Could you clarify how your "
                "question relates to your environment?"
            )
            return {
                **state,
                "intent_status": "IRRELEVANT",
                "clarifying_question": clarifying,
                "final_output": clarifying,
                "conversation_history": "",
                "current_agent": "intent_analyzer",
            }

        # Build the conversation history downstream stages will consume.
        if intent == "CONTINUATION" or intent == "AMBIGUOUS":
            # CONTINUATION uses semantic RAG for richer context.
            # AMBIGUOUS uses the same semantic context to build its continuation hypothesis.
            try:
                query_embedding = await embedding_service.embed_query(state["user_query"])
                conversation_history = stm.get_semantic_conversation_context(
                    session_id=session_id,
                    query_embedding=query_embedding,
                    limit=3,
                )
            except Exception as e:
                logger.warning(
                    "Semantic STM fetch failed, falling back to chronological: %s", e
                )
                conversation_history = recent_conversation
        else:
            # NEW_TOPIC: clear context so the Router doesn't bias on prior incidents.
            conversation_history = ""

        # ── AMBIGUOUS short-circuit (Stage 2 used in advisory dual-mode) ──
        if intent == "AMBIGUOUS":
            try:
                dual = await _extract_params_dual_mode(state, conversation_history)
                clarifying = dual.get("clarifying_question", "") or stage1_clarifying
            except Exception as e:
                logger.warning("Stage 2 dual-mode failed: %s — falling back to simple ask", e)
                dual = {}
                clarifying = (
                    "Your question could apply to more than one system. Are you continuing "
                    "the previous investigation, or starting a new topic? If new, please "
                    "tell me which system/project and what time window."
                )
            return {
                **state,
                "intent_status": "AMBIGUOUS",
                "clarifying_question": clarifying,
                "final_output": clarifying,
                "conversation_history": conversation_history,
                # Surface the advisory dual-mode info for trace/debug.
                "task_summary": dual.get("continuation_hypothesis", ""),
                "required_parameters": dual.get("continuation_required_parameters", []) or [],
                "missing_parameters": [
                    p.get("name", "")
                    for p in (dual.get("new_topic_required_parameters") or [])
                    if isinstance(p, dict) and p.get("name")
                ],
                "current_agent": "intent_analyzer",
            }

        # ── STAGE 2 (standard): Dynamic Parameter Mapping ─────────────
        # Runs for CONTINUATION and NEW_TOPIC only.
        try:
            params_result = await _extract_params_standard(
                state, conversation_history, intent
            )
        except Exception as e:
            # Fail open: do not block the swarm on a param-extractor failure.
            logger.warning(
                "Stage 2 param extraction failed: %s — proceeding without param gate", e
            )
            params_result = {}

        task_summary = params_result.get("task_summary", "") or ""
        required_parameters = params_result.get("required_parameters", []) or []
        missing_parameters = [
            p for p in (params_result.get("missing_parameters", []) or []) if p
        ]
        param_clarifying = params_result.get("clarifying_question", "") or ""

        logger.info(
            "Param Extractor: task='%s' required=%d missing=%s",
            task_summary, len(required_parameters), missing_parameters,
        )

        # ── MISSING_PARAMS short-circuit ─────────────────────────────
        if missing_parameters:
            if not param_clarifying:
                param_clarifying = (
                    "I need a bit more detail to proceed. Please provide: "
                    + ", ".join(missing_parameters)
                )
            logger.info(
                "Intent Analyzer: MISSING_PARAMS — halting swarm; asking for %s",
                missing_parameters,
            )
            return {
                **state,
                "intent_status": "MISSING_PARAMS",
                "clarifying_question": param_clarifying,
                "task_summary": task_summary,
                "required_parameters": required_parameters,
                "missing_parameters": missing_parameters,
                "final_output": param_clarifying,
                "conversation_history": conversation_history,
                "current_agent": "intent_analyzer",
            }

        # ── PROCEED to Supervisor Router ─────────────────────────────
        return {
            **state,
            "intent_status": intent,  # CONTINUATION or NEW_TOPIC
            "clarifying_question": "",
            "conversation_history": conversation_history,
            "task_summary": task_summary,
            "required_parameters": required_parameters,
            "missing_parameters": [],
            "current_agent": "intent_analyzer",
        }

    return intent_analyzer_node
