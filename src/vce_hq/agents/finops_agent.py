"""FinOps Agent with live diagnostics (ReAct loop).

Specializes in cloud consumption tracking, billing analysis, cost 
optimization, budget allocation, and acting as the "ruthless paranoid CFO".
Tracks hourly/daily/monthly patterns and maps bill differences to workload.

Follows the augmented ReAct pattern (PRD_Brain_vB1.2 §5.1).
"""

import json
import logging
import sqlite3

from langchain_google_genai import ChatGoogleGenerativeAI

from vce_hq.agents.rag import retrieve_context
from vce_hq.agents.state import AgentState
from vce_hq.config import settings
from vce_hq.db.models import AgentType, CommandExecution, ConversationTurn, TokenUsageRecord
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.embeddings.service import EmbeddingService
from vce_hq.execution.executor import CommandExecutor, CommandResult
from vce_hq.execution.validator import CommandDomain
from vce_hq.vault.credential_resolver import resolve_credentials
from vce_hq.vault.manager import CredentialManager
from vce_hq.discovery.probe import EnvironmentProfile
from vce_hq.cache_manager import cache_manager

logger = logging.getLogger(__name__)

_FINOPS_SYSTEM_PROMPT = """\
You are the FinOps Agent for VCE-HQ — the ruthless, paranoid CFO of the infrastructure.

You are NOT a simple chatbot. You actively analyze cloud consumption, tracking hourly, \
daily, and monthly usage patterns. Your mission is to ruthlessly optimize cost, eliminate \
waste, and ensure the cloud architecture is financially efficient based on the tenant's \
business vertical and P&L.

IMPORTANT: You report your findings to the Supervisor Router — NOT directly to the user. \
Provide raw, detailed cost analysis, anomaly detection (spikes), and architectural \
optimization recommendations. Do NOT format your output as a final user-facing answer. \
The Supervisor will cross-validate your findings and decide the next steps, potentially \
pushing the Cloud and OS Engineers to implement your recommended architecture changes.

Your specializations and responsibilities include:
1. Hourly tracking: Detect abrupt spikes and abusive usage levels.
2. Daily/Monthly tracking: Analyze component-level bill differences and map them against workload effectiveness.
3. Budget recalibration: Compare actual usage vs. ideal budgets based on industry PnL.
4. Waste cleanup: Identify idle/underutilized resources for resizing or termination.
5. Deep analysis: Relentlessly drill into the top 5 consumers in the billing dashboard.
6. Push for efficiency: If an architecture is wasteful, explicitly tell the Supervisor \
to dispatch the Cloud/OS engineers to investigate alternatives.

You will receive:
1. An instruction from the Supervisor Router
2. Retrieved context from the tenant's knowledge base (ADRs, past incidents)
3. Ongoing analysis from other agents (if any)

## CRITICAL: ALWAYS GATHER LIVE EVIDENCE FIRST (UNLESS EXEMPTED)
To verify costs, you can use CLI commands like 'gcloud alpha billing accounts list', \
'aws ce get-cost-and-usage', 'gcloud compute instances list' (to check idle status).
You MUST run commands to gather evidence BEFORE answering, UNLESS the Supervisor Router explicitly instructs you to just answer the question without running commands.

DIAGNOSTIC COMMANDS:
To request a command, include EXACTLY this JSON block in your response:

```json
{"action": "execute_command", "command": "<your command>", "reasoning": "<why you need this>"}
```

ALLOWED COMMANDS:
You can use billing and cost analysis CLI commands. The system's blocklist and current Execution Mode will automatically determine if a command is permitted.
- In Mode 1 & 2: Mutating/destructive billing commands are blocked.
- In Mode 3 (Full Access): Destructive billing commands (e.g., unlink) are allowed with HITL approval.
- NOTE: You do NOT execute infrastructure shutdowns directly. If resources must be deleted to save money, instruct the Supervisor Router to delegate the deletion to the Cloud Engineer.

RULES:
- Be ruthless about cost. If a resource is idle, flag it for deletion.
- If you lack business vertical or P&L data to determine the ideal budget, explicitly note this gap so the Supervisor can ask the user.
- Maximum 5 command iterations — use them efficiently.
- You CANNOT SSH into VMs. For infrastructure shutdowns, instruct the Supervisor Router to delegate to the Cloud Engineer.

## RESPONSE FORMAT

Produce a structured financial and architectural analysis:

## Cost Anomaly Detection
[Did you find any hourly spikes or abusive levels?]

## Top Consumers & Workload Effectiveness
[Analyze the top 5 billing items. Are they justified by the workload?]

## Waste Identification
[List specific idle or underutilized resources for daily cleanup/resizing]

## Architectural Optimization Push
[Specific changes the OS/Cloud Engineers should investigate to save money]

## Budget Recalibration
[Current usage vs. Ideal budget mapping]

## Live Evidence
[Exact CLI outputs that support your analysis]
"""


def create_finops_agent_node(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    credential_manager: CredentialManager,
    env_profile: EnvironmentProfile | None = None,
) -> callable:
    """Create the FinOps Agent node with ReAct loop for LangGraph.

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: For RAG query embedding.
        credential_manager: For retrieving tenant cloud credentials.
        env_profile: Auto-discovered environment profile.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    env_context = env_profile.to_prompt_context() if env_profile else ""
    # Attempt to get or create a context cache
    cache_name = cache_manager.get_or_create_cache(
        model_name=settings.llm_model,
        system_prompt=_FINOPS_SYSTEM_PROMPT,
        env_context=env_context,
    )

    llm_kwargs = {
        "model": settings.llm_model,
        "google_api_key": settings.google_api_key,
        "temperature": 0.2,
    }
    if cache_name:
        llm_kwargs["cached_content"] = cache_name

    llm = ChatGoogleGenerativeAI(**llm_kwargs)

    stm = ShortTermMemory(conn)

    # Re-using Cloud domain executor since FinOps relies on cloud CLI billing APIs
    executor = CommandExecutor(
        agent_name="finops_agent",
        domain=CommandDomain.CLOUD,
    )

    async def finops_agent_node(state: AgentState) -> AgentState:
        session_id = state.get("session_id", "unknown")
        logger.info("FinOps Agent: analyzing for session %s", session_id)

        command_log: list[dict] = list(state.get("command_log", []))
        command_count: int = state.get("command_count", 0)

        query = _build_query(state)

        # ── Step 1: RAG retrieval ─────────────────────────────
        context, _results = await retrieve_context(
            conn, embedding_service, query, top_k=5
        )

        # ── Handle Resumed HITL Command ──────────────────────────────
        if not state.get("hitl_pending") and state.get("hitl_command"):
            logger.info("FinOps Agent: Executing approved HITL command: %s", state["hitl_command"])
            cmd_str = state["hitl_command"]
            
            available_credentials = credential_manager.list_credentials_with_plaintext()
            with resolve_credentials(cmd_str, available_credentials) as env_overrides:
                result = await executor.execute(
                    cmd_str, env_overrides=env_overrides, reasoning="Approved via HITL", use_shell=True, skip_gate=True, original_query=query, adrs_context=context
                )
            
            command_log.append(result.to_dict())
            command_count += 1
            
            stm.log_command(CommandExecution(
                session_id=session_id, request_id=state.get("request_id"), agent=AgentType.FINOPS_AGENT, command=result.command, reasoning="Approved via HITL", exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, duration_ms=result.duration_ms, validated_by=result.validated_by, truncated=result.truncated,
            ))

        # ── Step 2-N: ReAct loop ──────────────────────────────
        command_outputs: list[str] = [_format_command_output_from_dict(c) for c in command_log]
        max_iterations = settings.cmd_max_iterations
        max_per_session = settings.cmd_max_per_session

        for iteration in range(1, max_iterations + 1):
            logger.info(
                "FinOps Agent: ReAct iteration %d/%d for session %s",
                iteration, max_iterations, session_id,
            )

            messages = _build_messages(state, context, command_outputs, iteration, max_iterations, env_context, cache_name)
            messages.append(("human", query))

            try:
                response = await llm.ainvoke(messages)
                
                usage = response.usage_metadata or {}
                if usage:
                    input_details = usage.get("input_token_details") or {}
                    output_details = usage.get("output_token_details") or {}
                    stm.log_token_usage(TokenUsageRecord(
                        session_id=session_id, request_id=state.get("request_id"),
                        tenant_id=state.get("tenant_id", ""),
                        agent=AgentType.FINOPS_AGENT,
                        prompt_tokens=usage.get("input_tokens", 0),
                        completion_tokens=usage.get("output_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        reasoning_tokens=output_details.get("reasoning", 0),
                        cache_read_tokens=input_details.get("cache_read", 0),
                        cache_creation_tokens=input_details.get("cache_creation", 0),
                        model_name=llm.model,
                    ))

                response_text = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in response.content) if isinstance(response.content, list) else str(response.content)
            except Exception as e:
                logger.error("FinOps Agent LLM call failed: %s", e)
                return {
                    **state,
                    "finops_analysis": f"FinOps Agent encountered an error: {e}",
                    "current_agent": "finops_agent",
                    "command_log": command_log,
                    "command_count": command_count,
                    "error": str(e),
                    "hitl_command": "",
                    "hitl_reason": "",
                }

            action_request = _extract_json_action(response_text)

            if action_request is None:
                logger.info(
                    "FinOps Agent: produced final analysis (iteration %d)",
                    iteration,
                )
                stm.add_turn(ConversationTurn(
                    session_id=session_id, request_id=state.get("request_id"),
                    agent=AgentType.FINOPS_AGENT,
                    content=response_text,
                ))
                return {
                    **state,
                    "finops_analysis": state.get("finops_analysis", "") + "\n\n" + response_text,
                    "current_agent": "finops_agent",
                    "command_log": command_log,
                    "command_count": command_count,
                    "hitl_command": "",
                    "hitl_reason": "",
                }

            # ── Execute the requested command ─────────────────
            command_request = action_request
            if not settings.cmd_enabled:
                command_outputs.append(
                    f"[Command execution is disabled globally. "
                    f"Requested: {command_request['command']}]"
                )
                continue

            if command_count >= max_per_session:
                command_outputs.append(
                    f"[Session command limit ({max_per_session}) reached. "
                    f"Requested: {command_request['command']}]"
                )
                continue

            available_credentials = credential_manager.list_credentials_with_plaintext()
            with resolve_credentials(command_request["command"], available_credentials) as env_overrides:
                result = await executor.execute(
                    command_request["command"],
                    env_overrides=env_overrides,
                    reasoning=command_request.get("reasoning", ""),
                    use_shell=True,
                    original_query=query,
                    adrs_context=context,
                )

            if getattr(result, "exit_code", None) == -3:
                logger.info("FinOps Agent pausing for HITL on command: %s", command_request["command"])
                return {
                    **state,
                    "hitl_pending": True,
                    "hitl_command": result.command,
                    "hitl_reason": result.stderr,
                    "current_agent": "finops_agent",
                    "command_log": command_log,
                    "command_count": command_count,
                }

            command_log.append(result.to_dict())
            command_count += 1

            stm.log_command(CommandExecution(
                session_id=session_id, request_id=state.get("request_id"),
                agent=AgentType.FINOPS_AGENT,
                command=result.command,
                reasoning=command_request.get("reasoning", ""),
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=result.duration_ms,
                validated_by=result.validated_by,
                truncated=result.truncated,
            ))

            output_text = _format_command_output(result)
            command_outputs.append(output_text)

        logger.warning("FinOps Agent: max iterations reached for session %s", session_id)
        final_messages = _build_messages(
            state, context, command_outputs, max_iterations + 1, max_iterations, env_context, cache_name
        )
        final_messages.append((
            "human",
            f"{query}\n\n"
            f"⚠️ You have reached the maximum number of diagnostic iterations. "
            f"Produce your best analysis with the data available."
        ))

        try:
            response = await llm.ainvoke(final_messages)
            
            usage = response.usage_metadata or {}
            if usage:
                input_details = usage.get("input_token_details") or {}
                output_details = usage.get("output_token_details") or {}
                stm.log_token_usage(TokenUsageRecord(
                    session_id=session_id, request_id=state.get("request_id"),
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.FINOPS_AGENT,
                    prompt_tokens=usage.get("input_tokens", 0),
                    completion_tokens=usage.get("output_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    reasoning_tokens=output_details.get("reasoning", 0),
                    cache_read_tokens=input_details.get("cache_read", 0),
                    cache_creation_tokens=input_details.get("cache_creation", 0),
                    model_name=llm.model,
                ))

            analysis = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in response.content) if isinstance(response.content, list) else str(response.content)
        except Exception as e:
            analysis = f"FinOps Agent exhausted iterations and encountered an error: {e}"

        return {
            **state,
            "finops_analysis": analysis,
            "current_agent": "finops_agent",
            "command_log": command_log,
            "command_count": command_count,
            "hitl_command": "",
            "hitl_reason": "",
        }

    return finops_agent_node


def _build_query(state: AgentState) -> str:
    parts: list[str] = []
    if state.get("event"):
        event = state["event"]
        parts.append(f"Alert from {event.get('source', 'unknown')}:")
        parts.append(f"Severity: {event.get('severity', 'unknown')}")
        parts.append(f"Title: {event.get('title', 'No title')}")
        parts.append(f"Body: {event.get('body', 'No body')}")
    elif state.get("user_query"):
        parts.append(state["user_query"])
    if state.get("route_reasoning"):
        parts.append(f"\nRouter reasoning: {state['route_reasoning']}")
    return "\n".join(parts)


def _build_messages(
    state: AgentState,
    context: str,
    command_outputs: list[str],
    iteration: int,
    max_iterations: int,
    env_context: str = "",
    cache_name: str | None = None,
) -> list[tuple[str, str]]:
    messages: list[tuple[str, str]] = []
    if not cache_name:
        messages.extend([
            ("system", _FINOPS_SYSTEM_PROMPT),
            ("system", f"IMPORTANT: You are currently operating in {settings.execution_mode}."),
        ])
        if env_context:
            messages.append(("system", env_context))
    else:
        messages.append(("system", f"IMPORTANT: You are currently operating in {settings.execution_mode}."))
    if state.get("router_instruction"):
        messages.append(("system", f"The Supervisor Router has assigned you this task:\n{state['router_instruction']}"))
    if state.get("conversation_history"):
        messages.append(("system", f"Conversation history:\n{state['conversation_history']}"))
    if context:
        messages.append(("system", f"Retrieved context from tenant knowledge base:\n{context}"))
    if state.get("cloud_analysis"):
        messages.append(("system", f"Cloud Engineer Output:\n{state['cloud_analysis']}"))
    if state.get("os_analysis"):
        messages.append(("system", f"OS Engineer Output:\n{state['os_analysis']}"))
    
    if command_outputs:
        combined = "\n\n".join(command_outputs)
        remaining = max_iterations - iteration
        messages.append(("system", f"Previous diagnostic command results:\n{combined}\n\nRemaining iterations: {remaining}"))
    return messages


def _extract_json_action(response: str) -> dict | None:
    import re
    json_pattern = re.compile(r"```json\s*\n?(.+?)\n?\s*```", re.DOTALL)
    matches = json_pattern.findall(response)
    for match in matches:
        try:
            data = json.loads(match)
            if isinstance(data, dict):
                if data.get("action") == "execute_command":
                    command = data.get("command", "").strip()
                    if command:
                        return {
                            "action": "execute_command",
                            "command": command,
                            "reasoning": data.get("reasoning", "Not specified"),
                        }
        except json.JSONDecodeError:
            continue
    return None


def _format_command_output(result: CommandResult) -> str:
    parts = [f"Command: {result.command}", f"Exit Code: {result.exit_code}"]
    if result.truncated:
        parts.append("⚠️ Output was truncated due to size limits")
    if result.stdout:
        parts.append(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        parts.append(f"STDERR:\n{result.stderr}")
    if result.exit_code == -1:
        parts.append("⚠️ Command was rejected by validation")

    return "\n".join(parts)


def _format_command_output_from_dict(c: dict) -> str:
    """Format a command result from its dict representation."""
    parts = [
        f"Command: {c.get('command')}",
        f"Exit Code: {c.get('exit_code')}",
    ]
    if c.get("truncated"):
        parts.append("⚠️ Output was truncated due to size limits")
    if c.get("stdout"):
        parts.append(f"STDOUT:\n{c.get('stdout')}")
    if c.get("stderr"):
        parts.append(f"STDERR:\n{c.get('stderr')}")
    if c.get("exit_code") == -1:
        parts.append("⚠️ Command was rejected by validation")

    return "\n".join(parts)
