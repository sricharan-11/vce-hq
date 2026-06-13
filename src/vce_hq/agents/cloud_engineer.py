"""Cloud Engineer Agent with RAG and live diagnostics (ReAct loop).

Specializes in cloud-provider APIs: IAM, networking (VPCs, firewalls,
load balancers), compute (VMs, containers, serverless), managed
services, and cloud-specific diagnostics.

Follows the augmented ReAct pattern (PRD_Brain_v1.0 §4.1).
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

logger = logging.getLogger(__name__)

_CLOUD_SYSTEM_PROMPT = """\
You are the Cloud Engineer Agent for VCE-HQ — an expert cloud infrastructure operator.

You are NOT a chatbot. You are an expert Cloud SRE who RUNS REAL CLI COMMANDS (gcloud, aws, az, kubectl) \
on the live infrastructure before reporting findings. You must ALWAYS gather live evidence first.

IMPORTANT: You report your findings to the Supervisor Router — NOT directly to the user. \
Provide raw, detailed diagnostic data. Do NOT format your output as a final user-facing \
answer. The Supervisor will cross-validate your findings and decide the next steps.

Your specializations include:
- IAM, Networking, Compute, Storage, Managed services, Monitoring, Cost, Kubernetes

You will receive:
1. An instruction from the Supervisor Router specifying what to investigate
2. Retrieved context from the tenant's knowledge base
3. (If applicable) The analysis from the OS Engineer Agent

## CRITICAL: ALWAYS RUN COMMANDS FIRST
On EVERY query, your FIRST response MUST include a cloud CLI command request.
NEVER produce a final answer without first running at least one diagnostic command.

## IMPORTANT: AUTHENTICATION IS AUTOMATIC
The system automatically injects credentials from the vault. You DO NOT need to run
'gcloud auth login', 'aws configure', or any login commands.
Just run the diagnostic commands directly (e.g., 'gcloud compute instances list').

DIAGNOSTIC COMMANDS:
To request a command, include EXACTLY this JSON block in your response:

```json
{"action": "execute_command", "command": "<your command>", "reasoning": "<why you need this>"}
```

ALLOWED COMMANDS (read-only only):
- AWS: aws ec2 describe-*, aws iam get-*, aws cloudwatch get-*, aws logs filter-log-events, aws rds describe-*, aws s3 ls
- GCP: gcloud compute instances list/describe, gcloud projects get-iam-policy, gcloud iam service-accounts list, gcloud container clusters list, gcloud logging read
- Azure: az vm show/list, az network nsg show/list, az monitor metrics list, az account show
- Kubernetes: kubectl get, kubectl describe, kubectl logs, kubectl top
- ONLY read/list/describe/show/get subcommands are permitted.
- NEVER request create/delete/update/modify/stop/start commands.

RULES:
- ALWAYS run at least one command before producing your final response
- Be specific with commands — target the exact resource the query is about
- Maximum 5 command iterations — use them efficiently
- You CANNOT SSH into VMs. Do NOT mention SSH limitations in your response. \
If OS-level data is needed (ports, processes, logs), just report the VM inventory \
and the Supervisor Router will delegate the SSH work to the OS Engineer.

## RESPONSE FORMAT — ADAPT TO THE QUERY TYPE

**You MUST choose the right response format based on what the user is asking:**

### TYPE 1: INFORMATIONAL QUERY (e.g., "list VMs", "show firewall rules", "what's my IAM policy?")
When the user is asking for information or data — NOT reporting a problem:
- Run the appropriate command
- Return the data clearly and directly
- Add a brief summary or insight if useful
- Do NOT produce a "Root Cause Analysis" or "Remediation Playbook" — there is nothing to fix!

Example response for "list the VMs":
```
Here are the VMs in your project **isolated-lab-for-testing**:

| NAME | ZONE | MACHINE_TYPE | STATUS |
|------|------|-------------|--------|
| instance-1 | us-central1-a | e2-medium | RUNNING |

**Summary:** 1 VM found, all running.
```

### TYPE 2: DIAGNOSTIC / INCIDENT QUERY (e.g., "why is my VM slow?", "API returning 503", alert payloads)
When the user reports a problem, an alert fires, or something is broken:
- Run diagnostic commands to gather evidence
- Produce a structured analysis:

## Root Cause Analysis
[Your analysis with confidence level, backed by real CLI output]

## Affected Resources
[Specific cloud resources identified with IDs/Names]

## Live Evidence
[Exact CLI outputs that support your analysis]

## Remediation Playbook
[Numbered steps with exact CLI commands — ONLY if remediation is needed]

## References
[Any relevant ADRs, runbooks, or past incidents from context]
"""


def create_cloud_engineer_node(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    credential_manager: CredentialManager,
    env_profile: EnvironmentProfile | None = None,
) -> callable:
    """Create the Cloud Engineer Agent node with ReAct loop for LangGraph.

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: For RAG query embedding.
        credential_manager: For retrieving tenant cloud credentials to
            inject into CLI subprocess calls.
        env_profile: Auto-discovered environment profile for infrastructure
            awareness.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    # Build environment context string for prompt injection
    env_context = env_profile.to_prompt_context() if env_profile else ""
    llm = ChatGoogleGenerativeAI(
        model=settings.llm_model,
        google_api_key=settings.google_api_key,
        temperature=0.2,
    )

    stm = ShortTermMemory(conn)

    executor = CommandExecutor(
        agent_name="cloud_engineer",
        domain=CommandDomain.CLOUD,
    )

    async def cloud_engineer_node(state: AgentState) -> AgentState:
        """Analyze an issue from the cloud engineering perspective with live diagnostics."""
        session_id = state.get("session_id", "unknown")
        logger.info("Cloud Engineer: analyzing for session %s", session_id)

        command_log: list[dict] = list(state.get("command_log", []))
        command_count: int = state.get("command_count", 0)

        query = _build_query(state)

        # ── Step 1: RAG retrieval ─────────────────────────────
        context, _results = await retrieve_context(
            conn, embedding_service, query, top_k=5
        )

        # ── Handle Resumed HITL Command ──────────────────────────────
        if not state.get("hitl_pending") and state.get("hitl_command"):
            logger.info("Cloud Engineer: Executing approved HITL command: %s", state["hitl_command"])
            cmd_str = state["hitl_command"]
            
            available_credentials = credential_manager.list_credentials_with_plaintext()
            with resolve_credentials(cmd_str, available_credentials) as env_overrides:
                result = await executor.execute(
                    cmd_str, env_overrides=env_overrides, reasoning="Approved via HITL", use_shell=True, skip_gate=True, original_query=query, adrs_context=context
                )
            
            command_log.append(result.to_dict())
            command_count += 1
            
            stm.log_command(CommandExecution(
                session_id=session_id, agent=AgentType.CLOUD_ENGINEER, command=result.command, reasoning="Approved via HITL", exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, duration_ms=result.duration_ms, validated_by=result.validated_by, truncated=result.truncated,
            ))

        # ── Step 2-N: ReAct loop ──────────────────────────────
        command_outputs: list[str] = [_format_command_output_from_dict(c) for c in command_log]
        max_iterations = settings.cmd_max_iterations
        max_per_session = settings.cmd_max_per_session

        for iteration in range(1, max_iterations + 1):
            logger.info(
                "Cloud Engineer: ReAct iteration %d/%d for session %s",
                iteration, max_iterations, session_id,
            )

            messages = _build_messages(state, context, command_outputs, iteration, max_iterations, env_context)
            messages.append(("human", query))

            try:
                response = await llm.ainvoke(messages)
                
                usage = response.usage_metadata or {}
                if usage:
                    input_details = usage.get("input_token_details") or {}
                    output_details = usage.get("output_token_details") or {}
                    stm.log_token_usage(TokenUsageRecord(
                        session_id=session_id,
                        tenant_id=state.get("tenant_id", ""),
                        agent=AgentType.CLOUD_ENGINEER,
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
                logger.error("Cloud Engineer LLM call failed: %s", e)
                return {
                    **state,
                    "cloud_analysis": f"Cloud Engineer Agent encountered an error: {e}",
                    "current_agent": "cloud_engineer",
                    "command_log": command_log,
                    "command_count": command_count,
                    "error": str(e),
                    "hitl_command": "",
                    "hitl_reason": "",
                }

            action_request = _extract_json_action(response_text)

            if action_request is None:
                logger.info(
                    "Cloud Engineer: produced final analysis (iteration %d)",
                    iteration,
                )
                # Persist the agent's analysis turn to STM
                stm.add_turn(ConversationTurn(
                    session_id=session_id,
                    agent=AgentType.CLOUD_ENGINEER,
                    content=response_text,
                ))
                return {
                    **state,
                    "cloud_analysis": state.get("cloud_analysis", "") + "\n\n" + response_text,
                    "current_agent": "cloud_engineer",
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

            # Retrieve all tenant credentials (decrypted) and resolve
            # the right env vars for this specific CLI command.
            available_credentials = credential_manager.list_credentials_with_plaintext()
            logger.info(
                "Cloud Engineer: found %d credentials in vault for tenant %s",
                len(available_credentials), credential_manager._tenant_id
            )

            with resolve_credentials(
                command_request["command"], available_credentials
            ) as env_overrides:
                if env_overrides:
                    logger.info(
                        "Cloud Engineer: resolving credentials for '%s' -> injected keys: %s",
                        command_request["command"], list(env_overrides.keys())
                    )
                else:
                    logger.warning(
                        "Cloud Engineer: NO credentials resolved for command '%s'",
                        command_request["command"]
                    )

                result = await executor.execute(
                    command_request["command"],
                    env_overrides=env_overrides,
                    reasoning=command_request.get("reasoning", ""),
                    use_shell=True,  # Cloud CLIs require /bin/sh PATH
                    original_query=query,
                    adrs_context=context,
                )

            if getattr(result, "exit_code", None) == -3:
                logger.info("Cloud Engineer pausing for HITL on command: %s", command_request["command"])
                return {
                    **state,
                    "hitl_pending": True,
                    "hitl_command": result.command,
                    "hitl_reason": result.stderr,
                    "current_agent": "cloud_engineer",
                    "command_log": command_log,
                    "command_count": command_count,
                }

            command_log.append(result.to_dict())
            command_count += 1

            # Persist command execution to STM audit trail
            stm.log_command(CommandExecution(
                session_id=session_id,
                agent=AgentType.CLOUD_ENGINEER,
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

        logger.warning(
            "Cloud Engineer: max iterations (%d) reached for session %s",
            max_iterations, session_id,
        )
        final_messages = _build_messages(
            state, context, command_outputs,
            max_iterations + 1, max_iterations, env_context,
        )
        final_messages.append((
            "human",
            f"{query}\n\n"
            f"⚠️ You have reached the maximum number of diagnostic iterations. "
            f"Produce your best analysis with the data available. "
            f"Flag areas where further investigation is needed.",
        ))

        try:
            response = await llm.ainvoke(final_messages)
            
            usage = response.usage_metadata or {}
            if usage:
                input_details = usage.get("input_token_details") or {}
                output_details = usage.get("output_token_details") or {}
                stm.log_token_usage(TokenUsageRecord(
                    session_id=session_id,
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.CLOUD_ENGINEER,
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
            analysis = (
                f"Cloud Engineer Agent exhausted iterations and encountered an error: {e}"
            )

        return {
            **state,
            "cloud_analysis": analysis,
            "current_agent": "cloud_engineer",
            "command_log": command_log,
            "command_count": command_count,
            "hitl_command": "",
            "hitl_reason": "",
        }

    return cloud_engineer_node


def _build_query(state: AgentState) -> str:
    """Build the analysis query from state."""
    parts: list[str] = []

    if state.get("event"):
        event = state["event"]
        parts.append(f"Alert from {event.get('source', 'unknown')}:")
        parts.append(f"Severity: {event.get('severity', 'unknown')}")
        parts.append(f"Title: {event.get('title', 'No title')}")
        parts.append(f"Body: {event.get('body', 'No body')}")
        tags = event.get("tags", [])
        if tags:
            parts.append(f"Tags: {', '.join(tags)}")
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
) -> list[tuple[str, str]]:
    """Build the LLM message list for a given ReAct iteration."""
    messages: list[tuple[str, str]] = [
        ("system", _CLOUD_SYSTEM_PROMPT),
        ("system", f"IMPORTANT: You are currently operating in {settings.execution_mode}."),
    ]

    if env_context:
        messages.append(("system", env_context))

    if state.get("router_instruction"):
        messages.append(
            ("system", f"The Supervisor Router has assigned you this task:\n{state['router_instruction']}")
        )

    if state.get("conversation_history"):
        messages.append(
            ("system", f"Conversation history:\n{state['conversation_history']}")
        )

    if context:
        messages.append(
            ("system", f"Retrieved context from tenant knowledge base:\n{context}")
        )

    if state.get("os_analysis"):
        messages.append(
            ("system",
             f"The OS Engineer Agent has already analyzed this incident:\n"
             f"{state['os_analysis']}\n\n"
             f"Build upon this analysis from the cloud perspective. "
             f"Identify any cloud-layer causes or contributing factors.")
        )

    if command_outputs:
        combined = "\n\n".join(command_outputs)
        remaining = max_iterations - iteration
        messages.append(
            ("system",
             f"Previous diagnostic command results:\n{combined}\n\n"
             f"Remaining command iterations: {remaining}")
        )

    return messages


def _extract_json_action(response: str) -> dict | None:
    """Extract an action request from the LLM response.

    Looks for a JSON block with ``action: execute_command``.

    Args:
        response: The full LLM response text.

    Returns:
        A dict containing the action parameters, or None.
    """
    import re
    json_pattern = re.compile(r"```json\s*\n?(.+?)\n?\s*```", re.DOTALL)
    matches = json_pattern.findall(response)

    for match in matches:
        try:
            data = json.loads(match)
            if isinstance(data, dict):
                action = data.get("action")
                if action == "execute_command":
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
    """Format a command result for injection into the next LLM iteration."""
    parts = [
        f"Command: {result.command}",
        f"Exit Code: {result.exit_code}",
    ]
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
