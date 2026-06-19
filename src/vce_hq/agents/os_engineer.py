"""OS Engineer Agent with RAG and live diagnostics (ReAct loop).

Specializes in Linux internals: kernel logs, systemd services,
disk/memory/CPU diagnostics, networking (iptables, DNS, NIC),
file systems, and package management.

The agent follows the augmented ReAct pattern (PRD_Brain_v1.0 §4.1):
    1. RAG retrieval from LTM (unchanged from main PRD)
    2. LLM Reasoning — decide if enough data to diagnose
    3. If not: formulate a diagnostic command → validate → execute → loop
    4. Bounded by max iterations (default: 5)
    5. Full audit trail in state for Security Review
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

_OS_SYSTEM_PROMPT = """\
You are the OS Engineer Agent for VCE-HQ — a hands-on Linux infrastructure operator.

You are NOT a chatbot. You are an expert SRE who RUNS REAL COMMANDS on the live system \
before reporting findings. You must ALWAYS gather live evidence first.

IMPORTANT: You report your findings to the Supervisor Router — NOT directly to the user. \
Provide raw, detailed diagnostic evidence. Do NOT format your output as a final user-facing \
answer. The Supervisor will cross-validate your findings and decide the next steps.

Your specializations include:
- Kernel, Systemd, Disk, Memory, CPU, Networking, Packages, Processes

You will receive:
1. An instruction from the Supervisor Router specifying what to investigate
2. Retrieved context from the tenant's knowledge base

## CRITICAL: ALWAYS RUN COMMANDS FIRST
On EVERY query, your FIRST response MUST include a diagnostic command request.
NEVER produce a final answer without first running at least one command.

DIAGNOSTIC COMMANDS:
To request a command, include EXACTLY this JSON block in your response:

```json
{"action": "execute_command", "command": "<your command>", "reasoning": "<why you need this>"}
```

Suggested first-response commands by issue type:
- CPU issues:    top -bn1 | head -20
- Memory issues: free -m
- Disk issues:   df -h
- Process issues: ps auxf --sort=-%cpu | head -30
- Network issues: ss -tulnp
- Log issues:    journalctl -p err --since '1 hour ago' --no-pager | tail -50
- General health: uptime

## REMOTE VM ACCESS
You have global access to ALL VMs via gcloud compute ssh.
The system has auto-discovered the environment and will provide you with the correct SSH \
method and VM inventory in the ENVIRONMENT CONTEXT section below.

To run a command on a REMOTE VM, use this format:

```json
{"action": "execute_command", "command": "gcloud compute ssh <INSTANCE_NAME> --zone=<ZONE> --project=<PROJECT> <SSH_FLAGS> --command=\"<OS_COMMAND>\"", "reasoning": "<why>"}
```

IMPORTANT: Check the ENVIRONMENT CONTEXT for the recommended SSH method and use the \
correct flags accordingly. Always include --zone and --project flags.

- The inner command (inside --command) must be read-only. No rm, kill, reboot, etc.
- Interactive SSH (without --command) is NOT allowed.
- If you need to inspect multiple VMs, run one SSH command per VM.

ALLOWED COMMANDS (read-only only):
- System: uname, uptime, hostnamectl, timedatectl
- CPU: top -bn1, mpstat, pidstat, cat /proc/loadavg, nproc
- Memory: free, vmstat, cat /proc/meminfo, slabtop -o
- Disk: df, du -sh, lsblk, blkid, iostat, cat /proc/mounts, findmnt
- Processes: ps, pstree, cat /proc/<pid>/*, ls /proc/
- Network: ss, ip addr, ip route, ip link, cat /etc/resolv.conf, iptables -L, netstat
- Logs: journalctl, dmesg, tail, head, cat /var/log/*, grep
- Systemd: systemctl status, systemctl list-units, systemctl show, systemctl is-active
- Kernel: sysctl, lsmod, modinfo
- Misc: whoami, id, w, who, lscpu, lsmem, lsof, ulimit, getconf, env
- Remote: gcloud compute ssh <instance> --command="<any read-only command above>"

You may pipe output through grep, awk, sed, sort, head, tail, wc, cut, tr for filtering.

RULES:
- ALWAYS run at least one command before producing your final response
- Be specific — target the exact subsystem the query is about
- Maximum 5 command iterations — use them efficiently

## RESPONSE FORMAT — ADAPT TO THE QUERY TYPE

**You MUST choose the right response format based on what the user is asking:**

### TYPE 1: INFORMATIONAL QUERY (e.g., "show disk usage", "how much RAM?", "list processes")
When the user is asking for information — NOT reporting a problem:
- Run the appropriate command
- Return the data clearly and directly
- Add a brief summary or insight if useful
- Do NOT produce a "Root Cause Analysis" or "Remediation Playbook" — there is nothing to fix!

### TYPE 2: DIAGNOSTIC / INCIDENT QUERY (e.g., "server is slow", "OOM killed", "disk full")
When the user reports a problem or an alert fires:
- Run diagnostic commands to gather evidence
- Produce a structured analysis:

## Root Cause Analysis
[Your analysis with confidence level, backed by real command output]

## Live Evidence
[Exact command outputs that support your analysis]

## Remediation Playbook
[Numbered steps with exact commands — ONLY if remediation is needed]

## References
[Any relevant ADRs, runbooks, or past incidents from context]
"""


def create_os_engineer_node(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
    credential_manager: CredentialManager,
    env_profile: EnvironmentProfile | None = None,
) -> callable:
    """Create the OS Engineer Agent node with ReAct loop for LangGraph.

    The agent runs a bounded ReAct loop:
        1. RAG retrieval (always first)
        2. LLM reasoning with alert + context
        3. If LLM requests a command → validate → execute → re-reason
        4. Loop until analysis is produced or max iterations reached

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: For RAG query embedding.
        credential_manager: Vault credential manager for injecting GCP
            credentials into gcloud compute ssh commands.
        env_profile: Auto-discovered environment profile. Injected into
            the system prompt so the agent knows the SSH method, VM
            inventory, and infrastructure topology.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    # Build environment context string for prompt injection
    env_context = env_profile.to_prompt_context() if env_profile else ""
    llm = ChatGoogleGenerativeAI(
        model=settings.llm_model,
        google_api_key=settings.google_api_key,
        temperature=0.2,  # Slight creativity for diagnosis
    )

    stm = ShortTermMemory(conn)

    executor = CommandExecutor(
        agent_name="os_engineer",
        domain=CommandDomain.OS,
    )

    async def os_engineer_node(state: AgentState) -> AgentState:
        """Analyze an issue from the OS engineering perspective with live diagnostics."""
        session_id = state.get("session_id", "unknown")
        logger.info("OS Engineer: analyzing for session %s", session_id)

        # Initialize command tracking
        command_log: list[dict] = list(state.get("command_log", []))
        command_count: int = state.get("command_count", 0)

        # Build the query for RAG retrieval
        query = _build_query(state)

        # ── Step 1: RAG retrieval (always first) ──────────────
        context, _results = await retrieve_context(
            conn, embedding_service, query, top_k=5
        )

        # ── Handle Resumed HITL Command ──────────────────────────────
        if not state.get("hitl_pending") and state.get("hitl_command"):
            logger.info("OS Engineer: Executing approved HITL command: %s", state["hitl_command"])
            cmd_str = state["hitl_command"]
            
            if cmd_str.startswith("gcloud compute ssh"):
                available_credentials = credential_manager.list_credentials_with_plaintext()
                with resolve_credentials(cmd_str, available_credentials) as env_overrides:
                    result = await executor.execute(
                        cmd_str, env_overrides=env_overrides, reasoning="Approved via HITL", use_shell=True, skip_gate=True, original_query=query, adrs_context=context
                    )
            else:
                result = await executor.execute(
                    cmd_str, reasoning="Approved via HITL", use_shell=True, skip_gate=True, original_query=query, adrs_context=context
                )
            
            command_log.append(result.to_dict())
            command_count += 1
            
            stm.log_command(CommandExecution(
                session_id=session_id, request_id=state.get("request_id"), agent=AgentType.OS_ENGINEER, command=result.command, reasoning="Approved via HITL", exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, duration_ms=result.duration_ms, validated_by=result.validated_by, truncated=result.truncated,
            ))

        # ── Step 2-N: ReAct loop ──────────────────────────────
        command_outputs: list[str] = [_format_command_output_from_dict(c) for c in command_log]
        max_iterations = settings.cmd_max_iterations
        max_per_session = settings.cmd_max_per_session

        for iteration in range(1, max_iterations + 1):
            logger.info(
                "OS Engineer: ReAct iteration %d/%d for session %s",
                iteration, max_iterations, session_id,
            )

            # Build messages for this iteration
            messages = _build_messages(state, context, command_outputs, iteration, max_iterations, env_context)
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
                        agent=AgentType.OS_ENGINEER,
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
                logger.error("OS Engineer LLM call failed: %s", e)
                return {
                    **state,
                    "os_analysis": f"OS Engineer Agent encountered an error: {e}",
                    "current_agent": "os_engineer",
                    "command_log": command_log,
                    "command_count": command_count,
                    "error": str(e),
                    "hitl_command": "",
                    "hitl_reason": "",
                }

            # Check if the LLM is requesting an action
            action_request = _extract_json_action(response_text)

            if action_request is None:
                # No action requested — LLM produced final analysis
                logger.info(
                    "OS Engineer: produced final analysis (iteration %d)",
                    iteration,
                )
                # Persist the agent's analysis turn to STM
                stm.add_turn(ConversationTurn(
                    session_id=session_id, request_id=state.get("request_id"),
                    agent=AgentType.OS_ENGINEER,
                    content=response_text,
                ))
                return {
                    **state,
                    "os_analysis": state.get("os_analysis", "") + "\n\n" + response_text,
                    "current_agent": "os_engineer",
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

            # Resolve credentials for gcloud SSH commands
            cmd_str = command_request["command"]
            if cmd_str.startswith("gcloud compute ssh"):
                available_credentials = credential_manager.list_credentials_with_plaintext()
                with resolve_credentials(
                    cmd_str, available_credentials
                ) as env_overrides:
                    result = await executor.execute(
                        cmd_str,
                        env_overrides=env_overrides,
                        reasoning=command_request.get("reasoning", ""),
                        use_shell=True,  # gcloud needs /bin/sh PATH
                        original_query=query,
                        adrs_context=context,
                    )
            else:
                result = await executor.execute(
                    cmd_str,
                    reasoning=command_request.get("reasoning", ""),
                    use_shell=True,  # OS commands need /bin/sh for pipes
                    original_query=query,
                    adrs_context=context,
                )

            if result.exit_code == -3:
                # HITL required, pause agent execution and return to graph
                logger.info("OS Engineer pausing for HITL on command: %s", cmd_str)
                return {
                    **state,
                    "hitl_pending": True,
                    "hitl_command": result.command,
                    "hitl_reason": result.stderr,
                    "current_agent": "os_engineer",
                    "command_log": command_log,
                    "command_count": command_count,
                }

            # Track execution
            command_log.append(result.to_dict())
            command_count += 1

            # Persist command execution to STM audit trail
            stm.log_command(CommandExecution(
                session_id=session_id, request_id=state.get("request_id"),
                agent=AgentType.OS_ENGINEER,
                command=result.command,
                reasoning=command_request.get("reasoning", ""),
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=result.duration_ms,
                validated_by=result.validated_by,
                truncated=result.truncated,
            ))

            # Format output for next iteration
            output_text = _format_command_output(result)
            command_outputs.append(output_text)

        # Max iterations reached — produce best-effort analysis
        logger.warning(
            "OS Engineer: max iterations (%d) reached for session %s",
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
                    session_id=session_id, request_id=state.get("request_id"),
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.OS_ENGINEER,
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
                f"OS Engineer Agent exhausted iterations and encountered an error: {e}"
            )

        return {
            **state,
            "os_analysis": analysis,
            "current_agent": "os_engineer",
            "command_log": command_log,
            "command_count": command_count,
            "hitl_command": "",
            "hitl_reason": "",
        }

    return os_engineer_node


def _build_query(state: AgentState) -> str:
    """Build the analysis query from state.

    Args:
        state: Current agent state.

    Returns:
        A formatted query string.
    """
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
    """Build the LLM message list for a given ReAct iteration.

    Args:
        state: Current agent state.
        context: RAG-retrieved context string.
        command_outputs: List of formatted command output strings from prior iterations.
        iteration: Current iteration number (1-indexed).
        max_iterations: Maximum allowed iterations.

    Returns:
        A list of (role, content) tuples for the LLM.
    """
    messages: list[tuple[str, str]] = [
        ("system", _OS_SYSTEM_PROMPT),
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
    """Format a command result for injection into the next LLM iteration.

    Args:
        result: The command execution result.

    Returns:
        A formatted string with command, exit code, and output.
    """
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
