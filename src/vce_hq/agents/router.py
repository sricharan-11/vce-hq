"""Main Router agent.

The Router is the entry point of the agent graph. It receives a
normalized event or user query and classifies it as:
    - ``os``: OS-level issue → route to OS Engineer Agent
    - ``cloud``: Cloud-platform issue → route to Cloud Engineer Agent
    - ``multi``: Cross-layer issue → execute both agents sequentially

The Router uses a single LLM call (v1-v3 strategy) and reads session
state (STM) for conversation context.
"""

import json
import logging
import sqlite3

from langchain_google_genai import ChatGoogleGenerativeAI

from vce_hq.agents.state import AgentState
from vce_hq.config import settings
from vce_hq.db.models import ConversationTurn, AgentType, TokenUsageRecord
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.discovery.probe import EnvironmentProfile
from vce_hq.execution.validator import get_allowlist_reference

logger = logging.getLogger(__name__)

_ROUTER_SYSTEM_PROMPT = """\
You are the Supervisor Router for VCE-HQ, an AI-powered infrastructure operations orchestrator.

You are the BRAIN. The specialist agents are your hands — they gather evidence and report \
back to YOU. They do NOT produce answers for the user. YOU are the only one who decides \
when the investigation is complete.

## YOUR AGENTS
- "os_engineer": Runs local shell commands AND has global SSH access to ALL VMs via \
gcloud compute ssh. Use for any OS-level inspection: listening ports, processes, memory, \
disk, logs, systemd, docker containers, networking INSIDE a VM. This is the ONLY agent \
that can SSH into VMs and see what is actually running.
- "cloud_engineer": Runs gcloud/aws/azure/kubectl CLI commands for cloud-layer inspection: \
listing VMs, firewall rules, IAM policies, load balancers, networking, storage buckets, etc. \
This agent CANNOT SSH into VMs — it operates at the cloud API layer only.
- "finops_agent": The ruthless, paranoid CFO agent. Use this agent for ANY queries related \
to cloud consumption, billing, resource utilization efficiency, budget allocation, or architectural \
cost-saving recommendations. It tracks hourly/daily/monthly usage patterns and maps bill \
differences to workload effectiveness.

You will receive the user query/alert, plus the ongoing analysis outputs from the agents \
if they have run.

## CRITICAL PRINCIPLE: NEVER GUESS — ALWAYS GATHER EVIDENCE
Cloud metadata (tags, names, labels) is NOT sufficient to answer questions about what a VM \
is doing. You MUST dispatch the os_engineer to SSH into running VMs and inspect them \
directly. Never produce a final answer based on naming conventions, tags, or assumptions \
when OS-level evidence is available.

## CLOSED-LOOP SUPERVISION
After each agent returns its findings:
1. Cross-validate the findings against the ORIGINAL user query.
2. Check: Does this fully answer what the user asked?
3. Check: Is any data missing? Are there VMs not yet inspected? Unanswered sub-questions?
4. If INCOMPLETE → formulate a new step targeting the gap, and re-delegate.
5. If COMPLETE → delegate to "security_review" to finalize the response.

NEVER finalize prematurely. If the user asked about ALL VMs and the agent only inspected \
2 out of 3, re-delegate to cover the missing one. If the user asked for functionality \
mapping and the agent only returned ports, re-delegate for docker ps and process info.

## ORCHESTRATION RULES
1. Formulate a working theory about what is needed.
2. Delegate ONE step at a time to the appropriate agent with a specific instruction.
3. After each agent returns, analyze the output, update your theory, and delegate the next step.
4. NEVER finalize until you have gathered real evidence from every relevant running VM.
5. Once you are satisfied that the findings fully address the user's query, delegate to \
"security_review" to finalize.

## COMMON MULTI-STEP PATTERNS

### "List listening ports / processes / services on all VMs":
- Step 1 → cloud_engineer: List all VMs with zones and status.
- Step 2 → os_engineer: SSH into EACH running VM and run the appropriate diagnostic \
(ss -tulnp, ps aux, docker ps, systemctl list-units, etc.)

### "Map VMs to their functionality / What is each VM doing?":
- Step 1 → cloud_engineer: Get full VM inventory with metadata, tags, and network config.
- Step 2 → os_engineer: SSH into EACH running VM and run a comprehensive audit: \
docker ps, ps aux --sort=-%mem, ss -tulnp, systemctl list-units --type=service --state=running. \
This gives real evidence of what each VM is doing — not guesses.

### "Why is X slow / broken / unreachable?":
- Step 1 → cloud_engineer: Check firewall rules, load balancers, network config.
- Step 2 → os_engineer: SSH into the affected VM and check CPU, memory, disk, logs, processes.

IMPORTANT: If a task requires OS-level data from remote VMs (ports, processes, disk, logs, \
containers, services), you MUST delegate to the os_engineer — never expect the \
cloud_engineer to SSH.

## FALLBACK ROUTING — NEVER ACCEPT "NOT POSSIBLE"
If an agent's output contains phrases like "not possible", "command rejected", \
"VALIDATION FAILED", "not supported", "permission denied", "not in allowlist", \
or "I cannot" — DO NOT finalize the response.

Instead:
1. Consult the AVAILABLE COMMANDS reference below.
2. Find an alternative command prefix that could achieve the same goal.
3. Re-delegate to the SAME agent (or a different one if the command belongs to another domain) \
with an explicit instruction to use the specific alternative command.
4. Only finalize (delegate to security_review) if there is truly NO alternative in the allowlist.

Example: If finops_agent tried `gcloud billing info describe` and it was rejected, you \
should see `gcloud billing accounts describe` in the available commands and re-delegate with: \
"Use `gcloud billing accounts describe <ACCOUNT_ID>` to retrieve billing details."

## AVAILABLE COMMANDS
{allowlist_ref}

You MUST respond with valid JSON only, no other text:
{{
  "theory": "Your current theory based on the evidence so far",
  "delegate_to": "os_engineer" | "cloud_engineer" | "finops_agent" | "security_review",
  "instruction": "Specific instructions for the delegated agent",
  "gaps": "What is still missing or incomplete (empty string if complete)"
}}
"""


def create_router_node(
    conn: sqlite3.Connection,
    env_profile: EnvironmentProfile | None = None,
) -> callable:
    """Create the Router node function for the LangGraph graph.

    Args:
        conn: Tenant-scoped SQLite connection for STM access.
        env_profile: Auto-discovered environment profile for infrastructure
            awareness during orchestration decisions.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    # Build environment context string for prompt injection
    env_context = env_profile.to_prompt_context() if env_profile else ""

    # Build the allowlist reference for fallback routing
    allowlist_ref = get_allowlist_reference()

    llm = ChatGoogleGenerativeAI(
        model=settings.llm_model,
        google_api_key=settings.google_api_key,
        temperature=0.0,  # Deterministic orchestration
    )
    stm = ShortTermMemory(conn)

    async def router_node(state: AgentState) -> AgentState:
        """Classify the input and determine agent routing."""
        logger.info("Router: orchestrating input for session %s", state.get("session_id"))

        # Build the user message from either event or query
        if state.get("event"):
            event = state["event"]
            user_message = (
                f"ALERT:\n"
                f"Source: {event.get('source', 'unknown')}\n"
                f"Severity: {event.get('severity', 'unknown')}\n"
                f"Title: {event.get('title', 'No title')}\n"
                f"Body: {event.get('body', 'No body')}\n"
                f"Tags: {', '.join(event.get('tags', []))}"
            )
        elif state.get("user_query"):
            user_message = f"USER QUERY: {state['user_query']}"
        else:
            return {**state, "error": "No event or user query provided to Router"}

        # Include conversation history for context continuity
        conversation = ""
        if state.get("session_id"):
            conversation = stm.get_conversation_text(state["session_id"])

        # Iteration tracking
        iterations = state.get("router_iterations", 0) + 1
        max_iterations = settings.router_max_iterations
        
        # Inject the dynamic allowlist reference into the prompt template
        system_prompt = _ROUTER_SYSTEM_PROMPT.format(allowlist_ref=allowlist_ref)

        messages = [
            ("system", system_prompt),
        ]
        
        messages.append(
            ("system", 
             f"You are on Router iteration {iterations}/{max_iterations}. "
             f"If this is your last iteration, you MUST delegate to 'security_review'.")
        )
        
        if env_context:
            messages.append(("system", env_context))
        if conversation:
            messages.append(("system", f"Previous conversation context:\n{conversation}"))
            
        if state.get("os_analysis"):
            messages.append(("system", f"OS Engineer Output:\n{state['os_analysis']}"))
        if state.get("cloud_analysis"):
            messages.append(("system", f"Cloud Engineer Output:\n{state['cloud_analysis']}"))
        if state.get("finops_analysis"):
            messages.append(("system", f"FinOps Agent Output:\n{state['finops_analysis']}"))

        messages.append(("human", user_message))

        try:
            response = await llm.ainvoke(messages)
            
            usage = response.usage_metadata or {}
            if usage:
                input_details = usage.get("input_token_details") or {}
                output_details = usage.get("output_token_details") or {}
                stm.log_token_usage(TokenUsageRecord(
                    session_id=state.get("session_id", ""),
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.ROUTER,
                    prompt_tokens=usage.get("input_tokens", 0),
                    completion_tokens=usage.get("output_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    reasoning_tokens=output_details.get("reasoning", 0),
                    cache_read_tokens=input_details.get("cache_read", 0),
                    cache_creation_tokens=input_details.get("cache_creation", 0),
                    model_name=llm.model,
                ))
            
            # Safely extract text content
            content = response.content
            if isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and "text" in block:
                        text_parts.append(block["text"])
                    elif isinstance(block, str):
                        text_parts.append(block)
                content = "".join(text_parts)
            elif not isinstance(content, str):
                content = str(content)
                
            # Clean markdown code blocks
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]
            elif content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            result = json.loads(content)
            
            theory = result.get("theory", "No theory provided")
            instruction = result.get("instruction", "Proceed with analysis")
            target = result.get("delegate_to", "security_review")
            
            # If we hit the max iterations, override the target
            if iterations >= max_iterations:
                target = "security_review"
            
            # Log the router's decision to STM
            stm.add_turn(ConversationTurn(
                session_id=state.get("session_id", ""),
                agent=AgentType.ROUTER,
                content=f"[ROUTER THEORY]: {theory}\n[DELEGATED TO {target.upper()}]: {instruction}",
            ))

            return {
                **state,
                "router_theory": theory,
                "router_instruction": instruction,
                "delegate_to": target,
                "current_agent": "router",
                "conversation_history": conversation,
                "router_iterations": iterations,
            }
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error("Router failed to parse LLM response: %s", e)
            # Fail-safe: end loop
            return {
                **state,
                "router_theory": "Failed to parse orchestrator.",
                "delegate_to": "security_review",
                "current_agent": "router",
                "conversation_history": conversation,
            }

    return router_node
