"""Security Review Agent (mandatory gate) with RAG.

Every agent-produced analysis passes through this gate before
surfacing to the user. The review is grounded in the tenant's
long-term vector memory (ADRs, past decisions, runbooks, infra
inventory) to ensure recommendations are consistent with the
tenant's established standards and architectural decisions.

This agent:
    - Validates that recommendations don't contradict tenant ADRs
    - Flags security concerns in proposed remediation steps
    - Enriches the output with relevant ADR references
    - Produces the final, validated analysis playbook
"""

import logging
import sqlite3

from langchain_google_genai import ChatGoogleGenerativeAI

from vce_hq.agents.rag import retrieve_context
from vce_hq.agents.state import AgentState
from vce_hq.cache_manager import cache_manager
from vce_hq.config import settings
from vce_hq.db.models import AgentType, TokenUsageRecord
from vce_hq.db.short_term import ShortTermMemory
from vce_hq.embeddings.service import EmbeddingService

logger = logging.getLogger(__name__)

_SECURITY_REVIEW_PROMPT = """\
You are the Security Review Agent for VCE-HQ. You are the MANDATORY final gate before \
any response reaches the tenant.

Your role is to:
1. Review the response from the OS and/or Cloud Engineer agents
2. Cross-reference any recommendations against the tenant's ADRs and operational standards
3. Flag security risks in any proposed remediation steps
4. Validate that no destructive commands were recommended
5. Review the executed command log — flag any commands that seemed unnecessarily broad or leaked sensitive data
6. Ensure sensitive data (API keys, passwords, tokens) in command outputs are redacted

You will receive:
- The response from the OS Engineer Agent and/or Cloud Engineer Agent
- The full log of any diagnostic commands they executed
- Retrieved context from the tenant's long-term memory (ADRs, past resolutions, standards)

CRITICAL RULES:
- You MUST NOT remove or rewrite valid analysis — only annotate, flag, or enhance it
- If a recommendation contradicts a tenant ADR, you MUST flag it clearly
- If a remediation step could cause data loss or service disruption, add a warning

## MANDATORY: TLDR FIRST
Every response you produce MUST begin with a TLDR section — a concise 1-3 sentence summary \
of the key findings. This lets busy engineers and CTOs immediately understand the result \
without reading the full analysis.

Format:
**TLDR:** [1-3 sentence executive summary of the findings]

Then continue with the detailed response below.

## RESPONSE FORMAT — ADAPT TO THE QUERY TYPE

**You MUST match your output format to the type of response the specialist agents produced:**

### FOR INFORMATIONAL RESPONSES (agent returned data like VM lists, disk usage, etc.):
Pass the data through cleanly. Do NOT wrap it in a "Security Review Status" / \
"Remediation Playbook" structure. Simply:
- Return the agent's response as-is
- Append any security notes ONLY if there are genuine concerns (e.g., sensitive data in output)
- If no concerns, just pass the response through without adding boilerplate

### FOR DIAGNOSTIC / INCIDENT RESPONSES (agent produced root cause analysis + remediation):
Use the full structured review format:

## Security Review Status
[PASSED | PASSED WITH WARNINGS | FLAGGED]

## Validated Analysis
[The complete analysis from the specialist agent(s), with your annotations]

## Security Flags
⚠️ ONLY include this section if the review status is PASSED WITH WARNINGS or FLAGGED.
If the review PASSED cleanly, DO NOT include this section at all — omit it entirely.
[List each specific contradiction, security concern, or warning as a bullet point]

## ADR References
⚠️ ONLY include this section if you actually found relevant ADRs or past decisions in the \
retrieved context. If no ADRs or past decisions were relevant, DO NOT include this section \
at all — omit it entirely. Do NOT write "None found".
[List the specific ADR names/titles and how they relate to the current analysis]

## Final Remediation Playbook
[The validated, enriched remediation steps — ONLY if the original response included remediation]
"""


def create_security_review_node(
    conn: sqlite3.Connection,
    embedding_service: EmbeddingService,
) -> callable:
    """Create the Security Review node for LangGraph.

    Args:
        conn: Tenant-scoped SQLite connection.
        embedding_service: For RAG query embedding.

    Returns:
        An async function compatible with LangGraph's node signature.
    """
    cache_name = cache_manager.get_or_create_cache(
        model_name=settings.llm_model,
        system_prompt=_SECURITY_REVIEW_PROMPT,
        env_context="",
    )

    llm_kwargs = {
        "model": settings.llm_model,
        "google_api_key": settings.google_api_key,
        "temperature": 0.0,
    }
    if cache_name:
        llm_kwargs["cached_content"] = cache_name

    llm = ChatGoogleGenerativeAI(**llm_kwargs)
    
    stm = ShortTermMemory(conn)

    async def security_review_node(state: AgentState) -> AgentState:
        """Perform mandatory security review on agent outputs."""
        logger.info("Security Review: validating for session %s", state.get("session_id"))

        # If the intent analyzer flagged this as irrelevant, just output the clarifying question
        if state.get("intent_status") == "IRRELEVANT" and state.get("clarifying_question"):
            return {
                **state,
                "security_review": state["clarifying_question"],
                "security_flags": [],
                "final_output": state["clarifying_question"],
                "current_agent": "security_review",
            }

        # Collect all agent outputs for review
        analysis_parts: list[str] = []

        if state.get("os_analysis"):
            analysis_parts.append(f"=== OS Engineer Analysis ===\n{state['os_analysis']}")

        if state.get("cloud_analysis"):
            analysis_parts.append(f"=== Cloud Engineer Analysis ===\n{state['cloud_analysis']}")

        if state.get("finops_analysis"):
            analysis_parts.append(f"=== FinOps Agent Analysis ===\n{state['finops_analysis']}")

        if not analysis_parts:
            return {
                **state,
                "security_review": "No agent analysis to review.",
                "security_flags": ["No analysis was produced by specialist agents."],
                "final_output": "Analysis failed: no specialist agent produced output.",
                "current_agent": "security_review",
            }

        command_log = state.get("command_log", [])
        if command_log:
            # Format the command log
            from vce_hq.execution.executor import CommandResult, format_command_log
            results = [
                CommandResult(
                    command_id=cmd.get("command_id", ""),
                    command=cmd.get("command", ""),
                    agent=cmd.get("agent", ""),
                    exit_code=cmd.get("exit_code"),
                    stdout=cmd.get("stdout", ""),
                    stderr=cmd.get("stderr", ""),
                    duration_ms=cmd.get("duration_ms", 0),
                    validated_by=cmd.get("validated_by", ""),
                    truncated=cmd.get("truncated", False),
                )
                for cmd in command_log
            ]
            cmd_log_text = format_command_log(results)
            analysis_parts.append(cmd_log_text)

        combined_analysis = "\n\n".join(analysis_parts)

        # RAG: retrieve ADRs and past decisions for grounding
        # We use the combined analysis as the query to find the most
        # relevant ADRs and past decisions.
        context, _results = await retrieve_context(
            conn,
            embedding_service,
            combined_analysis[:2000],  # Truncate for embedding input limits
            top_k=8,  # More results for thorough review
            category=None,  # Search all categories
            include_resolutions=True,
        )

        messages = []
        if not cache_name:
            messages.append(("system", _SECURITY_REVIEW_PROMPT))
        
        messages.append(("system", f"IMPORTANT: The agents operated in {settings.execution_mode}. Ensure their actions did not exceed this mode's capabilities."))

        if context:
            messages.append(
                ("system",
                 f"Tenant's long-term memory (ADRs, past decisions, standards):\n{context}")
            )

        messages.append(
            ("human",
             f"Please review the following agent analysis:\n\n{combined_analysis}")
        )

        try:
            response = await llm.ainvoke(messages)
            
            usage = response.usage_metadata or {}
            if usage:
                input_details = usage.get("input_token_details") or {}
                output_details = usage.get("output_token_details") or {}
                stm.log_token_usage(TokenUsageRecord(
                    session_id=state.get("session_id", ""),
                    request_id=state.get("request_id"),
                    tenant_id=state.get("tenant_id", ""),
                    agent=AgentType.SECURITY_REVIEW,
                    prompt_tokens=usage.get("input_tokens", 0),
                    completion_tokens=usage.get("output_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                    reasoning_tokens=output_details.get("reasoning", 0),
                    cache_read_tokens=input_details.get("cache_read", 0),
                    cache_creation_tokens=input_details.get("cache_creation", 0),
                    model_name=llm.model,
                ))

            content_str = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in response.content) if isinstance(response.content, list) else str(response.content)
            
            # Extract flags if any
            flags = _extract_flags(content_str)
            
            return {
                **state,
                "security_review": content_str,
                "security_flags": flags,
                "final_output": content_str,
                "current_agent": "security_review",
            }
        except Exception as e:
            logger.error("Security Review Agent failed: %s", e)
            # Fail-closed: if security review fails, DO NOT surface unreviewed analysis
            return {
                **state,
                "security_review": f"Security Review failed: {e}",
                "security_flags": [f"CRITICAL: Security Review could not complete ({e})"],
                "final_output": (
                    "⚠️ SECURITY REVIEW FAILED\n\n"
                    "The analysis could not be validated against tenant standards. "
                    "The unreviewed analysis has been withheld for safety.\n\n"
                    f"Error: {e}"
                ),
                "current_agent": "security_review",
                "error": str(e),
            }

    return security_review_node


def _extract_flags(review_content: str) -> list[str]:
    """Extract security flags from the review output.

    Looks for the "## Security Flags" section and extracts individual flags.

    Args:
        review_content: The full security review response.

    Returns:
        List of flag strings. Empty if no flags section found or flags are "None".
    """
    flags: list[str] = []

    lines = review_content.split("\n")
    in_flags_section = False

    for line in lines:
        if "## Security Flags" in line:
            in_flags_section = True
            continue
        if in_flags_section:
            if line.startswith("## "):
                break  # Next section
            stripped = line.strip().lstrip("- •*")
            if stripped and stripped.lower() != "none":
                flags.append(stripped)

    return flags
