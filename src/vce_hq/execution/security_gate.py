"""Pre-Execution LLM Security Gate.

Intercepts ELEVATED and CRITICAL risk commands before they execute.
Reviews the command against tenant ADRs, original query, and blast radius.
"""

import json
import logging
from dataclasses import dataclass
from enum import StrEnum

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from vce_hq.config import settings

logger = logging.getLogger(__name__)

class GateDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    REQUIRES_HITL = "requires_hitl"

@dataclass(frozen=True)
class SecurityGateResult:
    decision: GateDecision
    reason: str

# Use the same model setup as the rest of the app
genai.configure(api_key=settings.google_api_key)
_model = genai.GenerativeModel(
    model_name=settings.llm_model,
    system_instruction=(
        "You are the Pre-Execution Security Gate for an autonomous infrastructure agent. "
        "Your job is to review commands BEFORE they are executed in the tenant's environment.\n\n"
        "You will receive:\n"
        "1. The Original User Request\n"
        "2. The Tenant's Architecture Decision Records (ADRs) context\n"
        "3. The Command the agent wants to run\n"
        "4. The Agent's reasoning for running it\n"
        "5. The Command Risk Signal (ELEVATED=needs review, CRITICAL=destructive/high-blast-radius)\n\n"
        "Rules:\n"
        "- Review Depth (ELEVATED): Perform a blast radius assessment, check for cross-service dependencies, and ensure strict ADR compliance.\n"
        "- Review Depth (CRITICAL): Perform a deeper cascading effects analysis. You MUST evaluate if the destructive action will cause downstream failures.\n"
        "- If the command clearly violates the core security intent of a tenant ADR or is generally unsafe, REJECT it.\n"
        "- IMPORTANT: If an ADR provides a 'Command Template', treat it as a reference or guideline, NOT a rigid constraint. If the agent uses a different command (e.g., gcloud compute ssh instead of sshpass) that accomplishes the same goal safely, APPROVE it.\n"
        "- If the command has an ELEVATED risk and cross-service dependencies are violated, REJECT it.\n"
        "- If the command has a CRITICAL risk signal (Destructive), it REQUIRES_HITL (Human in the loop) regardless of safety.\n"
        "- If the command is safe and aligned, APPROVE it.\n\n"
        "Return JSON strictly in this schema:\n"
        "{\n"
        "  \"decision\": \"approved\" | \"rejected\" | \"requires_hitl\",\n"
        "  \"reason\": \"Detailed explanation of why.\"\n"
        "}"
    ),
)

async def review_command(
    command: str,
    domain: str,
    risk_signal: str,
    original_query: str,
    reasoning: str,
    adrs_context: str = "",
) -> SecurityGateResult:
    """Evaluate an ELEVATED/CRITICAL command using the LLM."""
    prompt = f"""
Please evaluate the following command.

Command: `{command}`
Domain: {domain}
Risk Signal: {risk_signal}

Original User Request:
{original_query}

Agent Reasoning:
{reasoning}

Tenant ADR Context:
{adrs_context if adrs_context else "No specific ADRs retrieved."}
"""
    try:
        response = await _model.generate_content_async(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
                temperature=0.0,
            ),
            safety_settings={
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            }
        )
        data = json.loads(response.text)
        decision = GateDecision(data.get("decision", "rejected").lower())
        return SecurityGateResult(
            decision=decision,
            reason=data.get("reason", "No reason provided")
        )
    except Exception as e:
        logger.error("Security gate LLM call failed: %s", e)
        # Fail safe
        return SecurityGateResult(
            decision=GateDecision.REJECTED,
            reason=f"Security gate internal error: {e}"
        )
